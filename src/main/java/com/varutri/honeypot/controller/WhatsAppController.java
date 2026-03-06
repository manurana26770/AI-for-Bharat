package com.varutri.honeypot.controller;

import com.varutri.honeypot.dto.ApiResponse;
import com.varutri.honeypot.dto.ChatRequest;
import com.varutri.honeypot.dto.ChatResponse;
import com.varutri.honeypot.dto.WhatsAppWebhook;
import com.varutri.honeypot.service.llm.HuggingFaceService;
import com.varutri.honeypot.service.data.SessionStore;
import com.varutri.honeypot.service.core.WhatsAppService;
import com.varutri.honeypot.service.data.EvidenceCollector;
import com.varutri.honeypot.service.ai.InformationExtractor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Controller for WhatsApp webhook integration.
 * Returns standardized ApiResponse objects with proper HTTP status codes.
 */
@Slf4j
@RestController
@RequestMapping("/api/whatsapp")
public class WhatsAppController {

    @Autowired
    private WhatsAppService whatsAppService;

    @Autowired
    private Optional<HuggingFaceService> huggingFaceService;

    @Autowired
    private SessionStore sessionStore;

    @Autowired
    private EvidenceCollector evidenceCollector;

    @Autowired
    private InformationExtractor informationExtractor;

    @Value("${whatsapp.verify.token:varutri_webhook_2026}")
    private String verifyToken;

    @Value("${llm.provider:huggingface}")
    private String llmProvider;

    // Map to track WhatsApp phone numbers to session IDs
    private final Map<String, String> phoneToSession = new HashMap<>();

    /**
     * Webhook verification endpoint (required by Meta)
     * GET /api/whatsapp/webhook
     * 
     * @return 200 OK with challenge on success
     * @return 403 Forbidden on verification failure
     */
    @GetMapping("/webhook")
    public ResponseEntity<?> verifyWebhook(
            @RequestParam("hub.mode") String mode,
            @RequestParam("hub.verify_token") String token,
            @RequestParam("hub.challenge") String challenge) {

        log.info("Webhook verification request: mode={}, token={}", mode, token);

        if ("subscribe".equals(mode) && verifyToken.equals(token)) {
            log.info(" Webhook verified successfully");
            // Meta expects the challenge string directly, not wrapped in JSON
            return ResponseEntity.ok(challenge);
        } else {
            log.warn(" Webhook verification failed");
            return ApiResponse.forbidden("VERIFICATION_FAILED",
                    "Webhook verification failed").toResponseEntity();
        }
    }

    /**
     * Webhook endpoint for receiving WhatsApp messages
     * POST /api/whatsapp/webhook
     * 
     * @return 200 OK always (WhatsApp requires 200 to confirm receipt)
     */
    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(@RequestBody WhatsAppWebhook webhook) {
        log.info("Received WhatsApp webhook: {}", webhook.getObject());

        try {
            if (webhook.getEntry() == null || webhook.getEntry().isEmpty()) {
                return ResponseEntity.ok("EVENT_RECEIVED");
            }

            for (WhatsAppWebhook.Entry entry : webhook.getEntry()) {
                if (entry.getChanges() == null)
                    continue;

                for (WhatsAppWebhook.Change change : entry.getChanges()) {
                    if (change.getValue() == null || change.getValue().getMessages() == null)
                        continue;

                    for (WhatsAppWebhook.Message message : change.getValue().getMessages()) {
                        handleIncomingMessage(message);
                    }
                }
            }

            // WhatsApp requires 200 response to confirm webhook receipt
            return ResponseEntity.ok("EVENT_RECEIVED");
        } catch (Exception e) {
            log.error("Error processing webhook: {}", e.getMessage(), e);
            // Still return 200 to WhatsApp to prevent retries
            return ResponseEntity.ok("EVENT_RECEIVED");
        }
    }

    /**
     * Handle incoming WhatsApp message
     */
    private void handleIncomingMessage(WhatsAppWebhook.Message message) {
        String from = message.getFrom();
        String messageText = null;
        String buttonPayload = null;

        // Extract message text
        if (message.getText() != null) {
            messageText = message.getText().getBody();
        } else if (message.getButton() != null) {
            buttonPayload = message.getButton().getPayload();
            messageText = message.getButton().getText();
        }

        if (messageText == null) {
            log.warn("No text in message from {}", from);
            return;
        }

        log.info("📱 WhatsApp message from {}: {}", from, messageText);

        // Check if this is a "Report to Varutri" button click
        if ("REPORT_SCAM".equals(buttonPayload)) {
            handleScamReport(from, messageText);
            return;
        }

        // Get or create session for this phone number
        String sessionId = phoneToSession.computeIfAbsent(from,
                phone -> "wa-" + phone + "-" + System.currentTimeMillis());

        // Forward to honeypot
        ChatResponse response = processScamMessage(sessionId, from, messageText);

        // Send response back to scammer via WhatsApp
        if (response != null && response.getReply() != null) {
            whatsAppService.sendMessage(from, response.getReply());
        }
    }

    /**
     * Handle scam report from user
     */
    private void handleScamReport(String userPhone, String scamMessage) {
        log.info("🚨 User {} reported scam message: {}", userPhone, scamMessage);

        // Create session
        String sessionId = "wa-user-" + userPhone + "-" + System.currentTimeMillis();
        phoneToSession.put(userPhone, sessionId);

        // Notify user that Varutri is taking over
        whatsAppService.notifyUserTakeover(userPhone, sessionId);

        // Send confirmation button
        whatsAppService.sendButtonMessage(
                userPhone,
                "I'll handle this scammer for you. Forward their messages to me, and I'll extract intelligence.",
                "Got it!",
                "CONFIRM_TAKEOVER");
    }

    /**
     * Process scam message through honeypot
     */
    private ChatResponse processScamMessage(String sessionId, String from, String messageText) {
        try {
            // Build chat request
            ChatRequest request = new ChatRequest();
            request.setSessionId(sessionId);

            ChatRequest.Message msg = new ChatRequest.Message();
            msg.setSender("scammer");
            msg.setText(messageText);
            msg.setTimestamp(System.currentTimeMillis());
            request.setMessage(msg);

            request.setConversationHistory(new ArrayList<>());
            request.setMetadata(new ChatRequest.Metadata());

            // Get AI response
            String aiResponse;
            // Determine active provider based on bean presence
            if (huggingFaceService.isPresent()) {
                aiResponse = huggingFaceService.get().generateResponse(messageText, request.getConversationHistory(),
                        "UNKNOWN", 0.0);
            } else {
                return ChatResponse.external("System error: No AI provider available.");
            }

            // Store conversation
            sessionStore.addMessage(sessionId, "scammer", messageText);
            sessionStore.addMessage(sessionId, "assistant", aiResponse);

            // Extract intelligence
            var intelligence = informationExtractor.extractInformation(messageText);
            evidenceCollector.collectEvidence(sessionId, messageText, aiResponse);

            // Notify user if significant intelligence found
            if (!intelligence.getUpiIds().isEmpty()) {
                whatsAppService.notifyIntelligenceExtracted(from, "UPI ID",
                        String.join(", ", intelligence.getUpiIds()));
            }
            if (!intelligence.getBankAccountNumbers().isEmpty()) {
                whatsAppService.notifyIntelligenceExtracted(from, "Bank Account",
                        String.join(", ", intelligence.getBankAccountNumbers()));
            }
            // SECURITY: Return ONLY the reply to external parties (scammers)
            // sessionId is stored internally but never exposed in response
            return ChatResponse.external(aiResponse);

        } catch (Exception e) {
            log.error("Error processing scam message: {}", e.getMessage(), e);
            return ChatResponse.external("I'm experiencing technical difficulties.");
        }
    }

    /**
     * Manual endpoint to initiate takeover
     * POST /api/whatsapp/takeover
     * 
     * @return 200 OK on success
     * @return 400 Bad Request if phone or message is missing
     */
    @PostMapping("/takeover")
    public ResponseEntity<ApiResponse<Map<String, String>>> initiateTakeover(
            @RequestBody Map<String, String> request) {
        String userPhone = request.get("phone");
        String scamMessage = request.get("message");

        if (userPhone == null || userPhone.isBlank()) {
            return ApiResponse.<Map<String, String>>badRequest("MISSING_PHONE",
                    "Phone number is required").toResponseEntity();
        }

        if (scamMessage == null || scamMessage.isBlank()) {
            return ApiResponse.<Map<String, String>>badRequest("MISSING_MESSAGE",
                    "Scam message is required").toResponseEntity();
        }

        handleScamReport(userPhone, scamMessage);

        Map<String, String> result = Map.of(
                "status", "success",
                "message", "Varutri takeover initiated",
                "phone", userPhone);

        return ApiResponse.ok(result, "Takeover initiated successfully");
    }

    /**
     * Get status of a WhatsApp session
     * GET /api/whatsapp/session/{phone}
     * 
     * @return 200 OK with session info
     * @return 404 Not Found if no session exists
     */
    @GetMapping("/session/{phone}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSessionStatus(@PathVariable String phone) {
        String sessionId = phoneToSession.get(phone);

        if (sessionId == null) {
            return ApiResponse.<Map<String, Object>>notFound("SESSION_NOT_FOUND",
                    "No active session for phone: " + phone).toResponseEntity();
        }

        int turnCount = sessionStore.getTurnCount(sessionId);
        EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);

        Map<String, Object> sessionInfo = Map.of(
                "phone", phone,
                "sessionId", sessionId,
                "turnCount", turnCount,
                "hasEvidence", evidence != null,
                "threatLevel", evidence != null ? evidence.getThreatLevel() : 0.0,
                "scamType", evidence != null ? evidence.getScamType() : "UNKNOWN");

        return ApiResponse.ok(sessionInfo, "Session retrieved successfully");
    }
}
