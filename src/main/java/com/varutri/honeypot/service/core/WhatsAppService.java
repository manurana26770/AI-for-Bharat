package com.varutri.honeypot.service.core;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

/**
 * Service for WhatsApp Cloud API integration
 */
@Slf4j
@Service
public class WhatsAppService {

    @Value("${whatsapp.api.token:}")
    private String apiToken;

    @Value("${whatsapp.phone.number.id:}")
    private String phoneNumberId;

    private final WebClient webClient;

    public WhatsAppService() {
        this.webClient = WebClient.builder()
                .baseUrl("https://graph.facebook.com/v18.0")
                .build();
    }

    /**
     * Send a text message via WhatsApp
     */
    public void sendMessage(String to, String text) {
        if (apiToken == null || apiToken.isEmpty()) {
            log.warn("WhatsApp API token not configured. Skipping message send.");
            return;
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("messaging_product", "whatsapp");
        payload.put("to", to);
        payload.put("type", "text");

        Map<String, String> textBody = new HashMap<>();
        textBody.put("body", text);
        payload.put("text", textBody);

        try {
            webClient.post()
                    .uri("/" + phoneNumberId + "/messages")
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .bodyValue(payload)
                    .retrieve()
                    .bodyToMono(String.class)
                    .doOnSuccess(response -> log.info("WhatsApp message sent to {}: {}", to, response))
                    .doOnError(error -> log.error("Failed to send WhatsApp message: {}", error.getMessage()))
                    .subscribe();
        } catch (Exception e) {
            log.error("Error sending WhatsApp message: {}", e.getMessage(), e);
        }
    }

    /**
     * Send an interactive button message
     */
    public void sendButtonMessage(String to, String bodyText, String buttonText, String buttonPayload) {
        if (apiToken == null || apiToken.isEmpty()) {
            log.warn("WhatsApp API token not configured. Skipping button message send.");
            return;
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("messaging_product", "whatsapp");
        payload.put("to", to);
        payload.put("type", "interactive");

        Map<String, Object> interactive = new HashMap<>();
        interactive.put("type", "button");

        Map<String, String> body = new HashMap<>();
        body.put("text", bodyText);
        interactive.put("body", body);

        Map<String, Object> action = new HashMap<>();
        Map<String, Object>[] buttons = new Map[] {
                Map.of(
                        "type", "reply",
                        "reply", Map.of(
                                "id", buttonPayload,
                                "title", buttonText))
        };
        action.put("buttons", buttons);
        interactive.put("action", action);

        payload.put("interactive", interactive);

        try {
            webClient.post()
                    .uri("/" + phoneNumberId + "/messages")
                    .header("Authorization", "Bearer " + apiToken)
                    .header("Content-Type", "application/json")
                    .bodyValue(payload)
                    .retrieve()
                    .bodyToMono(String.class)
                    .doOnSuccess(response -> log.info("WhatsApp button message sent to {}", to))
                    .doOnError(error -> log.error("Failed to send WhatsApp button: {}", error.getMessage()))
                    .subscribe();
        } catch (Exception e) {
            log.error("Error sending WhatsApp button message: {}", e.getMessage(), e);
        }
    }

    /**
     * Send notification to user about Varutri taking control
     */
    public void notifyUserTakeover(String userPhone, String sessionId) {
        String message = "✅ Varutri has taken control of this conversation.\n\n" +
                "I'll handle the scammer for you. You'll receive updates as intelligence is extracted.\n\n" +
                "Session ID: " + sessionId;
        sendMessage(userPhone, message);
    }

    /**
     * Send intelligence update to user
     */
    public void notifyIntelligenceExtracted(String userPhone, String intelligenceType, String value) {
        String message = "🚨 *Intelligence Extracted*\n\n" +
                intelligenceType + ": " + value + "\n\n" +
                "Varutri is still engaging the scammer...";
        sendMessage(userPhone, message);
    }

    /**
     * Send final report notification
     */
    public void notifyFinalReport(String userPhone, String sessionId, int totalMessages, int intelligenceCount) {
        String message = "✅ *Scam Conversation Complete*\n\n" +
                "Session: " + sessionId + "\n" +
                "Messages: " + totalMessages + "\n" +
                "Intelligence Extracted: " + intelligenceCount + " items\n\n" +
                "Report has been sent to authorities. Thank you for using Varutri!";
        sendMessage(userPhone, message);
    }
}

