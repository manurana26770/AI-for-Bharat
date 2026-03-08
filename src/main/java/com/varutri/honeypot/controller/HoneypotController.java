package com.varutri.honeypot.controller;

import com.varutri.honeypot.service.security.InputSanitizer;
import com.varutri.honeypot.service.core.GovernmentReportService;
import com.varutri.honeypot.service.data.SessionStore;
import com.varutri.honeypot.service.core.CallbackService;
import com.varutri.honeypot.service.ai.InformationExtractor;
import com.varutri.honeypot.service.ai.EnsembleThreatScorer;
import com.varutri.honeypot.service.llm.ChatLlmService;
import com.varutri.honeypot.service.data.EvidenceCollector;

import com.varutri.honeypot.dto.ApiResponse;
import com.varutri.honeypot.dto.ChatRequest;
import com.varutri.honeypot.dto.ChatResponse;
import com.varutri.honeypot.dto.ExtractedInfo;

import com.varutri.honeypot.dto.ThreatAssessmentResponse;
import com.varutri.honeypot.exception.ResourceNotFoundException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Main REST controller for honeypot chat API
 * Returns standardized ApiResponse objects with proper HTTP status codes
 */
@Slf4j
@RestController
@RequestMapping("/api")
@Tag(name = "Honeypot Chat", description = "Core honeypot chat endpoints — engage scammers, assess threats, collect evidence, and trigger callbacks")
public class HoneypotController {

    @Autowired
    private Optional<ChatLlmService> chatLlmService;

    @Autowired
    private SessionStore sessionStore;

    @Autowired
    private CallbackService callbackService;

    @Autowired
    private InformationExtractor informationExtractor;

    @Autowired
    private EvidenceCollector evidenceCollector;

    @Autowired
    private GovernmentReportService governmentReportService;

    @Autowired
    private InputSanitizer inputSanitizer;

    @Autowired
    private EnsembleThreatScorer ensembleThreatScorer;

    @Value("${varutri.session.max-turns:20}")
    private int maxTurns;

    @Value("${llm.provider:huggingface}")
    private String llmProvider;

    @Operation(
            summary = "Chat with a scammer",
            description = """
                    Main honeypot chat endpoint. Send a scammer's message and receive an AI-generated persona response.

                    **Pipeline:**
                    1. Input sanitization & prompt-injection detection
                    2. Parallel: Information extraction (UPI, bank accounts, phones, URLs) + 5-layer ensemble threat scoring
                    3. AI response generation via configured LLM (HuggingFace / AWS Bedrock)
                    4. Evidence collection & session tracking
                    5. Auto-callback when max turns reached or critical evidence found
                    """
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Chat message from the scammer",
            required = true,
            content = @Content(schema = @Schema(implementation = ChatRequest.class),
                    examples = @ExampleObject(name = "Bank Refund Scam", value = """
                            {
                              "sessionId": "session-001",
                              "message": {
                                "sender": "scammer",
                                "text": "Hello sir, your bank refund of Rs 5000 is pending. Please share your UPI ID to process.",
                                "timestamp": 1709827200000
                              },
                              "conversationHistory": [],
                              "metadata": {
                                "channel": "whatsapp",
                                "language": "en"
                              }
                            }
                            """))
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "AI persona reply generated successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid request body"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "LLM service unavailable")
    })
    @PostMapping("/chat")
    public java.util.concurrent.CompletableFuture<ResponseEntity<Map<String, String>>> chat(
            @Valid @RequestBody ChatRequest request) {

        long startTime = System.currentTimeMillis();
        String sessionId = inputSanitizer.sanitizeSessionId(request.getSessionId());
        String userMessage = request.getMessage().getText();
        String sender = request.getMessage().getSender();

        log.info("Received message for session {}: {} from {}",
                sessionId, inputSanitizer.sanitizeForLogging(userMessage), sender);

        if (inputSanitizer.containsPromptInjection(userMessage)) {
            log.warn("Potential prompt injection detected in session {}", sessionId);
        }

        // 1. Parallel Task: Extract Information (runs in common pool)
        java.util.concurrent.CompletableFuture<ExtractedInfo> extractionFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> informationExtractor.extractInformation(userMessage));

        // 2. Parallel Task: Threat Assessment (fully async pipeline)
        java.util.concurrent.CompletableFuture<EnsembleThreatScorer.ThreatAssessment> assessmentFuture = ensembleThreatScorer
                .assessThreatAsync(userMessage, request.getConversationHistory());

        // 3. Combine results and proceed to Response Generation
        return java.util.concurrent.CompletableFuture.allOf(extractionFuture, assessmentFuture)
                .thenCompose(v -> {
                    // Both parallel tasks are done
                    ExtractedInfo extracted = extractionFuture.join();
                    EnsembleThreatScorer.ThreatAssessment assessment = assessmentFuture.join();

                    double threatLevel = assessment.ensembleScore;
                    String scamType = assessment.primaryScamType;
                    String threatCategory = assessment.threatLevel;

                    if (assessment.isHighThreat()) {
                        log.warn(
                                "HIGH THREAT DETECTED! Session: {}, Type: {}, Level: {}, Confidence: {}%, Layers: {}/5",
                                sessionId, scamType, threatCategory,
                                String.format("%.0f", assessment.calibratedConfidence * 100),
                                assessment.triggeredLayers);
                    }

                    // Synchronous DB operations (Degraded mode support)
                    try {
                        sessionStore.addMessage(sessionId, sender, userMessage);
                    } catch (Exception e) {
                        log.warn("Failed to store user message (DB issue): {}", e.getMessage());
                    }

                    List<ChatRequest.ConversationMessage> conversationHistory = mergeConversationHistory(sessionId,
                            request.getConversationHistory());

                    // Capture for inner lambda
                    final ExtractedInfo finalExtracted = extracted;
                    final String finalScamType = scamType;
                    final double finalThreatLevel = threatLevel;
                    final String finalThreatCategory = threatCategory;

                    // 4. Async Response Generation
                    return generateResponseAsync(userMessage, conversationHistory, scamType, threatLevel)
                            .thenApply(aiResponse -> {
                                // 5. Post-response processing
                                try {
                                    sessionStore.addMessage(sessionId, "assistant", aiResponse);
                                    boolean hasNewIntel = evidenceCollector.collectEvidence(sessionId, userMessage,
                                            aiResponse);
                                    sessionStore.updateIntelligenceStatus(sessionId, hasNewIntel);

                                    EvidenceCollector.EvidencePackage currentEvidence = evidenceCollector
                                            .getEvidence(sessionId);
                                    boolean hasCritical = currentEvidence != null
                                            && currentEvidence.hasCriticalEvidence();
                                    boolean highThreat = currentEvidence != null && currentEvidence.isHighThreat();

                                    if (sessionStore.shouldTriggerCallback(sessionId, maxTurns, highThreat,
                                            hasCritical)) {
                                        log.info("Session {} reached max turns, triggering callback", sessionId);
                                        // Run non-critical callbacks in background
                                        java.util.concurrent.CompletableFuture.runAsync(() -> {
                                            try {
                                                sendFinalCallback(sessionId);
                                                governmentReportService.processAutoReport(sessionId);
                                            } catch (Exception ex) {
                                                log.warn("Failed to send callback (async): {}", ex.getMessage());
                                            }
                                        });
                                    }
                                } catch (Exception e) {
                                    log.warn("Failed to store assistant response/evidence (DB issue): {}",
                                            e.getMessage());
                                }

                                long processingTime = System.currentTimeMillis() - startTime;
                                log.info("Response generated for session {} (threat: {}, {}ms)",
                                        sessionId, finalThreatCategory, processingTime);

                                // Build flat response structure as requested
                                Map<String, String> response = Map.of(
                                        "status", "success",
                                        "reply", aiResponse);
                                return ResponseEntity.ok(response);
                            });
                })
                .exceptionally(e -> {
                    log.error("Error processing chat for session {}: {}", sessionId, e.getMessage(), e);
                    // Unwrap CompletionException
                    Throwable cause = e instanceof java.util.concurrent.CompletionException ? e.getCause() : e;

                    if (cause instanceof IllegalStateException) {
                        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .body(Map.of("status", "error", "reply", "AI service configuration error"));
                    }
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(Map.of("status", "error", "reply", "Failed to process message"));
                });
    }

    /**
     * Generate response asynchronously using configured LLM provider
     */
    private java.util.concurrent.CompletableFuture<String> generateResponseAsync(String userMessage,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String scamType, double threatLevel) {

        if (chatLlmService.isPresent()) {
            return chatLlmService.get().generateResponseAsync(userMessage, conversationHistory, scamType,
                    threatLevel);
        } else {
            return java.util.concurrent.CompletableFuture.failedFuture(
                    new IllegalStateException(
                            "No LLM service configured. Please set llm.provider to 'huggingface' or 'bedrock'"));
        }
    }

    @Operation(
            summary = "Health check",
            description = "Returns the health status of the honeypot service, including the active LLM provider and its availability."
    )
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Service is healthy")
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> health() {
        Map<String, Object> healthData = Map.of(
                "status", "healthy",
                "service", "varutri-honeypot",
                "llmProvider", llmProvider,
                "llmAvailable", chatLlmService.isPresent());

        return ApiResponse.ok(healthData, "Service is healthy");
    }

    @Operation(
            summary = "Assess threat level of a message",
            description = """
                    Runs a comprehensive 5-layer ensemble threat analysis on the provided message.

                    **Layers:** Keyword matching, Regex patterns, ML phishing detection, Semantic analysis, Contextual scoring.
                    Returns threat level (SAFE/LOW/MEDIUM/HIGH/CRITICAL), confidence %, scam type, and per-layer breakdown.
                    """
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Message to assess",
            content = @Content(schema = @Schema(implementation = ChatRequest.class),
                    examples = @ExampleObject(name = "Suspicious message", value = """
                            {
                              "sessionId": "assess-001",
                              "message": {
                                "sender": "scammer",
                                "text": "Congratulations! You won Rs 25 lakh lottery. Send Rs 5000 processing fee to UPI invest@oksbi",
                                "timestamp": 1709827200000
                              },
                              "conversationHistory": []
                            }
                            """))
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Threat assessment completed"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid request")
    })
    @PostMapping("/assess")
    public ResponseEntity<ApiResponse<ThreatAssessmentResponse>> assessThreat(
            @Valid @RequestBody ChatRequest request) {
        try {
            String sessionId = request.getSessionId();
            String userMessage = request.getMessage().getText();

            // Sanitize input
            userMessage = inputSanitizer.sanitizeMessageText(userMessage);

            log.info("Threat assessment requested for session: {}", sessionId);

            // Perform comprehensive ensemble threat analysis
            EnsembleThreatScorer.ThreatAssessment assessment = ensembleThreatScorer.assessThreat(userMessage,
                    request.getConversationHistory());

            // Convert to API response
            ThreatAssessmentResponse response = ThreatAssessmentResponse.fromAssessment(assessment);

            log.info("Assessment complete: {} ({}% confidence)",
                    response.getThreatLevel(),
                    response.getConfidencePercent());

            return ApiResponse.ok(response, "Threat assessment completed");

        } catch (Exception e) {
            log.error("Error in threat assessment: {}", e.getMessage(), e);
            return ApiResponse.<ThreatAssessmentResponse>internalError("ASSESSMENT_ERROR",
                    "Failed to complete threat assessment").toResponseEntity();
        }
    }

    @Operation(
            summary = "Trigger callback for a session",
            description = "Manually trigger the final callback report for a given session. Sends extracted intelligence to the hackathon platform."
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Callback sent successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Session not found")
    })
    @PostMapping("/callback/{sessionId}")
    public ResponseEntity<ApiResponse<Map<String, String>>> triggerCallback(
            @Parameter(description = "Session ID to trigger callback for", example = "session-001")
            @PathVariable String sessionId) {
        log.info("Manual callback triggered for session: {}", sessionId);

        EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);
        if (evidence == null) {
            throw new ResourceNotFoundException("Session", sessionId);
        }

        sendFinalCallback(sessionId);

        Map<String, String> result = Map.of(
                "sessionId", sessionId,
                "status", "callback_sent");

        return ApiResponse.ok(result, "Callback sent successfully");
    }

    @Operation(
            summary = "Get evidence for a session",
            description = "Retrieve the full evidence package for a specific session, including extracted UPI IDs, bank accounts, phone numbers, URLs, and conversation log."
    )
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Evidence retrieved"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "No evidence found for session")
    })
    @GetMapping("/evidence/{sessionId}")
    public ResponseEntity<ApiResponse<EvidenceCollector.EvidencePackage>> getEvidence(
            @Parameter(description = "Session ID", example = "session-001")
            @PathVariable String sessionId) {
        log.info("Evidence requested for session: {}", sessionId);

        EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);

        if (evidence == null) {
            throw new ResourceNotFoundException("Evidence", sessionId);
        }

        return ApiResponse.ok(evidence, "Evidence retrieved successfully");
    }

    @Operation(
            summary = "Get high-threat evidence",
            description = "Retrieve all evidence packages that have been classified as high threat (threat level >= 0.6)."
    )
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "High-threat evidence list retrieved")
    @GetMapping("/evidence/high-threat")
    public ResponseEntity<ApiResponse<List<EvidenceCollector.EvidencePackage>>> getHighThreatEvidence() {
        log.info("High-threat evidence requested");
        List<EvidenceCollector.EvidencePackage> evidence = evidenceCollector.getHighThreatEvidence();

        return ApiResponse.ok(evidence,
                String.format("Retrieved %d high-threat evidence package(s)", evidence.size()));
    }

    @Operation(
            summary = "Get all evidence",
            description = "Retrieve all collected evidence packages across all sessions."
    )
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "All evidence retrieved")
    @GetMapping("/evidence")
    public ResponseEntity<ApiResponse<List<EvidenceCollector.EvidencePackage>>> getAllEvidence() {
        log.info("All evidence requested");
        List<EvidenceCollector.EvidencePackage> evidence = evidenceCollector.getAllEvidence();

        return ApiResponse.ok(evidence,
                String.format("Retrieved %d evidence package(s)", evidence.size()));
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Merge conversation histories
     */
    private List<ChatRequest.ConversationMessage> mergeConversationHistory(
            String sessionId,
            List<ChatRequest.ConversationMessage> requestHistory) {
        if (requestHistory != null && !requestHistory.isEmpty()) {
            return requestHistory;
        }
        try {
            return sessionStore.getConversationHistory(sessionId);
        } catch (Exception e) {
            log.warn("Failed to fetch conversation history (DB issue): {}", e.getMessage());
            return new java.util.ArrayList<>();
        }
    }

    /**
     * Send final callback with extracted intelligence to GUVI
     */
    private void sendFinalCallback(String sessionId) {
        try {
            EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);

            if (evidence != null && evidence.getThreatLevel() >= 0.5) {
                String agentNotes = String.format("Scam type: %s, Threat level: %.2f, Engagement successful",
                        evidence.getScamType(), evidence.getThreatLevel());

                callbackService.sendFinalReport(
                        sessionId,
                        evidence.getExtractedInfo(),
                        evidence.getConversation().size(),
                        agentNotes);

                log.info("Final callback sent to GUVI for session {}", sessionId);
            } else {
                log.warn("No evidence found for session {}, skipping callback", sessionId);
            }

            sessionStore.clearSession(sessionId);

        } catch (Exception e) {
            log.error("Error sending final callback for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
}
