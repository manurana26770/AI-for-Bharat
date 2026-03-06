package com.varutri.honeypot.service.llm;

import com.varutri.honeypot.service.ai.PromptHardeningService;
import com.varutri.honeypot.service.ai.ResponseValidationService;
import com.varutri.honeypot.service.ai.ContextWindowManager;

import com.varutri.honeypot.dto.ChatRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelRequest;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelResponse;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * AWS Bedrock implementation of ChatLlmService.
 * Uses Claude 3 Sonnet via the Anthropic Messages API format.
 *
 * Integrated with PromptHardeningService for injection-resistant prompts
 * and ResponseValidationService for output quality assurance.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "llm.provider", havingValue = "bedrock")
public class BedrockService implements ChatLlmService {

    private final BedrockRuntimeClient bedrockClient;
    private final String modelId;
    private final PersonaService personaService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    @Lazy
    private PromptHardeningService promptHardeningService;

    @Autowired
    @Lazy
    private ContextWindowManager contextWindowManager;

    @Autowired
    @Lazy
    private ResponseValidationService responseValidationService;

    @Value("${aws.bedrock.max-tokens:200}")
    private int maxTokens;

    @Value("${aws.bedrock.temperature:0.7}")
    private double temperature;

    @Value("${validation.max-retries:2}")
    private int maxRetries;

    public BedrockService(
            BedrockRuntimeClient bedrockClient,
            @Value("${aws.bedrock.model-id:anthropic.claude-3-haiku-20240307-v1:0}") String modelId,
            PersonaService personaService) {
        this.bedrockClient = bedrockClient;
        this.modelId = modelId;
        this.personaService = personaService;

        log.info("BedrockService initialized — model: {}", modelId);
        log.info("Using persona: {}", personaService.getPersonaSummary());
    }

    @Override
    public String generateResponse(String userMessage,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String scamType, double threatLevel) {

        int attempts = 0;
        String lastResponse = null;
        ResponseValidationService.ValidationResult lastValidation = null;

        while (attempts <= maxRetries) {
            try {
                // Build system prompt with hardening
                String systemPrompt = buildSystemPrompt(userMessage, scamType, threatLevel);

                // Add retry guidance if needed
                if (attempts > 0 && lastValidation != null && responseValidationService != null) {
                    systemPrompt += "\n\n" + responseValidationService.getSuggestedFixes(lastValidation);
                    log.info("Retry attempt {} with validation guidance", attempts);
                }

                // Build messages with context management
                List<ChatRequest.ConversationMessage> managedHistory = manageContext(
                        systemPrompt, conversationHistory, userMessage);

                // Build Claude Messages API payload
                String requestBody = buildClaudeRequest(systemPrompt, managedHistory, userMessage,
                        maxTokens, temperature);

                log.debug("Sending request to Bedrock Claude (attempt {})", attempts + 1);

                InvokeModelResponse response = bedrockClient.invokeModel(InvokeModelRequest.builder()
                        .modelId(modelId)
                        .contentType("application/json")
                        .accept("application/json")
                        .body(SdkBytes.fromUtf8String(requestBody))
                        .build());

                lastResponse = parseClaudeResponse(response);

                if (lastResponse != null && !lastResponse.isBlank()) {
                    log.info("Received response from Bedrock Claude (length: {}, attempt: {})",
                            lastResponse.length(), attempts + 1);

                    // === RESPONSE VALIDATION ===
                    if (responseValidationService != null) {
                        lastValidation = responseValidationService.validateResponse(
                                lastResponse, userMessage, threatLevel);

                        if (lastValidation.isPassed()) {
                            log.info("Response validation PASSED: {}", lastValidation.getSummary());
                            return lastResponse;
                        } else {
                            log.warn("Response validation FAILED (attempt {}): {}",
                                    attempts + 1, lastValidation.getSummary());

                            if (lastValidation.canBeSanitized()) {
                                String sanitized = responseValidationService.sanitizeResponse(
                                        lastResponse, lastValidation);
                                ResponseValidationService.ValidationResult sanitizedValidation = responseValidationService
                                        .validateResponse(sanitized, userMessage, threatLevel);
                                if (sanitizedValidation.isPassed()) {
                                    log.info("Sanitized response passed validation");
                                    return sanitized;
                                }
                            }

                            if (lastValidation.needsRegeneration() && attempts < maxRetries) {
                                attempts++;
                                continue;
                            }
                        }
                    } else {
                        return lastResponse;
                    }
                } else {
                    log.error("Received null or empty response from Bedrock");
                    lastResponse = null;
                }

                attempts++;

            } catch (Exception e) {
                log.error("Error calling Bedrock API (attempt {}): {}", attempts + 1, e.getMessage());
                attempts++;
            }
        }

        // Fallback
        log.warn("All {} attempts failed, using fallback response", maxRetries + 1);
        return getFallbackResponse(userMessage, threatLevel);
    }

    @Override
    public CompletableFuture<String> generateResponseAsync(String userMessage,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String scamType, double threatLevel) {
        return CompletableFuture
                .supplyAsync(() -> generateResponse(userMessage, conversationHistory, scamType, threatLevel));
    }

    @Override
    public CompletableFuture<String> analyzeContextAsync(String systemPrompt, String userPrompt) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String requestBody = buildClaudeRequest(systemPrompt, null, userPrompt, 500, 0.3);

                InvokeModelResponse response = bedrockClient.invokeModel(InvokeModelRequest.builder()
                        .modelId(modelId)
                        .contentType("application/json")
                        .accept("application/json")
                        .body(SdkBytes.fromUtf8String(requestBody))
                        .build());

                String result = parseClaudeResponse(response);
                return result != null ? result : "";

            } catch (Exception e) {
                log.error("Bedrock context analysis failed: {}", e.getMessage());
                return "";
            }
        });
    }

    // ========================================================================
    // CLAUDE MESSAGES API HELPERS
    // ========================================================================

    /**
     * Build Claude 3 Messages API JSON payload.
     * Format: {
     * "anthropic_version": "bedrock-2023-05-31",
     * "max_tokens": N,
     * "temperature": T,
     * "system": "...",
     * "messages": [{"role":"user","content":"..."}, ...]
     * }
     */
    private String buildClaudeRequest(String systemPrompt,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String userMessage, int tokens, double temp) {
        try {
            ObjectNode root = objectMapper.createObjectNode();
            root.put("anthropic_version", "bedrock-2023-05-31");
            root.put("max_tokens", tokens);
            root.put("temperature", temp);
            root.put("system", systemPrompt);

            ArrayNode messages = objectMapper.createArrayNode();

            // Add conversation history (roles must alternate user/assistant)
            if (conversationHistory != null) {
                for (ChatRequest.ConversationMessage msg : conversationHistory) {
                    ObjectNode msgNode = objectMapper.createObjectNode();
                    String role = msg.getSender();
                    if ("scammer".equals(role)) {
                        role = "user";
                    } else if ("user".equals(role)) {
                        role = "assistant";
                    }
                    msgNode.put("role", role);
                    msgNode.put("content", msg.getText());
                    messages.add(msgNode);
                }
            }

            // Add current user message
            ObjectNode userMsg = objectMapper.createObjectNode();
            userMsg.put("role", "user");
            userMsg.put("content", userMessage);
            messages.add(userMsg);

            root.set("messages", messages);
            return objectMapper.writeValueAsString(root);

        } catch (Exception e) {
            throw new RuntimeException("Failed to build Claude request JSON", e);
        }
    }

    /**
     * Parse Claude 3 response: { "content": [{"type":"text","text":"..."}] }
     */
    private String parseClaudeResponse(InvokeModelResponse response) {
        try {
            String responseBody = response.body().asUtf8String();
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode content = root.path("content");
            if (content.isArray() && content.size() > 0) {
                return content.get(0).path("text").asText("").trim();
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to parse Claude response: {}", e.getMessage());
            return null;
        }
    }

    // ========================================================================
    // PROMPT BUILDING (same logic as HuggingFaceService)
    // ========================================================================

    private String buildSystemPrompt(String userMessage, String scamType, double threatLevel) {
        if (promptHardeningService != null) {
            PromptHardeningService.PromptInjectionAnalysis injectionCheck = promptHardeningService
                    .analyzeForInjection(userMessage);

            if (injectionCheck.isDetected()) {
                log.warn("Prompt injection attempt detected! Risk: {}",
                        String.format("%.0f%%", injectionCheck.getRiskScore() * 100));
                threatLevel = Math.max(threatLevel, 0.7);
            }

            String threatCategory = getThreatCategory(threatLevel);
            int triggeredLayers = estimateTriggeredLayers(threatLevel);

            PromptHardeningService.HardenedPrompt hardenedPromptObj = promptHardeningService.buildSystemPrompt(scamType,
                    threatLevel, threatCategory, triggeredLayers);

            return hardenedPromptObj.getSystemPrompt();
        } else {
            String prompt = personaService.getCurrentPersonaPrompt();
            if (threatLevel >= 0.6) {
                prompt += "\n\nSYSTEM ALERT: This user is a suspected scammer (Type: " + scamType + "). " +
                        "Be extra cautious. Ask for more details. Do NOT give money or bank details yet. " +
                        "Stall them by acting confused or asking to wait.";
            }
            return prompt;
        }
    }

    private List<ChatRequest.ConversationMessage> manageContext(
            String systemPrompt, List<ChatRequest.ConversationMessage> history, String userMessage) {
        if (contextWindowManager != null && history != null && !history.isEmpty()) {
            ContextWindowManager.ManagedContext managedContext = contextWindowManager.buildContext(
                    systemPrompt, history, null, userMessage);
            if (managedContext.isWasTruncated()) {
                log.info("Context truncated: {} turns kept, {} summarized",
                        managedContext.getTurnsPreserved(), managedContext.getTurnsSummarized());
            }
            return managedContext.getRecentMessages();
        }
        return history;
    }

    private String getThreatCategory(double threatLevel) {
        if (threatLevel >= 0.8)
            return "CRITICAL";
        if (threatLevel >= 0.6)
            return "HIGH";
        if (threatLevel >= 0.4)
            return "MEDIUM";
        if (threatLevel >= 0.2)
            return "LOW";
        return "SAFE";
    }

    private int estimateTriggeredLayers(double threatLevel) {
        if (threatLevel >= 0.8)
            return 5;
        if (threatLevel >= 0.6)
            return 4;
        if (threatLevel >= 0.4)
            return 3;
        if (threatLevel >= 0.2)
            return 2;
        if (threatLevel > 0)
            return 1;
        return 0;
    }

    private String getFallbackResponse(String userMessage, double threatLevel) {
        String personaName = personaService.getCurrentPersona().getName();
        String[] fallbacks;

        if (threatLevel >= 0.6) {
            fallbacks = new String[] {
                    "Sir, network is very slow here. Sending failed. Trying again...",
                    "Wait, the UPI app is updating. Give me 2 minutes.",
                    "I am trying to process the payment but it says server busy. One moment.",
                    "Hold on, let me check my balance first.",
                    "The details are not loading clearly. Can you send again?"
            };
        } else {
            fallbacks = new String[] {
                    "Okay, tell me exactly how to do this.",
                    "I am interested. What is the next step?",
                    "Share the details fast, I have free time now.",
                    "Is there any joining fee? Please clarify.",
                    "Okay, I am ready. Send the info."
            };
        }

        int index = (int) (Math.random() * fallbacks.length);
        String fallback = fallbacks[index];
        log.info("Using fallback response for persona {}: {}", personaName, fallback);
        return fallback;
    }
}
