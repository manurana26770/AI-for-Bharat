package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Chat response for honeypot interactions.
 * 
 * SECURITY NOTE:
 * - External responses (to scammers): Only include 'reply' field
 * - Internal responses (admin/monitoring): Can include metadata
 * 
 * The external response should NEVER reveal:
 * - Session IDs (tracking info)
 * - LLM provider details (infrastructure info)
 * - Processing times (timing attack vector)
 * - Threat assessments (reveals detection capability)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChatResponse {

    /**
     * The AI-generated reply to send to the external party (scammer).
     * This is the ONLY field that should be included in external responses.
     */
    @JsonProperty("reply")
    private String reply;

    // ==================== INTERNAL METADATA (NOT FOR EXTERNAL USE)
    // ====================
    // These fields are only populated for internal/admin endpoints
    // They should NEVER be returned to the scammer

    /**
     * Internal session tracking ID.
     * WARNING: Never expose to external parties.
     */
    @JsonProperty("sessionId")
    private String sessionId;

    /**
     * Threat assessment details.
     * WARNING: Never expose to external parties - reveals detection capabilities.
     */
    @JsonProperty("threatAssessment")
    private ThreatInfo threatAssessment;

    /**
     * Extracted intelligence from the scam message.
     * This IS safe to return - it's the intelligence gathered from the scammer.
     */
    @JsonProperty("extractedIntelligence")
    private ExtractedIntelligence extractedIntelligence;

    /**
     * Response generation metadata.
     * WARNING: Never expose to external parties - reveals infrastructure.
     */
    @JsonProperty("metadata")
    private ResponseMetadata metadata;

    // ==================== FACTORY METHODS FOR EXTERNAL RESPONSES
    // ====================

    /**
     * Create a SAFE external response with ONLY the reply.
     * Use this for responses going back to scammers.
     */
    public static ChatResponse external(String reply) {
        return ChatResponse.builder()
                .reply(reply)
                .build();
    }

    /**
     * Create a response with reply AND extracted intelligence.
     * Use this for honeypot responses that need to report gathered intel.
     */
    public static ChatResponse withIntelligence(String reply, ExtractedInfo extractedInfo) {
        ExtractedIntelligence intel = ExtractedIntelligence.fromExtractedInfo(extractedInfo);
        return ChatResponse.builder()
                .reply(reply)
                .extractedIntelligence(intel)
                .build();
    }

    /**
     * Create a minimal response (alias for external)
     */
    public static ChatResponse of(String reply) {
        return external(reply);
    }

    // ==================== FACTORY METHODS FOR INTERNAL RESPONSES
    // ====================

    /**
     * Create a full internal response with all metadata.
     * Use this ONLY for internal/admin endpoints.
     */
    public static ChatResponse internal(String sessionId, String reply,
            String scamType, double threatLevel, String llmProvider, long processingTimeMs) {
        return ChatResponse.builder()
                .sessionId(sessionId)
                .reply(reply)
                .threatAssessment(ThreatInfo.builder()
                        .scamType(scamType)
                        .threatLevel(threatLevel)
                        .isHighThreat(threatLevel >= 0.6)
                        .build())
                .metadata(ResponseMetadata.builder()
                        .llmProvider(llmProvider)
                        .generatedAt(System.currentTimeMillis())
                        .processingTimeMs(processingTimeMs)
                        .build())
                .build();
    }

    /**
     * Create an internal response for session tracking.
     * Use this ONLY for internal/admin endpoints.
     */
    public static ChatResponse forSession(String sessionId, String reply) {
        return ChatResponse.builder()
                .sessionId(sessionId)
                .reply(reply)
                .build();
    }

    /**
     * Strip sensitive metadata and return external-safe version
     */
    public ChatResponse toExternalResponse() {
        return ChatResponse.builder()
                .reply(this.reply)
                .build();
    }

    // ==================== NESTED DTOs (INTERNAL ONLY) ====================

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ThreatInfo {
        @JsonProperty("scamType")
        private String scamType;

        @JsonProperty("threatLevel")
        private double threatLevel;

        @JsonProperty("isHighThreat")
        private boolean isHighThreat;

        @JsonProperty("threatCategory")
        private String threatCategory;

        @JsonProperty("confidence")
        private Double confidence;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ResponseMetadata {
        @JsonProperty("validationPassed")
        private Boolean validationPassed;

        @JsonProperty("sanitized")
        private Boolean sanitized;

        @JsonProperty("retryCount")
        private Integer retryCount;

        @JsonProperty("llmProvider")
        private String llmProvider;

        @JsonProperty("generatedAt")
        private Long generatedAt;

        @JsonProperty("processingTimeMs")
        private Long processingTimeMs;
    }
}
