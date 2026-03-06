package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Final result payload for GUVI Hackathon callback
 * POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FinalResultRequest {

    @JsonProperty("sessionId")
    private String sessionId;

    @JsonProperty("scamDetected")
    private boolean scamDetected;

    @JsonProperty("totalMessagesExchanged")
    private int totalMessagesExchanged;

    @JsonProperty("extractedIntelligence")
    private ExtractedIntelligence extractedIntelligence;

    @JsonProperty("agentNotes")
    private String agentNotes;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExtractedIntelligence {
        @JsonProperty("bankAccounts")
        private List<String> bankAccounts;

        @JsonProperty("upiIds")
        private List<String> upiIds;

        @JsonProperty("phishingLinks")
        private List<String> phishingLinks;

        @JsonProperty("phoneNumbers")
        private List<String> phoneNumbers;

        @JsonProperty("suspiciousKeywords")
        private List<String> suspiciousKeywords;
    }
}
