package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for scam simulation scenarios
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScamScenario {

    private String scenarioId;
    private String scenarioName;
    private String scamType;
    private String description;
    private List<ScamMessage> messages;
    private ExpectedIntelligence expectedIntelligence;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScamMessage {
        private String sender; // "scammer" or "system"
        private String text;
        private int delayMs; // Delay before sending
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExpectedIntelligence {
        private List<String> expectedUpiIds;
        private List<String> expectedBankAccounts;
        private List<String> expectedPhoneNumbers;
        private List<String> expectedUrls;
        private List<String> expectedKeywords;
        private double minThreatLevel;
    }
}
