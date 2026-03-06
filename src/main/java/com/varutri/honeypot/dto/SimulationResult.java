package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for simulation test results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SimulationResult {

    private String sessionId;
    private String scenarioName;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private long durationMs;

    private int totalMessages;
    private List<ConversationTurn> conversation;

    private ExtractedInfo actualIntelligence;
    private ScamScenario.ExpectedIntelligence expectedIntelligence;

    private ValidationResults validation;
    private boolean passed;
    private String summary;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationTurn {
        private String sender;
        private String message;
        private String response;
        private LocalDateTime timestamp;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValidationResults {
        private boolean upiIdsMatch;
        private boolean bankAccountsMatch;
        private boolean phoneNumbersMatch;
        private boolean urlsMatch;
        private boolean keywordsMatch;
        private boolean threatLevelMet;
        private List<String> missingIntelligence;
        private List<String> unexpectedIntelligence;
    }
}
