package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for government scam report
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScamReport {

    private String reportId;
    private LocalDateTime timestamp;
    private String sessionId;

    // Scam details
    private String scamType;
    private double threatLevel;
    private int totalMessages;

    // Extracted intelligence
    private List<String> upiIds;
    private List<String> bankAccounts;
    private List<String> ifscCodes;
    private List<String> phoneNumbers;
    private List<String> urls;
    private List<String> suspiciousKeywords;

    // Full conversation
    private List<ConversationTurn> conversation;

    // Metadata
    private String victimProfile;
    private String reportedBy;
    private ReportStatus status;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationTurn {
        private LocalDateTime timestamp;
        private String sender;
        private String message;
    }

    public enum ReportStatus {
        PENDING,
        SENT,
        FAILED,
        ARCHIVED
    }
}
