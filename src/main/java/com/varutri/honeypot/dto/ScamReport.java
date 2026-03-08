package com.varutri.honeypot.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Scam intelligence report — compiled evidence for government authorities")
public class ScamReport {

    @Schema(description = "Unique report identifier", example = "RPT-20240307-abc123")
    private String reportId;
    private LocalDateTime timestamp;
    @Schema(description = "Session ID this report belongs to", example = "session-001")
    private String sessionId;

    @Schema(description = "Detected scam type", example = "FINANCIAL_FRAUD")
    private String scamType;
    @Schema(description = "Threat level (0.0 to 1.0)", example = "0.85")
    private double threatLevel;
    @Schema(description = "Total messages exchanged in session", example = "12")
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
