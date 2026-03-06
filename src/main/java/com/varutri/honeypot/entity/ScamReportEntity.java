package com.varutri.honeypot.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.index.Indexed;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * MongoDB entity for storing government scam reports
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "scam_reports")
public class ScamReportEntity {

    @Id
    private String id;

    @Indexed(unique = true)
    private String reportId;

    @Indexed
    private String sessionId;

    private LocalDateTime timestamp;

    // Scam details
    private String scamType;
    private double threatLevel;
    private int totalMessages;

    // Extracted intelligence
    @Builder.Default
    private List<String> upiIds = new ArrayList<>();
    @Builder.Default
    private List<String> bankAccounts = new ArrayList<>();
    @Builder.Default
    private List<String> ifscCodes = new ArrayList<>();
    @Builder.Default
    private List<String> phoneNumbers = new ArrayList<>();
    @Builder.Default
    private List<String> urls = new ArrayList<>();
    @Builder.Default
    private List<String> suspiciousKeywords = new ArrayList<>();

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
