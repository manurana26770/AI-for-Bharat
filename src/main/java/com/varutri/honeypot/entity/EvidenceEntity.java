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
 * MongoDB entity for storing evidence packages from scam conversations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "evidence")
public class EvidenceEntity {

    @Id
    private String id;

    @Indexed(unique = true)
    private String sessionId;

    private LocalDateTime firstContact;

    private LocalDateTime lastUpdated;

    private String scamType;

    private double threatLevel;

    private List<ConversationTurn> conversation;

    private ExtractedIntelligence extractedInfo;

    /**
     * Conversation turn record
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationTurn {
        private LocalDateTime timestamp;
        private String userMessage;
        private String assistantReply;
    }

    /**
     * Extracted intelligence from scam messages
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ExtractedIntelligence {
        @Builder.Default
        private List<String> upiIds = new ArrayList<>();
        @Builder.Default
        private List<String> bankAccountNumbers = new ArrayList<>();
        @Builder.Default
        private List<String> ifscCodes = new ArrayList<>();
        @Builder.Default
        private List<String> phoneNumbers = new ArrayList<>();
        @Builder.Default
        private List<String> urls = new ArrayList<>();
        @Builder.Default
        private List<String> emails = new ArrayList<>();
        @Builder.Default
        private List<String> suspiciousKeywords = new ArrayList<>();
    }

    /**
     * Initialize with session ID
     */
    public static EvidenceEntity createNew(String sessionId) {
        return EvidenceEntity.builder()
                .sessionId(sessionId)
                .firstContact(LocalDateTime.now())
                .lastUpdated(LocalDateTime.now())
                .scamType("UNKNOWN")
                .threatLevel(0.0)
                .conversation(new ArrayList<>())
                .extractedInfo(new ExtractedIntelligence())
                .build();
    }
}
