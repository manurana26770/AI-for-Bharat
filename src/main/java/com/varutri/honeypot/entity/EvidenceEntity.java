package com.varutri.honeypot.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.ArrayList;
import java.util.List;

/**
 * DynamoDB entity for storing evidence packages from scam conversations.
 * Table: varutri_evidence | Partition Key: sessionId
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class EvidenceEntity {

    private String sessionId;

    private String firstContact;

    private String lastUpdated;

    private String scamType;

    private double threatLevel;

    private List<ConversationTurn> conversation;

    private ExtractedIntelligence extractedInfo;

    @DynamoDbPartitionKey
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Conversation turn record
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class ConversationTurn {
        private String timestamp;
        private String userMessage;
        private String assistantReply;
    }

    /**
     * Extracted intelligence from scam messages
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class ExtractedIntelligence {
        private List<String> upiIds = new ArrayList<>();
        private List<String> bankAccountNumbers = new ArrayList<>();
        private List<String> ifscCodes = new ArrayList<>();
        private List<String> phoneNumbers = new ArrayList<>();
        private List<String> urls = new ArrayList<>();
        private List<String> emails = new ArrayList<>();
        private List<String> suspiciousKeywords = new ArrayList<>();
    }

    /**
     * Initialize with session ID
     */
    public static EvidenceEntity createNew(String sessionId) {
        EvidenceEntity entity = new EvidenceEntity();
        entity.setSessionId(sessionId);
        entity.setFirstContact(java.time.LocalDateTime.now().toString());
        entity.setLastUpdated(java.time.LocalDateTime.now().toString());
        entity.setScamType("UNKNOWN");
        entity.setThreatLevel(0.0);
        entity.setConversation(new ArrayList<>());
        entity.setExtractedInfo(new ExtractedIntelligence());
        return entity;
    }
}
