package com.varutri.honeypot.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * DynamoDB entity for storing conversation sessions.
 * Table: varutri_sessions | Partition Key: sessionId
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class SessionEntity {

    private String sessionId;

    private List<ConversationMessage> conversationHistory;

    private int turnCount;

    private int lastIntelligenceTurn;

    private int consecutiveTurnsWithoutIntel;

    private String createdAt;

    private String updatedAt;

    @DynamoDbPartitionKey
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Nested class for conversation messages
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class ConversationMessage {
        private String sender;
        private String text;
        private Long timestamp;
    }

    /**
     * Add a message to the conversation history
     */
    public void addMessage(String sender, String text) {
        if (conversationHistory == null) {
            conversationHistory = new ArrayList<>();
        }
        ConversationMessage msg = new ConversationMessage();
        msg.setSender(sender);
        msg.setText(text);
        msg.setTimestamp(System.currentTimeMillis());
        conversationHistory.add(msg);
        if ("scammer".equals(sender) || "user".equals(sender)) {
            turnCount++;
        }
        updatedAt = LocalDateTime.now().toString();
    }
}
