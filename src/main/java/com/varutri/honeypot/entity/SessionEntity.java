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
 * MongoDB entity for storing conversation sessions
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "sessions")
public class SessionEntity {

    @Id
    private String id;

    @Indexed(unique = true)
    private String sessionId;

    private List<ConversationMessage> conversationHistory;

    private int turnCount;

    private int lastIntelligenceTurn;

    private int consecutiveTurnsWithoutIntel;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    /**
     * Nested class for conversation messages
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
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
        conversationHistory.add(ConversationMessage.builder()
                .sender(sender)
                .text(text)
                .timestamp(System.currentTimeMillis())
                .build());
        if ("scammer".equals(sender) || "user".equals(sender)) {
            turnCount++;
        }
        updatedAt = LocalDateTime.now();
    }
}
