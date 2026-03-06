package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Incoming chat request from GUVI Hackathon platform
 * Matches official problem statement format with comprehensive validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChatRequest {

    /**
     * Session identifier - must be alphanumeric with dashes/underscores only
     * Prevents injection attacks in logs and queries
     */
    @NotBlank(message = "Session ID is required")
    @Size(min = 1, max = 100, message = "Session ID must be between 1 and 100 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Session ID can only contain letters, numbers, underscores, and dashes")
    @JsonProperty("sessionId")
    private String sessionId;

    /**
     * The message object containing sender and text
     */
    @NotNull(message = "Message is required")
    @Valid // Cascade validation to nested object
    @JsonProperty("message")
    private Message message;

    /**
     * Conversation history for context
     */
    @JsonProperty("conversationHistory")
    @Valid // Validate each item in the list
    @Size(max = 100, message = "Conversation history cannot exceed 100 messages")
    private List<@Valid ConversationMessage> conversationHistory;

    /**
     * Optional metadata about the request
     */
    @JsonProperty("metadata")
    @Valid
    private Metadata metadata;

    /**
     * Message object as per GUVI format with validation
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Message {

        /**
         * Sender type - restricted to known values
         */
        @JsonProperty("sender")
        @NotBlank(message = "Sender is required")
        @Pattern(regexp = "^(scammer|user|assistant|bot|system)$", message = "Sender must be one of: scammer, user, assistant, bot, system")
        private String sender;

        /**
         * Message text - limited size to prevent DoS
         */
        @JsonProperty("text")
        @NotBlank(message = "Message text is required")
        @Size(min = 1, max = 5000, message = "Message text must be between 1 and 5000 characters")
        private String text;

        /**
         * Timestamp in Epoch format (ms)
         */
        @JsonProperty("timestamp")
        @Min(value = 0, message = "Timestamp must be a valid epoch time in ms")
        private Long timestamp;
    }

    /**
     * Conversation history message format with validation
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationMessage {

        @JsonProperty("sender")
        @NotBlank(message = "Conversation message sender is required")
        @Pattern(regexp = "^(scammer|user|assistant|bot|system)$", message = "Sender must be one of: scammer, user, assistant, bot, system")
        private String sender;

        @JsonProperty("text")
        @NotBlank(message = "Conversation message text is required")
        @Size(min = 1, max = 5000, message = "Message text must be between 1 and 5000 characters")
        private String text;

        @JsonProperty("timestamp")
        @Min(value = 0, message = "Timestamp must be a valid epoch time in ms")
        private Long timestamp;
    }

    /**
     * Optional metadata with validation
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Metadata {

        @JsonProperty("channel")
        @Size(max = 50, message = "Channel cannot exceed 50 characters")
        @Pattern(regexp = "^[a-zA-Z0-9_-]*$", message = "Channel contains invalid characters")
        private String channel;

        @JsonProperty("language")
        @Size(max = 10, message = "Language code cannot exceed 10 characters")
        @Pattern(regexp = "^[a-zA-Z-]*$", message = "Language code contains invalid characters")
        private String language;

        @JsonProperty("locale")
        @Size(max = 10, message = "Locale cannot exceed 10 characters")
        @Pattern(regexp = "^[a-zA-Z_-]*$", message = "Locale contains invalid characters")
        private String locale;
    }
}
