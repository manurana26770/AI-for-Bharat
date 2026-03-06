package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO for WhatsApp webhook messages from Meta Cloud API
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class WhatsAppWebhook {

    @JsonProperty("object")
    private String object;

    @JsonProperty("entry")
    private List<Entry> entry;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Entry {
        @JsonProperty("id")
        private String id;

        @JsonProperty("changes")
        private List<Change> changes;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Change {
        @JsonProperty("value")
        private Value value;

        @JsonProperty("field")
        private String field;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Value {
        @JsonProperty("messaging_product")
        private String messagingProduct;

        @JsonProperty("metadata")
        private Metadata metadata;

        @JsonProperty("contacts")
        private List<Contact> contacts;

        @JsonProperty("messages")
        private List<Message> messages;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Metadata {
        @JsonProperty("display_phone_number")
        private String displayPhoneNumber;

        @JsonProperty("phone_number_id")
        private String phoneNumberId;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Contact {
        @JsonProperty("profile")
        private Profile profile;

        @JsonProperty("wa_id")
        private String waId;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Profile {
        @JsonProperty("name")
        private String name;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Message {
        @JsonProperty("from")
        private String from;

        @JsonProperty("id")
        private String id;

        @JsonProperty("timestamp")
        private String timestamp;

        @JsonProperty("type")
        private String type;

        @JsonProperty("text")
        private TextMessage text;

        @JsonProperty("button")
        private ButtonMessage button;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TextMessage {
        @JsonProperty("body")
        private String body;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ButtonMessage {
        @JsonProperty("payload")
        private String payload;

        @JsonProperty("text")
        private String text;
    }
}
