package com.varutri.honeypot.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.util.ArrayList;
import java.util.List;

/**
 * DynamoDB entity for storing government scam reports.
 * Table: varutri_scam_reports | Partition Key: reportId | GSI: sessionId-index
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class ScamReportEntity {

    private String reportId;

    private String sessionId;

    private String timestamp;

    // Scam details
    private String scamType;
    private double threatLevel;
    private int totalMessages;

    // Extracted intelligence
    private List<String> upiIds = new ArrayList<>();
    private List<String> bankAccounts = new ArrayList<>();
    private List<String> ifscCodes = new ArrayList<>();
    private List<String> phoneNumbers = new ArrayList<>();
    private List<String> urls = new ArrayList<>();
    private List<String> suspiciousKeywords = new ArrayList<>();

    // Full conversation
    private List<ConversationTurn> conversation;

    // Metadata
    private String victimProfile;
    private String reportedBy;
    private String status;

    @DynamoDbPartitionKey
    public String getReportId() {
        return reportId;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "sessionId-index")
    public String getSessionId() {
        return sessionId;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @DynamoDbBean
    public static class ConversationTurn {
        private String timestamp;
        private String sender;
        private String message;
    }

    // Status constants (replaces enum for DynamoDB compatibility)
    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_SENT = "SENT";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_ARCHIVED = "ARCHIVED";
}
