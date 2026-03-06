package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * Extracted intelligence from scam messages - SAFE to return in API response.
 * This represents the intelligence gathered FROM the scammer, not about the
 * system.
 * 
 * Contains: phone numbers, UPI IDs, bank accounts, IFSC codes, URLs, emails,
 * keywords
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ExtractedIntelligence {

    /**
     * Phone numbers found in the message (Indian format)
     */
    @JsonProperty("phoneNumbers")
    @Builder.Default
    private List<String> phoneNumbers = new ArrayList<>();

    /**
     * UPI IDs found (e.g., user@paytm, 9876543210@ybl)
     */
    @JsonProperty("upiIds")
    @Builder.Default
    private List<String> upiIds = new ArrayList<>();

    /**
     * Bank account numbers found
     */
    @JsonProperty("bankAccounts")
    @Builder.Default
    private List<String> bankAccounts = new ArrayList<>();

    /**
     * IFSC codes found
     */
    @JsonProperty("ifscCodes")
    @Builder.Default
    private List<String> ifscCodes = new ArrayList<>();

    /**
     * URLs found in the message (potential phishing links)
     */
    @JsonProperty("urls")
    @Builder.Default
    private List<String> urls = new ArrayList<>();

    /**
     * Email addresses found
     */
    @JsonProperty("emails")
    @Builder.Default
    private List<String> emails = new ArrayList<>();

    /**
     * Suspicious keywords detected
     */
    @JsonProperty("suspiciousKeywords")
    @Builder.Default
    private List<String> suspiciousKeywords = new ArrayList<>();

    /**
     * Detected scam type (LOTTERY, INVESTMENT, PHISHING, etc.)
     */
    @JsonProperty("scamType")
    private String scamType;

    /**
     * Threat level (0.0 to 1.0)
     */
    @JsonProperty("threatLevel")
    private double threatLevel;

    /**
     * Human-readable threat category (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
     */
    @JsonProperty("threatCategory")
    private String threatCategory;

    /**
     * Whether any intelligence was extracted
     */
    public boolean hasIntelligence() {
        return !phoneNumbers.isEmpty() ||
                !upiIds.isEmpty() ||
                !bankAccounts.isEmpty() ||
                !ifscCodes.isEmpty() ||
                !urls.isEmpty() ||
                !emails.isEmpty();
    }

    /**
     * Create from ExtractedInfo DTO
     */
    public static ExtractedIntelligence fromExtractedInfo(ExtractedInfo info) {
        if (info == null) {
            return ExtractedIntelligence.builder().build();
        }

        return ExtractedIntelligence.builder()
                .phoneNumbers(info.getPhoneNumbers() != null ? info.getPhoneNumbers() : new ArrayList<>())
                .upiIds(info.getUpiIds() != null ? info.getUpiIds() : new ArrayList<>())
                .bankAccounts(info.getBankAccountNumbers() != null ? info.getBankAccountNumbers() : new ArrayList<>())
                .ifscCodes(info.getIfscCodes() != null ? info.getIfscCodes() : new ArrayList<>())
                .urls(info.getUrls() != null ? info.getUrls() : new ArrayList<>())
                .emails(info.getEmails() != null ? info.getEmails() : new ArrayList<>())
                .suspiciousKeywords(
                        info.getSuspiciousKeywords() != null ? info.getSuspiciousKeywords() : new ArrayList<>())
                .scamType(info.getScamType())
                .threatLevel(info.getThreatLevel())
                .build();
    }

    /**
     * Create with threat assessment details
     */
    public static ExtractedIntelligence fromExtractedInfo(ExtractedInfo info, String scamType, double threatLevel,
            String threatCategory) {
        ExtractedIntelligence intel = fromExtractedInfo(info);
        intel.setScamType(scamType);
        intel.setThreatLevel(threatLevel);
        intel.setThreatCategory(threatCategory);
        return intel;
    }
}
