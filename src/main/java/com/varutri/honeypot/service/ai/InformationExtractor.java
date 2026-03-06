package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.dto.ExtractedInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for extracting sensitive information from scam messages
 * Extracts: UPI IDs, bank details, phone numbers, URLs, emails
 */
@Slf4j
@Service
public class InformationExtractor {

    @Autowired
    private ScamDetector scamDetector;

    // Regex patterns for various information types
    private static final Pattern UPI_PATTERN = Pattern.compile(
            "\\b\\d{10}@[a-zA-Z]+\\b|\\b[a-zA-Z0-9._-]+@(paytm|phonepe|googlepay|ybl|oksbi|axl|ibl|icici)\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\b(?:\\+91[\\s-]?)?[6-9]\\d{9}\\b");

    private static final Pattern BANK_ACCOUNT_PATTERN = Pattern.compile(
            "\\b\\d{9,18}\\b");

    private static final Pattern IFSC_PATTERN = Pattern.compile(
            "\\b[A-Z]{4}0[A-Z0-9]{6}\\b");

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");

    /**
     * Extract all sensitive information from a message
     */
    public ExtractedInfo extractInformation(String message) {
        if (message == null || message.trim().isEmpty()) {
            return new ExtractedInfo();
        }

        ExtractedInfo info = new ExtractedInfo();

        info.setUpiIds(extractUPIIds(message));
        info.setPhoneNumbers(extractPhoneNumbers(message));
        info.setBankAccountNumbers(extractBankAccounts(message));
        info.setIfscCodes(extractIFSCCodes(message));
        info.setUrls(extractURLs(message));
        info.setEmails(extractEmails(message));

        // Extract suspicious keywords using ScamDetector
        info.setSuspiciousKeywords(scamDetector.extractSuspiciousKeywords(message));

        logExtractedInfo(info);
        return info;
    }

    /**
     * Extract UPI IDs (e.g., 9876543210@paytm, user@ybl)
     */
    private List<String> extractUPIIds(String message) {
        return extractMatches(message, UPI_PATTERN);
    }

    /**
     * Extract phone numbers (Indian format)
     */
    private List<String> extractPhoneNumbers(String message) {
        return extractMatches(message, PHONE_PATTERN);
    }

    /**
     * Extract potential bank account numbers
     */
    private List<String> extractBankAccounts(String message) {
        List<String> accounts = extractMatches(message, BANK_ACCOUNT_PATTERN);
        // Filter to keep only likely bank account numbers (9-18 digits)
        return accounts.stream()
                .filter(acc -> acc.length() >= 9 && acc.length() <= 18)
                .toList();
    }

    /**
     * Extract IFSC codes
     */
    private List<String> extractIFSCCodes(String message) {
        return extractMatches(message, IFSC_PATTERN);
    }

    /**
     * Extract URLs
     */
    private List<String> extractURLs(String message) {
        return extractMatches(message, URL_PATTERN);
    }

    /**
     * Extract email addresses
     */
    private List<String> extractEmails(String message) {
        List<String> emails = extractMatches(message, EMAIL_PATTERN);
        // Filter out UPI IDs that might match email pattern
        return emails.stream()
                .filter(email -> !email.matches(".*@(paytm|phonepe|googlepay|ybl|oksbi|axl|ibl|icici)"))
                .toList();
    }

    /**
     * Helper method to extract matches using a regex pattern
     */
    private List<String> extractMatches(String message, Pattern pattern) {
        List<String> matches = new ArrayList<>();
        Matcher matcher = pattern.matcher(message);
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        return matches;
    }

    /**
     * Log extracted information for monitoring
     */
    private void logExtractedInfo(ExtractedInfo info) {
        if (!info.getUpiIds().isEmpty()) {
            log.warn("Extracted UPI IDs: {}", info.getUpiIds());
        }
        if (!info.getPhoneNumbers().isEmpty()) {
            log.warn("Extracted Phone Numbers: {}", info.getPhoneNumbers());
        }
        if (!info.getBankAccountNumbers().isEmpty()) {
            log.warn("Extracted Bank Accounts: {}", info.getBankAccountNumbers());
        }
        if (!info.getIfscCodes().isEmpty()) {
            log.warn("Extracted IFSC Codes: {}", info.getIfscCodes());
        }
        if (!info.getUrls().isEmpty()) {
            log.warn("Extracted URLs: {}", info.getUrls());
        }
        if (!info.getEmails().isEmpty()) {
            log.warn("Extracted Emails: {}", info.getEmails());
        }
    }
}

