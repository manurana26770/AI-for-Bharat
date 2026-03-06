package com.varutri.honeypot.service.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

/**
 * Input sanitization service for security
 * Prevents injection attacks in logs, reports, and database
 */
@Slf4j
@Service
public class InputSanitizer {

    // Patterns for detecting potentially malicious input
    private static final Pattern NEWLINE_PATTERN = Pattern.compile("[\\r\\n\\t]");
    private static final Pattern NON_PRINTABLE_PATTERN = Pattern.compile("[^\\x20-\\x7E\\xA0-\\xFF]");
    private static final Pattern MONGO_OPERATOR_PATTERN = Pattern.compile("^\\$");
    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]*>");
    private static final Pattern SCRIPT_PATTERN = Pattern.compile("(?i)<script[^>]*>.*?</script>");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern
            .compile("(?i)(union|select|insert|update|delete|drop|--|;)");

    /**
     * Sanitize input for safe logging
     * Removes newlines to prevent log injection attacks
     * 
     * @param input Raw input string
     * @return Sanitized string safe for logging
     */
    public String sanitizeForLogging(String input) {
        if (input == null) {
            return null;
        }

        // Replace newlines, tabs with spaces (prevents log injection)
        String sanitized = NEWLINE_PATTERN.matcher(input).replaceAll(" ");

        // Remove non-printable characters
        sanitized = NON_PRINTABLE_PATTERN.matcher(sanitized).replaceAll("");

        // Truncate for log readability
        if (sanitized.length() > 200) {
            sanitized = sanitized.substring(0, 200) + "...[truncated]";
        }

        return sanitized;
    }

    /**
     * Sanitize input for HTML/report output
     * Escapes HTML special characters to prevent XSS
     * 
     * @param input Raw input string
     * @return HTML-escaped string safe for reports
     */
    public String sanitizeForReport(String input) {
        if (input == null) {
            return null;
        }

        // HTML entity encoding
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    /**
     * Sanitize input for MongoDB storage
     * Prevents NoSQL injection attacks
     * 
     * @param input Raw input string
     * @return Safe string for MongoDB
     * @throws SecurityException if input contains MongoDB operators
     */
    public String sanitizeForMongo(String input) {
        if (input == null) {
            return null;
        }

        // Check for MongoDB operators (security risk)
        if (MONGO_OPERATOR_PATTERN.matcher(input.trim()).find()) {
            log.warn("🚨 Potential NoSQL injection detected: {}", sanitizeForLogging(input));
            throw new SecurityException("Input contains invalid characters");
        }

        return input;
    }

    /**
     * Sanitize session ID for safe database queries
     * Only allows alphanumeric, dash, underscore
     * 
     * @param sessionId Raw session ID
     * @return Sanitized session ID
     * @throws SecurityException if session ID contains invalid characters
     */
    public String sanitizeSessionId(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new SecurityException("Session ID is required");
        }

        // Only allow safe characters
        if (!sessionId.matches("^[a-zA-Z0-9_-]+$")) {
            log.warn("🚨 Invalid session ID format: {}", sanitizeForLogging(sessionId));
            throw new SecurityException("Session ID contains invalid characters");
        }

        if (sessionId.length() > 100) {
            throw new SecurityException("Session ID too long");
        }

        return sessionId;
    }

    /**
     * Full sanitization for message text
     * Removes dangerous content while preserving meaning
     * 
     * @param text Raw message text
     * @return Sanitized text
     */
    public String sanitizeMessageText(String text) {
        if (text == null) {
            return null;
        }

        String sanitized = text;

        // Remove script tags (XSS prevention)
        sanitized = SCRIPT_PATTERN.matcher(sanitized).replaceAll("[removed]");

        // Remove other HTML tags
        sanitized = HTML_TAG_PATTERN.matcher(sanitized).replaceAll("");

        // Limit length
        if (sanitized.length() > 5000) {
            sanitized = sanitized.substring(0, 5000);
        }

        return sanitized.trim();
    }

    /**
     * Check if input contains potential SQL injection
     * Note: MongoDB uses different syntax, but still good to check
     * 
     * @param input Input to check
     * @return true if potentially dangerous
     */
    public boolean containsSqlInjection(String input) {
        if (input == null) {
            return false;
        }
        return SQL_INJECTION_PATTERN.matcher(input).find();
    }

    /**
     * Check if input contains potential prompt injection
     * Detects common prompt injection patterns
     * 
     * @param input Input to check
     * @return true if potentially contains prompt injection
     */
    public boolean containsPromptInjection(String input) {
        if (input == null) {
            return false;
        }

        String lower = input.toLowerCase();

        // Common prompt injection patterns
        return lower.contains("ignore previous") ||
                lower.contains("ignore all") ||
                lower.contains("disregard") ||
                lower.contains("system prompt") ||
                lower.contains("new instructions") ||
                lower.contains("forget everything") ||
                lower.contains("you are now") ||
                lower.contains("act as");
    }

    /**
     * Log potential security threat for monitoring
     * 
     * @param type     Type of threat detected
     * @param input    The malicious input (sanitized for logging)
     * @param clientId Client identifier
     */
    public void logSecurityThreat(String type, String input, String clientId) {
        log.warn("🚨 SECURITY THREAT - Type: {}, Client: {}, Input: {}",
                type,
                sanitizeForLogging(clientId),
                sanitizeForLogging(input));
    }
}

