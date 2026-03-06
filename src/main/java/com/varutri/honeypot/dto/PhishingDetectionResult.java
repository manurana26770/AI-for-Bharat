package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for phishing detection model result
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PhishingDetectionResult {
    private boolean isPhishing;
    private double confidence;
    private String label;

    /**
     * Create a result indicating phishing was detected
     */
    public static PhishingDetectionResult phishing(double confidence) {
        return new PhishingDetectionResult(true, confidence, "phishing");
    }

    /**
     * Create a result indicating content is safe
     */
    public static PhishingDetectionResult safe(double confidence) {
        return new PhishingDetectionResult(false, confidence, "safe");
    }

    /**
     * Create a fallback result when detection fails
     */
    public static PhishingDetectionResult unknown() {
        return new PhishingDetectionResult(false, 0.0, "unknown");
    }
}
