package com.varutri.honeypot.dto;

import com.varutri.honeypot.service.ai.EnsembleThreatScorer;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.stream.Collectors;

/**
 * API Response DTO for Threat Assessment
 * Provides a clean, serializable representation of the ensemble scoring results
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatAssessmentResponse {

    // Core threat information
    private String threatLevel; // SAFE, LOW, MEDIUM, HIGH, CRITICAL
    private double threatScore; // 0.0 - 1.0
    private double confidencePercent; // 0 - 100
    private String primaryScamType; // Detected scam category

    // Detection summary
    private int layersTriggered; // Number of detection layers that fired
    private int totalLayers; // Total number of layers (5)

    // Evidence and explanation
    private List<EvidenceItem> topEvidence;
    private List<LayerSummary> layerBreakdown;
    private String humanReadableExplanation;

    // Original input
    private String originalMessage;
    private String normalizedMessage;
    private String timestamp;

    /**
     * Create response from EnsembleThreatScorer result
     */
    public static ThreatAssessmentResponse fromAssessment(EnsembleThreatScorer.ThreatAssessment assessment) {
        ThreatAssessmentResponseBuilder builder = ThreatAssessmentResponse.builder()
                .threatLevel(assessment.threatLevel)
                .threatScore(Math.round(assessment.ensembleScore * 100.0) / 100.0)
                .confidencePercent(Math.round(assessment.calibratedConfidence * 100.0))
                .primaryScamType(assessment.primaryScamType)
                .layersTriggered(assessment.triggeredLayers)
                .totalLayers(5)
                .originalMessage(assessment.originalMessage)
                .normalizedMessage(assessment.normalizedMessage)
                .timestamp(assessment.timestamp)
                .humanReadableExplanation(assessment.explanation);

        // Convert evidence
        if (assessment.topEvidence != null) {
            builder.topEvidence(assessment.topEvidence.stream()
                    .limit(5)
                    .map(e -> new EvidenceItem(e.description,
                            Math.round(e.confidence * 100),
                            e.source))
                    .collect(Collectors.toList()));
        }

        // Convert layer breakdown
        if (assessment.layerResults != null) {
            builder.layerBreakdown(assessment.layerResults.stream()
                    .map(layer -> LayerSummary.builder()
                            .layerName(formatLayerName(layer.layerName))
                            .triggered(layer.triggered)
                            .score(Math.round(layer.rawScore * 100.0) / 100.0)
                            .weight(Math.round(layer.weight * 100))
                            .detectedType(layer.detectedType)
                            .details(layer.details)
                            .evidenceCount(layer.evidence != null ? layer.evidence.size() : 0)
                            .build())
                    .collect(Collectors.toList()));
        }

        return builder.build();
    }

    private static String formatLayerName(String name) {
        if (name == null)
            return "Unknown";
        return name.replace("_", " ")
                .toLowerCase()
                .replaceFirst("^.", String.valueOf(Character.toUpperCase(name.charAt(0))));
    }

    /**
     * Get a simple threat summary for quick display
     */
    public String getQuickSummary() {
        return String.format("%s threat (%.0f%% confident) - %s",
                threatLevel, confidencePercent, primaryScamType);
    }

    /**
     * Check if this should trigger an alert
     */
    public boolean shouldAlert() {
        return "HIGH".equals(threatLevel) || "CRITICAL".equals(threatLevel);
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EvidenceItem {
        private String description;
        private long confidencePercent;
        private String detectionLayer;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LayerSummary {
        private String layerName;
        private boolean triggered;
        private double score;
        private long weight;
        private String detectedType;
        private String details;
        private int evidenceCount;
    }
}

