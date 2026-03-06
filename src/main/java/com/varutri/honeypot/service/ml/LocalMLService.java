package com.varutri.honeypot.service.ml;

import com.varutri.honeypot.dto.PhishingDetectionResult;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Local ML inference service — REST client to the Python sidecar.
 *
 * Communicates with a FastAPI service (ml-sidecar) that hosts:
 * 1. MiniLM (sentence-transformers/all-MiniLM-L6-v2) → embeddings
 * 2. DeBERTa (MoritzLaurer/deberta-v3-base-zeroshot-v1) → zero-shot
 * classification
 *
 * No in-process inference — all ML runs in the Python container.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "local.ml.enabled", havingValue = "true", matchIfMissing = true)
public class LocalMLService {

    private static final int EMBEDDING_DIMENSIONS = 384;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    @Value("${local.ml.service.url:http://localhost:8000}")
    private String sidecarUrl;

    private WebClient webClient;
    private boolean modelsAvailable = false;

    @PostConstruct
    public void init() {
        this.webClient = WebClient.builder()
                .baseUrl(sidecarUrl)
                .build();

        log.info("LocalMLService configured — sidecar URL: {}", sidecarUrl);

        // Check if sidecar is already available
        try {
            Map<String, Object> health = webClient.get()
                    .uri("/health")
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                    })
                    .timeout(Duration.ofSeconds(5))
                    .block();

            if (health != null && Boolean.TRUE.equals(health.get("embedding_model"))
                    && Boolean.TRUE.equals(health.get("zeroshot_model"))) {
                modelsAvailable = true;
                log.info("✅ ML sidecar is healthy — models are loaded");
            } else {
                log.warn("ML sidecar responded but models are not ready yet");
            }
        } catch (Exception e) {
            log.warn("ML sidecar not reachable at startup ({}). Will retry on first call.", e.getMessage());
        }
    }

    // =========================================================================
    // PUBLIC API: Embeddings
    // =========================================================================

    /**
     * Get sentence embedding vector for the given text.
     * Calls the Python sidecar's /embed endpoint.
     *
     * @param text Input text to embed
     * @return float array of embeddings (384 dimensions)
     */
    public float[] getEmbedding(String text) {
        if (!checkAvailability()) {
            return new float[EMBEDDING_DIMENSIONS];
        }

        try {
            Map<String, String> request = Map.of("text", text);

            Map<String, Object> response = webClient.post()
                    .uri("/embed")
                    .bodyValue(request)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                    })
                    .timeout(REQUEST_TIMEOUT)
                    .block();

            if (response != null && response.containsKey("embedding")) {
                @SuppressWarnings("unchecked")
                List<Number> embeddingList = (List<Number>) response.get("embedding");
                float[] result = new float[embeddingList.size()];
                for (int i = 0; i < embeddingList.size(); i++) {
                    result[i] = embeddingList.get(i).floatValue();
                }
                return result;
            }

            log.warn("Empty embedding response from sidecar");
            return new float[EMBEDDING_DIMENSIONS];

        } catch (Exception e) {
            log.error("Embedding request failed: {}", e.getMessage());
            return new float[EMBEDDING_DIMENSIONS];
        }
    }

    // =========================================================================
    // PUBLIC API: Zero-Shot Classification
    // =========================================================================

    /**
     * Classify text against a list of candidate labels using the Python sidecar.
     *
     * @param text            Input text to classify
     * @param candidateLabels List of labels to score against
     * @return Map of label → probability (0.0 to 1.0), sorted by descending score
     */
    public Map<String, Double> classifyZeroShot(String text, List<String> candidateLabels) {
        if (!checkAvailability()) {
            return candidateLabels.stream().collect(Collectors.toMap(l -> l, l -> 0.0));
        }

        try {
            Map<String, Object> request = Map.of(
                    "text", text,
                    "candidate_labels", candidateLabels);

            Map<String, Object> response = webClient.post()
                    .uri("/classify")
                    .bodyValue(request)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                    })
                    .timeout(REQUEST_TIMEOUT)
                    .block();

            if (response != null && response.containsKey("scores")) {
                @SuppressWarnings("unchecked")
                Map<String, Number> rawScores = (Map<String, Number>) response.get("scores");
                Map<String, Double> scores = new LinkedHashMap<>();
                rawScores.entrySet().stream()
                        .sorted(Map.Entry.<String, Number>comparingByValue(
                                Comparator.comparingDouble(Number::doubleValue)).reversed())
                        .forEach(e -> scores.put(e.getKey(), e.getValue().doubleValue()));
                return scores;
            }

            log.warn("Empty classification response from sidecar");
            return candidateLabels.stream().collect(Collectors.toMap(l -> l, l -> 0.0));

        } catch (Exception e) {
            log.error("Classification request failed: {}", e.getMessage());
            return candidateLabels.stream().collect(Collectors.toMap(l -> l, l -> 0.0));
        }
    }

    // =========================================================================
    // PUBLIC API: Phishing Detection
    // =========================================================================

    /**
     * Detect phishing by running zero-shot classification with phishing-specific
     * labels.
     *
     * @param text Text to analyze for phishing
     * @return PhishingDetectionResult with label and confidence
     */
    public PhishingDetectionResult detectPhishing(String text) {
        List<String> labels = Arrays.asList(
                "phishing attempt",
                "scam message",
                "legitimate message");

        Map<String, Double> scores = classifyZeroShot(text, labels);

        double phishingScore = scores.getOrDefault("phishing attempt", 0.0)
                + scores.getOrDefault("scam message", 0.0);
        double legitimateScore = scores.getOrDefault("legitimate message", 0.0);

        if (phishingScore > legitimateScore) {
            return PhishingDetectionResult.phishing(phishingScore);
        } else {
            return PhishingDetectionResult.safe(legitimateScore);
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /**
     * Check if the ML sidecar is reachable and models are loaded.
     */
    public boolean isAvailable() {
        return modelsAvailable;
    }

    /**
     * Lazy check — if models weren't available at startup, try again.
     */
    private boolean checkAvailability() {
        if (modelsAvailable) {
            return true;
        }

        // Retry health check
        try {
            Map<String, Object> health = webClient.get()
                    .uri("/health")
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                    })
                    .timeout(Duration.ofSeconds(3))
                    .block();

            if (health != null && Boolean.TRUE.equals(health.get("embedding_model"))
                    && Boolean.TRUE.equals(health.get("zeroshot_model"))) {
                modelsAvailable = true;
                log.info("✅ ML sidecar is now healthy — models loaded");
                return true;
            }
        } catch (Exception e) {
            // Still not available
        }

        log.warn("ML sidecar not available — returning default scores");
        return false;
    }
}
