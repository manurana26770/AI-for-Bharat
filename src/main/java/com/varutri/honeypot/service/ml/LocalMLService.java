package com.varutri.honeypot.service.ml;

import ai.djl.MalformedModelException;
import ai.djl.huggingface.tokenizers.HuggingFaceTokenizer;
import ai.djl.huggingface.tokenizers.Encoding;
import ai.djl.inference.Predictor;
import ai.djl.modality.Classifications;
import ai.djl.ndarray.NDArray;
import ai.djl.ndarray.NDList;
import ai.djl.ndarray.NDManager;
import ai.djl.ndarray.types.DataType;
import ai.djl.ndarray.types.Shape;
import ai.djl.repository.zoo.Criteria;
import ai.djl.repository.zoo.ModelNotFoundException;
import ai.djl.repository.zoo.ZooModel;
import ai.djl.translate.TranslateException;
import ai.djl.translate.Translator;
import ai.djl.translate.TranslatorContext;

import com.varutri.honeypot.dto.PhishingDetectionResult;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Local ML inference service using Deep Java Library (DJL).
 * 
 * Runs two models locally inside the JVM:
 * 1. MiniLM (sentence-transformers/all-MiniLM-L6-v2) for embeddings
 * 2. DeBERTa (MoritzLaurer/deberta-v3-base-zeroshot-v1) for zero-shot
 * classification
 * 
 * No external API calls needed — all inference happens in-process.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "local.ml.enabled", havingValue = "true", matchIfMissing = true)
public class LocalMLService {

    @Value("${local.ml.embedding.model-name:sentence-transformers/all-MiniLM-L6-v2}")
    private String embeddingModelName;

    @Value("${local.ml.embedding.dimensions:384}")
    private int embeddingDimensions;

    @Value("${local.ml.zeroshot.model-name:MoritzLaurer/deberta-v3-base-zeroshot-v1}")
    private String zeroShotModelName;

    @Value("${local.ml.zeroshot.max-length:512}")
    private int zeroShotMaxLength;

    @Value("${local.ml.cache-dir:./models-cache}")
    private String cacheDir;

    // MiniLM embedding model
    private ZooModel<NDList, NDList> embeddingModel;
    private HuggingFaceTokenizer embeddingTokenizer;

    // DeBERTa zero-shot classification model
    private ZooModel<NDList, NDList> zeroShotModel;
    private HuggingFaceTokenizer zeroShotTokenizer;

    private boolean modelsLoaded = false;

    @PostConstruct
    public void loadModels() {
        log.info("Loading local ML models...");
        long startTime = System.currentTimeMillis();

        try {
            Path cachePath = Paths.get(cacheDir);
            System.setProperty("DJL_CACHE_DIR", cachePath.toAbsolutePath().toString());

            loadEmbeddingModel();
            loadZeroShotModel();

            modelsLoaded = true;
            long elapsed = System.currentTimeMillis() - startTime;
            log.info("All local ML models loaded successfully in {}ms", elapsed);
        } catch (Exception e) {
            log.error("Failed to load local ML models: {}", e.getMessage(), e);
            modelsLoaded = false;
        }
    }

    private void loadEmbeddingModel() throws ModelNotFoundException, MalformedModelException, IOException {
        log.info(" Loading embedding model: {}", embeddingModelName);

        // Load tokenizer
        embeddingTokenizer = HuggingFaceTokenizer.builder()
                .optTokenizerName(embeddingModelName)
                .optMaxLength(256)
                .optPadding(true)
                .optTruncation(true)
                .build();

        // Load model via DJL Criteria
        Criteria<NDList, NDList> criteria = Criteria.builder()
                .setTypes(NDList.class, NDList.class)
                .optModelUrls("djl://ai.djl.huggingface.pytorch/" + embeddingModelName)
                .optEngine("PyTorch")
                .optTranslator(new RawTranslator())
                .build();

        embeddingModel = criteria.loadModel();
        log.info("Embedding model loaded: {}", embeddingModelName);
    }

    private void loadZeroShotModel() throws ModelNotFoundException, MalformedModelException, IOException {
        log.info("  Loading zero-shot model: {}", zeroShotModelName);

        // Load tokenizer
        zeroShotTokenizer = HuggingFaceTokenizer.builder()
                .optTokenizerName(zeroShotModelName)
                .optMaxLength(zeroShotMaxLength)
                .optPadding(true)
                .optTruncation(true)
                .build();

        // Load model
        Criteria<NDList, NDList> criteria = Criteria.builder()
                .setTypes(NDList.class, NDList.class)
                .optModelUrls("djl://ai.djl.huggingface.pytorch/" + zeroShotModelName)
                .optEngine("PyTorch")
                .optTranslator(new RawTranslator())
                .build();

        zeroShotModel = criteria.loadModel();
        log.info("  ✅ Zero-shot model loaded: {}", zeroShotModelName);
    }

    // =========================================================================
    // PUBLIC API: Embeddings
    // =========================================================================

    /**
     * Get sentence embedding vector for the given text.
     * Uses MiniLM to produce a 384-dimensional float vector.
     *
     * @param text Input text to embed
     * @return float array of embeddings (384 dimensions)
     */
    public synchronized float[] getEmbedding(String text) {
        if (!modelsLoaded || embeddingModel == null) {
            log.warn("Embedding model not loaded, returning empty array");
            return new float[embeddingDimensions];
        }

        try (Predictor<NDList, NDList> predictor = embeddingModel.newPredictor(new RawTranslator())) {
            NDManager manager = embeddingModel.getNDManager().newSubManager();

            // Tokenize
            Encoding encoding = embeddingTokenizer.encode(text);
            long[] inputIds = encoding.getIds();
            long[] attentionMask = encoding.getAttentionMask();

            // Create input tensors
            NDArray inputIdArray = manager.create(inputIds).reshape(1, inputIds.length);
            NDArray attentionMaskArray = manager.create(attentionMask).reshape(1, attentionMask.length);

            NDList input = new NDList(inputIdArray, attentionMaskArray);

            // Run inference
            NDList output = predictor.predict(input);

            // Mean pooling over token embeddings (output[0] is last hidden state)
            NDArray lastHiddenState = output.get(0); // shape: [1, seq_len, 384]
            NDArray mask = attentionMaskArray.toType(DataType.FLOAT32, false)
                    .reshape(1, attentionMask.length, 1);
            NDArray maskedEmbeddings = lastHiddenState.mul(mask);
            NDArray summed = maskedEmbeddings.sum(new int[] { 1 }); // [1, 384]
            NDArray counts = mask.sum(new int[] { 1 }).clip(1e-9f, Float.MAX_VALUE); // avoid div by 0
            NDArray meanPooled = summed.div(counts).squeeze(0); // [384]

            float[] result = meanPooled.toFloatArray();

            manager.close();
            return result;

        } catch (TranslateException e) {
            log.error("Embedding inference failed: {}", e.getMessage());
            return new float[embeddingDimensions];
        }
    }

    // =========================================================================
    // PUBLIC API: Zero-Shot Classification
    // =========================================================================

    /**
     * Classify text against a list of candidate labels using DeBERTa NLI.
     * 
     * Replicates HuggingFace's zero-shot-classification pipeline:
     * For each label, construct hypothesis "This example is {label}",
     * run NLI, and use entailment score as the classification probability.
     *
     * @param text            Input text to classify
     * @param candidateLabels List of labels to score against
     * @return Map of label → probability (0.0 to 1.0), sorted by descending score
     */
    public synchronized Map<String, Double> classifyZeroShot(String text, List<String> candidateLabels) {
        if (!modelsLoaded || zeroShotModel == null) {
            log.warn("Zero-shot model not loaded, returning empty scores");
            return candidateLabels.stream()
                    .collect(Collectors.toMap(l -> l, l -> 0.0));
        }

        try {
            Map<String, Double> scores = new LinkedHashMap<>();

            // For each candidate label, run NLI inference
            for (String label : candidateLabels) {
                double entailmentScore = computeEntailmentScore(text, label);
                scores.put(label, entailmentScore);
            }

            // Normalize scores via softmax
            double maxScore = scores.values().stream().mapToDouble(d -> d).max().orElse(0);
            double sumExp = scores.values().stream()
                    .mapToDouble(d -> Math.exp(d - maxScore))
                    .sum();

            Map<String, Double> normalized = new LinkedHashMap<>();
            scores.entrySet().stream()
                    .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                    .forEach(e -> normalized.put(
                            e.getKey(),
                            Math.exp(e.getValue() - maxScore) / sumExp));

            return normalized;

        } catch (Exception e) {
            log.error("Zero-shot classification failed: {}", e.getMessage());
            return candidateLabels.stream()
                    .collect(Collectors.toMap(l -> l, l -> 0.0));
        }
    }

    /**
     * Compute the entailment (raw logit) score for a text-hypothesis pair.
     */
    private double computeEntailmentScore(String text, String label) throws TranslateException {
        try (Predictor<NDList, NDList> predictor = zeroShotModel.newPredictor(new RawTranslator())) {
            NDManager manager = zeroShotModel.getNDManager().newSubManager();

            String hypothesis = "This example is " + label + ".";

            // Tokenize as a sentence pair
            Encoding encoding = zeroShotTokenizer.encode(text, hypothesis);
            long[] inputIds = encoding.getIds();
            long[] attentionMask = encoding.getAttentionMask();

            NDArray inputIdArray = manager.create(inputIds).reshape(1, inputIds.length);
            NDArray attentionMaskArray = manager.create(attentionMask).reshape(1, attentionMask.length);

            NDList input = new NDList(inputIdArray, attentionMaskArray);

            NDList output = predictor.predict(input);

            // Output logits: [1, num_classes] where classes are [entailment,
            // not_entailment]
            // or [contradiction, neutral, entailment] depending on model
            NDArray logits = output.get(0).squeeze(0); // [num_classes]
            float[] logitValues = logits.toFloatArray();

            manager.close();

            // For deberta-v3-base-zeroshot-v1: 2 classes [not_entailment, entailment]
            // Return the entailment logit (last one)
            return logitValues[logitValues.length - 1];
        }
    }

    // =========================================================================
    // PUBLIC API: Phishing Detection
    // =========================================================================

    /**
     * Detect phishing by running zero-shot classification with phishing-specific
     * labels.
     * Uses the same DeBERTa model — no separate model needed.
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

        // Combine "phishing attempt" and "scam message" scores
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
     * Check if models are loaded and ready for inference.
     */
    public boolean isAvailable() {
        return modelsLoaded;
    }

    @PreDestroy
    public void cleanup() {
        log.info("🧹 Releasing local ML model resources...");
        if (embeddingModel != null) {
            embeddingModel.close();
        }
        if (embeddingTokenizer != null) {
            embeddingTokenizer.close();
        }
        if (zeroShotModel != null) {
            zeroShotModel.close();
        }
        if (zeroShotTokenizer != null) {
            zeroShotTokenizer.close();
        }
        log.info(" Local ML resources released.");
    }

    /**
     * Pass-through translator that sends raw NDList in and out.
     * We handle tokenization manually for full control.
     */
    private static class RawTranslator implements Translator<NDList, NDList> {
        @Override
        public NDList processInput(TranslatorContext ctx, NDList input) {
            return input;
        }

        @Override
        public NDList processOutput(TranslatorContext ctx, NDList output) {
            return output;
        }
    }
}
