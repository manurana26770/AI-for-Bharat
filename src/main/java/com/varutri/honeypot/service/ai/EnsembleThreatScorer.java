package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.service.ml.LocalMLService;

import com.varutri.honeypot.dto.ChatRequest;
import com.varutri.honeypot.dto.PhishingDetectionResult;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

/**
 * Ensemble Threat Scorer - Phase 5: Final Layer
 * 
 * Combines ALL detection layers with weighted scoring:
 * 1. Text Normalization (obfuscation detection)
 * 2. Regex Pattern Matching (keyword-based)
 * 3. Advanced Pattern Matching (fuzzy, phonetic, n-gram)
 * 4. Semantic ML Analysis (embeddings, intent, manipulation)
 * 5. AI Phishing Model (DistilBERT classification)
 * 
 * Features:
 * - Weighted ensemble combination
 * - Confidence calibration
 * - Explainable output with evidence
 * - Multi-signal agreement bonus
 */
@Slf4j
@Service
public class EnsembleThreatScorer {

    @Autowired
    private TextNormalizer textNormalizer;

    @Autowired
    private AdvancedPatternMatcher advancedPatternMatcher;

    @Autowired(required = false)
    private SemanticScamAnalyzer semanticScamAnalyzer;

    @Autowired(required = false)
    private LocalMLService localMLService;

    // ========================================================================
    // LAYER WEIGHTS (should sum to ~1.0 for base scoring)
    // ========================================================================
    private static final double WEIGHT_NORMALIZATION = 0.10; // Obfuscation detection
    private static final double WEIGHT_REGEX = 0.15; // Keyword matching
    private static final double WEIGHT_ADVANCED = 0.20; // Fuzzy/phonetic/n-gram
    private static final double WEIGHT_SEMANTIC = 0.30; // ML embeddings/intent
    private static final double WEIGHT_AI_MODEL = 0.25; // Phishing classifier

    // Confidence thresholds
    private static final double HIGH_THREAT_THRESHOLD = 0.70;
    private static final double MEDIUM_THREAT_THRESHOLD = 0.40;
    private static final double LOW_THREAT_THRESHOLD = 0.20;

    // ========================================================================
    // MAIN ANALYSIS METHOD
    // ========================================================================

    /**
     * Perform comprehensive ensemble threat analysis (Synchronous wrapper)
     */
    public ThreatAssessment assessThreat(String message,
            List<ChatRequest.ConversationMessage> conversationHistory) {
        return assessThreatAsync(message, conversationHistory).join();
    }

    /**
     * Perform comprehensive ensemble threat analysis ASYNCHRONOUSLY
     * Executes all 5 detection layers in PARALLEL for maximum performance
     */
    public java.util.concurrent.CompletableFuture<ThreatAssessment> assessThreatAsync(String message,
            List<ChatRequest.ConversationMessage> conversationHistory) {

        ThreatAssessment assessment = new ThreatAssessment();
        assessment.originalMessage = message;
        assessment.timestamp = Instant.now().toString();
        assessment.layerResults = java.util.Collections.synchronizedList(new ArrayList<>());

        // ========================================
        // LAYER 1: Text Normalization (CPU Bound)
        // ========================================
        java.util.concurrent.CompletableFuture<Void> normFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> analyzeNormalization(message))
                .thenAccept(result -> {
                    assessment.layerResults.add(result);
                    // Normalized text is needed by other layers, but providing strict dependency
                    // would sequentialize them. Instead, other layers run on original text
                    // or do their own on-demand normalization if needed for parallelism.
                    // However, for best accuracy, we'll store it here.
                    assessment.normalizedMessage = result.normalizedText;
                });

        // We need normalized text for regex and advanced patterns to be most effective.
        // To maintain parallelism, we can run a light normalization locally or wait for
        // norm layer.
        // For speed, we will run them in parallel on original message, or slightly
        // simplified normalization.
        // Let's assume for high performance we run them on original message or do a
        // quick lower-case.

        // ========================================
        // LAYER 2: Regex Pattern Matching (CPU Bound)
        // ========================================
        java.util.concurrent.CompletableFuture<Void> regexFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> analyzeRegexPatterns(message)) // Using simple message to avoid waiting
                .thenAccept(result -> assessment.layerResults.add(result));

        // ========================================
        // LAYER 3: Advanced Pattern Matching (CPU Bound)
        // ========================================
        java.util.concurrent.CompletableFuture<Void> advancedFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> analyzeAdvancedPatterns(message))
                .thenAccept(result -> assessment.layerResults.add(result));

        // ========================================
        // LAYER 4: Semantic ML Analysis (I/O Bound - Async)
        // ========================================
        java.util.concurrent.CompletableFuture<Void> semanticFuture;
        if (semanticScamAnalyzer != null) {
            semanticFuture = semanticScamAnalyzer.analyzeMessage(message, conversationHistory)
                    .thenAccept(semanticResult -> {
                        LayerResult result = new LayerResult();
                        result.layerName = "SEMANTIC_ML";
                        result.weight = WEIGHT_SEMANTIC;

                        result.rawScore = semanticResult.combinedScore;
                        result.triggered = semanticResult.hasSignificantMatch();
                        result.detectedType = semanticResult.primaryScamType;

                        // Add evidence
                        for (Map.Entry<String, Double> entry : semanticResult.semanticMatches.entrySet()) {
                            result.addEvidence(String.format("Semantic match: %s", entry.getKey()), entry.getValue());
                        }
                        for (SemanticScamAnalyzer.IntentScore intent : semanticResult.detectedIntents) {
                            if (intent.isSuspicious) {
                                result.addEvidence("Suspicious intent: " + intent.intent, intent.confidence);
                            }
                        }

                        assessment.layerResults.add(result);
                    })
                    .exceptionally(ex -> {
                        log.error("Semantic analysis failed", ex);
                        return null;
                    });
        } else {
            semanticFuture = java.util.concurrent.CompletableFuture.completedFuture(null);
        }

        // ========================================
        // LAYER 5: AI Phishing Model (I/O Bound - Async)
        // ========================================
        java.util.concurrent.CompletableFuture<Void> aiFuture;
        if (localMLService != null && localMLService.isAvailable()) {
            aiFuture = java.util.concurrent.CompletableFuture
                    .runAsync(() -> {
                        PhishingDetectionResult aiResult = localMLService.detectPhishing(message);
                        LayerResult result = new LayerResult();
                        result.layerName = "AI_PHISHING_MODEL";
                        result.weight = WEIGHT_AI_MODEL;

                        if (aiResult != null) {
                            result.rawScore = aiResult.isPhishing() ? aiResult.getConfidence() : 0.0;
                            result.triggered = aiResult.isPhishing();

                            if (aiResult.isPhishing()) {
                                result.addEvidence("AI Model detected phishing", aiResult.getConfidence());
                                result.detectedType = "PHISHING";
                            }
                        }
                        assessment.layerResults.add(result);
                    })
                    .exceptionally(ex -> {
                        log.error("AI model failed", ex);
                        return null;
                    });
        } else {
            aiFuture = java.util.concurrent.CompletableFuture.completedFuture(null);
        }

        // ========================================
        // ENSEMBLE AGGREGATION
        // ========================================
        return java.util.concurrent.CompletableFuture.allOf(
                normFuture, regexFuture, advancedFuture, semanticFuture, aiFuture)
                .thenApply(v -> {
                    // All layers finished
                    calculateEnsembleScore(assessment);
                    calibrateConfidence(assessment);
                    generateExplanation(assessment);

                    // Log high threats
                    if (assessment.threatLevel != null &&
                            (assessment.threatLevel.equals("HIGH") || assessment.threatLevel.equals("CRITICAL"))) {
                        log.warn("THREAT DETECTED: {} - Score: {}", assessment.threatLevel, assessment.ensembleScore);
                    }

                    return assessment;
                });
    }

    // ========================================================================
    // LAYER ANALYZERS
    // ========================================================================

    private LayerResult analyzeNormalization(String message) {
        LayerResult result = new LayerResult();
        result.layerName = "TEXT_NORMALIZATION";
        result.weight = WEIGHT_NORMALIZATION;

        try {
            TextNormalizer.NormalizationReport report = textNormalizer.analyzeText(message);
            result.normalizedText = report.normalizedText;

            // Score based on obfuscation detected
            double score = 0.0;
            if (report.hasObfuscation) {
                score = 0.8; // High score if obfuscation detected
                result.addEvidence("Obfuscation detected", 0.8);
            }
            if (report.hasLeetspeak) {
                score = Math.max(score, 0.7);
                result.addEvidence("Leetspeak detected", 0.7);
            }
            if (report.hasHomoglyphs) {
                score = Math.max(score, 0.75);
                result.addEvidence("Homoglyph characters detected", 0.75);
            }
            if (report.hasZeroWidth) {
                score = Math.max(score, 0.85);
                result.addEvidence("Zero-width characters detected (stealth)", 0.85);
            }
            if (report.wasModified()) {
                result.addEvidence("Text was modified during normalization", 0.5);
            }

            result.rawScore = score;
            result.triggered = score > 0.5;
            result.details = report.hasObfuscation ? "Evasion techniques detected" : "No obfuscation detected";

        } catch (Exception e) {
            result.error = e.getMessage();
            result.rawScore = 0.0;
        }

        return result;
    }

    private LayerResult analyzeRegexPatterns(String normalizedMessage) {
        LayerResult result = new LayerResult();
        result.layerName = "REGEX_PATTERNS";
        result.weight = WEIGHT_REGEX;

        // Check various keyword categories
        Map<String, List<String>> keywordCategories = getKeywordCategories();
        List<String> matchedCategories = new ArrayList<>();
        List<String> matchedKeywords = new ArrayList<>();

        String lowerMessage = normalizedMessage.toLowerCase();

        for (Map.Entry<String, List<String>> entry : keywordCategories.entrySet()) {
            String category = entry.getKey();
            for (String keyword : entry.getValue()) {
                if (lowerMessage.contains(keyword)) {
                    if (!matchedCategories.contains(category)) {
                        matchedCategories.add(category);
                    }
                    if (!matchedKeywords.contains(keyword)) {
                        matchedKeywords.add(keyword);
                    }
                    result.addEvidence("Keyword: \"" + keyword + "\" [" + category + "]", 0.6);
                }
            }
        }

        // Calculate score based on matches
        double score = 0.0;
        if (!matchedKeywords.isEmpty()) {
            // Base score from keyword count
            score = Math.min(0.3 + (matchedKeywords.size() * 0.1), 0.8);

            // Bonus for multiple categories (cross-category signals are stronger)
            if (matchedCategories.size() >= 2) {
                score += 0.15;
                result.addEvidence("Multiple scam categories detected: " + matchedCategories, 0.8);
            }
            if (matchedCategories.size() >= 3) {
                score += 0.1;
            }
        }

        result.rawScore = Math.min(score, 1.0);
        result.triggered = !matchedKeywords.isEmpty();
        result.detectedType = matchedCategories.isEmpty() ? null : matchedCategories.get(0);
        result.details = matchedKeywords.isEmpty() ? "No keyword matches"
                : "Found " + matchedKeywords.size() + " keywords in " + matchedCategories.size() + " categories";

        return result;
    }

    private LayerResult analyzeAdvancedPatterns(String normalizedMessage) {
        LayerResult result = new LayerResult();
        result.layerName = "ADVANCED_PATTERNS";
        result.weight = WEIGHT_ADVANCED;

        try {
            AdvancedPatternMatcher.PatternAnalysisResult patternResult = advancedPatternMatcher
                    .analyzeMessage(normalizedMessage);

            result.rawScore = patternResult.combinedScore;
            result.triggered = patternResult.hasMatches();

            // Add evidence for each match type
            for (AdvancedPatternMatcher.FuzzyMatch match : patternResult.fuzzyMatches) {
                result.addEvidence(
                        String.format("Fuzzy match: \"%s\" ≈ \"%s\" (%.0f%% similar)",
                                match.inputWord, match.matchedKeyword, match.jaroWinklerScore * 100),
                        match.jaroWinklerScore);
            }

            for (AdvancedPatternMatcher.PhoneticMatch match : patternResult.phoneticMatches) {
                result.addEvidence(
                        String.format("Phonetic match: \"%s\" sounds like \"%s\"",
                                match.inputWord, match.matchedKeyword),
                        match.confidence);
            }

            for (AdvancedPatternMatcher.NgramMatch match : patternResult.ngramMatches) {
                if (match.normalizedScore > 0.5) {
                    result.addEvidence(
                            String.format("N-gram match: pattern similar to \"%s\"", match.matchedKeyword),
                            match.normalizedScore);
                }
            }

            if (!patternResult.detectedCategories.isEmpty()) {
                result.detectedType = patternResult.detectedCategories.iterator().next();
            }

            result.details = String.format("Fuzzy: %d, Phonetic: %d, N-gram: %d matches",
                    patternResult.fuzzyMatches.size(),
                    patternResult.phoneticMatches.size(),
                    patternResult.ngramMatches.size());

        } catch (Exception e) {
            result.error = e.getMessage();
            result.rawScore = 0.0;
        }

        return result;
    }

    private LayerResult analyzeSemanticML(String normalizedMessage,
            List<ChatRequest.ConversationMessage> history) {
        LayerResult result = new LayerResult();
        result.layerName = "SEMANTIC_ML";
        result.weight = WEIGHT_SEMANTIC;

        if (semanticScamAnalyzer == null) {
            result.details = "Semantic analyzer not available";
            result.rawScore = 0.0;
            return result;
        }

        try {
            SemanticScamAnalyzer.SemanticAnalysisResult semanticResult = semanticScamAnalyzer
                    .analyzeMessage(normalizedMessage, history).join();

            result.rawScore = semanticResult.combinedScore;
            result.triggered = semanticResult.hasSignificantMatch();
            result.detectedType = semanticResult.primaryScamType;

            // Add semantic similarity evidence
            for (Map.Entry<String, Double> entry : semanticResult.semanticMatches.entrySet()) {
                result.addEvidence(
                        String.format("Semantic similarity to %s patterns: %.0f%%",
                                entry.getKey(), entry.getValue() * 100),
                        entry.getValue());
            }

            // Add intent detection evidence
            for (SemanticScamAnalyzer.IntentScore intent : semanticResult.detectedIntents) {
                if (intent.isSuspicious) {
                    result.addEvidence(
                            String.format("Suspicious intent: \"%s\" (%.0f%% confidence)",
                                    intent.intent, intent.confidence * 100),
                            intent.confidence);
                }
            }

            // Add manipulation tactics evidence
            for (SemanticScamAnalyzer.ManipulationTactic tactic : semanticResult.manipulationTactics) {
                result.addEvidence(
                        String.format("Manipulation tactic: \"%s\" [%s severity]",
                                tactic.tactic, tactic.severity),
                        tactic.confidence);
            }

            result.details = String.format("Intents: %d, Tactics: %d, Semantic matches: %d",
                    semanticResult.detectedIntents.size(),
                    semanticResult.manipulationTactics.size(),
                    semanticResult.semanticMatches.size());

        } catch (Exception e) {
            result.error = e.getMessage();
            result.rawScore = 0.0;
            result.details = "Semantic analysis failed: " + e.getMessage();
        }

        return result;
    }

    private LayerResult analyzeAIModel(String message) {
        LayerResult result = new LayerResult();
        result.layerName = "AI_PHISHING_MODEL";
        result.weight = WEIGHT_AI_MODEL;

        if (localMLService == null || !localMLService.isAvailable()) {
            result.details = "AI model not available";
            result.rawScore = 0.0;
            return result;
        }

        try {
            PhishingDetectionResult aiResult = localMLService.detectPhishing(message);

            if (aiResult != null) {
                result.rawScore = aiResult.isPhishing() ? aiResult.getConfidence() : 0.0;
                result.triggered = aiResult.isPhishing();

                if (aiResult.isPhishing()) {
                    result.addEvidence(
                            String.format("AI model classified as PHISHING (%.0f%% confidence)",
                                    aiResult.getConfidence() * 100),
                            aiResult.getConfidence());
                    result.detectedType = "PHISHING";
                }

                result.details = String.format("Model: DeBERTa (local), Label: %s, Confidence: %.2f",
                        aiResult.getLabel(), aiResult.getConfidence());
            } else {
                result.details = "AI model returned null result";
            }

        } catch (Exception e) {
            result.error = e.getMessage();
            result.rawScore = 0.0;
            result.details = "AI model failed: " + e.getMessage();
        }

        return result;
    }

    // ========================================================================
    // ENSEMBLE SCORING
    // ========================================================================

    private void calculateEnsembleScore(ThreatAssessment assessment) {
        double weightedSum = 0.0;
        double totalWeight = 0.0;
        int triggeredLayers = 0;
        Set<String> detectedTypes = new HashSet<>();

        for (LayerResult layer : assessment.layerResults) {
            double effectiveWeight = layer.weight;

            // Track which layers triggered
            if (layer.triggered) {
                triggeredLayers++;
            }

            // Collect detected types
            if (layer.detectedType != null) {
                detectedTypes.add(layer.detectedType);
            }

            // Add weighted contribution
            weightedSum += layer.rawScore * effectiveWeight;
            totalWeight += effectiveWeight;
        }

        // Base ensemble score
        double ensembleScore = totalWeight > 0 ? weightedSum / totalWeight : 0.0;

        // AGREEMENT BONUS: Multiple layers agreeing increases confidence
        if (triggeredLayers >= 3) {
            ensembleScore += 0.10; // Strong agreement bonus
            assessment.addExplanation("Multiple detection layers agree (+" + triggeredLayers + " layers)");
        } else if (triggeredLayers >= 2) {
            ensembleScore += 0.05; // Moderate agreement bonus
        }

        // TYPE CONSISTENCY BONUS: Same type detected by multiple layers
        if (detectedTypes.size() == 1 && triggeredLayers >= 2) {
            ensembleScore += 0.05;
            assessment.addExplanation("Consistent scam type detected across layers");
        }

        // Cap at 1.0
        assessment.ensembleScore = Math.min(ensembleScore, 1.0);
        assessment.triggeredLayers = triggeredLayers;

        // Determine primary scam type
        assessment.primaryScamType = determinePrimaryType(assessment.layerResults);
    }

    private String determinePrimaryType(List<LayerResult> layers) {
        Map<String, Double> typeScores = new HashMap<>();

        for (LayerResult layer : layers) {
            if (layer.detectedType != null && layer.rawScore > 0.3) {
                typeScores.merge(layer.detectedType,
                        layer.rawScore * layer.weight,
                        Double::sum);
            }
        }

        return typeScores.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("UNKNOWN");
    }

    // ========================================================================
    // CONFIDENCE CALIBRATION
    // ========================================================================

    private void calibrateConfidence(ThreatAssessment assessment) {
        double rawScore = assessment.ensembleScore;

        // Calibration based on layer agreement
        double agreementFactor = assessment.triggeredLayers / 5.0; // 5 layers total

        // Calibrated confidence considers both score and agreement
        double calibrated = (rawScore * 0.7) + (agreementFactor * 0.3);

        // Apply sigmoid-like calibration for extreme values
        if (rawScore > 0.8) {
            calibrated = 0.85 + (rawScore - 0.8) * 0.5; // Flatten high end
        } else if (rawScore < 0.2) {
            calibrated = rawScore * 0.8; // Reduce low-end false positives
        }

        assessment.calibratedConfidence = Math.min(calibrated, 1.0);

        // Determine threat level
        if (assessment.calibratedConfidence >= HIGH_THREAT_THRESHOLD) {
            assessment.threatLevel = assessment.calibratedConfidence >= 0.85 ? "CRITICAL" : "HIGH";
        } else if (assessment.calibratedConfidence >= MEDIUM_THREAT_THRESHOLD) {
            assessment.threatLevel = "MEDIUM";
        } else if (assessment.calibratedConfidence >= LOW_THREAT_THRESHOLD) {
            assessment.threatLevel = "LOW";
        } else {
            assessment.threatLevel = "SAFE";
        }
    }

    // ========================================================================
    // EXPLANATION GENERATION
    // ========================================================================

    private void generateExplanation(ThreatAssessment assessment) {
        StringBuilder summary = new StringBuilder();

        // Overall assessment
        summary.append(String.format("Threat Level: %s (%.0f%% confidence)\n",
                assessment.threatLevel, assessment.calibratedConfidence * 100));

        if (!assessment.primaryScamType.equals("UNKNOWN")) {
            summary.append(String.format("Primary Scam Type: %s\n", assessment.primaryScamType));
        }

        summary.append(String.format("Detection Layers Triggered: %d/5\n\n", assessment.triggeredLayers));

        // Layer-by-layer breakdown
        summary.append("=== DETECTION BREAKDOWN ===\n");
        for (LayerResult layer : assessment.layerResults) {
            String status = layer.triggered ? "⚠️ TRIGGERED" : "✓ Clear";
            summary.append(String.format("%s: %s (score: %.2f)\n",
                    layer.layerName, status, layer.rawScore));

            // Add top evidence items
            if (!layer.evidence.isEmpty()) {
                int count = 0;
                for (Evidence ev : layer.evidence) {
                    if (count++ < 3 && ev.confidence > 0.5) { // Top 3 high-confidence
                        summary.append(String.format("  → %s\n", ev.description));
                    }
                }
            }
        }

        // Key findings
        summary.append("\n=== KEY EVIDENCE ===\n");
        List<Evidence> allEvidence = new ArrayList<>();
        for (LayerResult layer : assessment.layerResults) {
            allEvidence.addAll(layer.evidence);
        }
        allEvidence.sort((a, b) -> Double.compare(b.confidence, a.confidence));

        int evidenceCount = 0;
        for (Evidence ev : allEvidence) {
            if (evidenceCount++ < 5) { // Top 5 overall
                summary.append(String.format("• %s (%.0f%%)\n", ev.description, ev.confidence * 100));
            }
        }

        assessment.explanation = summary.toString();
        assessment.topEvidence = allEvidence.subList(0, Math.min(10, allEvidence.size()));
    }

    // ========================================================================
    // KEYWORD CATEGORIES
    // ========================================================================

    private Map<String, List<String>> getKeywordCategories() {
        Map<String, List<String>> categories = new LinkedHashMap<>();

        categories.put("LOTTERY", Arrays.asList(
                "lottery", "won", "prize", "winner", "congratulations", "claim", "lucky draw",
                "jackpot", "sweepstakes", "selected"));

        categories.put("INVESTMENT", Arrays.asList(
                "investment", "returns", "profit", "earn money", "guaranteed", "double your money",
                "stock market", "trading", "crypto", "bitcoin", "forex", "passive income"));

        categories.put("PHISHING", Arrays.asList(
                "verify account", "update details", "confirm identity", "suspended account",
                "click here", "urgent action", "limited time", "expire", "password reset"));

        categories.put("TECH_SUPPORT", Arrays.asList(
                "virus", "infected", "security alert", "microsoft", "tech support",
                "computer problem", "refund", "subscription", "renewal", "malware"));

        categories.put("JOB_SCAM", Arrays.asList(
                "work from home", "part time job", "easy money", "no experience",
                "registration fee", "joining fee", "training fee", "data entry"));

        categories.put("URGENCY", Arrays.asList(
                "urgent", "immediately", "now", "today", "limited time", "hurry",
                "act fast", "don't miss", "last chance", "expires"));

        categories.put("PAYMENT", Arrays.asList(
                "send money", "transfer", "payment", "upi", "bank account", "ifsc",
                "account number", "paytm", "phonepe", "googlepay", "deposit"));

        return categories;
    }

    // ========================================================================
    // DATA CLASSES
    // ========================================================================

    @Data
    public static class ThreatAssessment {
        public String originalMessage;
        public String normalizedMessage;
        public String timestamp;

        // Scoring
        public double ensembleScore;
        public double calibratedConfidence;
        public String threatLevel;
        public String primaryScamType;
        public int triggeredLayers;

        // Detailed results
        public List<LayerResult> layerResults = new ArrayList<>();
        public List<Evidence> topEvidence = new ArrayList<>();
        public List<String> explanations = new ArrayList<>();
        public String explanation;

        public void addExplanation(String text) {
            explanations.add(text);
        }

        public boolean isHighThreat() {
            return "HIGH".equals(threatLevel) || "CRITICAL".equals(threatLevel);
        }

        public boolean isMediumOrHigher() {
            return !threatLevel.equals("SAFE") && !threatLevel.equals("LOW");
        }

        @Override
        public String toString() {
            return String.format("ThreatAssessment{level=%s, score=%.2f, confidence=%.0f%%, type=%s, layers=%d/5}",
                    threatLevel, ensembleScore, calibratedConfidence * 100, primaryScamType, triggeredLayers);
        }
    }

    @Data
    public static class LayerResult {
        public String layerName;
        public double weight;
        public double rawScore;
        public boolean triggered;
        public String detectedType;
        public String details;
        public String error;
        public String normalizedText; // Only for normalization layer
        public List<Evidence> evidence = new ArrayList<>();

        public void addEvidence(String description, double confidence) {
            evidence.add(new Evidence(description, confidence, layerName));
        }
    }

    @Data
    public static class Evidence {
        public String description;
        public double confidence;
        public String source;

        public Evidence(String description, double confidence, String source) {
            this.description = description;
            this.confidence = confidence;
            this.source = source;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s (%.0f%%)", source, description, confidence * 100);
        }
    }
}
