package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.service.ml.LocalMLService;

import com.varutri.honeypot.dto.PhishingDetectionResult;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Service for detecting scam patterns and calculating threat levels
 * Combines text normalization, regex-based detection, and AI-powered phishing
 * detection
 * 
 * Text normalization handles evasion techniques:
 * - Leetspeak: l0ttery → lottery
 * - Homoglyphs: Cyrillic chars → Latin
 * - Obfuscation: l.o.t.t.e.r.y → lottery
 */
@Slf4j
@Service
public class ScamDetector {

    // Text normalizer for handling evasion techniques
    @Autowired
    private TextNormalizer textNormalizer;

    // Advanced pattern matcher for fuzzy, phonetic, and n-gram matching
    @Autowired
    private AdvancedPatternMatcher advancedPatternMatcher;

    // Semantic scam analyzer for ML-based detection (embeddings, intent, tactics)
    @Autowired(required = false)
    private SemanticScamAnalyzer semanticScamAnalyzer;

    // Local ML service for AI-powered phishing detection
    @Autowired(required = false)
    private LocalMLService localMLService;

    // Cache for AI detection result to avoid duplicate calls
    private final ThreadLocal<PhishingDetectionResult> cachedAiResult = new ThreadLocal<>();

    // Cache for normalization analysis
    private final ThreadLocal<TextNormalizer.NormalizationReport> cachedNormReport = new ThreadLocal<>();

    // Cache for advanced pattern analysis
    private final ThreadLocal<AdvancedPatternMatcher.PatternAnalysisResult> cachedPatternResult = new ThreadLocal<>();

    // Cache for semantic analysis result
    private final ThreadLocal<SemanticScamAnalyzer.SemanticAnalysisResult> cachedSemanticResult = new ThreadLocal<>();

    // Scam type keywords
    private static final List<String> INVESTMENT_SCAM_KEYWORDS = Arrays.asList(
            "investment", "returns", "profit", "earn money", "guaranteed", "double your money",
            "stock market", "trading", "crypto", "bitcoin", "forex");

    private static final List<String> LOTTERY_SCAM_KEYWORDS = Arrays.asList(
            "lottery", "won", "prize", "winner", "congratulations", "claim", "lucky draw");

    private static final List<String> TECH_SUPPORT_SCAM_KEYWORDS = Arrays.asList(
            "virus", "infected", "security alert", "microsoft", "tech support", "computer problem",
            "refund", "subscription", "renewal");

    private static final List<String> PHISHING_KEYWORDS = Arrays.asList(
            "verify account", "update details", "confirm identity", "suspended account",
            "click here", "urgent action", "limited time", "expire");

    private static final List<String> JOB_SCAM_KEYWORDS = Arrays.asList(
            "work from home", "part time job", "easy money", "no experience", "registration fee",
            "joining fee", "training fee");

    private static final List<String> URGENCY_KEYWORDS = Arrays.asList(
            "urgent", "immediately", "now", "today", "limited time", "hurry", "act fast",
            "don't miss", "last chance", "expires");

    private static final List<String> PAYMENT_REQUEST_KEYWORDS = Arrays.asList(
            "send money", "transfer", "payment", "upi", "bank account", "ifsc", "account number",
            "paytm", "phonepe", "googlepay", "deposit");

    /**
     * Detect scam type based on message content
     * Uses a 5-LAYER detection pipeline:
     * 1. Text normalization (leetspeak, homoglyphs, obfuscation)
     * 2. Regex-based keyword matching
     * 3. Advanced pattern matching (fuzzy, phonetic, n-gram)
     * 4. Semantic ML analysis (embeddings, intent, manipulation tactics)
     * 5. AI phishing model detection
     */
    public String detectScamType(String message) {
        // === LAYER 1: Text Normalization ===
        TextNormalizer.NormalizationReport normReport = textNormalizer.analyzeText(message);
        cachedNormReport.set(normReport);

        String normalizedMessage = normReport.normalizedText;

        // Log if obfuscation was detected (potential evasion attempt)
        if (normReport.hasObfuscation) {
            log.warn("Text obfuscation detected! Original: '{}', Normalized: '{}'",
                    truncate(message, 50), truncate(normalizedMessage, 50));
        }

        // === LAYER 2: Regex-based detection on NORMALIZED text ===
        String regexResult = detectScamTypeByRegex(normalizedMessage);

        // If regex found a specific type, return it
        if (!regexResult.equals("UNKNOWN")) {
            if (normReport.hasObfuscation) {
                return regexResult + "_OBFUSCATED";
            }
            return regexResult;
        }

        // === LAYER 3: Advanced Pattern Matching (fuzzy, phonetic, n-gram) ===
        AdvancedPatternMatcher.PatternAnalysisResult patternResult = advancedPatternMatcher
                .analyzeMessage(normalizedMessage);
        cachedPatternResult.set(patternResult);

        if (patternResult.combinedScore >= 0.5 && !patternResult.detectedCategories.isEmpty()) {
            // Get the most likely scam type from advanced matching
            String detectedType = patternResult.detectedCategories.iterator().next();
            log.info("Advanced pattern matching detected: {} (score: {}, methods: fuzzy={}, phonetic={}, ngram={})",
                    detectedType,
                    String.format("%.2f", patternResult.combinedScore),
                    patternResult.fuzzyMatches.size(),
                    patternResult.phoneticMatches.size(),
                    patternResult.ngramMatches.size());

            String suffix = normReport.hasObfuscation ? "_OBFUSCATED" : "_ADVANCED";
            return detectedType + suffix;
        }

        // === LAYER 4: Semantic ML Analysis (embeddings, intent, manipulation) ===
        if (semanticScamAnalyzer != null) {
            try {
                SemanticScamAnalyzer.SemanticAnalysisResult semanticResult = semanticScamAnalyzer
                        .analyzeMessage(normalizedMessage, null).join();
                cachedSemanticResult.set(semanticResult);

                if (semanticResult.hasSignificantMatch()) {
                    log.info("Semantic ML detected: {} (score: {}, intents={}, tactics={})",
                            semanticResult.primaryScamType,
                            String.format("%.2f", semanticResult.combinedScore),
                            semanticResult.detectedIntents.size(),
                            semanticResult.manipulationTactics.size());

                    String suffix = normReport.hasObfuscation ? "_OBFUSCATED" : "_SEMANTIC";
                    return semanticResult.primaryScamType + suffix;
                }
            } catch (Exception e) {
                log.debug("Semantic analysis skipped: {}", e.getMessage());
            }
        }

        // === LAYER 5: AI Phishing Model Detection ===
        PhishingDetectionResult aiResult = getAiPhishingResult(message);
        if (aiResult != null && aiResult.isPhishing() && aiResult.getConfidence() > 0.7) {
            log.info("AI model detected phishing with confidence: {}",
                    String.format("%.2f", aiResult.getConfidence()));
            return "PHISHING_AI_DETECTED";
        }

        return "UNKNOWN";
    }

    /**
     * Truncate string for logging
     */
    private String truncate(String text, int maxLength) {
        if (text == null)
            return "";
        return text.length() > maxLength ? text.substring(0, maxLength) + "..." : text;
    }

    /**
     * Regex-based scam type detection
     */
    private String detectScamTypeByRegex(String lowerMessage) {
        if (containsKeywords(lowerMessage, INVESTMENT_SCAM_KEYWORDS)) {
            return "INVESTMENT_SCAM";
        } else if (containsKeywords(lowerMessage, LOTTERY_SCAM_KEYWORDS)) {
            return "LOTTERY_SCAM";
        } else if (containsKeywords(lowerMessage, TECH_SUPPORT_SCAM_KEYWORDS)) {
            return "TECH_SUPPORT_SCAM";
        } else if (containsKeywords(lowerMessage, PHISHING_KEYWORDS)) {
            return "PHISHING";
        } else if (containsKeywords(lowerMessage, JOB_SCAM_KEYWORDS)) {
            return "JOB_SCAM";
        }
        return "UNKNOWN";
    }

    /**
     * Get AI phishing detection result (cached per request)
     */
    private PhishingDetectionResult getAiPhishingResult(String message) {
        // Check if we have a cached result
        PhishingDetectionResult cached = cachedAiResult.get();
        if (cached != null) {
            return cached;
        }

        // Call local ML service if available
        if (localMLService != null && localMLService.isAvailable()) {
            try {
                PhishingDetectionResult result = localMLService.detectPhishing(message);
                cachedAiResult.set(result);
                return result;
            } catch (Exception e) {
                log.warn("AI phishing detection failed, falling back to regex only: {}", e.getMessage());
            }
        }

        return null;
    }

    /**
     * Clear the cached AI result, normalization report, pattern result, and
     * semantic result
     * (call after processing a message)
     */
    public void clearCache() {
        cachedAiResult.remove();
        cachedNormReport.remove();
        cachedPatternResult.remove();
        cachedSemanticResult.remove();
    }

    /**
     * Calculate threat level (0.0 to 1.0)
     * Combines all 5 detection layers: normalization, regex, advanced patterns,
     * semantic ML, and AI
     */
    public double calculateThreatLevel(String message) {
        double threatLevel = 0.0;

        // Get or create normalization report
        TextNormalizer.NormalizationReport normReport = cachedNormReport.get();
        if (normReport == null) {
            normReport = textNormalizer.analyzeText(message);
            cachedNormReport.set(normReport);
        }

        String normalizedMessage = normReport.normalizedText;

        // Obfuscation attempt adds to threat level (indicates evasion behavior)
        if (normReport.hasObfuscation) {
            threatLevel += 0.12;
            log.debug("Obfuscation detected, adding 0.12 to threat level");
        }

        // Base threat from regex-based scam type detection on NORMALIZED text
        String scamType = detectScamTypeByRegex(normalizedMessage);
        if (!scamType.equals("UNKNOWN")) {
            threatLevel += 0.20;
        }

        // Urgency indicators (on normalized text)
        if (containsKeywords(normalizedMessage, URGENCY_KEYWORDS)) {
            threatLevel += 0.12;
        }

        // Payment requests (on normalized text)
        if (containsKeywords(normalizedMessage, PAYMENT_REQUEST_KEYWORDS)) {
            threatLevel += 0.20;
        }

        // Multiple suspicious patterns (regex-based)
        int patternCount = 0;
        if (containsKeywords(normalizedMessage, INVESTMENT_SCAM_KEYWORDS))
            patternCount++;
        if (containsKeywords(normalizedMessage, LOTTERY_SCAM_KEYWORDS))
            patternCount++;
        if (containsKeywords(normalizedMessage, TECH_SUPPORT_SCAM_KEYWORDS))
            patternCount++;
        if (containsKeywords(normalizedMessage, PHISHING_KEYWORDS))
            patternCount++;
        if (containsKeywords(normalizedMessage, JOB_SCAM_KEYWORDS))
            patternCount++;

        if (patternCount >= 2) {
            threatLevel += 0.12;
        }

        // === Advanced Pattern Matching Contribution (max 0.15) ===
        AdvancedPatternMatcher.PatternAnalysisResult patternResult = cachedPatternResult.get();
        if (patternResult == null) {
            patternResult = advancedPatternMatcher.analyzeMessage(normalizedMessage);
            cachedPatternResult.set(patternResult);
        }

        double advancedContribution = patternResult.combinedScore * 0.15;
        threatLevel += advancedContribution;

        if (advancedContribution > 0.05) {
            log.debug("Advanced pattern matching added {} to threat level (fuzzy={}, phonetic={}, ngram={})",
                    String.format("%.2f", advancedContribution),
                    patternResult.fuzzyMatches.size(),
                    patternResult.phoneticMatches.size(),
                    patternResult.ngramMatches.size());
        }

        // === Semantic ML Analysis Contribution (max 0.20) ===
        if (semanticScamAnalyzer != null) {
            try {
                SemanticScamAnalyzer.SemanticAnalysisResult semanticResult = cachedSemanticResult.get();
                if (semanticResult == null) {
                    semanticResult = semanticScamAnalyzer.analyzeMessage(normalizedMessage, null).join();
                    cachedSemanticResult.set(semanticResult);
                }

                double semanticContribution = semanticResult.combinedScore * 0.20;
                threatLevel += semanticContribution;

                if (semanticContribution > 0.05) {
                    log.debug("Semantic ML added {} to threat level (intents={}, tactics={})",
                            String.format("%.2f", semanticContribution),
                            semanticResult.detectedIntents.size(),
                            semanticResult.manipulationTactics.size());
                }
            } catch (Exception e) {
                log.debug("Semantic analysis contribution skipped: {}", e.getMessage());
            }
        }

        // === AI Model Contribution (max 0.15) ===
        PhishingDetectionResult aiResult = getAiPhishingResult(message);
        if (aiResult != null && aiResult.isPhishing()) {
            double aiContribution = aiResult.getConfidence() * 0.15;
            threatLevel += aiContribution;
            log.debug("AI phishing detection added {} to threat level", String.format("%.2f", aiContribution));
        }

        // Clear cache after calculating
        clearCache();

        return Math.min(threatLevel, 1.0);
    }

    /**
     * Extract suspicious keywords found in message
     */
    public List<String> extractSuspiciousKeywords(String message) {
        String lowerMessage = message.toLowerCase();
        List<String> found = new ArrayList<>();

        List<List<String>> allKeywordLists = Arrays.asList(
                INVESTMENT_SCAM_KEYWORDS,
                LOTTERY_SCAM_KEYWORDS,
                TECH_SUPPORT_SCAM_KEYWORDS,
                PHISHING_KEYWORDS,
                JOB_SCAM_KEYWORDS,
                URGENCY_KEYWORDS,
                PAYMENT_REQUEST_KEYWORDS);

        for (List<String> keywords : allKeywordLists) {
            for (String keyword : keywords) {
                if (lowerMessage.contains(keyword) && !found.contains(keyword)) {
                    found.add(keyword);
                }
            }
        }

        // Add AI detection indicator if applicable
        PhishingDetectionResult aiResult = getAiPhishingResult(message);
        if (aiResult != null && aiResult.isPhishing() && aiResult.getConfidence() > 0.7) {
            found.add("[AI_PHISHING_DETECTED:" + String.format("%.2f", aiResult.getConfidence()) + "]");
        }

        return found;
    }

    /**
     * Check if message contains any keywords from the list
     */
    private boolean containsKeywords(String message, List<String> keywords) {
        return keywords.stream().anyMatch(message::contains);
    }

    /**
     * Determine if threat level warrants an alert
     */
    public boolean shouldTriggerAlert(double threatLevel) {
        return threatLevel >= 0.6; // Alert if 60% or higher threat
    }

    /**
     * Check if AI phishing detection is available
     */
    public boolean isAiDetectionAvailable() {
        return localMLService != null && localMLService.isAvailable();
    }
}
