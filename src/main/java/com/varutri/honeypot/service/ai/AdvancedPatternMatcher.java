package com.varutri.honeypot.service.ai;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.language.DoubleMetaphone;
import org.apache.commons.codec.language.Soundex;
import org.apache.commons.text.similarity.JaroWinklerSimilarity;
import org.apache.commons.text.similarity.LevenshteinDistance;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Advanced Pattern Matching Service for Scam Detection
 * 
 * Implements three sophisticated matching techniques:
 * 1. Fuzzy Matching (Levenshtein distance, Jaro-Winkler similarity)
 * 2. N-gram Based Detection (character and word n-grams)
 * 3. Phonetic Matching (Soundex, Double Metaphone)
 * 
 * These techniques catch scam messages that evade simple keyword matching
 * through misspellings, phonetic substitutions, or word variations.
 */
@Slf4j
@Service
public class AdvancedPatternMatcher {

    // ========================================================================
    // PHONETIC ENCODERS
    // ========================================================================
    private final Soundex soundex = new Soundex();
    private final DoubleMetaphone doubleMetaphone = new DoubleMetaphone();

    // ========================================================================
    // SIMILARITY CALCULATORS
    // ========================================================================
    private final LevenshteinDistance levenshtein = LevenshteinDistance.getDefaultInstance();
    private final JaroWinklerSimilarity jaroWinkler = new JaroWinklerSimilarity();

    // ========================================================================
    // SCAM KEYWORD DATABASE
    // ========================================================================

    // Core scam keywords with their phonetic encodings (precomputed for speed)
    private final Map<String, PhoneticEntry> phoneticDatabase = new HashMap<>();

    // N-gram index for fast pattern matching
    private final Map<String, Set<String>> bigramIndex = new HashMap<>();
    private final Map<String, Set<String>> trigramIndex = new HashMap<>();

    // Scam keywords organized by category
    private static final Map<String, List<String>> SCAM_KEYWORDS = new LinkedHashMap<>();
    static {
        SCAM_KEYWORDS.put("LOTTERY", Arrays.asList(
                "lottery", "lotto", "jackpot", "prize", "winner", "won", "winning",
                "lucky draw", "lucky number", "lucky winner", "congratulations",
                "claim prize", "prize money", "cash prize"));

        SCAM_KEYWORDS.put("INVESTMENT", Arrays.asList(
                "investment", "invest", "returns", "profit", "earn money", "guaranteed",
                "double money", "triple", "high returns", "passive income", "bitcoin",
                "crypto", "forex", "trading", "stock market", "mutual fund"));

        SCAM_KEYWORDS.put("PHISHING", Arrays.asList(
                "verify account", "verify identity", "update details", "confirm identity",
                "suspended account", "click here", "urgent action", "limited time",
                "expire", "security alert", "password reset", "login required"));

        SCAM_KEYWORDS.put("TECH_SUPPORT", Arrays.asList(
                "virus", "infected", "malware", "security alert", "microsoft",
                "tech support", "computer problem", "refund", "subscription",
                "renewal", "antivirus", "hacked"));

        SCAM_KEYWORDS.put("JOB_SCAM", Arrays.asList(
                "work from home", "part time job", "easy money", "no experience",
                "registration fee", "joining fee", "training fee", "typing job",
                "data entry", "guaranteed income"));

        SCAM_KEYWORDS.put("PAYMENT", Arrays.asList(
                "send money", "transfer", "payment", "bank account", "account number",
                "ifsc", "upi", "paytm", "phonepe", "googlepay", "deposit", "withdraw"));

        SCAM_KEYWORDS.put("URGENCY", Arrays.asList(
                "urgent", "immediately", "now", "today", "hurry", "act fast",
                "last chance", "expires", "deadline", "limited time", "quick"));
    }

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    @PostConstruct
    public void initialize() {
        log.info("Initializing Advanced Pattern Matcher...");

        // Build phonetic database
        for (Map.Entry<String, List<String>> entry : SCAM_KEYWORDS.entrySet()) {
            String category = entry.getKey();
            for (String keyword : entry.getValue()) {
                addToPhoneticDatabase(keyword, category);
                addToNgramIndex(keyword, category);
            }
        }

        log.info("✅ Advanced Pattern Matcher initialized with {} keywords, {} bigrams, {} trigrams",
                phoneticDatabase.size(), bigramIndex.size(), trigramIndex.size());
    }

    private void addToPhoneticDatabase(String keyword, String category) {
        try {
            // Split multi-word keywords
            String[] words = keyword.toLowerCase().split("\\s+");
            for (String word : words) {
                if (word.length() >= 3) { // Skip very short words
                    PhoneticEntry entry = new PhoneticEntry();
                    entry.word = word;
                    entry.category = category;
                    entry.soundexCode = encodeSoundex(word);
                    entry.metaphoneCode = encodeMetaphone(word);
                    phoneticDatabase.put(word, entry);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to encode phonetic for: {}", keyword);
        }
    }

    private void addToNgramIndex(String keyword, String category) {
        String lowerKeyword = keyword.toLowerCase();

        // Generate character bigrams
        for (String bigram : generateCharacterNgrams(lowerKeyword, 2)) {
            bigramIndex.computeIfAbsent(bigram, k -> new HashSet<>()).add(keyword);
        }

        // Generate character trigrams
        for (String trigram : generateCharacterNgrams(lowerKeyword, 3)) {
            trigramIndex.computeIfAbsent(trigram, k -> new HashSet<>()).add(keyword);
        }
    }

    // ========================================================================
    // FUZZY MATCHING
    // ========================================================================

    /**
     * Find fuzzy matches for a word in the scam keyword database
     * Uses Levenshtein distance and Jaro-Winkler similarity
     * 
     * @param word        Word to check
     * @param maxDistance Maximum Levenshtein distance allowed
     * @return List of matching keywords with scores
     */
    public List<FuzzyMatch> fuzzyMatch(String word, int maxDistance) {
        List<FuzzyMatch> matches = new ArrayList<>();
        String lowerWord = word.toLowerCase();

        if (lowerWord.length() < 3) {
            return matches; // Skip very short words
        }

        for (Map.Entry<String, PhoneticEntry> entry : phoneticDatabase.entrySet()) {
            String keyword = entry.getKey();
            PhoneticEntry phoneticEntry = entry.getValue();

            // Calculate Levenshtein distance
            int distance = levenshtein.apply(lowerWord, keyword);

            // Only consider if within threshold
            if (distance <= maxDistance && distance > 0) {
                // Calculate similarity score (0-1)
                double jaroWinklerScore = jaroWinkler.apply(lowerWord, keyword);

                if (jaroWinklerScore >= 0.8) { // High similarity threshold
                    FuzzyMatch match = new FuzzyMatch();
                    match.inputWord = word;
                    match.matchedKeyword = keyword;
                    match.category = phoneticEntry.category;
                    match.levenshteinDistance = distance;
                    match.jaroWinklerScore = jaroWinklerScore;
                    matches.add(match);
                }
            }
        }

        // Sort by similarity (highest first)
        matches.sort((a, b) -> Double.compare(b.jaroWinklerScore, a.jaroWinklerScore));

        return matches;
    }

    /**
     * Find fuzzy matches in a full message
     */
    public List<FuzzyMatch> fuzzyMatchMessage(String message, int maxDistance) {
        List<FuzzyMatch> allMatches = new ArrayList<>();
        String[] words = message.toLowerCase().split("\\W+");

        for (String word : words) {
            allMatches.addAll(fuzzyMatch(word, maxDistance));
        }

        return allMatches;
    }

    // ========================================================================
    // PHONETIC MATCHING
    // ========================================================================

    /**
     * Find phonetic matches using Soundex and Double Metaphone
     * Catches words that SOUND like scam keywords even if spelled differently
     * 
     * @param word Word to check
     * @return List of phonetically similar keywords
     */
    public List<PhoneticMatch> phoneticMatch(String word) {
        List<PhoneticMatch> matches = new ArrayList<>();
        String lowerWord = word.toLowerCase();

        if (lowerWord.length() < 3) {
            return matches;
        }

        String wordSoundex = encodeSoundex(lowerWord);
        String wordMetaphone = encodeMetaphone(lowerWord);

        for (Map.Entry<String, PhoneticEntry> entry : phoneticDatabase.entrySet()) {
            PhoneticEntry phoneticEntry = entry.getValue();

            boolean soundexMatch = wordSoundex != null &&
                    wordSoundex.equals(phoneticEntry.soundexCode);
            boolean metaphoneMatch = wordMetaphone != null &&
                    wordMetaphone.equals(phoneticEntry.metaphoneCode);

            if ((soundexMatch || metaphoneMatch) && !lowerWord.equals(entry.getKey())) {
                PhoneticMatch match = new PhoneticMatch();
                match.inputWord = word;
                match.matchedKeyword = entry.getKey();
                match.category = phoneticEntry.category;
                match.soundexMatch = soundexMatch;
                match.metaphoneMatch = metaphoneMatch;
                match.confidence = calculatePhoneticConfidence(soundexMatch, metaphoneMatch);
                matches.add(match);
            }
        }

        // Sort by confidence
        matches.sort((a, b) -> Double.compare(b.confidence, a.confidence));

        return matches;
    }

    /**
     * Find phonetic matches in a full message
     */
    public List<PhoneticMatch> phoneticMatchMessage(String message) {
        List<PhoneticMatch> allMatches = new ArrayList<>();
        String[] words = message.split("\\W+");

        for (String word : words) {
            allMatches.addAll(phoneticMatch(word));
        }

        return allMatches;
    }

    private double calculatePhoneticConfidence(boolean soundexMatch, boolean metaphoneMatch) {
        if (soundexMatch && metaphoneMatch) {
            return 0.95; // Both algorithms agree
        } else if (metaphoneMatch) {
            return 0.85; // Metaphone is more accurate
        } else {
            return 0.70; // Only Soundex match
        }
    }

    // ========================================================================
    // N-GRAM MATCHING
    // ========================================================================

    /**
     * Find N-gram based matches
     * Uses character n-grams to detect similar words even with typos
     * 
     * @param text Text to analyze
     * @return Map of potential scam keywords with match scores
     */
    public List<NgramMatch> ngramMatch(String text) {
        List<NgramMatch> matches = new ArrayList<>();
        String lowerText = text.toLowerCase();

        // Generate n-grams from input text
        Set<String> textBigrams = generateCharacterNgrams(lowerText, 2);
        Set<String> textTrigrams = generateCharacterNgrams(lowerText, 3);

        // Find keywords with overlapping n-grams
        Map<String, Double> keywordScores = new HashMap<>();

        // Check bigram overlap
        for (String bigram : textBigrams) {
            Set<String> matchingKeywords = bigramIndex.get(bigram);
            if (matchingKeywords != null) {
                for (String keyword : matchingKeywords) {
                    keywordScores.merge(keyword, 1.0, Double::sum);
                }
            }
        }

        // Check trigram overlap (weighted higher)
        for (String trigram : textTrigrams) {
            Set<String> matchingKeywords = trigramIndex.get(trigram);
            if (matchingKeywords != null) {
                for (String keyword : matchingKeywords) {
                    keywordScores.merge(keyword, 2.0, Double::sum); // Higher weight
                }
            }
        }

        // Calculate normalized scores and filter
        for (Map.Entry<String, Double> entry : keywordScores.entrySet()) {
            String keyword = entry.getKey();
            double score = entry.getValue();

            // Normalize by keyword length
            int expectedNgrams = keyword.length() - 1 + (keyword.length() - 2) * 2; // bigrams + trigrams*2
            double normalizedScore = score / Math.max(expectedNgrams, 1);

            if (normalizedScore >= 0.3) { // Threshold for significant match
                NgramMatch match = new NgramMatch();
                match.matchedKeyword = keyword;
                match.rawScore = score;
                match.normalizedScore = normalizedScore;
                match.category = findCategoryForKeyword(keyword);
                matches.add(match);
            }
        }

        // Sort by normalized score
        matches.sort((a, b) -> Double.compare(b.normalizedScore, a.normalizedScore));

        // Limit results
        return matches.stream().limit(10).collect(Collectors.toList());
    }

    // ========================================================================
    // COMBINED ANALYSIS
    // ========================================================================

    /**
     * Perform comprehensive pattern analysis on a message
     * Combines all three techniques for maximum detection
     * 
     * @param message Message to analyze
     * @return Combined analysis result
     */
    public PatternAnalysisResult analyzeMessage(String message) {
        PatternAnalysisResult result = new PatternAnalysisResult();
        result.originalMessage = message;

        // 1. Fuzzy matching (catches typos and misspellings)
        result.fuzzyMatches = fuzzyMatchMessage(message, 2);

        // 2. Phonetic matching (catches sound-alike substitutions)
        result.phoneticMatches = phoneticMatchMessage(message);

        // 3. N-gram matching (catches partial matches and variations)
        result.ngramMatches = ngramMatch(message);

        // Calculate combined threat score
        result.combinedScore = calculateCombinedScore(result);

        // Determine detected categories
        result.detectedCategories = extractCategories(result);

        // Log significant findings
        if (result.combinedScore >= 0.5) {
            log.info("🎯 Advanced pattern analysis: score={}, categories={}, fuzzy={}, phonetic={}, ngram={}",
                    String.format("%.2f", result.combinedScore),
                    result.detectedCategories,
                    result.fuzzyMatches.size(),
                    result.phoneticMatches.size(),
                    result.ngramMatches.size());
        }

        return result;
    }

    private double calculateCombinedScore(PatternAnalysisResult result) {
        double score = 0.0;

        // Fuzzy matches (weight: 0.3)
        if (!result.fuzzyMatches.isEmpty()) {
            double avgFuzzyScore = result.fuzzyMatches.stream()
                    .mapToDouble(m -> m.jaroWinklerScore)
                    .average()
                    .orElse(0);
            score += avgFuzzyScore * 0.3;
        }

        // Phonetic matches (weight: 0.4)
        if (!result.phoneticMatches.isEmpty()) {
            double avgPhoneticScore = result.phoneticMatches.stream()
                    .mapToDouble(m -> m.confidence)
                    .average()
                    .orElse(0);
            score += avgPhoneticScore * 0.4;
        }

        // N-gram matches (weight: 0.3)
        if (!result.ngramMatches.isEmpty()) {
            double avgNgramScore = result.ngramMatches.stream()
                    .mapToDouble(m -> m.normalizedScore)
                    .average()
                    .orElse(0);
            score += avgNgramScore * 0.3;
        }

        // Bonus for multiple detection methods agreeing
        int methodsWithMatches = 0;
        if (!result.fuzzyMatches.isEmpty())
            methodsWithMatches++;
        if (!result.phoneticMatches.isEmpty())
            methodsWithMatches++;
        if (!result.ngramMatches.isEmpty())
            methodsWithMatches++;

        if (methodsWithMatches >= 2) {
            score += 0.1; // Agreement bonus
        }

        return Math.min(score, 1.0);
    }

    private Set<String> extractCategories(PatternAnalysisResult result) {
        Set<String> categories = new HashSet<>();

        result.fuzzyMatches.forEach(m -> categories.add(m.category));
        result.phoneticMatches.forEach(m -> categories.add(m.category));
        result.ngramMatches.stream()
                .filter(m -> m.category != null)
                .forEach(m -> categories.add(m.category));

        return categories;
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    private String encodeSoundex(String word) {
        try {
            return soundex.encode(word);
        } catch (Exception e) {
            return null;
        }
    }

    private String encodeMetaphone(String word) {
        try {
            return doubleMetaphone.encode(word);
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> generateCharacterNgrams(String text, int n) {
        Set<String> ngrams = new HashSet<>();
        String cleaned = text.replaceAll("\\s+", " ").toLowerCase();

        for (int i = 0; i <= cleaned.length() - n; i++) {
            ngrams.add(cleaned.substring(i, i + n));
        }

        return ngrams;
    }

    private String findCategoryForKeyword(String keyword) {
        for (Map.Entry<String, List<String>> entry : SCAM_KEYWORDS.entrySet()) {
            if (entry.getValue().contains(keyword.toLowerCase())) {
                return entry.getKey();
            }
        }
        return null;
    }

    // ========================================================================
    // DATA CLASSES
    // ========================================================================

    private static class PhoneticEntry {
        String word;
        String category;
        String soundexCode;
        String metaphoneCode;
    }

    public static class FuzzyMatch {
        public String inputWord;
        public String matchedKeyword;
        public String category;
        public int levenshteinDistance;
        public double jaroWinklerScore;

        @Override
        public String toString() {
            return String.format("FuzzyMatch{%s→%s, dist=%d, jw=%.2f, cat=%s}",
                    inputWord, matchedKeyword, levenshteinDistance, jaroWinklerScore, category);
        }
    }

    public static class PhoneticMatch {
        public String inputWord;
        public String matchedKeyword;
        public String category;
        public boolean soundexMatch;
        public boolean metaphoneMatch;
        public double confidence;

        @Override
        public String toString() {
            return String.format("PhoneticMatch{%s→%s, soundex=%s, metaphone=%s, conf=%.2f, cat=%s}",
                    inputWord, matchedKeyword, soundexMatch, metaphoneMatch, confidence, category);
        }
    }

    public static class NgramMatch {
        public String matchedKeyword;
        public String category;
        public double rawScore;
        public double normalizedScore;

        @Override
        public String toString() {
            return String.format("NgramMatch{%s, raw=%.1f, norm=%.2f, cat=%s}",
                    matchedKeyword, rawScore, normalizedScore, category);
        }
    }

    public static class PatternAnalysisResult {
        public String originalMessage;
        public List<FuzzyMatch> fuzzyMatches = new ArrayList<>();
        public List<PhoneticMatch> phoneticMatches = new ArrayList<>();
        public List<NgramMatch> ngramMatches = new ArrayList<>();
        public double combinedScore;
        public Set<String> detectedCategories = new HashSet<>();

        public boolean hasMatches() {
            return !fuzzyMatches.isEmpty() || !phoneticMatches.isEmpty() || !ngramMatches.isEmpty();
        }

        @Override
        public String toString() {
            return String.format("PatternAnalysis{score=%.2f, categories=%s, fuzzy=%d, phonetic=%d, ngram=%d}",
                    combinedScore, detectedCategories, fuzzyMatches.size(),
                    phoneticMatches.size(), ngramMatches.size());
        }
    }
}

