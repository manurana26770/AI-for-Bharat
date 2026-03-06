package com.varutri.honeypot.service.ai;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Text normalization service for scam detection
 * 
 * Handles common evasion techniques:
 * - Leetspeak: l0ttery → lottery, pr1ze → prize
 * - Homoglyphs: Cyrillic 'о' → Latin 'o'
 * - Obfuscation: l.o.t.t.e.r.y → lottery
 * - Zero-width chars: invisible characters removed
 * - Unicode normalization: NFKC form
 */
@Slf4j
@Service
public class TextNormalizer {

    // ========================================================================
    // LEETSPEAK MAPPINGS
    // Common substitutions scammers use to bypass keyword filters
    // ========================================================================
    private static final Map<Character, Character> LEETSPEAK_MAP = new HashMap<>();
    static {
        // Numbers to letters
        LEETSPEAK_MAP.put('0', 'o');
        LEETSPEAK_MAP.put('1', 'i');
        LEETSPEAK_MAP.put('2', 'z');
        LEETSPEAK_MAP.put('3', 'e');
        LEETSPEAK_MAP.put('4', 'a');
        LEETSPEAK_MAP.put('5', 's');
        LEETSPEAK_MAP.put('6', 'g');
        LEETSPEAK_MAP.put('7', 't');
        LEETSPEAK_MAP.put('8', 'b');
        LEETSPEAK_MAP.put('9', 'g');

        // Special characters to letters
        LEETSPEAK_MAP.put('@', 'a');
        LEETSPEAK_MAP.put('$', 's');
        LEETSPEAK_MAP.put('!', 'i');
        LEETSPEAK_MAP.put('|', 'i');
        LEETSPEAK_MAP.put('+', 't');
        LEETSPEAK_MAP.put('(', 'c');
        LEETSPEAK_MAP.put(')', 'd');
    }

    // ========================================================================
    // HOMOGLYPH MAPPINGS
    // Characters that look similar but are from different Unicode blocks
    // ========================================================================
    private static final Map<Character, Character> HOMOGLYPH_MAP = new HashMap<>();
    static {
        // Cyrillic to Latin
        HOMOGLYPH_MAP.put('а', 'a'); // Cyrillic 'a'
        HOMOGLYPH_MAP.put('е', 'e'); // Cyrillic 'e'
        HOMOGLYPH_MAP.put('о', 'o'); // Cyrillic 'o'
        HOMOGLYPH_MAP.put('р', 'p'); // Cyrillic 'r' (looks like 'p')
        HOMOGLYPH_MAP.put('с', 'c'); // Cyrillic 's' (looks like 'c')
        HOMOGLYPH_MAP.put('у', 'y'); // Cyrillic 'u' (looks like 'y')
        HOMOGLYPH_MAP.put('х', 'x'); // Cyrillic 'kh' (looks like 'x')
        HOMOGLYPH_MAP.put('і', 'i'); // Ukrainian 'i'
        HOMOGLYPH_MAP.put('ј', 'j'); // Cyrillic 'je'
        HOMOGLYPH_MAP.put('ѕ', 's'); // Cyrillic 'dze'

        // Greek to Latin
        HOMOGLYPH_MAP.put('α', 'a'); // Greek alpha
        HOMOGLYPH_MAP.put('ο', 'o'); // Greek omicron
        HOMOGLYPH_MAP.put('ε', 'e'); // Greek epsilon
        HOMOGLYPH_MAP.put('ι', 'i'); // Greek iota
        HOMOGLYPH_MAP.put('ν', 'v'); // Greek nu (looks like 'v')
        HOMOGLYPH_MAP.put('ρ', 'p'); // Greek rho

        // Fullwidth Latin (often used in Asian spam)
        HOMOGLYPH_MAP.put('ａ', 'a');
        HOMOGLYPH_MAP.put('ｂ', 'b');
        HOMOGLYPH_MAP.put('ｃ', 'c');
        HOMOGLYPH_MAP.put('ｄ', 'd');
        HOMOGLYPH_MAP.put('ｅ', 'e');
        HOMOGLYPH_MAP.put('ｆ', 'f');
        HOMOGLYPH_MAP.put('ｇ', 'g');
        HOMOGLYPH_MAP.put('ｈ', 'h');
        HOMOGLYPH_MAP.put('ｉ', 'i');
        HOMOGLYPH_MAP.put('ｊ', 'j');
        HOMOGLYPH_MAP.put('ｋ', 'k');
        HOMOGLYPH_MAP.put('ｌ', 'l');
        HOMOGLYPH_MAP.put('ｍ', 'm');
        HOMOGLYPH_MAP.put('ｎ', 'n');
        HOMOGLYPH_MAP.put('ｏ', 'o');
        HOMOGLYPH_MAP.put('ｐ', 'p');
        HOMOGLYPH_MAP.put('ｑ', 'q');
        HOMOGLYPH_MAP.put('ｒ', 'r');
        HOMOGLYPH_MAP.put('ｓ', 's');
        HOMOGLYPH_MAP.put('ｔ', 't');
        HOMOGLYPH_MAP.put('ｕ', 'u');
        HOMOGLYPH_MAP.put('ｖ', 'v');
        HOMOGLYPH_MAP.put('ｗ', 'w');
        HOMOGLYPH_MAP.put('ｘ', 'x');
        HOMOGLYPH_MAP.put('ｙ', 'y');
        HOMOGLYPH_MAP.put('ｚ', 'z');

        // Special lookalikes
        HOMOGLYPH_MAP.put('ℓ', 'l'); // Script small l
        HOMOGLYPH_MAP.put('ℯ', 'e'); // Script small e
        HOMOGLYPH_MAP.put('ℴ', 'o'); // Script small o
        HOMOGLYPH_MAP.put('ℹ', 'i'); // Information source
    }

    // ========================================================================
    // PATTERNS FOR CLEANING
    // ========================================================================

    // Zero-width characters (invisible but can break keyword matching)
    private static final Pattern ZERO_WIDTH_PATTERN = Pattern.compile(
            "[\\u200B\\u200C\\u200D\\u2060\\uFEFF]");

    // Multiple spaces
    private static final Pattern MULTI_SPACE_PATTERN = Pattern.compile("\\s{2,}");

    // Non-printable control characters
    private static final Pattern CONTROL_CHAR_PATTERN = Pattern.compile("[\\p{Cc}\\p{Cf}]");

    // ========================================================================
    // MAIN NORMALIZATION METHOD
    // ========================================================================

    /**
     * Fully normalize text for scam detection
     * Applies all normalization techniques in order
     * 
     * @param text Raw input text
     * @return Normalized text ready for keyword matching
     */
    public String normalize(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        String normalized = text;

        // Step 1: Unicode NFKC normalization (handles many fullwidth chars
        // automatically)
        normalized = unicodeNormalize(normalized);

        // Step 2: Remove zero-width and control characters
        normalized = removeInvisibleChars(normalized);

        // Step 3: Replace homoglyphs with Latin equivalents
        normalized = replaceHomoglyphs(normalized);

        // Step 4: Convert leetspeak to normal text
        normalized = convertLeetspeak(normalized);

        // Step 5: Remove obfuscation separators (l.o.t.t.e.r.y → lottery)
        normalized = removeObfuscation(normalized);

        // Step 6: Normalize whitespace
        normalized = normalizeWhitespace(normalized);

        // Step 7: Convert to lowercase
        normalized = normalized.toLowerCase();

        return normalized.trim();
    }

    /**
     * Apply Unicode NFKC normalization
     * Converts compatibility characters to their normalized forms
     * e.g., '①' → '1', '℃' → '°C'
     */
    public String unicodeNormalize(String text) {
        if (text == null)
            return null;
        return Normalizer.normalize(text, Normalizer.Form.NFKC);
    }

    /**
     * Remove zero-width and control characters
     * These can be used to hide text or break keyword matching
     */
    public String removeInvisibleChars(String text) {
        if (text == null)
            return null;
        String result = ZERO_WIDTH_PATTERN.matcher(text).replaceAll("");
        result = CONTROL_CHAR_PATTERN.matcher(result).replaceAll("");
        return result;
    }

    /**
     * Replace homoglyphs (lookalike characters) with Latin equivalents
     * e.g., Cyrillic 'о' → Latin 'o'
     */
    public String replaceHomoglyphs(String text) {
        if (text == null)
            return null;

        StringBuilder result = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            char normalized = HOMOGLYPH_MAP.getOrDefault(c, c);
            result.append(normalized);
        }
        return result.toString();
    }

    /**
     * Convert leetspeak to normal text
     * e.g., l0ttery → lottery, pr1ze → prize
     */
    public String convertLeetspeak(String text) {
        if (text == null)
            return null;

        StringBuilder result = new StringBuilder(text.length());
        char[] chars = text.toCharArray();

        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];

            // Only convert if surrounded by letters (context-aware)
            // This prevents "2024" from becoming "zoza"
            boolean prevIsLetter = i > 0 && Character.isLetter(chars[i - 1]);
            boolean nextIsLetter = i < chars.length - 1 && Character.isLetter(chars[i + 1]);

            if ((prevIsLetter || nextIsLetter) && LEETSPEAK_MAP.containsKey(c)) {
                result.append(LEETSPEAK_MAP.get(c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Remove obfuscation separators
     * e.g., l.o.t.t.e.r.y → lottery, w-i-n-n-e-r → winner
     */
    public String removeObfuscation(String text) {
        if (text == null)
            return null;

        // First pass: remove separators between single characters
        // Matches patterns like "l.o.t.t.e.r.y" or "p-r-i-z-e"
        String result = text;

        // Pattern: single letter followed by separator followed by single letter,
        // repeated
        // This handles "l.o.t.t.e.r.y" style obfuscation
        StringBuilder cleaned = new StringBuilder();
        char[] chars = result.toCharArray();

        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];

            // Skip separators between letters
            if (isSeparator(c)) {
                // Check if this is between two single letters
                boolean prevSingleLetter = i > 0 && Character.isLetter(chars[i - 1]);
                boolean nextSingleLetter = i < chars.length - 1 && Character.isLetter(chars[i + 1]);

                // Also check if we're in a pattern of single-char-separator-single-char
                boolean isObfuscationPattern = isInObfuscationPattern(chars, i);

                if (prevSingleLetter && nextSingleLetter && isObfuscationPattern) {
                    continue; // Skip this separator
                }
            }
            cleaned.append(c);
        }

        return cleaned.toString();
    }

    /**
     * Check if we're in an obfuscation pattern
     * Returns true for patterns like "l.o.t.t.e.r.y"
     */
    private boolean isInObfuscationPattern(char[] chars, int separatorIndex) {
        // Look back and forward to detect patterns
        int letterCount = 0;
        int separatorCount = 0;

        // Check surrounding context (5 chars each direction)
        int start = Math.max(0, separatorIndex - 5);
        int end = Math.min(chars.length - 1, separatorIndex + 5);

        for (int i = start; i <= end; i++) {
            if (Character.isLetter(chars[i])) {
                letterCount++;
            } else if (isSeparator(chars[i])) {
                separatorCount++;
            }
        }

        // If we have many separators relative to letters, it's likely obfuscation
        return separatorCount >= 2 && letterCount >= separatorCount;
    }

    /**
     * Check if character is a common obfuscation separator
     */
    private boolean isSeparator(char c) {
        return c == '.' || c == '-' || c == '_' || c == '*' ||
                c == '~' || c == '·' || c == '•' || c == ' ';
    }

    /**
     * Normalize whitespace
     * Converts multiple spaces to single space
     */
    public String normalizeWhitespace(String text) {
        if (text == null)
            return null;
        return MULTI_SPACE_PATTERN.matcher(text).replaceAll(" ");
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * Check if text contains potential obfuscation
     * Useful for logging/alerting
     */
    public boolean containsObfuscation(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        String normalized = normalize(text);
        String original = text.toLowerCase();

        // If normalized text is significantly different, obfuscation was present
        int originalLength = original.replaceAll("\\s", "").length();
        int normalizedLength = normalized.replaceAll("\\s", "").length();

        // Check for leetspeak
        boolean hasLeetspeak = containsLeetspeak(text);

        // Check for homoglyphs
        boolean hasHomoglyphs = containsHomoglyphs(text);

        // Check for zero-width chars
        boolean hasZeroWidth = ZERO_WIDTH_PATTERN.matcher(text).find();

        // Check for separator obfuscation (l.o.t.t.e.r.y style)
        boolean hasSeparatorObfuscation = originalLength > normalizedLength + 3;

        return hasLeetspeak || hasHomoglyphs || hasZeroWidth || hasSeparatorObfuscation;
    }

    /**
     * Check if text contains leetspeak characters
     */
    public boolean containsLeetspeak(String text) {
        if (text == null)
            return false;

        for (char c : text.toCharArray()) {
            if (LEETSPEAK_MAP.containsKey(c)) {
                // Check if surrounded by letters (context-aware)
                int idx = text.indexOf(c);
                boolean prevLetter = idx > 0 && Character.isLetter(text.charAt(idx - 1));
                boolean nextLetter = idx < text.length() - 1 && Character.isLetter(text.charAt(idx + 1));

                if (prevLetter || nextLetter) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if text contains homoglyph characters
     */
    public boolean containsHomoglyphs(String text) {
        if (text == null)
            return false;

        for (char c : text.toCharArray()) {
            if (HOMOGLYPH_MAP.containsKey(c)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get detailed normalization report
     * Useful for evidence collection and logging
     */
    public NormalizationReport analyzeText(String text) {
        NormalizationReport report = new NormalizationReport();
        report.originalText = text;
        report.normalizedText = normalize(text);
        report.hasLeetspeak = containsLeetspeak(text);
        report.hasHomoglyphs = containsHomoglyphs(text);
        report.hasZeroWidth = text != null && ZERO_WIDTH_PATTERN.matcher(text).find();
        report.hasObfuscation = containsObfuscation(text);

        if (report.hasObfuscation) {
            log.info("Text obfuscation detected: leetspeak={}, homoglyphs={}, zeroWidth={}",
                    report.hasLeetspeak, report.hasHomoglyphs, report.hasZeroWidth);
        }

        return report;
    }

    /**
     * Normalization analysis report
     */
    public static class NormalizationReport {
        public String originalText;
        public String normalizedText;
        public boolean hasLeetspeak;
        public boolean hasHomoglyphs;
        public boolean hasZeroWidth;
        public boolean hasObfuscation;

        public boolean wasModified() {
            return originalText != null && !originalText.toLowerCase().equals(normalizedText);
        }
    }
}

