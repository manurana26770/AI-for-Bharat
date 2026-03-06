package com.varutri.honeypot.service.ai;
import com.varutri.honeypot.service.llm.PersonaService;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase 3: Response Validation Service
 * 
 * Critical component for honeypot response quality assurance.
 * Validates AI-generated responses to ensure:
 * 1. Persona consistency (never breaks character)
 * 2. No harmful/dangerous content
 * 3. No AI identity leakage
 * 4. Appropriate length and format
 * 5. Authentic elderly person speaking style
 * 
 * Returns detailed validation results with specific issues and suggested fixes.
 */
@Slf4j
@Service
public class ResponseValidationService {

    @Autowired
    private PersonaService personaService;

    @Value("${validation.max-response-length:500}")
    private int maxResponseLength;

    @Value("${validation.min-response-length:5}")
    private int minResponseLength;

    @Value("${validation.strict-mode:true}")
    private boolean strictMode;

    // ==================== DETECTION PATTERNS ====================

    // AI Identity Leakage Patterns (CRITICAL - must never appear)
    private static final List<Pattern> AI_IDENTITY_PATTERNS = Arrays.asList(
            // Direct AI claims
            Pattern.compile(
                    "\\b(i am|i'm|im)\\s+(an?\\s+)?(ai|artificial intelligence|language model|llm|chatbot|bot|assistant|gpt|claude|llama|neural network|machine learning model)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bas an? (ai|artificial intelligence|language model|assistant|chatbot)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile(
                    "\\b(created|made|built|trained|programmed|designed)\\s+(by|at)\\s+(openai|anthropic|google|meta|microsoft|hugging\\s*face)\\b",
                    Pattern.CASE_INSENSITIVE),

            // AI capability disclaimers
            Pattern.compile(
                    "\\bi (cannot|can't|am unable to|don't have the ability to)\\s+(provide|give|offer)\\s+(medical|legal|financial)\\s+advice\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(my training|my programming|my instructions|my guidelines)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(large language model|natural language processing|nlp|transformer|neural network)\\b",
                    Pattern.CASE_INSENSITIVE),

            // Meta-references
            Pattern.compile(
                    "\\b(this conversation|our chat|this interaction)\\s+(is being|will be)\\s+(recorded|monitored|logged)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bprompt\\s*(injection|engineering|hacking)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile(
                    "\\b(jailbreak|jailbroken|bypass|override)\\s+(my|the)?\\s*(restrictions|guidelines|instructions)\\b",
                    Pattern.CASE_INSENSITIVE));

    // Honeypot/Investigation Leakage (CRITICAL)
    private static final List<Pattern> HONEYPOT_LEAKAGE_PATTERNS = Arrays.asList(
            Pattern.compile("\\b(honeypot|honey\\s*pot|scam\\s*baiting|scam\\s*bait|trap)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(law enforcement|police|cyber\\s*crime|investigation|investigating)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(evidence|collect(ing)?\\s+evidence|recording\\s+(this|you))\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(report(ing)?\\s+(to|you)\\s+(police|authorities)|varutri)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(i know|i can tell|i detect|you('re| are))\\s+(a\\s+)?scam(mer)?\\b",
                    Pattern.CASE_INSENSITIVE));

    // Harmful Content Patterns
    private static final List<Pattern> HARMFUL_CONTENT_PATTERNS = Arrays.asList(
            // Violence/threats
            Pattern.compile("\\b(kill|murder|attack|hurt|harm|injure|assault)\\s+(you|them|him|her|someone)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(bomb|explosive|weapon|gun|knife)\\s*(making|build|create|instructions)\\b",
                    Pattern.CASE_INSENSITIVE),

            // Illegal activities
            Pattern.compile("\\b(drug|cocaine|heroin|meth)\\s*(deal|sell|buy|making)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(child\\s*(porn|abuse)|csam|cp)\\b", Pattern.CASE_INSENSITIVE),

            // Self-harm
            Pattern.compile("\\b(suicide|kill\\s*yourself|end\\s*(your|my)\\s*life)\\b", Pattern.CASE_INSENSITIVE));

    // Inappropriate for Persona (elderly Indian person)
    private static final List<Pattern> PERSONA_BREAK_PATTERNS = Arrays.asList(
            // Modern slang inappropriate for elderly
            Pattern.compile("\\b(lol|lmao|rofl|bruh|bro|dude|lit|slay|based|cap|no\\s*cap|fr\\s*fr|bussin|goat)\\b",
                    Pattern.CASE_INSENSITIVE),

            // Tech-savvy language inappropriate for persona
            Pattern.compile(
                    "\\b(blockchain|cryptocurrency|bitcoin|ethereum|nft|defi|smart\\s*contract|metaverse|web3)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile(
                    "\\b(api|json|http|https|url|endpoint|backend|frontend|database|algorithm|code|programming)\\b",
                    Pattern.CASE_INSENSITIVE),

            // Formal/robotic language
            Pattern.compile(
                    "\\b(certainly|absolutely|definitely|i'd be happy to|i understand your|regarding your|in response to)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(however|moreover|furthermore|additionally|subsequently|nevertheless)\\b",
                    Pattern.CASE_INSENSITIVE),

            // English too perfect for persona (check for complex words)
            Pattern.compile(
                    "\\b(juxtaposition|paradigm|methodology|implementation|infrastructure|comprehensive|substantial)\\b",
                    Pattern.CASE_INSENSITIVE));

    // Real financial advice (should not give)
    private static final List<Pattern> FINANCIAL_ADVICE_PATTERNS = Arrays.asList(
            Pattern.compile("\\b(you should (invest|buy|sell)|i recommend|financial advice|investment tip)\\b",
                    Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b(stock market|mutual fund|sip|fixed deposit|interest rate)\\s*(is|will|should)\\b",
                    Pattern.CASE_INSENSITIVE));

    // Emoji detection (persona doesn't use emojis)
    private static final Pattern EMOJI_PATTERN = Pattern.compile(
            "[\\x{1F600}-\\x{1F64F}\\x{1F300}-\\x{1F5FF}\\x{1F680}-\\x{1F6FF}\\x{1F1E0}-\\x{1F1FF}\\x{2600}-\\x{26FF}\\x{2700}-\\x{27BF}]");

    // ==================== MAIN VALIDATION METHOD ====================

    /**
     * Validate an AI-generated response
     * 
     * @param response    The AI response to validate
     * @param userMessage The original user message (for context)
     * @param threatLevel The detected threat level
     * @return ValidationResult with pass/fail status and detailed issues
     */
    public ValidationResult validateResponse(String response, String userMessage, double threatLevel) {
        ValidationResult result = ValidationResult.builder()
                .originalResponse(response)
                .timestamp(System.currentTimeMillis())
                .build();

        List<ValidationIssue> issues = new ArrayList<>();

        // Check if response is null or empty
        if (response == null || response.trim().isEmpty()) {
            issues.add(ValidationIssue.critical("EMPTY_RESPONSE",
                    "Response is null or empty",
                    "Generate a new response"));
            return buildFailedResult(result, issues);
        }

        String trimmedResponse = response.trim();

        // === LAYER 1: CRITICAL CHECKS (Immediate failure) ===

        // Check AI identity leakage
        List<ValidationIssue> aiLeakage = checkAIIdentityLeakage(trimmedResponse);
        issues.addAll(aiLeakage);

        // Check honeypot/investigation leakage
        List<ValidationIssue> honeypotLeakage = checkHoneypotLeakage(trimmedResponse);
        issues.addAll(honeypotLeakage);

        // Check harmful content
        List<ValidationIssue> harmfulContent = checkHarmfulContent(trimmedResponse);
        issues.addAll(harmfulContent);

        // === LAYER 2: PERSONA CONSISTENCY CHECKS ===

        // Check persona break
        List<ValidationIssue> personaBreaks = checkPersonaBreaks(trimmedResponse);
        issues.addAll(personaBreaks);

        // Check emoji usage (persona doesn't use emojis)
        ValidationIssue emojiIssue = checkEmojiUsage(trimmedResponse);
        if (emojiIssue != null) {
            issues.add(emojiIssue);
        }

        // Check response authenticity (elderly speaking style)
        List<ValidationIssue> authenticityIssues = checkAuthenticityMarkers(trimmedResponse);
        issues.addAll(authenticityIssues);

        // === LAYER 3: QUALITY CHECKS ===

        // Check response length
        ValidationIssue lengthIssue = checkResponseLength(trimmedResponse);
        if (lengthIssue != null) {
            issues.add(lengthIssue);
        }

        // Check for real financial advice
        List<ValidationIssue> financialAdvice = checkFinancialAdvice(trimmedResponse);
        issues.addAll(financialAdvice);

        // Check for suspicious engagement (too eager to help scammer)
        ValidationIssue engagementIssue = checkEngagementLevel(trimmedResponse, threatLevel);
        if (engagementIssue != null) {
            issues.add(engagementIssue);
        }

        // === LAYER 4: FORMAT CHECKS ===

        // Check for code blocks or technical formatting
        ValidationIssue formatIssue = checkFormatting(trimmedResponse);
        if (formatIssue != null) {
            issues.add(formatIssue);
        }

        // === LAYER 5: PERSONA NAME CHECK ===

        // Check if response accidentally mentions the wrong name or AI identifiers
        ValidationIssue personaNameIssue = checkPersonaNameConsistency(trimmedResponse);
        if (personaNameIssue != null) {
            issues.add(personaNameIssue);
        }

        // === BUILD RESULT ===
        return buildResult(result, issues, trimmedResponse);
    }

    /**
     * Check if response maintains persona name consistency
     * Uses personaService to get current persona name
     */
    private ValidationIssue checkPersonaNameConsistency(String response) {
        if (personaService == null) {
            return null;
        }

        String personaName = personaService.getCurrentPersona().getName();
        String lower = response.toLowerCase();

        // Check if wrong name is mentioned
        String[] wrongNames = { "claude", "gpt", "siri", "alexa", "cortana", "bixby", "assistant" };
        for (String wrongName : wrongNames) {
            if (lower.contains("i am " + wrongName) || lower.contains("i'm " + wrongName) ||
                    lower.contains("my name is " + wrongName)) {
                return ValidationIssue.critical("WRONG_NAME",
                        "Response contains wrong identity: using '" + wrongName + "' instead of persona",
                        "Use persona name: " + personaName);
            }
        }

        // Log persona being used for debugging
        log.trace("Validating response for persona: {}", personaName);

        return null;
    }

    // ==================== INDIVIDUAL CHECK METHODS ====================

    private List<ValidationIssue> checkAIIdentityLeakage(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        for (Pattern pattern : AI_IDENTITY_PATTERNS) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                issues.add(ValidationIssue.critical("AI_IDENTITY_LEAK",
                        "AI identity leaked: '" + matcher.group() + "'",
                        "Remove AI reference, respond as persona"));
                log.warn("AI identity leakage detected in response: {}", matcher.group());
            }
        }

        return issues;
    }

    private List<ValidationIssue> checkHoneypotLeakage(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        for (Pattern pattern : HONEYPOT_LEAKAGE_PATTERNS) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                issues.add(ValidationIssue.critical("HONEYPOT_LEAK",
                        "Honeypot/investigation context leaked: '" + matcher.group() + "'",
                        "Never mention honeypot, investigation, or that you suspect scam"));
                log.warn("Honeypot leakage detected in response: {}", matcher.group());
            }
        }

        return issues;
    }

    private List<ValidationIssue> checkHarmfulContent(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        for (Pattern pattern : HARMFUL_CONTENT_PATTERNS) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                issues.add(ValidationIssue.critical("HARMFUL_CONTENT",
                        "Harmful content detected: '" + matcher.group() + "'",
                        "Remove harmful content, stay in character"));
                log.error("Harmful content detected in response: {}", matcher.group());
            }
        }

        return issues;
    }

    private List<ValidationIssue> checkPersonaBreaks(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        for (Pattern pattern : PERSONA_BREAK_PATTERNS) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                issues.add(ValidationIssue.warning("PERSONA_BREAK",
                        "Language inappropriate for persona: '" + matcher.group() + "'",
                        "Use simpler language appropriate for elderly person"));
            }
        }

        return issues;
    }

    private ValidationIssue checkEmojiUsage(String response) {
        Matcher matcher = EMOJI_PATTERN.matcher(response);
        if (matcher.find()) {
            return ValidationIssue.warning("EMOJI_USAGE",
                    "Emoji detected: '" + matcher.group() + "'",
                    "Remove emojis - persona doesn't use them");
        }
        return null;
    }

    private List<ValidationIssue> checkAuthenticityMarkers(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        // Check if response sounds too formal/robotic
        String lower = response.toLowerCase();

        // Count formal phrases
        int formalCount = 0;
        String[] formalPhrases = { "i would like to", "i am pleased to", "thank you for your",
                "please be advised", "kindly note", "i hope this helps" };
        for (String phrase : formalPhrases) {
            if (lower.contains(phrase)) {
                formalCount++;
            }
        }

        if (formalCount >= 2) {
            issues.add(ValidationIssue.warning("TOO_FORMAL",
                    "Response sounds too formal (" + formalCount + " formal phrases)",
                    "Make it sound more casual and natural"));
        }

        // Check sentence complexity (average words per sentence)
        String[] sentences = response.split("[.!?]+");
        if (sentences.length > 0) {
            int totalWords = response.split("\\s+").length;
            double avgWordsPerSentence = (double) totalWords / sentences.length;

            if (avgWordsPerSentence > 25) {
                issues.add(ValidationIssue.info("COMPLEX_SENTENCES",
                        "Sentences too complex (avg " + String.format("%.1f", avgWordsPerSentence) + " words)",
                        "Use shorter, simpler sentences"));
            }
        }

        return issues;
    }

    private ValidationIssue checkResponseLength(String response) {
        int length = response.length();

        if (length < minResponseLength) {
            return ValidationIssue.warning("TOO_SHORT",
                    "Response too short (" + length + " chars, min: " + minResponseLength + ")",
                    "Provide a longer, more engaging response");
        }

        if (length > maxResponseLength) {
            return ValidationIssue.warning("TOO_LONG",
                    "Response too long (" + length + " chars, max: " + maxResponseLength + ")",
                    "Keep response shorter, like a WhatsApp message");
        }

        return null;
    }

    private List<ValidationIssue> checkFinancialAdvice(String response) {
        List<ValidationIssue> issues = new ArrayList<>();

        for (Pattern pattern : FINANCIAL_ADVICE_PATTERNS) {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                issues.add(ValidationIssue.warning("FINANCIAL_ADVICE",
                        "Real financial advice detected: '" + matcher.group() + "'",
                        "Persona should ask questions, not give financial advice"));
            }
        }

        return issues;
    }

    private ValidationIssue checkEngagementLevel(String response, double threatLevel) {
        String lower = response.toLowerCase();

        // For high threats, check if we're being too eager
        if (threatLevel >= 0.6) {
            // Check if giving away too much
            String[] eagerPhrases = { "yes, i'll send", "here is my", "i'm sending now",
                    "i'll transfer", "take my", "here are my details" };

            for (String phrase : eagerPhrases) {
                if (lower.contains(phrase)) {
                    return ValidationIssue.warning("TOO_EAGER",
                            "Too eager to comply with potential scammer",
                            "Should stall, ask questions, express hesitation");
                }
            }
        }

        return null;
    }

    private ValidationIssue checkFormatting(String response) {
        // Check for code blocks
        if (response.contains("```") || response.contains("~~~")) {
            return ValidationIssue.warning("CODE_BLOCKS",
                    "Response contains code blocks",
                    "Remove code formatting - elderly person wouldn't use it");
        }

        // Check for markdown formatting
        if (response.contains("**") || response.contains("__") || response.contains("##")) {
            return ValidationIssue.info("MARKDOWN_FORMATTING",
                    "Response contains markdown formatting",
                    "Remove markdown - use plain text");
        }

        // Check for bullet points with asterisks
        if (Pattern.compile("^\\s*[*-]\\s+", Pattern.MULTILINE).matcher(response).find()) {
            return ValidationIssue.info("BULLET_POINTS",
                    "Response contains bullet point formatting",
                    "Use natural prose instead of lists");
        }

        return null;
    }

    // ==================== RESULT BUILDING ====================

    private ValidationResult buildResult(ValidationResult result, List<ValidationIssue> issues, String response) {
        // Count issues by severity
        long criticalCount = issues.stream().filter(i -> i.getSeverity() == IssueSeverity.CRITICAL).count();
        long warningCount = issues.stream().filter(i -> i.getSeverity() == IssueSeverity.WARNING).count();
        long infoCount = issues.stream().filter(i -> i.getSeverity() == IssueSeverity.INFO).count();

        // Determine if passed
        boolean passed;
        if (strictMode) {
            // Strict mode: fail on any critical or warning
            passed = criticalCount == 0 && warningCount == 0;
        } else {
            // Lenient mode: fail only on critical
            passed = criticalCount == 0;
        }

        // Calculate quality score (0-100)
        double qualityScore = 100.0;
        for (ValidationIssue issue : issues) {
            switch (issue.getSeverity()) {
                case CRITICAL -> qualityScore -= 40;
                case WARNING -> qualityScore -= 15;
                case INFO -> qualityScore -= 5;
            }
        }
        qualityScore = Math.max(0, qualityScore);

        result.setPassed(passed);
        result.setIssues(issues);
        result.setQualityScore(qualityScore);
        result.setCriticalIssueCount((int) criticalCount);
        result.setWarningCount((int) warningCount);
        result.setInfoCount((int) infoCount);

        // Log summary
        if (passed) {
            log.debug("Response validation PASSED (score: {:.1f}, {} issues)", qualityScore, issues.size());
        } else {
            log.warn("Response validation FAILED (score: {:.1f}, {} critical, {} warnings)",
                    qualityScore, criticalCount, warningCount);
        }

        return result;
    }

    private ValidationResult buildFailedResult(ValidationResult result, List<ValidationIssue> issues) {
        result.setPassed(false);
        result.setIssues(issues);
        result.setQualityScore(0.0);
        result.setCriticalIssueCount((int) issues.stream()
                .filter(i -> i.getSeverity() == IssueSeverity.CRITICAL).count());
        return result;
    }

    /**
     * Get suggested fixes as a formatted string for retry prompts
     */
    public String getSuggestedFixes(ValidationResult result) {
        if (result.isPassed()) {
            return "";
        }

        StringBuilder fixes = new StringBuilder();
        fixes.append("Your previous response had issues. Fix these:\n\n");

        for (ValidationIssue issue : result.getIssues()) {
            if (issue.getSeverity() == IssueSeverity.CRITICAL) {
                fixes.append("CRITICAL: ").append(issue.getSuggestion()).append("\n");
            } else if (issue.getSeverity() == IssueSeverity.WARNING) {
                fixes.append("WARNING: ").append(issue.getSuggestion()).append("\n");
            }
        }

        return fixes.toString();
    }

    /**
     * Sanitize response by attempting to fix minor issues
     * Only fixes non-critical issues that can be safely auto-corrected
     */
    public String sanitizeResponse(String response, ValidationResult validationResult) {
        if (response == null)
            return null;

        String sanitized = response;

        // Remove emojis
        sanitized = EMOJI_PATTERN.matcher(sanitized).replaceAll("");

        // Remove code blocks
        sanitized = sanitized.replaceAll("```[\\s\\S]*?```", "");
        sanitized = sanitized.replaceAll("~~~[\\s\\S]*?~~~", "");

        // Remove markdown formatting
        sanitized = sanitized.replaceAll("\\*\\*([^*]+)\\*\\*", "$1");
        sanitized = sanitized.replaceAll("__([^_]+)__", "$1");
        sanitized = sanitized.replaceAll("##+ ?", "");

        // Trim whitespace
        sanitized = sanitized.trim();

        // Truncate if too long
        if (sanitized.length() > maxResponseLength) {
            // Find last sentence boundary
            int lastSentence = sanitized.lastIndexOf('.', maxResponseLength);
            if (lastSentence > minResponseLength) {
                sanitized = sanitized.substring(0, lastSentence + 1);
            } else {
                sanitized = sanitized.substring(0, maxResponseLength) + "...";
            }
        }

        return sanitized;
    }

    // ==================== DTOs ====================

    public enum IssueSeverity {
        CRITICAL, // Must fail validation
        WARNING, // May fail in strict mode
        INFO // Just for information
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValidationResult {
        private boolean passed;
        private String originalResponse;
        private List<ValidationIssue> issues;
        private double qualityScore;
        private int criticalIssueCount;
        private int warningCount;
        private int infoCount;
        private long timestamp;

        /**
         * Check if response needs regeneration
         */
        public boolean needsRegeneration() {
            return !passed && criticalIssueCount > 0;
        }

        /**
         * Check if response can be salvaged with minor edits
         */
        public boolean canBeSanitized() {
            return criticalIssueCount == 0;
        }

        /**
         * Get summary string
         */
        public String getSummary() {
            if (passed) {
                return String.format("PASSED (score: %.1f, %d info notes)", qualityScore, infoCount);
            } else {
                return String.format("FAILED (score: %.1f, %d critical, %d warnings)",
                        qualityScore, criticalIssueCount, warningCount);
            }
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ValidationIssue {
        private IssueSeverity severity;
        private String code;
        private String description;
        private String suggestion;

        public static ValidationIssue critical(String code, String description, String suggestion) {
            return ValidationIssue.builder()
                    .severity(IssueSeverity.CRITICAL)
                    .code(code)
                    .description(description)
                    .suggestion(suggestion)
                    .build();
        }

        public static ValidationIssue warning(String code, String description, String suggestion) {
            return ValidationIssue.builder()
                    .severity(IssueSeverity.WARNING)
                    .code(code)
                    .description(description)
                    .suggestion(suggestion)
                    .build();
        }

        public static ValidationIssue info(String code, String description, String suggestion) {
            return ValidationIssue.builder()
                    .severity(IssueSeverity.INFO)
                    .code(code)
                    .description(description)
                    .suggestion(suggestion)
                    .build();
        }
    }
}

