package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.service.llm.HuggingFaceService;
import com.varutri.honeypot.service.ml.LocalMLService;

import com.varutri.honeypot.dto.ChatRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Semantic Scam Analyzer Service - Phase 3 ML Analysis
 * 
 * Implements sophisticated ML-based scam detection:
 * 1. Sentence Embeddings using local MiniLM (via DJL)
 * 2. Semantic Similarity to known scam patterns
 * 3. Intent Detection using local DeBERTa (via DJL)
 * 4. LLM-based Contextual Analysis (via HF Chat API)
 * 5. Manipulation Tactics Detection using local DeBERTa
 * 6. Multi-turn Conversation Context Understanding
 *
 * Embeddings and classification run locally — no external inference API calls.
 * Only the LLM contextual analysis uses the HF Chat Completions API.
 */
@Slf4j
@Service
public class SemanticScamAnalyzer {

    private final LocalMLService localMLService;
    private final WebClient chatWebClient;
    private final String llmModel;

    // Thread pool for parallel ML tasks
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    // Known scam patterns for semantic matching
    private static final Map<String, List<String>> SCAM_PATTERNS = new LinkedHashMap<>();
    static {
        SCAM_PATTERNS.put("LOTTERY_SCAM", Arrays.asList(
                "Congratulations! You have won a lottery prize",
                "You are the lucky winner of our sweepstakes",
                "Claim your prize money now before it expires",
                "You have been selected as the grand prize winner",
                "Your email was randomly selected for a cash prize"));

        SCAM_PATTERNS.put("INVESTMENT_SCAM", Arrays.asList(
                "Invest now and get guaranteed 300% returns",
                "Double your money in just 7 days risk-free",
                "Secret investment opportunity for high returns",
                "Earn passive income with our trading platform",
                "Exclusive crypto opportunity with guaranteed profits"));

        SCAM_PATTERNS.put("PHISHING", Arrays.asList(
                "Your account has been suspended, verify immediately",
                "Click here to update your bank details",
                "Your password will expire, reset it now",
                "Unusual activity detected, confirm your identity",
                "Security alert: unauthorized access to your account"));

        SCAM_PATTERNS.put("TECH_SUPPORT_SCAM", Arrays.asList(
                "Your computer is infected with viruses",
                "Microsoft detected malware on your system",
                "Call our tech support to fix your computer",
                "Your antivirus subscription needs renewal",
                "Security breach detected, immediate action required"));

        SCAM_PATTERNS.put("JOB_SCAM", Arrays.asList(
                "Work from home and earn $5000 per week",
                "No experience required, start earning today",
                "Part-time job opportunity with high salary",
                "Pay registration fee to start your new job",
                "Easy data entry job from home with great pay"));

        SCAM_PATTERNS.put("ROMANCE_SCAM", Arrays.asList(
                "I am stuck abroad and need money urgently",
                "I want to visit you but need money for visa",
                "Please send money so we can meet",
                "I love you and need your financial help",
                "Emergency! I need money for medical treatment"));

        SCAM_PATTERNS.put("URGENCY_MANIPULATION", Arrays.asList(
                "Act now or you will lose this opportunity",
                "Limited time offer expires in 24 hours",
                "This is your last chance to claim",
                "Urgent response required immediately",
                "Don't miss out on this exclusive deal"));
    }

    // Manipulation tactics patterns
    private static final List<String> MANIPULATION_TACTICS = Arrays.asList(
            "urgency and time pressure",
            "fear of missing out",
            "authority impersonation",
            "emotional manipulation",
            "social proof and testimonials",
            "reciprocity and obligation",
            "scarcity tactics",
            "trust building with personal details");

    @Autowired
    public SemanticScamAnalyzer(
            LocalMLService localMLService,
            @Value("${huggingface.api-key}") String apiKey,
            @Value("${huggingface.model:meta-llama/Llama-3.3-70B-Instruct}") String llmModel) {

        this.localMLService = localMLService;
        this.llmModel = llmModel;

        this.chatWebClient = WebClient.builder()
                .baseUrl("https://router.huggingface.co/v1")
                .defaultHeader("Authorization", "Bearer " + apiKey)
                .defaultHeader("Content-Type", "application/json")
                .build();

        log.info("SemanticScamAnalyzer initialized with LOCAL ML models (MiniLM + DeBERTa)");
    }

    @PostConstruct
    public void initialize() {
        log.info("Pre-computing embeddings for {} scam pattern categories...", SCAM_PATTERNS.size());
    }

    // ========================================================================
    // MAIN ANALYSIS METHOD (ASYNC)
    // ========================================================================

    /**
     * Perform comprehensive semantic analysis on a message asynchronously
     * Combines all ML techniques in PARALLEL for maximum performance
     */
    public CompletableFuture<SemanticAnalysisResult> analyzeMessage(String message,
            List<ChatRequest.ConversationMessage> conversationHistory) {

        SemanticAnalysisResult result = new SemanticAnalysisResult();
        result.originalMessage = message;

        // 1. Semantic Similarity (Async)
        CompletableFuture<Map<String, Double>> similarityFuture = computeSemanticSimilarity(message)
                .exceptionally(ex -> {
                    log.warn("Semantic similarity failed: {}", ex.getMessage());
                    return new HashMap<>();
                });

        // 2. Intent Classification (Async)
        CompletableFuture<List<IntentScore>> intentFuture = classifyIntent(message)
                .exceptionally(ex -> {
                    log.warn("Intent classification failed: {}", ex.getMessage());
                    return new ArrayList<>();
                });

        // 3. Manipulation Tactics (Async)
        CompletableFuture<List<ManipulationTactic>> tacticsFuture = detectManipulationTactics(message)
                .exceptionally(ex -> {
                    log.warn("Tactics detection failed: {}", ex.getMessage());
                    return new ArrayList<>();
                });

        // 4. Contextual Analysis (Async)
        CompletableFuture<ContextualAnalysis> contextFuture;
        if (conversationHistory != null && !conversationHistory.isEmpty()) {
            contextFuture = analyzeConversationContext(message, conversationHistory)
                    .exceptionally(ex -> {
                        log.warn("Context analysis failed: {}", ex.getMessage());
                        return new ContextualAnalysis();
                    });
        } else {
            contextFuture = CompletableFuture.completedFuture(new ContextualAnalysis());
        }

        // Combine all results when they complete
        return CompletableFuture.allOf(similarityFuture, intentFuture, tacticsFuture, contextFuture)
                .thenApply(v -> {
                    result.semanticMatches = similarityFuture.join();
                    result.detectedIntents = intentFuture.join();
                    result.manipulationTactics = tacticsFuture.join();
                    result.contextualAnalysis = contextFuture.join();

                    // 5. Calculate combined threat score
                    result.combinedScore = calculateCombinedScore(result);

                    // 6. Determine primary scam type
                    result.primaryScamType = determinePrimaryScamType(result);

                    if (result.combinedScore >= 0.5) {
                        log.info("Semantic analysis: score={}, type={}, intents={}, tactics={}",
                                String.format("%.2f", result.combinedScore),
                                result.primaryScamType,
                                result.detectedIntents.size(),
                                result.manipulationTactics.size());
                    }

                    return result;
                });
    }

    // ========================================================================
    // SEMANTIC SIMILARITY (ASYNC)
    // ========================================================================

    private CompletableFuture<Map<String, Double>> computeSemanticSimilarity(String message) {
        return CompletableFuture.supplyAsync(() -> {
            Map<String, Double> similarities = new HashMap<>();

            // Get message embedding locally using MiniLM
            float[] messageEmbedding = localMLService.getEmbedding(message);
            if (messageEmbedding == null || isZeroVector(messageEmbedding)) {
                return similarities;
            }

            try {
                for (Map.Entry<String, List<String>> entry : SCAM_PATTERNS.entrySet()) {
                    String category = entry.getKey();
                    double maxSimilarity = 0.0;

                    int checks = 0;
                    for (String pattern : entry.getValue()) {
                        if (checks++ > 3)
                            break;

                        // Local embedding — ~5ms per call, no network
                        float[] patternEmbedding = localMLService.getEmbedding(pattern);

                        if (patternEmbedding != null) {
                            double similarity = cosineSimilarity(messageEmbedding, patternEmbedding);
                            maxSimilarity = Math.max(maxSimilarity, similarity);
                        }
                    }

                    if (maxSimilarity > 0.5) {
                        similarities.put(category, maxSimilarity);
                    }
                }
            } catch (Exception e) {
                log.warn("Error computing semantic similarity: {}", e.getMessage());
            }

            return similarities;
        }, executorService);
    }

    private boolean isZeroVector(float[] vec) {
        for (float v : vec) {
            if (v != 0.0f)
                return false;
        }
        return true;
    }

    private double cosineSimilarity(float[] a, float[] b) {
        if (a.length != b.length)
            return 0.0;
        double dotProduct = 0.0;
        double normA = 0.0;
        double normB = 0.0;
        for (int i = 0; i < a.length; i++) {
            dotProduct += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        if (normA == 0 || normB == 0)
            return 0.0;
        return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    }

    // ========================================================================
    // INTENT CLASSIFICATION (ASYNC)
    // ========================================================================

    private CompletableFuture<List<IntentScore>> classifyIntent(String message) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> candidateLabels = Arrays.asList(
                    "requesting money or payment", "creating urgency or fear",
                    "offering too-good-to-be-true deals", "impersonating authority or company",
                    "asking for personal information", "building romantic relationship",
                    "offering job opportunity", "claiming prize or lottery win",
                    "legitimate business communication", "friendly casual conversation");

            // Local DeBERTa zero-shot classification — no network call
            Map<String, Double> scores = localMLService.classifyZeroShot(message, candidateLabels);

            List<IntentScore> intents = new ArrayList<>();
            for (Map.Entry<String, Double> entry : scores.entrySet()) {
                if (entry.getValue() > 0.3) {
                    IntentScore intent = new IntentScore();
                    intent.intent = entry.getKey();
                    intent.confidence = entry.getValue();
                    intent.isSuspicious = isSuspiciousIntent(entry.getKey());
                    intents.add(intent);
                }
            }
            intents.sort((a, b) -> Double.compare(b.confidence, a.confidence));
            return intents;
        }, executorService);
    }

    private boolean isSuspiciousIntent(String intent) {
        return intent.contains("money") || intent.contains("urgency") ||
                intent.contains("too-good-to-be-true") || intent.contains("impersonating") ||
                intent.contains("personal information") || intent.contains("prize") ||
                intent.contains("lottery");
    }

    // ========================================================================
    // MANIPULATION TACTICS (ASYNC)
    // ========================================================================

    private CompletableFuture<List<ManipulationTactic>> detectManipulationTactics(String message) {
        return CompletableFuture.supplyAsync(() -> {
            // Local DeBERTa zero-shot classification — no network call
            Map<String, Double> scores = localMLService.classifyZeroShot(message, MANIPULATION_TACTICS);

            List<ManipulationTactic> tactics = new ArrayList<>();
            for (Map.Entry<String, Double> entry : scores.entrySet()) {
                if (entry.getValue() > 0.4) {
                    ManipulationTactic tactic = new ManipulationTactic();
                    tactic.tactic = entry.getKey();
                    tactic.confidence = entry.getValue();
                    tactic.severity = calculateSeverity(entry.getKey(), entry.getValue());
                    tactics.add(tactic);
                }
            }
            tactics.sort((a, b) -> Double.compare(b.confidence, a.confidence));
            return tactics;
        }, executorService);
    }

    private String calculateSeverity(String tactic, double confidence) {
        if (confidence > 0.8)
            return "HIGH";
        if (confidence > 0.6)
            return "MEDIUM";
        return "LOW";
    }

    // ========================================================================
    // CONTEXTUAL ANALYSIS (ASYNC)
    // ========================================================================

    private CompletableFuture<ContextualAnalysis> analyzeConversationContext(String currentMessage,
            List<ChatRequest.ConversationMessage> history) {

        StringBuilder conversationContext = new StringBuilder();
        if (history != null) {
            for (ChatRequest.ConversationMessage msg : history) {
                conversationContext.append(msg.getSender()).append(": ")
                        .append(msg.getText()).append("\n");
            }
        }
        conversationContext.append("user: ").append(currentMessage);

        String prompt = buildAnalysisPrompt(conversationContext.toString());

        List<HuggingFaceService.Message> messages = new ArrayList<>();
        HuggingFaceService.Message systemMsg = new HuggingFaceService.Message();
        systemMsg.setRole("system");
        systemMsg.setContent("You are a scam detection expert. Analyze conversations for fraud patterns. " +
                "Respond ONLY in JSON format with these fields: " +
                "isScam (boolean), scamType (string), confidence (0.0-1.0), " +
                "evidence (list of suspicious phrases), tactics (list of manipulation tactics used), " +
                "escalationPattern (string describing how the scam is progressing)");
        messages.add(systemMsg);

        HuggingFaceService.Message userMsg = new HuggingFaceService.Message();
        userMsg.setRole("user");
        userMsg.setContent(prompt);
        messages.add(userMsg);

        HuggingFaceService.ChatCompletionRequest request = new HuggingFaceService.ChatCompletionRequest();
        request.setModel(llmModel);
        request.setMessages(messages);
        request.setMaxTokens(500);
        request.setTemperature(0.3);

        return chatWebClient.post()
                .uri("/chat/completions")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(HuggingFaceService.ChatCompletionResponse.class)
                .timeout(Duration.ofSeconds(30))
                .toFuture()
                .thenApply(response -> {
                    ContextualAnalysis analysis = new ContextualAnalysis();
                    if (response != null && response.getChoices() != null && !response.getChoices().isEmpty()) {
                        String llmResponse = response.getChoices().get(0).getMessage().getContent();
                        analysis = parseContextualAnalysis(llmResponse);
                        analysis.conversationTurns = (history != null ? history.size() : 0) + 1;
                    }
                    return analysis;
                });
    }

    private String buildAnalysisPrompt(String conversation) {
        return "Analyze this conversation for potential scam patterns:\n\n" +
                "---CONVERSATION---\n" + conversation + "\n---END---\n\n" +
                "Identify:\n" +
                "1. Is this a scam attempt?\n" +
                "2. What type of scam (lottery, investment, phishing, romance, job, tech support)?\n" +
                "3. What manipulation tactics are being used?\n" +
                "4. How is the scam escalating over the conversation?\n" +
                "5. What specific phrases are suspicious?\n\n" +
                "Respond in JSON format only.";
    }

    private ContextualAnalysis parseContextualAnalysis(String llmResponse) {
        ContextualAnalysis analysis = new ContextualAnalysis();
        try {
            analysis.rawResponse = llmResponse;
            if (llmResponse.contains("\"isScam\"") || llmResponse.contains("\"is_scam\"")) {
                analysis.isScam = llmResponse.toLowerCase().contains("\"isscam\": true") ||
                        llmResponse.toLowerCase().contains("\"is_scam\": true") ||
                        llmResponse.toLowerCase().contains("\"isscam\":true");
            }
            if (llmResponse.contains("\"confidence\"")) {
                String[] parts = llmResponse.split("\"confidence\"\\s*:\\s*");
                if (parts.length > 1) {
                    String value = parts[1].split("[,}]")[0].trim();
                    try {
                        analysis.confidence = Double.parseDouble(value);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            analysis.analyzed = true;
        } catch (Exception e) {
            log.warn("Error parsing contextual analysis response: {}", e.getMessage());
        }
        return analysis;
    }

    // ========================================================================
    // SCORING AND CLASSIFICATION
    // ========================================================================

    private double calculateCombinedScore(SemanticAnalysisResult result) {
        double score = 0.0;
        if (!result.semanticMatches.isEmpty()) {
            double maxSimilarity = result.semanticMatches.values().stream()
                    .max(Double::compare).orElse(0.0);
            score += maxSimilarity * 0.35;
        }
        long suspiciousIntents = result.detectedIntents.stream().filter(i -> i.isSuspicious).count();
        if (suspiciousIntents > 0) {
            double avgConfidence = result.detectedIntents.stream()
                    .filter(i -> i.isSuspicious).mapToDouble(i -> i.confidence).average().orElse(0.0);
            score += avgConfidence * 0.30;
        }
        if (!result.manipulationTactics.isEmpty()) {
            double avgTacticScore = result.manipulationTactics.stream()
                    .mapToDouble(t -> t.confidence).average().orElse(0.0);
            score += avgTacticScore * 0.20;
        }
        if (result.contextualAnalysis != null && result.contextualAnalysis.analyzed) {
            if (result.contextualAnalysis.isScam) {
                score += result.contextualAnalysis.confidence * 0.15;
            }
        }
        return Math.min(score, 1.0);
    }

    private String determinePrimaryScamType(SemanticAnalysisResult result) {
        if (!result.semanticMatches.isEmpty()) {
            return result.semanticMatches.entrySet().stream()
                    .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("UNKNOWN");
        }
        if (!result.detectedIntents.isEmpty()) {
            IntentScore topIntent = result.detectedIntents.get(0);
            return mapIntentToScamType(topIntent.intent);
        }
        return "UNKNOWN";
    }

    private String mapIntentToScamType(String intent) {
        if (intent.contains("money") || intent.contains("payment"))
            return "PAYMENT_SCAM";
        if (intent.contains("prize") || intent.contains("lottery"))
            return "LOTTERY_SCAM";
        if (intent.contains("job"))
            return "JOB_SCAM";
        if (intent.contains("romantic"))
            return "ROMANCE_SCAM";
        if (intent.contains("personal information"))
            return "PHISHING";
        if (intent.contains("impersonating"))
            return "IMPERSONATION";
        return "GENERAL_SCAM";
    }

    // ========================================================================
    // DTOs (HF-specific DTOs removed — local ML handles formats internally)
    // ========================================================================

    @Data
    public static class SemanticAnalysisResult {
        public String originalMessage;
        public Map<String, Double> semanticMatches = new HashMap<>();
        public List<IntentScore> detectedIntents = new ArrayList<>();
        public List<ManipulationTactic> manipulationTactics = new ArrayList<>();
        public ContextualAnalysis contextualAnalysis;
        public double combinedScore;
        public String primaryScamType;
        public String error;

        public boolean hasSignificantMatch() {
            return combinedScore >= 0.5;
        }
    }

    @Data
    public static class IntentScore {
        public String intent;
        public double confidence;
        public boolean isSuspicious;
    }

    @Data
    public static class ManipulationTactic {
        public String tactic;
        public double confidence;
        public String severity;
    }

    @Data
    public static class ContextualAnalysis {
        public boolean analyzed;
        public boolean isScam;
        public double confidence;
        public int conversationTurns;
        public String rawResponse;
        public String error;
    }
}
