package com.varutri.honeypot.service.llm;

import com.varutri.honeypot.dto.ChatRequest;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Abstraction interface for LLM chat services.
 * 
 * Implementations:
 * - HuggingFaceService (llm.provider=huggingface) — HF Chat Completions API
 * - BedrockService (llm.provider=bedrock) — AWS Bedrock Claude Messages API
 */
public interface ChatLlmService {

    /**
     * Generate a conversational response with prompt hardening and validation.
     *
     * @param userMessage         The scammer's current message
     * @param conversationHistory Previous conversation turns
     * @param scamType            Detected scam type (or "UNKNOWN")
     * @param threatLevel         Ensemble threat score (0.0 to 1.0)
     * @return Generated AI persona response
     */
    String generateResponse(String userMessage,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String scamType, double threatLevel);

    /**
     * Async wrapper around generateResponse.
     */
    CompletableFuture<String> generateResponseAsync(String userMessage,
            List<ChatRequest.ConversationMessage> conversationHistory,
            String scamType, double threatLevel);

    /**
     * Used by SemanticScamAnalyzer for contextual scam analysis.
     * Sends a system + user prompt pair and returns the raw LLM text response.
     *
     * @param systemPrompt System-level instructions (e.g., "You are a scam
     *                     detection expert...")
     * @param userPrompt   The conversation to analyze
     * @return Raw LLM response text
     */
    CompletableFuture<String> analyzeContextAsync(String systemPrompt, String userPrompt);
}
