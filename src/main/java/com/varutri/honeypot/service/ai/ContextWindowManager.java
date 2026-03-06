package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.dto.ChatRequest;
import com.varutri.honeypot.dto.ExtractedInfo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase 1.5: Context Window Manager
 * 
 * Manages conversation history within LLM token limits.
 * Implements smart prioritization to preserve important context:
 * 1. Always keeps recent messages for immediate context
 * 2. Preserves messages containing extracted intelligence
 * 3. Summarizes older messages to save tokens
 * 4. Ensures system prompt and current message fit within budget
 */
@Slf4j
@Service
public class ContextWindowManager {

    // Token budget configuration
    @Value("${context.max-tokens:4096}")
    private int maxContextTokens;

    @Value("${context.system-prompt-budget:1000}")
    private int systemPromptBudget;

    @Value("${context.intelligence-budget:200}")
    private int intelligenceBudget;

    @Value("${context.summary-budget:400}")
    private int summaryBudget;

    @Value("${context.recent-messages-budget:2000}")
    private int recentMessagesBudget;

    @Value("${context.response-buffer:300}")
    private int responseBuffer;

    @Value("${context.recent-turns-to-keep:6}")
    private int recentTurnsToKeep;

    // Patterns for detecting important content
    private static final Pattern UPI_PATTERN = Pattern.compile(
            "\\b\\d{10}@[a-zA-Z]+\\b|\\b[a-zA-Z0-9._-]+@(paytm|phonepe|googlepay|ybl|oksbi|axl|ibl|icici)\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern PHONE_PATTERN = Pattern.compile(
            "\\b(?:\\+91[\\s-]?)?[6-9]\\d{9}\\b");
    private static final Pattern BANK_PATTERN = Pattern.compile(
            "\\b\\d{9,18}\\b");
    private static final Pattern AMOUNT_PATTERN = Pattern.compile(
            "(?i)\\b(rs\\.?|₹|inr|rupees?)\\s*\\d+|\\d+\\s*(rs\\.?|₹|lakhs?|crores?)\\b");

    /**
     * Build optimized context within token limits
     * 
     * @param systemPrompt          The hardened system prompt
     * @param fullHistory           Complete conversation history
     * @param extractedIntelligence Already extracted intelligence
     * @param currentMessage        Current user message
     * @return ManagedContext with optimized messages
     */
    public ManagedContext buildContext(
            String systemPrompt,
            List<ChatRequest.ConversationMessage> fullHistory,
            ExtractedInfo extractedIntelligence,
            String currentMessage) {

        ManagedContext context = new ManagedContext();
        context.setTokenBudget(maxContextTokens);

        // Step 1: Calculate token usage for fixed elements
        int systemPromptTokens = estimateTokens(systemPrompt);
        int currentMessageTokens = estimateTokens(currentMessage);
        int fixedTokens = systemPromptTokens + currentMessageTokens + responseBuffer;

        context.setSystemPrompt(systemPrompt);
        context.setSystemPromptTokens(systemPromptTokens);
        context.setCurrentMessage(currentMessage);

        log.debug("Token budget breakdown - Total: {}, Fixed: {} (System: {}, Current: {}, Buffer: {})",
                maxContextTokens, fixedTokens, systemPromptTokens, currentMessageTokens, responseBuffer);

        // Step 2: Calculate available tokens for history
        int availableForHistory = maxContextTokens - fixedTokens;

        if (availableForHistory < 200) {
            // Not enough space for history - use minimal context
            log.warn("Insufficient token budget for history. Available: {}", availableForHistory);
            context.setRecentMessages(new ArrayList<>());
            context.setWasTruncated(true);
            context.setTotalTokens(fixedTokens);
            return context;
        }

        // Step 3: Build intelligence summary (always include if available)
        String intelligenceSummary = buildIntelligenceSummary(extractedIntelligence);
        int intelligenceTokens = estimateTokens(intelligenceSummary);

        if (intelligenceTokens > 0) {
            context.setIntelligenceSummary(intelligenceSummary);
            context.setIntelligenceSummaryTokens(intelligenceTokens);
            availableForHistory -= intelligenceTokens;
        }

        // Step 4: Handle conversation history
        if (fullHistory == null || fullHistory.isEmpty()) {
            context.setRecentMessages(new ArrayList<>());
            context.setTotalTokens(fixedTokens + intelligenceTokens);
            return context;
        }

        // Step 5: Prioritize and select messages
        List<PrioritizedMessage> prioritizedMessages = prioritizeMessages(fullHistory);

        // Step 6: Select messages within budget
        SelectedMessages selection = selectMessagesWithinBudget(
                prioritizedMessages, availableForHistory, fullHistory.size());

        context.setRecentMessages(selection.selectedMessages);
        context.setConversationSummary(selection.summary);
        context.setConversationSummaryTokens(selection.summaryTokens);
        context.setWasTruncated(selection.wasTruncated);
        context.setTurnsPreserved(selection.selectedMessages.size());
        context.setTurnsSummarized(selection.summarizedCount);

        // Calculate total tokens
        int historyTokens = selection.selectedMessages.stream()
                .mapToInt(m -> estimateTokens(m.getText()))
                .sum();

        context.setTotalTokens(fixedTokens + intelligenceTokens +
                selection.summaryTokens + historyTokens);

        log.info("Context built: {}/{} tokens, {} turns preserved, {} summarized, truncated: {}",
                context.getTotalTokens(), maxContextTokens,
                context.getTurnsPreserved(), context.getTurnsSummarized(),
                context.isWasTruncated());

        return context;
    }

    /**
     * Build a summary of extracted intelligence
     */
    private String buildIntelligenceSummary(ExtractedInfo info) {
        if (info == null) {
            return "";
        }

        StringBuilder summary = new StringBuilder();
        summary.append("[INTELLIGENCE COLLECTED]\n");

        boolean hasIntelligence = false;

        if (info.getUpiIds() != null && !info.getUpiIds().isEmpty()) {
            summary.append("• UPI IDs: ").append(String.join(", ", info.getUpiIds())).append("\n");
            hasIntelligence = true;
        }
        if (info.getPhoneNumbers() != null && !info.getPhoneNumbers().isEmpty()) {
            summary.append("• Phone Numbers: ").append(String.join(", ", info.getPhoneNumbers())).append("\n");
            hasIntelligence = true;
        }
        if (info.getBankAccountNumbers() != null && !info.getBankAccountNumbers().isEmpty()) {
            summary.append("• Bank Accounts: ").append(String.join(", ", info.getBankAccountNumbers())).append("\n");
            hasIntelligence = true;
        }
        if (info.getIfscCodes() != null && !info.getIfscCodes().isEmpty()) {
            summary.append("• IFSC Codes: ").append(String.join(", ", info.getIfscCodes())).append("\n");
            hasIntelligence = true;
        }
        if (info.getUrls() != null && !info.getUrls().isEmpty()) {
            summary.append("• URLs: ").append(String.join(", ", info.getUrls())).append("\n");
            hasIntelligence = true;
        }
        if (info.getEmails() != null && !info.getEmails().isEmpty()) {
            summary.append("• Emails: ").append(String.join(", ", info.getEmails())).append("\n");
            hasIntelligence = true;
        }
        if (info.getScamType() != null && !"UNKNOWN".equals(info.getScamType())) {
            summary.append("• Detected Scam Type: ").append(info.getScamType()).append("\n");
            hasIntelligence = true;
        }

        return hasIntelligence ? summary.toString() : "";
    }

    /**
     * Prioritize messages based on importance
     * Higher priority = more likely to be kept
     */
    private List<PrioritizedMessage> prioritizeMessages(
            List<ChatRequest.ConversationMessage> messages) {

        List<PrioritizedMessage> prioritized = new ArrayList<>();
        int totalMessages = messages.size();

        for (int i = 0; i < messages.size(); i++) {
            ChatRequest.ConversationMessage msg = messages.get(i);
            PrioritizedMessage pm = new PrioritizedMessage();
            pm.setOriginalIndex(i);
            pm.setMessage(msg);
            pm.setTokens(estimateTokens(msg.getText()));

            // Calculate priority score (0-100)
            double priority = 0;

            // Recency bonus (last 6 messages get high priority)
            int positionFromEnd = totalMessages - i;
            if (positionFromEnd <= recentTurnsToKeep) {
                priority += 50 + (recentTurnsToKeep - positionFromEnd) * 5; // 50-80 for recent
            } else {
                priority += Math.max(0, 30 - (positionFromEnd - recentTurnsToKeep) * 2);
            }

            // Intelligence content bonus
            String text = msg.getText();
            if (containsIntelligence(text)) {
                priority += 25;
                pm.setContainsIntelligence(true);
            }

            // Amount/money mention bonus
            if (AMOUNT_PATTERN.matcher(text).find()) {
                priority += 10;
            }

            // First message bonus (establishes context)
            if (i == 0) {
                priority += 15;
            }

            // Penalize very long messages (they use too many tokens)
            if (pm.getTokens() > 200) {
                priority -= 10;
            }

            pm.setPriority(Math.min(100, Math.max(0, priority)));
            prioritized.add(pm);
        }

        // Sort by priority (highest first)
        prioritized.sort((a, b) -> Double.compare(b.getPriority(), a.getPriority()));

        return prioritized;
    }

    /**
     * Check if a message contains extractable intelligence
     */
    private boolean containsIntelligence(String text) {
        if (text == null)
            return false;

        return UPI_PATTERN.matcher(text).find() ||
                PHONE_PATTERN.matcher(text).find() ||
                BANK_PATTERN.matcher(text).find();
    }

    /**
     * Select messages within token budget
     */
    private SelectedMessages selectMessagesWithinBudget(
            List<PrioritizedMessage> prioritized,
            int availableTokens,
            int originalCount) {

        SelectedMessages result = new SelectedMessages();
        result.selectedMessages = new ArrayList<>();

        int usedTokens = 0;
        Set<Integer> selectedIndices = new HashSet<>();
        List<ChatRequest.ConversationMessage> toSummarize = new ArrayList<>();

        // First pass: Select high-priority messages
        for (PrioritizedMessage pm : prioritized) {
            if (usedTokens + pm.getTokens() <= availableTokens - summaryBudget) {
                selectedIndices.add(pm.getOriginalIndex());
                usedTokens += pm.getTokens();
            }
        }

        // Rebuild messages in original order
        for (PrioritizedMessage pm : prioritized) {
            if (selectedIndices.contains(pm.getOriginalIndex())) {
                result.selectedMessages.add(pm.getMessage());
            } else {
                toSummarize.add(pm.getMessage());
            }
        }

        // Sort by original index to maintain conversation flow
        result.selectedMessages.sort(Comparator.comparingInt(msg -> {
            for (PrioritizedMessage pm : prioritized) {
                if (pm.getMessage() == msg) {
                    return pm.getOriginalIndex();
                }
            }
            return 0;
        }));

        // Generate summary for non-selected messages
        if (!toSummarize.isEmpty()) {
            result.summary = generateConversationSummary(toSummarize);
            result.summaryTokens = estimateTokens(result.summary);
            result.summarizedCount = toSummarize.size();
            result.wasTruncated = true;
        } else {
            result.summary = "";
            result.summaryTokens = 0;
            result.summarizedCount = 0;
            result.wasTruncated = false;
        }

        return result;
    }

    /**
     * Generate a summary of conversation messages
     * This is a simple rule-based summary (for production, could use LLM)
     */
    private String generateConversationSummary(
            List<ChatRequest.ConversationMessage> messages) {

        if (messages.isEmpty()) {
            return "";
        }

        StringBuilder summary = new StringBuilder();
        summary.append("[EARLIER CONVERSATION SUMMARY]\n");

        // Extract key topics mentioned
        Set<String> topics = new LinkedHashSet<>();
        Set<String> mentionedAmounts = new LinkedHashSet<>();
        int userMessageCount = 0;
        int assistantMessageCount = 0;

        for (ChatRequest.ConversationMessage msg : messages) {
            String text = msg.getText().toLowerCase();

            // Count message types
            if ("user".equals(msg.getSender()) || "scammer".equals(msg.getSender())) {
                userMessageCount++;
            } else {
                assistantMessageCount++;
            }

            // Extract mentioned amounts
            Matcher amountMatcher = AMOUNT_PATTERN.matcher(msg.getText());
            while (amountMatcher.find()) {
                mentionedAmounts.add(amountMatcher.group());
            }

            // Detect topics
            if (text.contains("lottery") || text.contains("prize") || text.contains("won")) {
                topics.add("lottery/prize claims");
            }
            if (text.contains("bank") || text.contains("account") || text.contains("transfer")) {
                topics.add("banking requests");
            }
            if (text.contains("otp") || text.contains("verify") || text.contains("confirm")) {
                topics.add("verification requests");
            }
            if (text.contains("urgent") || text.contains("hurry") || text.contains("immediately")) {
                topics.add("urgency tactics");
            }
            if (text.contains("fee") || text.contains("processing") || text.contains("tax")) {
                topics.add("fee requests");
            }
            if (text.contains("kyc") || text.contains("aadhaar") || text.contains("pan")) {
                topics.add("KYC/identity requests");
            }
        }

        summary.append(String.format("• %d earlier exchanges (%d from user, %d from assistant)\n",
                messages.size(), userMessageCount, assistantMessageCount));

        if (!topics.isEmpty()) {
            summary.append("• Topics discussed: ")
                    .append(String.join(", ", topics))
                    .append("\n");
        }

        if (!mentionedAmounts.isEmpty()) {
            summary.append("• Amounts mentioned: ")
                    .append(String.join(", ", mentionedAmounts))
                    .append("\n");
        }

        return summary.toString();
    }

    /**
     * Estimate token count for text (approximately 4 characters = 1 token)
     */
    public int estimateTokens(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        // More accurate estimation considering whitespace and special characters
        return (int) Math.ceil(text.length() / 3.5);
    }

    /**
     * Format messages for LLM consumption
     * Returns list suitable for chat completion API
     */
    public List<ChatRequest.ConversationMessage> formatForLLM(ManagedContext context) {
        List<ChatRequest.ConversationMessage> formatted = new ArrayList<>();

        // Add intelligence summary as a system-injected message if present
        if (context.getIntelligenceSummary() != null && !context.getIntelligenceSummary().isEmpty()) {
            ChatRequest.ConversationMessage intelMsg = new ChatRequest.ConversationMessage();
            intelMsg.setSender("system");
            intelMsg.setText(context.getIntelligenceSummary());
            formatted.add(intelMsg);
        }

        // Add conversation summary if present
        if (context.getConversationSummary() != null && !context.getConversationSummary().isEmpty()) {
            ChatRequest.ConversationMessage summaryMsg = new ChatRequest.ConversationMessage();
            summaryMsg.setSender("system");
            summaryMsg.setText(context.getConversationSummary());
            formatted.add(summaryMsg);
        }

        // Add recent messages
        formatted.addAll(context.getRecentMessages());

        return formatted;
    }

    // ==================== DTOs ====================

    /**
     * Result of context window management
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ManagedContext {
        private String systemPrompt;
        private int systemPromptTokens;

        private String intelligenceSummary;
        private int intelligenceSummaryTokens;

        private String conversationSummary;
        private int conversationSummaryTokens;

        private List<ChatRequest.ConversationMessage> recentMessages;
        private String currentMessage;

        private int totalTokens;
        private int tokenBudget;
        private boolean wasTruncated;
        private int turnsPreserved;
        private int turnsSummarized;

        /**
         * Check if context is within budget
         */
        public boolean isWithinBudget() {
            return totalTokens <= tokenBudget;
        }

        /**
         * Get remaining token capacity
         */
        public int getRemainingTokens() {
            return tokenBudget - totalTokens;
        }

        /**
         * Get usage percentage
         */
        public double getUsagePercentage() {
            return (double) totalTokens / tokenBudget * 100;
        }
    }

    /**
     * Internal class for message prioritization
     */
    @Data
    private static class PrioritizedMessage {
        private int originalIndex;
        private ChatRequest.ConversationMessage message;
        private int tokens;
        private double priority;
        private boolean containsIntelligence;
    }

    /**
     * Internal class for message selection result
     */
    private static class SelectedMessages {
        List<ChatRequest.ConversationMessage> selectedMessages;
        String summary;
        int summaryTokens;
        int summarizedCount;
        boolean wasTruncated;
    }
}

