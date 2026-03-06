package com.varutri.honeypot.service.ai;

import com.varutri.honeypot.service.data.EvidenceCollector;

import com.varutri.honeypot.dto.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Service for running scam simulations and testing
 */
@Slf4j
@Service
public class ScamSimulator {

    @Autowired
    private InformationExtractor informationExtractor;

    @Autowired
    private ScamDetector scamDetector;

    @Autowired
    private EvidenceCollector evidenceCollector;

    private final WebClient webClient = WebClient.builder()
            .baseUrl("http://localhost:8080")
            .build();

    /**
     * Run a complete scam scenario simulation
     */
    public SimulationResult runScenario(ScamScenario scenario) {
        log.info("Starting simulation: {}", scenario.getScenarioName());

        LocalDateTime startTime = LocalDateTime.now();
        String sessionId = "sim-" + System.currentTimeMillis();
        List<SimulationResult.ConversationTurn> conversation = new ArrayList<>();

        ExtractedInfo aggregatedIntelligence = new ExtractedInfo();

        try {
            // Simulate each message in the scenario
            for (ScamScenario.ScamMessage scamMsg : scenario.getMessages()) {

                // Delay if specified
                if (scamMsg.getDelayMs() > 0) {
                    Thread.sleep(scamMsg.getDelayMs());
                }

                // Build request
                ChatRequest request = new ChatRequest();
                request.setSessionId(sessionId);

                ChatRequest.Message message = new ChatRequest.Message();
                message.setSender(scamMsg.getSender());
                message.setText(scamMsg.getText());
                message.setTimestamp(System.currentTimeMillis());
                request.setMessage(message);

                request.setConversationHistory(new ArrayList<>());
                request.setMetadata(new ChatRequest.Metadata());

                // Send to API
                ChatResponse response = webClient.post()
                        .uri("/api/chat")
                        .header("x-api-key", "varutri_shield_2026")
                        .bodyValue(request)
                        .retrieve()
                        .bodyToMono(ChatResponse.class)
                        .block();

                // Record turn
                SimulationResult.ConversationTurn turn = SimulationResult.ConversationTurn.builder()
                        .sender(scamMsg.getSender())
                        .message(scamMsg.getText())
                        .response(response != null ? response.getReply() : "ERROR")
                        .timestamp(LocalDateTime.now())
                        .build();
                conversation.add(turn);

                // Extract intelligence from this message
                ExtractedInfo turnIntel = informationExtractor.extractInformation(scamMsg.getText());
                mergeIntelligence(aggregatedIntelligence, turnIntel);

                log.info("Turn {}: {} -> {}", conversation.size(),
                        scamMsg.getText().substring(0, Math.min(50, scamMsg.getText().length())),
                        response != null ? response.getReply() : "ERROR");
            }

            // Get final evidence
            EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);
            if (evidence != null) {
                aggregatedIntelligence = evidence.getExtractedInfo();
            }

            LocalDateTime endTime = LocalDateTime.now();

            // Validate results
            SimulationResult.ValidationResults validation = validateResults(
                    aggregatedIntelligence,
                    scenario.getExpectedIntelligence());

            // Build result
            return SimulationResult.builder()
                    .sessionId(sessionId)
                    .scenarioName(scenario.getScenarioName())
                    .startTime(startTime)
                    .endTime(endTime)
                    .durationMs(java.time.Duration.between(startTime, endTime).toMillis())
                    .totalMessages(conversation.size())
                    .conversation(conversation)
                    .actualIntelligence(aggregatedIntelligence)
                    .expectedIntelligence(scenario.getExpectedIntelligence())
                    .validation(validation)
                    .passed(validation.isUpiIdsMatch() && validation.isBankAccountsMatch()
                            && validation.isPhoneNumbersMatch() && validation.isThreatLevelMet())
                    .summary(generateSummary(validation))
                    .build();

        } catch (Exception e) {
            log.error("Simulation failed: {}", e.getMessage(), e);
            return SimulationResult.builder()
                    .sessionId(sessionId)
                    .scenarioName(scenario.getScenarioName())
                    .startTime(startTime)
                    .endTime(LocalDateTime.now())
                    .passed(false)
                    .summary("FAILED: " + e.getMessage())
                    .build();
        }
    }

    /**
     * Validate extracted intelligence against expected values
     */
    private SimulationResult.ValidationResults validateResults(
            ExtractedInfo actual,
            ScamScenario.ExpectedIntelligence expected) {

        List<String> missing = new ArrayList<>();
        List<String> unexpected = new ArrayList<>();

        boolean upiMatch = validateList(actual.getUpiIds(), expected.getExpectedUpiIds(), "UPI", missing, unexpected);
        boolean bankMatch = validateList(actual.getBankAccountNumbers(), expected.getExpectedBankAccounts(), "Bank",
                missing, unexpected);
        boolean phoneMatch = validateList(actual.getPhoneNumbers(), expected.getExpectedPhoneNumbers(), "Phone",
                missing, unexpected);
        boolean urlMatch = validateList(actual.getUrls(), expected.getExpectedUrls(), "URL", missing, unexpected);
        boolean keywordMatch = validateList(actual.getSuspiciousKeywords(), expected.getExpectedKeywords(), "Keyword",
                missing, unexpected);

        // Check threat level
        double actualThreat = scamDetector.calculateThreatLevel(
                String.join(" ", actual.getSuspiciousKeywords()));
        boolean threatMet = actualThreat >= expected.getMinThreatLevel();

        return SimulationResult.ValidationResults.builder()
                .upiIdsMatch(upiMatch)
                .bankAccountsMatch(bankMatch)
                .phoneNumbersMatch(phoneMatch)
                .urlsMatch(urlMatch)
                .keywordsMatch(keywordMatch)
                .threatLevelMet(threatMet)
                .missingIntelligence(missing)
                .unexpectedIntelligence(unexpected)
                .build();
    }

    private boolean validateList(List<String> actual, List<String> expected,
            String type, List<String> missing, List<String> unexpected) {
        if (expected == null || expected.isEmpty()) {
            return true;
        }

        for (String exp : expected) {
            if (!actual.contains(exp)) {
                missing.add(type + ": " + exp);
            }
        }

        for (String act : actual) {
            if (!expected.contains(act)) {
                unexpected.add(type + ": " + act);
            }
        }

        return missing.isEmpty();
    }

    private void mergeIntelligence(ExtractedInfo target, ExtractedInfo source) {
        target.getUpiIds().addAll(source.getUpiIds());
        target.getBankAccountNumbers().addAll(source.getBankAccountNumbers());
        target.getPhoneNumbers().addAll(source.getPhoneNumbers());
        target.getUrls().addAll(source.getUrls());
        target.getSuspiciousKeywords().addAll(source.getSuspiciousKeywords());
    }

    private String generateSummary(SimulationResult.ValidationResults validation) {
        StringBuilder summary = new StringBuilder();

        if (validation.isUpiIdsMatch() && validation.isBankAccountsMatch()
                && validation.isPhoneNumbersMatch() && validation.isThreatLevelMet()) {
            summary.append("PASSED: All intelligence extracted successfully");
        } else {
            summary.append("FAILED: ");
            if (!validation.getMissingIntelligence().isEmpty()) {
                summary.append("Missing: ").append(validation.getMissingIntelligence());
            }
        }

        return summary.toString();
    }
}
