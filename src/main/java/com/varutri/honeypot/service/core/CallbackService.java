package com.varutri.honeypot.service.core;

import com.varutri.honeypot.dto.ExtractedInfo;
import com.varutri.honeypot.dto.FinalResultRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Service to send final intelligence report to GUVI Hackathon API
 */
@Slf4j
@Service
public class CallbackService {

    private final WebClient webClient;
    private static final String GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

    public CallbackService() {
        this.webClient = WebClient.builder()
                .baseUrl(GUVI_CALLBACK_URL)
                .defaultHeader("Content-Type", "application/json")
                .build();

        log.info("Callback service initialized with GUVI endpoint: {}", GUVI_CALLBACK_URL);
    }

    /**
     * Send final intelligence report to GUVI Hackathon API
     */
    public void sendFinalReport(String sessionId, ExtractedInfo intelligence, int totalMessages, String agentNotes) {
        try {
            // Build extracted intelligence
            FinalResultRequest.ExtractedIntelligence extractedIntel = FinalResultRequest.ExtractedIntelligence.builder()
                    .bankAccounts(intelligence.getBankAccountNumbers())
                    .upiIds(intelligence.getUpiIds())
                    .phishingLinks(intelligence.getUrls())
                    .phoneNumbers(intelligence.getPhoneNumbers())
                    .suspiciousKeywords(intelligence.getSuspiciousKeywords())
                    .build();

            // Build final request
            FinalResultRequest request = FinalResultRequest.builder()
                    .sessionId(sessionId)
                    .scamDetected(true)
                    .totalMessagesExchanged(totalMessages)
                    .extractedIntelligence(extractedIntel)
                    .agentNotes(agentNotes != null ? agentNotes : "Scam detected and intelligence extracted")
                    .build();

            log.info("Sending final report to GUVI for session {}: {} UPIs, {} accounts, {} URLs, {} phones, {} turns",
                    sessionId,
                    intelligence.getUpiIds().size(),
                    intelligence.getBankAccountNumbers().size(),
                    intelligence.getUrls().size(),
                    intelligence.getPhoneNumbers().size(),
                    totalMessages);

            // Send to GUVI
            Mono<String> responseMono = webClient.post()
                    .bodyValue(request)
                    .retrieve()
                    .bodyToMono(String.class);

            String response = responseMono.block();

            log.info("Final report sent successfully to GUVI for session {}: {}", sessionId, response);

        } catch (Exception e) {
            log.error("Error sending final report to GUVI for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
}

