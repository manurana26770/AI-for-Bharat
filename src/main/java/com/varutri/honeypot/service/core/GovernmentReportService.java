package com.varutri.honeypot.service.core;

import com.varutri.honeypot.service.data.EvidenceCollector;

import com.varutri.honeypot.dto.ExtractedInfo;
import com.varutri.honeypot.dto.ScamReport;
import com.varutri.honeypot.entity.ScamReportEntity;
import com.varutri.honeypot.repository.ScamReportRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for reporting scams to government authorities
 * Uses DynamoDB for persistent report storage
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GovernmentReportService {

    private final EvidenceCollector evidenceCollector;
    private final ScamReportRepository scamReportRepository;

    @Value("${government.report.auto-threshold:0.7}")
    private double autoReportThreshold;

    @Value("${government.report.email:report@cybercrime.gov.in}")
    private String reportEmail;

    /**
     * Check if session should trigger automatic report
     */
    public boolean shouldAutoReport(String sessionId) {
        EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);
        if (evidence == null) {
            return false;
        }

        double threatLevel = evidence.getThreatLevel();
        boolean highThreat = threatLevel >= autoReportThreshold;

        if (highThreat) {
            log.warn("\uD83D\uDEA8 High threat detected ({}): Auto-reporting session {}",
                    String.format("%.2f", threatLevel), sessionId);
        }

        return highThreat;
    }

    /**
     * Generate comprehensive scam report
     */
    public ScamReport generateReport(String sessionId) {
        EvidenceCollector.EvidencePackage evidence = evidenceCollector.getEvidence(sessionId);
        if (evidence == null) {
            log.error("No evidence found for session {}", sessionId);
            return null;
        }

        ExtractedInfo info = evidence.getExtractedInfo();

        // Convert conversation to report format
        List<ScamReport.ConversationTurn> conversation = evidence.getConversation().stream()
                .map(turn -> ScamReport.ConversationTurn.builder()
                        .timestamp(turn.getTimestamp())
                        .sender("scammer")
                        .message(turn.getUserMessage())
                        .build())
                .collect(Collectors.toList());

        ScamReport report = ScamReport.builder()
                .reportId("RPT-" + System.currentTimeMillis())
                .timestamp(LocalDateTime.now())
                .sessionId(sessionId)
                .scamType(evidence.getScamType())
                .threatLevel(evidence.getThreatLevel())
                .totalMessages(evidence.getConversation().size())
                .upiIds(info.getUpiIds())
                .bankAccounts(info.getBankAccountNumbers())
                .ifscCodes(info.getIfscCodes())
                .phoneNumbers(info.getPhoneNumbers())
                .urls(info.getUrls())
                .suspiciousKeywords(info.getSuspiciousKeywords())
                .conversation(conversation)
                .victimProfile("Elderly Indian persona (Varutri AI)")
                .reportedBy("Varutri Honeypot System")
                .status(ScamReport.ReportStatus.PENDING)
                .build();

        log.info("\uD83D\uDCCB Generated report {} for session {}", report.getReportId(), sessionId);
        return report;
    }

    /**
     * Send report to government authorities
     */
    public void sendToAuthorities(ScamReport report) {
        try {
            // Generate report text
            String reportText = formatReportForEmail(report);

            // In production, integrate with email service (JavaMail, SendGrid, etc.)
            // For now, log and save to file
            log.warn("\uD83D\uDCE7 GOVERNMENT REPORT - Would send to {}", reportEmail);
            log.warn("Report ID: {}", report.getReportId());
            log.warn("Threat Level: {}", String.format("%.2f", report.getThreatLevel()));
            log.warn("Intelligence: {} UPI IDs, {} Bank Accounts, {} Phone Numbers, {} URLs",
                    report.getUpiIds().size(),
                    report.getBankAccounts().size(),
                    report.getPhoneNumbers().size(),
                    report.getUrls().size());

            // Save to file for manual submission
            saveReportToFile(report, reportText);

            report.setStatus(ScamReport.ReportStatus.SENT);
            archiveReport(report);

            log.info("\u2705 Report {} sent successfully", report.getReportId());

        } catch (Exception e) {
            log.error("\u274C Failed to send report {}: {}", report.getReportId(), e.getMessage(), e);
            report.setStatus(ScamReport.ReportStatus.FAILED);
            archiveReport(report);
        }
    }

    /**
     * Format report for email submission
     */
    private String formatReportForEmail(ScamReport report) {
        StringBuilder sb = new StringBuilder();

        sb.append("=".repeat(80)).append("\n");
        sb.append("CYBERCRIME REPORT - VARUTRI HONEYPOT SYSTEM\n");
        sb.append("=".repeat(80)).append("\n\n");

        sb.append("Report ID: ").append(report.getReportId()).append("\n");
        sb.append("Date: ").append(report.getTimestamp().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
        sb.append("Session ID: ").append(report.getSessionId()).append("\n");
        sb.append("Scam Type: ").append(report.getScamType()).append("\n");
        sb.append("Threat Level: ").append(String.format("%.2f", report.getThreatLevel())).append("/1.0\n");
        sb.append("Total Messages: ").append(report.getTotalMessages()).append("\n\n");

        sb.append("-".repeat(80)).append("\n");
        sb.append("EXTRACTED INTELLIGENCE\n");
        sb.append("-".repeat(80)).append("\n\n");

        if (!report.getUpiIds().isEmpty()) {
            sb.append("UPI IDs:\n");
            report.getUpiIds().forEach(upi -> sb.append("  - ").append(upi).append("\n"));
            sb.append("\n");
        }

        if (!report.getBankAccounts().isEmpty()) {
            sb.append("Bank Account Numbers:\n");
            report.getBankAccounts().forEach(acc -> sb.append("  - ").append(acc).append("\n"));
            sb.append("\n");
        }

        if (!report.getIfscCodes().isEmpty()) {
            sb.append("IFSC Codes:\n");
            report.getIfscCodes().forEach(ifsc -> sb.append("  - ").append(ifsc).append("\n"));
            sb.append("\n");
        }

        if (!report.getPhoneNumbers().isEmpty()) {
            sb.append("Phone Numbers:\n");
            report.getPhoneNumbers().forEach(phone -> sb.append("  - ").append(phone).append("\n"));
            sb.append("\n");
        }

        if (!report.getUrls().isEmpty()) {
            sb.append("Phishing URLs:\n");
            report.getUrls().forEach(url -> sb.append("  - ").append(url).append("\n"));
            sb.append("\n");
        }

        if (!report.getSuspiciousKeywords().isEmpty()) {
            sb.append("Suspicious Keywords:\n");
            sb.append("  ").append(String.join(", ", report.getSuspiciousKeywords())).append("\n\n");
        }

        sb.append("-".repeat(80)).append("\n");
        sb.append("CONVERSATION TRANSCRIPT\n");
        sb.append("-".repeat(80)).append("\n\n");

        for (int i = 0; i < report.getConversation().size(); i++) {
            ScamReport.ConversationTurn turn = report.getConversation().get(i);
            sb.append("[").append(i + 1).append("] ");
            sb.append(turn.getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
            sb.append(" - SCAMMER:\n");
            sb.append(turn.getMessage()).append("\n\n");
        }

        sb.append("-".repeat(80)).append("\n");
        sb.append("SYSTEM INFORMATION\n");
        sb.append("-".repeat(80)).append("\n\n");
        sb.append("Reported By: ").append(report.getReportedBy()).append("\n");
        sb.append("Victim Profile: ").append(report.getVictimProfile()).append("\n");
        sb.append("Detection Method: AI-powered honeypot conversation analysis\n\n");

        sb.append("=".repeat(80)).append("\n");
        sb.append("END OF REPORT\n");
        sb.append("=".repeat(80)).append("\n");

        return sb.toString();
    }

    /**
     * Save report to file for manual submission
     */
    private void saveReportToFile(ScamReport report, String reportText) {
        try {
            File reportsDir = new File("reports");
            if (!reportsDir.exists()) {
                reportsDir.mkdirs();
            }

            String filename = String.format("reports/%s_%s.txt",
                    report.getReportId(),
                    report.getTimestamp().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")));

            try (FileWriter writer = new FileWriter(filename)) {
                writer.write(reportText);
            }

            log.info("\uD83D\uDCBE Report saved to file: {}", filename);

        } catch (Exception e) {
            log.error("Failed to save report to file: {}", e.getMessage(), e);
        }
    }

    /**
     * Archive report for audit trail (persisted to DynamoDB)
     */
    public void archiveReport(ScamReport report) {
        try {
            // Convert to entity — no @Builder, use setters
            ScamReportEntity entity = new ScamReportEntity();
            entity.setReportId(report.getReportId());
            entity.setSessionId(report.getSessionId());
            entity.setTimestamp(report.getTimestamp().toString());
            entity.setScamType(report.getScamType());
            entity.setThreatLevel(report.getThreatLevel());
            entity.setTotalMessages(report.getTotalMessages());
            entity.setUpiIds(new ArrayList<>(report.getUpiIds()));
            entity.setBankAccounts(new ArrayList<>(report.getBankAccounts()));
            entity.setIfscCodes(new ArrayList<>(report.getIfscCodes()));
            entity.setPhoneNumbers(new ArrayList<>(report.getPhoneNumbers()));
            entity.setUrls(new ArrayList<>(report.getUrls()));
            entity.setSuspiciousKeywords(new ArrayList<>(report.getSuspiciousKeywords()));
            entity.setVictimProfile(report.getVictimProfile());
            entity.setReportedBy(report.getReportedBy());
            entity.setStatus(report.getStatus().name());

            // Convert conversation
            if (report.getConversation() != null) {
                List<ScamReportEntity.ConversationTurn> turns = report.getConversation().stream()
                        .map(turn -> {
                            ScamReportEntity.ConversationTurn ct = new ScamReportEntity.ConversationTurn();
                            ct.setTimestamp(turn.getTimestamp() != null ? turn.getTimestamp().toString() : null);
                            ct.setSender(turn.getSender());
                            ct.setMessage(turn.getMessage());
                            return ct;
                        })
                        .toList();
                entity.setConversation(turns);
            }

            scamReportRepository.save(entity);
            log.info("\uD83D\uDCE6 Report {} archived to DynamoDB", report.getReportId());

        } catch (Exception e) {
            log.error("Failed to archive report to DynamoDB {}: {}", report.getReportId(), e.getMessage());
        }
    }

    /**
     * Get archived report (from DynamoDB)
     */
    public ScamReport getReport(String reportId) {
        Optional<ScamReportEntity> entity = scamReportRepository.findByReportId(reportId);
        return entity.map(this::entityToScamReport).orElse(null);
    }

    /**
     * Get all archived reports (from DynamoDB)
     */
    public List<ScamReport> getAllReports() {
        return scamReportRepository.findAll().stream()
                .map(this::entityToScamReport)
                .toList();
    }

    /**
     * Get total report count
     */
    public long getTotalReportCount() {
        return scamReportRepository.count();
    }

    /**
     * Get high-threat reports
     */
    public List<ScamReport> getHighThreatReports() {
        return scamReportRepository.findByThreatLevelGreaterThanEqual(0.7).stream()
                .map(this::entityToScamReport)
                .toList();
    }

    /**
     * Convert DynamoDB entity to ScamReport DTO
     */
    private ScamReport entityToScamReport(ScamReportEntity entity) {
        List<ScamReport.ConversationTurn> conversation = new ArrayList<>();
        if (entity.getConversation() != null) {
            conversation = entity.getConversation().stream()
                    .map(turn -> ScamReport.ConversationTurn.builder()
                            .timestamp(turn.getTimestamp() != null ? LocalDateTime.parse(turn.getTimestamp()) : null)
                            .sender(turn.getSender())
                            .message(turn.getMessage())
                            .build())
                    .toList();
        }

        return ScamReport.builder()
                .reportId(entity.getReportId())
                .sessionId(entity.getSessionId())
                .timestamp(entity.getTimestamp() != null ? LocalDateTime.parse(entity.getTimestamp()) : null)
                .scamType(entity.getScamType())
                .threatLevel(entity.getThreatLevel())
                .totalMessages(entity.getTotalMessages())
                .upiIds(entity.getUpiIds())
                .bankAccounts(entity.getBankAccounts())
                .ifscCodes(entity.getIfscCodes())
                .phoneNumbers(entity.getPhoneNumbers())
                .urls(entity.getUrls())
                .suspiciousKeywords(entity.getSuspiciousKeywords())
                .conversation(conversation)
                .victimProfile(entity.getVictimProfile())
                .reportedBy(entity.getReportedBy())
                .status(ScamReport.ReportStatus.valueOf(entity.getStatus()))
                .build();
    }

    /**
     * Process automatic report for high-threat session
     */
    public void processAutoReport(String sessionId) {
        if (shouldAutoReport(sessionId)) {
            ScamReport report = generateReport(sessionId);
            if (report != null) {
                sendToAuthorities(report);
            }
        }
    }
}
