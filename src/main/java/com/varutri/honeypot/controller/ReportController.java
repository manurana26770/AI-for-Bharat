package com.varutri.honeypot.controller;

import com.varutri.honeypot.dto.ScamReport;
import com.varutri.honeypot.service.core.GovernmentReportService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller for government reporting endpoints
 */
@Slf4j
@RestController
@RequestMapping("/api/report")
public class ReportController {

    @Autowired
    private GovernmentReportService governmentReportService;

    /**
     * Manually trigger government report for a session
     */
    @PostMapping("/manual")
    public ResponseEntity<?> manualReport(@RequestBody Map<String, String> request) {
        String sessionId = request.get("sessionId");

        if (sessionId == null || sessionId.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", "error",
                    "message", "Session ID is required"));
        }

        log.info("📝 Manual report requested for session: {}", sessionId);

        try {
            ScamReport report = governmentReportService.generateReport(sessionId);

            if (report == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "status", "error",
                        "message", "No evidence found for session"));
            }

            governmentReportService.sendToAuthorities(report);

            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "reportId", report.getReportId(),
                    "message", "Report generated and sent to authorities",
                    "threatLevel", report.getThreatLevel(),
                    "intelligenceCount",
                    report.getUpiIds().size() +
                            report.getBankAccounts().size() +
                            report.getPhoneNumbers().size() +
                            report.getUrls().size()));

        } catch (Exception e) {
            log.error("Error generating manual report: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to generate report: " + e.getMessage()));
        }
    }

    /**
     * Get report by ID
     */
    @GetMapping("/{reportId}")
    public ResponseEntity<?> getReport(@PathVariable String reportId) {
        ScamReport report = governmentReportService.getReport(reportId);

        if (report == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(report);
    }

    /**
     * Get all archived reports
     */
    @GetMapping("/all")
    public ResponseEntity<List<ScamReport>> getAllReports() {
        List<ScamReport> reports = governmentReportService.getAllReports();
        return ResponseEntity.ok(reports);
    }

    /**
     * Get report statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        List<ScamReport> reports = governmentReportService.getAllReports();

        long totalReports = reports.size();
        long highThreatReports = reports.stream()
                .filter(r -> r.getThreatLevel() >= 0.7)
                .count();

        int totalUpiIds = reports.stream()
                .mapToInt(r -> r.getUpiIds().size())
                .sum();

        int totalBankAccounts = reports.stream()
                .mapToInt(r -> r.getBankAccounts().size())
                .sum();

        int totalPhoneNumbers = reports.stream()
                .mapToInt(r -> r.getPhoneNumbers().size())
                .sum();

        int totalUrls = reports.stream()
                .mapToInt(r -> r.getUrls().size())
                .sum();

        return ResponseEntity.ok(Map.of(
                "totalReports", totalReports,
                "highThreatReports", highThreatReports,
                "intelligenceExtracted", Map.of(
                        "upiIds", totalUpiIds,
                        "bankAccounts", totalBankAccounts,
                        "phoneNumbers", totalPhoneNumbers,
                        "phishingUrls", totalUrls)));
    }
}

