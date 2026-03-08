package com.varutri.honeypot.controller;

import com.varutri.honeypot.dto.ScamReport;
import com.varutri.honeypot.service.core.GovernmentReportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Reports", description = "Scam intelligence reports — generate, retrieve, and analyze reports sent to government authorities")
public class ReportController {

    @Autowired
    private GovernmentReportService governmentReportService;

    @Operation(
            summary = "Generate and send a manual report",
            description = """
                    Manually generate a government scam report for a specific session.
                    Compiles all extracted intelligence (UPI IDs, bank accounts, phone numbers, phishing URLs)
                    and sends it to cyber-crime authorities.
                    """
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Session ID to report",
            content = @Content(examples = @ExampleObject(value = """
                    {
                      "sessionId": "session-001"
                    }
                    """))
    )
    @ApiResponse(responseCode = "200", description = "Report generated and sent")
    @ApiResponse(responseCode = "400", description = "Session ID missing or no evidence found")
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

    @Operation(
            summary = "Get report by ID",
            description = "Retrieve a specific scam report by its unique report ID."
    )
    @ApiResponse(responseCode = "200", description = "Report found")
    @ApiResponse(responseCode = "404", description = "Report not found")
    @GetMapping("/{reportId}")
    public ResponseEntity<?> getReport(
            @Parameter(description = "Report ID", example = "RPT-20240307-abc123")
            @PathVariable String reportId) {
        ScamReport report = governmentReportService.getReport(reportId);

        if (report == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(report);
    }

    @Operation(
            summary = "Get all reports",
            description = "Retrieve all archived scam reports."
    )
    @ApiResponse(responseCode = "200", description = "All reports returned")
    @GetMapping("/all")
    public ResponseEntity<List<ScamReport>> getAllReports() {
        List<ScamReport> reports = governmentReportService.getAllReports();
        return ResponseEntity.ok(reports);
    }

    @Operation(
            summary = "Get report statistics",
            description = "Returns aggregate statistics across all reports: total count, high-threat count, and total extracted intelligence (UPI IDs, bank accounts, phone numbers, phishing URLs)."
    )
    @ApiResponse(responseCode = "200", description = "Statistics returned")
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

