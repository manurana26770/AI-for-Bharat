package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.ScamReportEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DynamoDB repository for scam reports.
 * Table: varutri_scam_reports (partition key: reportId, GSI: sessionId-index)
 */
@Slf4j
@Repository
public class ScamReportRepository {

    private final DynamoDbTable<ScamReportEntity> table;

    public ScamReportRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.table-prefix:varutri_}") String prefix) {
        this.table = enhancedClient.table(prefix + "scam_reports",
                TableSchema.fromBean(ScamReportEntity.class));
        log.info("ScamReportRepository initialized for DynamoDB table: {}scam_reports", prefix);
    }

    /**
     * Find report by reportId (partition key lookup — O(1))
     */
    public Optional<ScamReportEntity> findByReportId(String reportId) {
        try {
            ScamReportEntity item = table.getItem(Key.builder()
                    .partitionValue(reportId)
                    .build());
            return Optional.ofNullable(item);
        } catch (Exception e) {
            log.error("Error finding report {}: {}", reportId, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Find all reports for a session (uses GSI: sessionId-index)
     */
    public List<ScamReportEntity> findBySessionId(String sessionId) {
        try {
            DynamoDbIndex<ScamReportEntity> index = table.index("sessionId-index");
            List<ScamReportEntity> results = new ArrayList<>();
            index.query(QueryEnhancedRequest.builder()
                    .queryConditional(QueryConditional.keyEqualTo(
                            Key.builder().partitionValue(sessionId).build()))
                    .build())
                    .stream()
                    .flatMap(page -> page.items().stream())
                    .forEach(results::add);
            return results;
        } catch (Exception e) {
            log.error("Error finding reports by session {}: {}", sessionId, e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find reports by status (scan with filter)
     */
    public List<ScamReportEntity> findByStatus(String status) {
        try {
            List<ScamReportEntity> results = new ArrayList<>();
            table.scan(ScanEnhancedRequest.builder()
                    .filterExpression(Expression.builder()
                            .expression("#s = :status")
                            .putExpressionName("#s", "status")
                            .putExpressionValue(":status",
                                    AttributeValue.builder().s(status).build())
                            .build())
                    .build())
                    .items().forEach(results::add);
            return results;
        } catch (Exception e) {
            log.error("Error finding reports by status {}: {}", status, e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Save or update a scam report
     */
    public void save(ScamReportEntity entity) {
        try {
            table.putItem(entity);
        } catch (Exception e) {
            log.error("Error saving report {}: {}", entity.getReportId(), e.getMessage());
            throw e;
        }
    }

    /**
     * Find all reports (full table scan)
     */
    public List<ScamReportEntity> findAll() {
        try {
            List<ScamReportEntity> results = new ArrayList<>();
            table.scan().items().forEach(results::add);
            return results;
        } catch (Exception e) {
            log.error("Error scanning all reports: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find high-threat reports (scan with filter)
     */
    public List<ScamReportEntity> findByThreatLevelGreaterThanEqual(double threshold) {
        try {
            List<ScamReportEntity> results = new ArrayList<>();
            table.scan(ScanEnhancedRequest.builder()
                    .filterExpression(Expression.builder()
                            .expression("threatLevel >= :tl")
                            .putExpressionValue(":tl",
                                    AttributeValue.builder().n(String.valueOf(threshold)).build())
                            .build())
                    .build())
                    .items().forEach(results::add);
            return results;
        } catch (Exception e) {
            log.error("Error finding high-threat reports: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Count all reports (full table scan)
     */
    public long count() {
        try {
            AtomicLong count = new AtomicLong(0);
            table.scan().items().forEach(item -> count.incrementAndGet());
            return count.get();
        } catch (Exception e) {
            log.error("Error counting reports: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * Count reports by scam type (scan with filter)
     */
    public long countByScamType(String scamType) {
        try {
            AtomicLong count = new AtomicLong(0);
            table.scan(ScanEnhancedRequest.builder()
                    .filterExpression(Expression.builder()
                            .expression("scamType = :st")
                            .putExpressionValue(":st",
                                    AttributeValue.builder().s(scamType).build())
                            .build())
                    .build())
                    .items().forEach(item -> count.incrementAndGet());
            return count.get();
        } catch (Exception e) {
            log.error("Error counting reports by type {}: {}", scamType, e.getMessage());
            return 0;
        }
    }
}
