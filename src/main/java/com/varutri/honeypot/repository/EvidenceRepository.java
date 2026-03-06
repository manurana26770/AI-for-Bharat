package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.EvidenceEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Expression;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.ScanEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DynamoDB repository for evidence data.
 * Table: varutri_evidence (partition key: sessionId)
 */
@Slf4j
@Repository
public class EvidenceRepository {

    private final DynamoDbTable<EvidenceEntity> table;

    public EvidenceRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.table-prefix:varutri_}") String prefix) {
        this.table = enhancedClient.table(prefix + "evidence",
                TableSchema.fromBean(EvidenceEntity.class));
        log.info("EvidenceRepository initialized for DynamoDB table: {}evidence", prefix);
    }

    /**
     * Find evidence by sessionId (partition key lookup — O(1))
     */
    public Optional<EvidenceEntity> findBySessionId(String sessionId) {
        try {
            EvidenceEntity item = table.getItem(Key.builder()
                    .partitionValue(sessionId)
                    .build());
            return Optional.ofNullable(item);
        } catch (Exception e) {
            log.error("Error finding evidence by session {}: {}", sessionId, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Check if evidence exists for session
     */
    public boolean existsBySessionId(String sessionId) {
        return findBySessionId(sessionId).isPresent();
    }

    /**
     * Save or update evidence entity
     */
    public void save(EvidenceEntity entity) {
        try {
            table.putItem(entity);
        } catch (Exception e) {
            log.error("Error saving evidence {}: {}", entity.getSessionId(), e.getMessage());
            throw e;
        }
    }

    /**
     * Find all evidence (full table scan)
     */
    public List<EvidenceEntity> findAll() {
        try {
            List<EvidenceEntity> results = new ArrayList<>();
            table.scan().items().forEach(results::add);
            return results;
        } catch (Exception e) {
            log.error("Error scanning all evidence: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Find all high-threat evidence (scan with filter)
     */
    public List<EvidenceEntity> findByThreatLevelGreaterThanEqual(double threshold) {
        try {
            List<EvidenceEntity> results = new ArrayList<>();
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
            log.error("Error finding high-threat evidence: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Delete evidence by sessionId
     */
    public void deleteBySessionId(String sessionId) {
        try {
            table.deleteItem(Key.builder()
                    .partitionValue(sessionId)
                    .build());
        } catch (Exception e) {
            log.error("Error deleting evidence {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Count all evidence items (full table scan)
     */
    public long count() {
        try {
            AtomicLong count = new AtomicLong(0);
            table.scan().items().forEach(item -> count.incrementAndGet());
            return count.get();
        } catch (Exception e) {
            log.error("Error counting evidence: {}", e.getMessage());
            return 0;
        }
    }
}
