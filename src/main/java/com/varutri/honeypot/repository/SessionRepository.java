package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.SessionEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * DynamoDB repository for session data.
 * Table: varutri_sessions (partition key: sessionId)
 */
@Slf4j
@Repository
public class SessionRepository {

    private final DynamoDbTable<SessionEntity> table;

    public SessionRepository(DynamoDbEnhancedClient enhancedClient,
            @Value("${aws.dynamodb.table-prefix:varutri_}") String prefix) {
        this.table = enhancedClient.table(prefix + "sessions",
                TableSchema.fromBean(SessionEntity.class));
        log.info("SessionRepository initialized for DynamoDB table: {}sessions", prefix);
    }

    /**
     * Find session by sessionId (partition key lookup — O(1))
     */
    public Optional<SessionEntity> findBySessionId(String sessionId) {
        try {
            SessionEntity item = table.getItem(Key.builder()
                    .partitionValue(sessionId)
                    .build());
            return Optional.ofNullable(item);
        } catch (Exception e) {
            log.error("Error finding session by id {}: {}", sessionId, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Check if session exists (partition key lookup)
     */
    public boolean existsBySessionId(String sessionId) {
        return findBySessionId(sessionId).isPresent();
    }

    /**
     * Save or update a session entity
     */
    public void save(SessionEntity entity) {
        try {
            table.putItem(entity);
        } catch (Exception e) {
            log.error("Error saving session {}: {}", entity.getSessionId(), e.getMessage());
            throw e;
        }
    }

    /**
     * Delete session by sessionId
     */
    public void deleteBySessionId(String sessionId) {
        try {
            table.deleteItem(Key.builder()
                    .partitionValue(sessionId)
                    .build());
        } catch (Exception e) {
            log.error("Error deleting session {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Count all sessions (full table scan — use sparingly)
     */
    public long count() {
        try {
            AtomicLong count = new AtomicLong(0);
            table.scan().items().forEach(item -> count.incrementAndGet());
            return count.get();
        } catch (Exception e) {
            log.error("Error counting sessions: {}", e.getMessage());
            return 0;
        }
    }
}
