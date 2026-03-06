package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.SessionEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * MongoDB repository for session data
 */
@Repository
public interface SessionRepository extends MongoRepository<SessionEntity, String> {

    /**
     * Find session by sessionId
     */
    Optional<SessionEntity> findBySessionId(String sessionId);

    /**
     * Check if session exists
     */
    boolean existsBySessionId(String sessionId);

    /**
     * Delete session by sessionId
     */
    void deleteBySessionId(String sessionId);
}
