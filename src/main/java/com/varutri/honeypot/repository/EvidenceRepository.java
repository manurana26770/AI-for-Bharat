package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.EvidenceEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * MongoDB repository for evidence data
 */
@Repository
public interface EvidenceRepository extends MongoRepository<EvidenceEntity, String> {

    /**
     * Find evidence by sessionId
     */
    Optional<EvidenceEntity> findBySessionId(String sessionId);

    /**
     * Check if evidence exists for session
     */
    boolean existsBySessionId(String sessionId);

    /**
     * Find all high-threat evidence (threatLevel >= threshold)
     */
    List<EvidenceEntity> findByThreatLevelGreaterThanEqual(double threshold);

    /**
     * Find evidence by scam type
     */
    List<EvidenceEntity> findByScamType(String scamType);

    /**
     * Delete evidence by sessionId
     */
    void deleteBySessionId(String sessionId);
}
