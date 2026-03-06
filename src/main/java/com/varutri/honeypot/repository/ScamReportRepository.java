package com.varutri.honeypot.repository;

import com.varutri.honeypot.entity.ScamReportEntity;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * MongoDB repository for scam reports
 */
@Repository
public interface ScamReportRepository extends MongoRepository<ScamReportEntity, String> {

    /**
     * Find report by reportId
     */
    Optional<ScamReportEntity> findByReportId(String reportId);

    /**
     * Find all reports for a session
     */
    List<ScamReportEntity> findBySessionId(String sessionId);

    /**
     * Find reports by status
     */
    List<ScamReportEntity> findByStatus(ScamReportEntity.ReportStatus status);

    /**
     * Find high-threat reports
     */
    List<ScamReportEntity> findByThreatLevelGreaterThanEqual(double threshold);

    /**
     * Count reports by scam type
     */
    long countByScamType(String scamType);
}
