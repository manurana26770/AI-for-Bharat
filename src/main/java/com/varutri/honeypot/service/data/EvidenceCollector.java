package com.varutri.honeypot.service.data;

import com.varutri.honeypot.service.ai.InformationExtractor;
import com.varutri.honeypot.service.ai.ScamDetector;
import com.varutri.honeypot.service.ai.EnsembleThreatScorer;

import com.varutri.honeypot.dto.ExtractedInfo;
import com.varutri.honeypot.entity.EvidenceEntity;
import com.varutri.honeypot.repository.EvidenceRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for collecting and storing evidence from scam conversations
 * Uses MongoDB for persistent storage with in-memory cache
 * 
 * Now uses EnsembleThreatScorer for unified threat detection
 */
@Slf4j
@Service
public class EvidenceCollector {

    private final EvidenceRepository evidenceRepository;
    private final InformationExtractor informationExtractor;
    private final ScamDetector scamDetector; // Only used for extractSuspiciousKeywords()
    private final EnsembleThreatScorer ensembleThreatScorer; // Unified threat scoring

    // In-memory cache for fast access
    private final Map<String, EvidencePackage> evidenceCache = new ConcurrentHashMap<>();

    @Autowired
    public EvidenceCollector(EvidenceRepository evidenceRepository,
            InformationExtractor informationExtractor,
            ScamDetector scamDetector,
            EnsembleThreatScorer ensembleThreatScorer) {
        this.evidenceRepository = evidenceRepository;
        this.informationExtractor = informationExtractor;
        this.scamDetector = scamDetector;
        this.ensembleThreatScorer = ensembleThreatScorer;
    }

    /**
     * Collect evidence from a conversation turn
     * Uses EnsembleThreatScorer for unified threat detection
     */
    public boolean collectEvidence(String sessionId, String userMessage, String assistantReply) {
        EvidencePackage evidence = getOrCreateEvidence(sessionId);

        // Add conversation turn
        ConversationTurn turn = new ConversationTurn();
        turn.setTimestamp(LocalDateTime.now());
        turn.setUserMessage(userMessage);
        turn.setAssistantReply(assistantReply);
        evidence.getConversation().add(turn);

        // Extract information from user message
        ExtractedInfo extracted = informationExtractor.extractInformation(userMessage);

        // Merge extracted info
        boolean hasNewIntel = mergeExtractedInfo(evidence.getExtractedInfo(), extracted);

        // === UNIFIED ENSEMBLE THREAT SCORING ===
        EnsembleThreatScorer.ThreatAssessment assessment = ensembleThreatScorer.assessThreat(userMessage, null);

        // Extract keywords using ScamDetector (lightweight operation)
        List<String> keywords = scamDetector.extractSuspiciousKeywords(userMessage);

        // Update evidence with ensemble results
        if (!assessment.primaryScamType.equals("UNKNOWN")) {
            evidence.setScamType(assessment.primaryScamType);
        }
        evidence.setThreatLevel(Math.max(evidence.getThreatLevel(), assessment.ensembleScore));
        evidence.setThreatCategory(assessment.threatLevel); // SAFE/LOW/MEDIUM/HIGH/CRITICAL
        evidence.setConfidence(assessment.calibratedConfidence);
        evidence.setTriggeredLayers(assessment.triggeredLayers);
        evidence.getExtractedInfo().setSuspiciousKeywords(keywords);

        // Store top evidence items if high threat
        if (assessment.isHighThreat() && assessment.topEvidence != null) {
            List<String> evidenceDescriptions = assessment.topEvidence.stream()
                    .limit(5)
                    .map(e -> e.description)
                    .toList();
            evidence.setEnsembleEvidence(evidenceDescriptions);
        }

        evidence.setLastUpdated(LocalDateTime.now());

        // Persist to MongoDB
        persistEvidence(sessionId, evidence);

        log.info("Evidence collected for session {}: Threat={} ({}), Confidence={}%, Layers={}/5",
                sessionId,
                assessment.threatLevel,
                String.format("%.2f", assessment.ensembleScore),
                String.format("%.0f", assessment.calibratedConfidence * 100),
                assessment.triggeredLayers);

        return hasNewIntel;
    }

    /**
     * Get or create evidence package
     */
    private EvidencePackage getOrCreateEvidence(String sessionId) {
        // Check cache first
        EvidencePackage cached = evidenceCache.get(sessionId);
        if (cached != null) {
            return cached;
        }

        // Check MongoDB
        Optional<EvidenceEntity> existingEntity = evidenceRepository.findBySessionId(sessionId);
        if (existingEntity.isPresent()) {
            EvidencePackage evidence = entityToEvidencePackage(existingEntity.get());
            evidenceCache.put(sessionId, evidence);
            log.debug("Loaded evidence from MongoDB: {}", sessionId);
            return evidence;
        }

        // Create new evidence package
        EvidencePackage newEvidence = new EvidencePackage(sessionId);
        evidenceCache.put(sessionId, newEvidence);
        return newEvidence;
    }

    /**
     * Get evidence package for a session
     */
    public EvidencePackage getEvidence(String sessionId) {
        // Check cache first
        EvidencePackage cached = evidenceCache.get(sessionId);
        if (cached != null) {
            return cached;
        }

        // Check MongoDB
        Optional<EvidenceEntity> entity = evidenceRepository.findBySessionId(sessionId);
        if (entity.isPresent()) {
            EvidencePackage evidence = entityToEvidencePackage(entity.get());
            evidenceCache.put(sessionId, evidence);
            return evidence;
        }

        return null;
    }

    /**
     * Get all evidence packages (from MongoDB)
     */
    public List<EvidencePackage> getAllEvidence() {
        return evidenceRepository.findAll().stream()
                .map(this::entityToEvidencePackage)
                .toList();
    }

    /**
     * Get high-threat evidence packages (from MongoDB)
     */
    public List<EvidencePackage> getHighThreatEvidence() {
        return evidenceRepository.findByThreatLevelGreaterThanEqual(0.6).stream()
                .map(this::entityToEvidencePackage)
                .toList();
    }

    /**
     * Get total evidence count
     */
    public long getTotalEvidenceCount() {
        return evidenceRepository.count();
    }

    /**
     * Persist evidence to MongoDB
     */
    private void persistEvidence(String sessionId, EvidencePackage evidence) {
        try {
            EvidenceEntity entity = evidenceRepository.findBySessionId(sessionId)
                    .orElse(EvidenceEntity.createNew(sessionId));

            // Update entity fields
            entity.setScamType(evidence.getScamType());
            entity.setThreatLevel(evidence.getThreatLevel());
            entity.setLastUpdated(LocalDateTime.now());

            // Convert conversation turns
            List<EvidenceEntity.ConversationTurn> mongoTurns = evidence.getConversation().stream()
                    .map(turn -> EvidenceEntity.ConversationTurn.builder()
                            .timestamp(turn.getTimestamp())
                            .userMessage(turn.getUserMessage())
                            .assistantReply(turn.getAssistantReply())
                            .build())
                    .toList();
            entity.setConversation(mongoTurns);

            // Convert extracted info
            ExtractedInfo info = evidence.getExtractedInfo();
            EvidenceEntity.ExtractedIntelligence mongoInfo = EvidenceEntity.ExtractedIntelligence.builder()
                    .upiIds(new ArrayList<>(info.getUpiIds()))
                    .bankAccountNumbers(new ArrayList<>(info.getBankAccountNumbers()))
                    .ifscCodes(new ArrayList<>(info.getIfscCodes()))
                    .phoneNumbers(new ArrayList<>(info.getPhoneNumbers()))
                    .urls(new ArrayList<>(info.getUrls()))
                    .emails(new ArrayList<>(info.getEmails()))
                    .suspiciousKeywords(new ArrayList<>(info.getSuspiciousKeywords()))
                    .build();
            entity.setExtractedInfo(mongoInfo);

            evidenceRepository.save(entity);
            log.debug("Persisted evidence to MongoDB: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to persist evidence to MongoDB {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Convert MongoDB entity to EvidencePackage
     */
    private EvidencePackage entityToEvidencePackage(EvidenceEntity entity) {
        EvidencePackage evidence = new EvidencePackage(entity.getSessionId());
        evidence.setFirstContact(entity.getFirstContact());
        evidence.setLastUpdated(entity.getLastUpdated());
        evidence.setScamType(entity.getScamType());
        evidence.setThreatLevel(entity.getThreatLevel());

        // Convert conversation turns
        if (entity.getConversation() != null) {
            List<ConversationTurn> turns = entity.getConversation().stream()
                    .map(turn -> {
                        ConversationTurn ct = new ConversationTurn();
                        ct.setTimestamp(turn.getTimestamp());
                        ct.setUserMessage(turn.getUserMessage());
                        ct.setAssistantReply(turn.getAssistantReply());
                        return ct;
                    })
                    .toList();
            evidence.setConversation(new ArrayList<>(turns));
        }

        // Convert extracted info
        if (entity.getExtractedInfo() != null) {
            EvidenceEntity.ExtractedIntelligence mongoInfo = entity.getExtractedInfo();
            ExtractedInfo info = new ExtractedInfo();
            info.setUpiIds(new ArrayList<>(mongoInfo.getUpiIds()));
            info.setBankAccountNumbers(new ArrayList<>(mongoInfo.getBankAccountNumbers()));
            info.setIfscCodes(new ArrayList<>(mongoInfo.getIfscCodes()));
            info.setPhoneNumbers(new ArrayList<>(mongoInfo.getPhoneNumbers()));
            info.setUrls(new ArrayList<>(mongoInfo.getUrls()));
            info.setEmails(new ArrayList<>(mongoInfo.getEmails()));
            info.setSuspiciousKeywords(new ArrayList<>(mongoInfo.getSuspiciousKeywords()));
            evidence.setExtractedInfo(info);
        }

        return evidence;
    }

    /**
     * Merge extracted information
     */
    private boolean mergeExtractedInfo(ExtractedInfo target, ExtractedInfo source) {
        final boolean[] added = { false };

        source.getUpiIds().forEach(upi -> {
            if (!target.getUpiIds().contains(upi)) {
                target.getUpiIds().add(upi);
                added[0] = true;
            }
        });
        source.getPhoneNumbers().forEach(phone -> {
            if (!target.getPhoneNumbers().contains(phone)) {
                target.getPhoneNumbers().add(phone);
            }
        });
        source.getBankAccountNumbers().forEach(acc -> {
            if (!target.getBankAccountNumbers().contains(acc)) {
                target.getBankAccountNumbers().add(acc);
            }
        });
        source.getIfscCodes().forEach(ifsc -> {
            if (!target.getIfscCodes().contains(ifsc)) {
                target.getIfscCodes().add(ifsc);
            }
        });
        source.getUrls().forEach(url -> {
            if (!target.getUrls().contains(url)) {
                target.getUrls().add(url);
            }
        });
        source.getEmails().forEach(email -> {
            if (!target.getEmails().contains(email)) {
                target.getEmails().add(email);
                added[0] = true;
            }
        });

        return added[0];
    }

    /**
     * Evidence package for law enforcement
     * Enhanced with ensemble scoring information
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EvidencePackage {
        private String sessionId;
        private LocalDateTime firstContact;
        private LocalDateTime lastUpdated;
        private String scamType = "UNKNOWN";
        private double threatLevel = 0.0;

        // Ensemble scoring fields
        private String threatCategory = "SAFE"; // SAFE/LOW/MEDIUM/HIGH/CRITICAL
        private double confidence = 0.0; // Calibrated confidence (0.0-1.0)
        private int triggeredLayers = 0; // Number of detection layers triggered (0-5)
        private List<String> ensembleEvidence = new ArrayList<>(); // Top evidence descriptions

        private List<ConversationTurn> conversation = new ArrayList<>();
        private ExtractedInfo extractedInfo = new ExtractedInfo();

        public EvidencePackage(String sessionId) {
            this.sessionId = sessionId;
            this.firstContact = LocalDateTime.now();
            this.lastUpdated = LocalDateTime.now();
        }

        /**
         * Check if this evidence represents a high-threat case
         */
        public boolean isHighThreat() {
            return "HIGH".equals(threatCategory) || "CRITICAL".equals(threatCategory);
        }

        public boolean hasCriticalEvidence() {
            return !extractedInfo.getUpiIds().isEmpty() ||
                    !extractedInfo.getBankAccountNumbers().isEmpty() ||
                    !extractedInfo.getPhoneNumbers().isEmpty() ||
                    !extractedInfo.getUrls().isEmpty();
        }
    }

    /**
     * Single conversation turn
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ConversationTurn {
        private LocalDateTime timestamp;
        private String userMessage;
        private String assistantReply;
    }
}
