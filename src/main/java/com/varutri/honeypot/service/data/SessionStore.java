package com.varutri.honeypot.service.data;

import com.varutri.honeypot.dto.ChatRequest;
import com.varutri.honeypot.entity.SessionEntity;
import com.varutri.honeypot.repository.SessionRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session storage for tracking conversations
 * Now uses MongoDB for persistent storage with in-memory cache for performance
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionStore {

    private final SessionRepository sessionRepository;

    // In-memory cache for fast access (write-through to MongoDB)
    private final ConcurrentHashMap<String, SessionData> sessionCache = new ConcurrentHashMap<>();

    /**
     * Get or create session data
     */
    public SessionData getOrCreateSession(String sessionId) {
        // Check cache first
        SessionData cached = sessionCache.get(sessionId);
        if (cached != null) {
            return cached;
        }

        // Check MongoDB
        Optional<SessionEntity> existingEntity = sessionRepository.findBySessionId(sessionId);
        if (existingEntity.isPresent()) {
            SessionData sessionData = entityToSessionData(existingEntity.get());
            sessionCache.put(sessionId, sessionData);
            log.debug("Loaded session from MongoDB: {}", sessionId);
            return sessionData;
        }

        // Create new session
        log.info("Creating new session: {}", sessionId);
        SessionEntity newEntity = SessionEntity.builder()
                .sessionId(sessionId)
                .conversationHistory(new ArrayList<>())
                .turnCount(0)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        sessionRepository.save(newEntity);

        SessionData newSession = new SessionData(sessionId);
        sessionCache.put(sessionId, newSession);
        return newSession;
    }

    /**
     * Add message to conversation history
     */
    public void addMessage(String sessionId, String role, String content) {
        SessionData session = getOrCreateSession(sessionId);
        session.addMessage(role, content);

        // Persist to MongoDB
        persistSession(sessionId, session);

        log.debug("Added message to session {}: {} - {}", sessionId, role, content);
    }

    /**
     * Get conversation history
     */
    public List<ChatRequest.ConversationMessage> getConversationHistory(String sessionId) {
        return getOrCreateSession(sessionId).getConversationHistory();
    }

    /**
     * Get turn count for session
     */
    public int getTurnCount(String sessionId) {
        return getOrCreateSession(sessionId).getTurnCount();
    }

    /**
     * Check if session should trigger final callback
     */
    /**
     * Check if session should trigger final callback
     * Uses Dynamic Termination Strategy (Satuation Logic)
     */
    public boolean shouldTriggerCallback(String sessionId, int maxTurns, boolean isHighThreat,
            boolean hasCriticalEvidence) {
        SessionData session = getOrCreateSession(sessionId);
        int turnCount = session.getTurnCount();

        // 1. Safety Hard Limit (DoS Protection) -> Increased to 2x maxTurns for safety
        if (turnCount >= maxTurns * 2) {
            log.warn("Session {} hit hard safety limit of {} turns", sessionId, maxTurns * 2);
            return true;
        }

        // 2. Intelligence Saturation (The "Stale" Check)
        // If we have high threat + critical evidence + no new info for 5 turns -> STOP
        if (isHighThreat && hasCriticalEvidence && session.getConsecutiveTurnsWithoutIntel() >= 5) {
            log.info("Session {} saturated: High threat, critical evidence found, and 5 turns without new info",
                    sessionId);
            return true;
        }

        return false;
    }

    /**
     * Update intelligence tracking status
     */
    public void updateIntelligenceStatus(String sessionId, boolean hasNewIntel) {
        SessionData session = getOrCreateSession(sessionId);
        if (hasNewIntel) {
            session.setConsecutiveTurnsWithoutIntel(0);
            session.setLastIntelligenceTurn(session.getTurnCount());
        } else {
            session.setConsecutiveTurnsWithoutIntel(session.getConsecutiveTurnsWithoutIntel() + 1);
        }
        persistSession(sessionId, session);
    }

    /**
     * Clear session data (from both cache and MongoDB)
     */
    public void clearSession(String sessionId) {
        sessionCache.remove(sessionId);
        sessionRepository.deleteBySessionId(sessionId);
        log.info("Cleared session from cache and MongoDB: {}", sessionId);
    }

    /**
     * Get all messages as strings for intelligence extraction
     */
    public List<String> getAllMessages(String sessionId) {
        return getOrCreateSession(sessionId).getConversationHistory().stream()
                .map(ChatRequest.ConversationMessage::getText)
                .toList();
    }

    /**
     * Persist session to MongoDB
     */
    private void persistSession(String sessionId, SessionData sessionData) {
        try {
            SessionEntity entity = sessionRepository.findBySessionId(sessionId)
                    .orElse(SessionEntity.builder()
                            .sessionId(sessionId)
                            .createdAt(LocalDateTime.now())
                            .build());

            // Convert conversation history
            List<SessionEntity.ConversationMessage> mongoHistory = sessionData.getConversationHistory().stream()
                    .map(msg -> SessionEntity.ConversationMessage.builder()
                            .sender(msg.getSender())
                            .text(msg.getText())
                            .timestamp(msg.getTimestamp())
                            .build())
                    .toList();

            entity.setConversationHistory(mongoHistory);
            entity.setTurnCount(sessionData.getTurnCount());
            entity.setLastIntelligenceTurn(sessionData.getLastIntelligenceTurn());
            entity.setConsecutiveTurnsWithoutIntel(sessionData.getConsecutiveTurnsWithoutIntel());
            entity.setUpdatedAt(LocalDateTime.now());

            sessionRepository.save(entity);
            log.debug("Persisted session to MongoDB: {}", sessionId);
        } catch (Exception e) {
            log.error("Failed to persist session to MongoDB {}: {}", sessionId, e.getMessage());
            // Don't throw - we still have in-memory cache as fallback
        }
    }

    /**
     * Convert MongoDB entity to SessionData
     */
    private SessionData entityToSessionData(SessionEntity entity) {
        SessionData sessionData = new SessionData(entity.getSessionId());
        sessionData.setTurnCount(entity.getTurnCount());
        sessionData.setLastIntelligenceTurn(entity.getLastIntelligenceTurn());
        sessionData.setConsecutiveTurnsWithoutIntel(entity.getConsecutiveTurnsWithoutIntel());

        if (entity.getConversationHistory() != null) {
            List<ChatRequest.ConversationMessage> history = entity.getConversationHistory().stream()
                    .map(msg -> new ChatRequest.ConversationMessage(
                            msg.getSender(),
                            msg.getText(),
                            msg.getTimestamp()))
                    .toList();
            sessionData.setConversationHistory(new ArrayList<>(history));
        }

        return sessionData;
    }

    /**
     * Get total session count (from MongoDB)
     */
    public long getTotalSessionCount() {
        return sessionRepository.count();
    }

    @Data
    @AllArgsConstructor
    public static class SessionData {
        private String sessionId;
        private List<ChatRequest.ConversationMessage> conversationHistory;
        private int turnCount;
        private int lastIntelligenceTurn;
        private int consecutiveTurnsWithoutIntel;

        public SessionData(String sessionId) {
            this.sessionId = sessionId;
            this.conversationHistory = new ArrayList<>();
            this.turnCount = 0;
            this.lastIntelligenceTurn = 0;
            this.consecutiveTurnsWithoutIntel = 0;
        }

        public void addMessage(String sender, String text) {
            conversationHistory
                    .add(new ChatRequest.ConversationMessage(sender, text, System.currentTimeMillis()));
            if ("scammer".equals(sender) || "user".equals(sender)) {
                turnCount++;
            }
        }
    }
}
