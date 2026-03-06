package com.varutri.honeypot.service.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing rate limiting using Token Bucket algorithm
 * Each client (identified by API key or IP) gets their own bucket
 * Includes automatic cleanup of inactive clients to prevent memory leaks
 */
@Slf4j
@Service
public class RateLimitService {

    /**
     * Wrapper class to track bucket with last access time
     */
    private static class BucketWrapper {
        final Bucket bucket;
        volatile Instant lastAccess;

        BucketWrapper(Bucket bucket) {
            this.bucket = bucket;
            this.lastAccess = Instant.now();
        }

        void touch() {
            this.lastAccess = Instant.now();
        }

        boolean isExpired(Duration maxIdleTime) {
            return Instant.now().isAfter(lastAccess.plus(maxIdleTime));
        }
    }

    // Store buckets for each client with last access tracking
    private final Map<String, BucketWrapper> clientBuckets = new ConcurrentHashMap<>();

    @Value("${rate.limit.requests-per-minute:60}")
    private int requestsPerMinute;

    @Value("${rate.limit.burst-capacity:10}")
    private int burstCapacity;

    @Value("${rate.limit.cleanup-interval-minutes:60}")
    private int cleanupIntervalMinutes;

    @Value("${rate.limit.max-idle-minutes:30}")
    private int maxIdleMinutes;

    /**
     * Try to consume a token for the given client
     * 
     * @param clientId API key or IP address
     * @return true if request is allowed, false if rate limited
     */
    public boolean tryConsume(String clientId) {
        BucketWrapper wrapper = clientBuckets.computeIfAbsent(clientId, this::createNewBucketWrapper);
        wrapper.touch(); // Update last access time

        boolean consumed = wrapper.bucket.tryConsume(1);

        if (!consumed) {
            log.warn("🚫 Rate limit exceeded for client: {}", maskClientId(clientId));
        }

        return consumed;
    }

    /**
     * Get remaining tokens for a client
     */
    public long getRemainingTokens(String clientId) {
        BucketWrapper wrapper = clientBuckets.get(clientId);
        if (wrapper == null) {
            return requestsPerMinute;
        }
        return wrapper.bucket.getAvailableTokens();
    }

    /**
     * Get time until next token is available (in seconds)
     */
    public long getSecondsUntilRefill(String clientId) {
        BucketWrapper wrapper = clientBuckets.get(clientId);
        if (wrapper == null) {
            return 0;
        }

        // Estimate based on refill rate
        long availableTokens = wrapper.bucket.getAvailableTokens();
        if (availableTokens > 0) {
            return 0;
        }

        // Tokens refill over 1 minute
        return 60 / requestsPerMinute;
    }

    /**
     * Create a new bucket wrapper for a client with configured limits
     */
    private BucketWrapper createNewBucketWrapper(String clientId) {
        log.debug("Creating rate limit bucket for client: {}", maskClientId(clientId));

        // Using modern Bucket4j API - simple bandwidth with capacity and refill period
        // Allows 'requestsPerMinute' tokens, refilled completely every minute
        // Plus burst capacity for sudden spikes
        Bandwidth limit = Bandwidth.builder()
                .capacity(burstCapacity + requestsPerMinute)
                .refillGreedy(requestsPerMinute, Duration.ofMinutes(1))
                .build();

        Bucket bucket = Bucket.builder()
                .addLimit(limit)
                .build();

        return new BucketWrapper(bucket);
    }

    /**
     * Scheduled cleanup of inactive client buckets
     * Runs every hour by default (configurable via
     * rate.limit.cleanup-interval-minutes)
     * Removes buckets that haven't been accessed in maxIdleMinutes
     */
    @Scheduled(fixedRateString = "${rate.limit.cleanup-interval-ms:3600000}")
    public void cleanupInactiveBuckets() {
        if (clientBuckets.isEmpty()) {
            return;
        }

        int sizeBefore = clientBuckets.size();
        Duration maxIdleTime = Duration.ofMinutes(maxIdleMinutes);

        // Remove expired buckets
        clientBuckets.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().isExpired(maxIdleTime);
            if (expired) {
                log.debug("Removing expired rate limit bucket for: {}", maskClientId(entry.getKey()));
            }
            return expired;
        });

        int removed = sizeBefore - clientBuckets.size();
        if (removed > 0) {
            log.info("🧹 Rate limit cleanup: removed {} inactive buckets, {} remaining",
                    removed, clientBuckets.size());
        }
    }

    /**
     * Mask client ID for logging (security)
     */
    private String maskClientId(String clientId) {
        if (clientId == null || clientId.length() < 8) {
            return "***";
        }
        return clientId.substring(0, 4) + "****" + clientId.substring(clientId.length() - 4);
    }

    /**
     * Clear all buckets (for testing or reset)
     */
    public void clearAllBuckets() {
        clientBuckets.clear();
        log.info("Cleared all rate limit buckets");
    }

    /**
     * Get statistics about rate limiting
     */
    public Map<String, Object> getStatistics() {
        return Map.of(
                "totalClients", clientBuckets.size(),
                "requestsPerMinute", requestsPerMinute,
                "burstCapacity", burstCapacity,
                "maxIdleMinutes", maxIdleMinutes,
                "cleanupIntervalMinutes", cleanupIntervalMinutes);
    }
}

