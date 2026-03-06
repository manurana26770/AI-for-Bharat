package com.varutri.honeypot.exception;

/**
 * Exception thrown when rate limits are exceeded.
 */
public class RateLimitExceededException extends RuntimeException {

    private final int limit;
    private final int windowSeconds;

    public RateLimitExceededException(String message) {
        super(message);
        this.limit = 0;
        this.windowSeconds = 0;
    }

    public RateLimitExceededException(int limit, int windowSeconds) {
        super("Rate limit exceeded: " + limit + " requests per " + windowSeconds + " seconds");
        this.limit = limit;
        this.windowSeconds = windowSeconds;
    }

    public int getLimit() {
        return limit;
    }

    public int getWindowSeconds() {
        return windowSeconds;
    }
}
