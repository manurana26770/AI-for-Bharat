package com.varutri.honeypot.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.varutri.honeypot.service.security.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Filter that enforces rate limiting on API requests
 * Runs before ApiKeyFilter to block abusive requests early
 */
@Slf4j
@Component
@Order(1) // Run before ApiKeyFilter (which is Order(2))
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${rate.limit.enabled:true}")
    private boolean rateLimitEnabled;

    private static final String API_KEY_HEADER = "x-api-key";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Skip if rate limiting is disabled
        if (!rateLimitEnabled) {
            filterChain.doFilter(request, response);
            return;
        }

        // Skip rate limiting for health endpoints
        String path = request.getRequestURI();
        if (isExemptPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get client identifier (API key or IP)
        String clientId = getClientIdentifier(request);

        // Try to consume a token
        if (rateLimitService.tryConsume(clientId)) {
            // Add rate limit headers
            addRateLimitHeaders(response, clientId);

            // Allow request to proceed
            filterChain.doFilter(request, response);
        } else {
            // Rate limit exceeded - return 429
            handleRateLimitExceeded(response, clientId);
        }
    }

    /**
     * Get client identifier (prefer API key, fallback to IP)
     */
    private String getClientIdentifier(HttpServletRequest request) {
        // Try to get API key first
        String apiKey = request.getHeader(API_KEY_HEADER);
        if (apiKey != null && !apiKey.isBlank()) {
            return "key:" + apiKey;
        }

        // Fallback to IP address
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isBlank()) {
            // Get first IP in case of proxy chain
            ip = ip.split(",")[0].trim();
        } else {
            ip = request.getRemoteAddr();
        }
        return "ip:" + ip;
    }

    /**
     * Check if path is exempt from rate limiting
     */
    private boolean isExemptPath(String path) {
        return path.startsWith("/actuator") ||
                path.startsWith("/health") ||
                path.equals("/");
    }

    /**
     * Add rate limit headers to response
     */
    private void addRateLimitHeaders(HttpServletResponse response, String clientId) {
        long remaining = rateLimitService.getRemainingTokens(clientId);
        response.setHeader("X-RateLimit-Remaining", String.valueOf(remaining));
        response.setHeader("X-RateLimit-Limit", "60");
    }

    /**
     * Handle rate limit exceeded - return 429 Too Many Requests
     */
    private void handleRateLimitExceeded(HttpServletResponse response, String clientId) throws IOException {
        long retryAfter = rateLimitService.getSecondsUntilRefill(clientId);

        response.setStatus(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        response.setHeader("X-RateLimit-Remaining", "0");

        Map<String, Object> errorResponse = Map.of(
                "success", false,
                "error", "Rate limit exceeded",
                "message", "Too many requests. Please slow down and try again.",
                "retryAfter", retryAfter,
                "code", 429);

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

        log.warn("🚫 Rate limit response sent to client: {}",
                clientId.substring(0, Math.min(clientId.length(), 10)) + "...");
    }
}

