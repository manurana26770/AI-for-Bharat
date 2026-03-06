package com.varutri.honeypot.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Security filter to validate API key in request headers
 * Runs after RateLimitFilter (Order 1)
 */
@Slf4j
@Component
@Order(2) // Run after RateLimitFilter (which is Order 1)
public class ApiKeyFilter extends OncePerRequestFilter {

    @Value("${varutri.api-key}")
    private String validApiKey;

    private static final String API_KEY_HEADER = "x-api-key";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String requestApiKey = request.getHeader(API_KEY_HEADER);

        // Allow health check endpoint without API key
        if (request.getRequestURI().contains("/actuator") ||
                request.getRequestURI().contains("/health")) {
            filterChain.doFilter(request, response);
            return;
        }

        if (requestApiKey == null || requestApiKey.isEmpty()) {
            log.warn("Missing API key in request from IP: {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"error\",\"reply\":\"Missing API key\"}");
            return;
        }

        // Use constant-time comparison to prevent timing attacks
        if (!java.security.MessageDigest.isEqual(
                validApiKey.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                requestApiKey.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {

            log.warn("Invalid API key attempt from IP: {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"error\",\"reply\":\"Invalid API key\"}");
            return;
        }

        log.debug("API key validated successfully");
        filterChain.doFilter(request, response);
    }
}
