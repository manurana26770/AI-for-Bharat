package com.varutri.honeypot.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Map;

/**
 * Standardized API response wrapper.
 * All API endpoints should return this format for consistency.
 * 
 * Success Response:
 * {
 * "success": true,
 * "status": 200,
 * "message": "Request processed successfully",
 * "data": { ... },
 * "timestamp": "2024-01-15T10:30:00Z"
 * }
 * 
 * Error Response:
 * {
 * "success": false,
 * "status": 400,
 * "message": "Validation failed",
 * "error": {
 * "code": "VALIDATION_ERROR",
 * "details": "Message is required"
 * },
 * "timestamp": "2024-01-15T10:30:00Z"
 * }
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    @JsonProperty("success")
    private boolean success;

    @JsonProperty("status")
    private int status;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private T data;

    @JsonProperty("error")
    private ErrorDetails error;

    @JsonProperty("timestamp")
    private String timestamp;

    @JsonProperty("requestId")
    private String requestId;

    // ==================== SUCCESS BUILDERS ====================

    /**
     * Create a successful response with data
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .status(HttpStatus.OK.value())
                .message("Request processed successfully")
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a successful response with data and custom message
     */
    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .status(HttpStatus.OK.value())
                .message(message)
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a successful response with custom status code
     */
    public static <T> ApiResponse<T> success(T data, HttpStatus status, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .status(status.value())
                .message(message)
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 201 Created response
     */
    public static <T> ApiResponse<T> created(T data, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .status(HttpStatus.CREATED.value())
                .message(message)
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 202 Accepted response (for async operations)
     */
    public static <T> ApiResponse<T> accepted(T data, String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .status(HttpStatus.ACCEPTED.value())
                .message(message)
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }

    // ==================== ERROR BUILDERS ====================

    /**
     * Create a 400 Bad Request error
     */
    public static <T> ApiResponse<T> badRequest(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.BAD_REQUEST.value())
                .message("Bad request")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 401 Unauthorized error
     */
    public static <T> ApiResponse<T> unauthorized(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.UNAUTHORIZED.value())
                .message("Unauthorized")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 403 Forbidden error
     */
    public static <T> ApiResponse<T> forbidden(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.FORBIDDEN.value())
                .message("Forbidden")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 404 Not Found error
     */
    public static <T> ApiResponse<T> notFound(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.NOT_FOUND.value())
                .message("Resource not found")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 422 Unprocessable Entity error (validation errors)
     */
    public static <T> ApiResponse<T> validationError(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.UNPROCESSABLE_ENTITY.value())
                .message("Validation failed")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 429 Too Many Requests error
     */
    public static <T> ApiResponse<T> tooManyRequests(String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.TOO_MANY_REQUESTS.value())
                .message("Rate limit exceeded")
                .error(new ErrorDetails("RATE_LIMIT_EXCEEDED", details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 500 Internal Server Error
     */
    public static <T> ApiResponse<T> internalError(String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .message("Internal server error")
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Create a 503 Service Unavailable error
     */
    public static <T> ApiResponse<T> serviceUnavailable(String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                .message("Service temporarily unavailable")
                .error(new ErrorDetails("SERVICE_UNAVAILABLE", details))
                .timestamp(Instant.now().toString())
                .build();
    }

    /**
     * Generic error with custom status
     */
    public static <T> ApiResponse<T> error(HttpStatus status, String errorCode, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .status(status.value())
                .message(status.getReasonPhrase())
                .error(new ErrorDetails(errorCode, details))
                .timestamp(Instant.now().toString())
                .build();
    }

    // ==================== RESPONSE ENTITY HELPERS ====================

    /**
     * Convert to ResponseEntity with matching HTTP status
     */
    public ResponseEntity<ApiResponse<T>> toResponseEntity() {
        return ResponseEntity.status(this.status).body(this);
    }

    /**
     * Static helper to create ResponseEntity from success response
     */
    public static <T> ResponseEntity<ApiResponse<T>> ok(T data) {
        return ApiResponse.success(data).toResponseEntity();
    }

    /**
     * Static helper to create ResponseEntity from success response with message
     */
    public static <T> ResponseEntity<ApiResponse<T>> ok(T data, String message) {
        return ApiResponse.success(data, message).toResponseEntity();
    }

    // ==================== ERROR DETAILS DTO ====================

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ErrorDetails {
        @JsonProperty("code")
        private String code;

        @JsonProperty("details")
        private String details;

        @JsonProperty("field")
        private String field;

        @JsonProperty("metadata")
        private Map<String, Object> metadata;

        public ErrorDetails(String code, String details) {
            this.code = code;
            this.details = details;
        }

        public ErrorDetails(String code, String details, String field) {
            this.code = code;
            this.details = details;
            this.field = field;
        }
    }
}
