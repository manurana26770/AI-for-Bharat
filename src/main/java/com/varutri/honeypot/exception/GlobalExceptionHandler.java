package com.varutri.honeypot.exception;

import com.varutri.honeypot.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Global exception handler for consistent error responses.
 * All exceptions are transformed into standardized ApiResponse format.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handle validation errors from @Valid annotations
     * Returns 400 Bad Request with field-level error details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Map<String, String>>> handleValidationErrors(
            MethodArgumentNotValidException ex) {
        
        Map<String, String> fieldErrors = new HashMap<>();
        
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = error instanceof FieldError 
                    ? ((FieldError) error).getField() 
                    : error.getObjectName();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        log.warn("Validation failed: {}", fieldErrors);

        String errorDetails = fieldErrors.entrySet().stream()
                .map(e -> e.getKey() + ": " + e.getValue())
                .collect(Collectors.joining("; "));

        ApiResponse<Map<String, String>> response = ApiResponse.<Map<String, String>>builder()
                .success(false)
                .status(HttpStatus.BAD_REQUEST.value())
                .message("Validation failed")
                .data(fieldErrors)
                .error(new ApiResponse.ErrorDetails("VALIDATION_ERROR", errorDetails))
                .timestamp(java.time.Instant.now().toString())
                .build();

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle malformed JSON or unreadable request body
     * Returns 400 Bad Request
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponse<Void>> handleMalformedJson(HttpMessageNotReadableException ex) {
        log.warn("Malformed JSON request: {}", ex.getMessage());

        return ApiResponse.<Void>badRequest("INVALID_JSON", 
                "Invalid JSON format in request body").toResponseEntity();
    }

    /**
     * Handle security exceptions (sanitization failures)
     * Returns 400 Bad Request
     */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ApiResponse<Void>> handleSecurityException(SecurityException ex) {
        log.warn("Security exception: {}", ex.getMessage());

        return ApiResponse.<Void>badRequest("SECURITY_VIOLATION", 
                "Request rejected for security reasons").toResponseEntity();
    }

    /**
     * Handle IllegalArgumentException
     * Returns 400 Bad Request
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Illegal argument: {}", ex.getMessage());

        return ApiResponse.<Void>badRequest("INVALID_ARGUMENT", 
                ex.getMessage()).toResponseEntity();
    }

    /**
     * Handle method not supported (wrong HTTP method)
     * Returns 405 Method Not Allowed
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<Void>> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex) {
        log.warn("Method not supported: {}", ex.getMessage());

        String supportedMethods = ex.getSupportedHttpMethods() != null 
                ? ex.getSupportedHttpMethods().toString() 
                : "unknown";

        return ApiResponse.<Void>error(
                HttpStatus.METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "HTTP method '" + ex.getMethod() + "' not supported. Supported: " + supportedMethods
        ).toResponseEntity();
    }

    /**
     * Handle 404 Not Found
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleNotFound(NoHandlerFoundException ex) {
        log.warn("Endpoint not found: {}", ex.getRequestURL());

        return ApiResponse.<Void>notFound("ENDPOINT_NOT_FOUND", 
                "Endpoint not found: " + ex.getRequestURL()).toResponseEntity();
    }

    /**
     * Handle resource not found exceptions
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse<Void>> handleResourceNotFound(ResourceNotFoundException ex) {
        log.warn("Resource not found: {}", ex.getMessage());

        return ApiResponse.<Void>notFound("RESOURCE_NOT_FOUND", 
                ex.getMessage()).toResponseEntity();
    }

    /**
     * Handle rate limit exceeded
     */
    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiResponse<Void>> handleRateLimitExceeded(RateLimitExceededException ex) {
        log.warn("Rate limit exceeded: {}", ex.getMessage());

        return ApiResponse.<Void>tooManyRequests(ex.getMessage()).toResponseEntity();
    }

    /**
     * Handle LLM service failures
     */
    @ExceptionHandler(LLMServiceException.class)
    public ResponseEntity<ApiResponse<Void>> handleLLMServiceException(LLMServiceException ex) {
        log.error("LLM service failure: {}", ex.getMessage());

        return ApiResponse.<Void>serviceUnavailable(
                "AI service temporarily unavailable. Please try again.").toResponseEntity();
    }

    /**
     * Handle all other uncaught exceptions
     * Returns 500 Internal Server Error
     * Logs full stack trace but returns safe message to client
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage(), ex);

        return ApiResponse.<Void>internalError("INTERNAL_ERROR", 
                "An internal error occurred. Please try again later.").toResponseEntity();
    }
}
