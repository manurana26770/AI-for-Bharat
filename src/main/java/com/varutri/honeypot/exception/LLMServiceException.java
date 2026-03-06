package com.varutri.honeypot.exception;

/**
 * Exception thrown when LLM service fails (HuggingFace, Ollama, etc.).
 */
public class LLMServiceException extends RuntimeException {

    private final String provider;
    private final String model;

    public LLMServiceException(String message) {
        super(message);
        this.provider = null;
        this.model = null;
    }

    public LLMServiceException(String message, Throwable cause) {
        super(message, cause);
        this.provider = null;
        this.model = null;
    }

    public LLMServiceException(String provider, String model, String message) {
        super("LLM error [" + provider + "/" + model + "]: " + message);
        this.provider = provider;
        this.model = model;
    }

    public LLMServiceException(String provider, String model, String message, Throwable cause) {
        super("LLM error [" + provider + "/" + model + "]: " + message, cause);
        this.provider = provider;
        this.model = model;
    }

    public String getProvider() {
        return provider;
    }

    public String getModel() {
        return model;
    }
}
