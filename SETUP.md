# Varutri Honeypot - Setup & Deployment Guide

##  Quick Start

### 1. Prerequisites Check
```bash
# Verify Java 17+
java -version

# Verify Maven
mvn -version

# Verify Ollama is installed
ollama --version
```

### 2. Start Ollama
```bash
# Start Ollama service
ollama serve

# In another terminal, pull Llama 3
ollama pull llama3

# Test Ollama
curl -X POST http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3","prompt":"Test","stream":false}'
```

### 3. Run the Application
```bash
# Build the project
mvn clean install

# Run Spring Boot app
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

### 4. Test the API
```bash
curl -X POST http://localhost:8080/api/chat \
  -H "x-api-key: varutri_shield_2026" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-001",
    "message": "Hello, I have a special offer for you",
    "conversationHistory": []
  }'
```

## 🌐 Deploy with ngrok

For buildathon integration:

```bash
# Install ngrok (if not installed)
brew install ngrok

# Start ngrok tunnel
ngrok http 8080
```

Copy the `https://` URL and provide it to the GUVI Mock Scammer API.

## 🧪 Run Tests

```bash
# Run all tests
mvn test

# Run specific test
mvn test -Dtest=IntelligenceExtractorTest
```

##  Monitor Logs

The application logs all important events:
- 📩 Incoming messages
-  Detected intelligence (UPI, accounts, URLs)
-  Successful responses
-  Final callbacks sent

Check console output for real-time monitoring.

## 🔧 Configuration

Edit `src/main/resources/application.properties`:

- **API Key**: Change `varutri.api-key`
- **Max Turns**: Adjust `varutri.session.max-turns`
- **Ollama Model**: Change `ollama.model` (llama3, mistral, etc.)

## 📝 Important Notes

1. **Ollama Must Be Running**: The application will fail if Ollama is not accessible
2. **API Key Required**: All requests must include `x-api-key` header
3. **Session Management**: Sessions auto-clear after sending final callback
4. **Intelligence Logging**: Check logs for detected UPI IDs, accounts, and URLs

## 🏆 Buildathon Success Checklist

-  API responds with correct JSON format
-  API key validation works
-  Persona-driven conversations
-  Intelligence extraction (UPI/Bank/URLs)
-  Final callback to GUVI API
-  Session tracking and turn counting
-  Comprehensive logging

##  Troubleshooting

### Ollama Connection Failed
```bash
# Check if Ollama is running
curl http://localhost:11434/api/generate

# Restart Ollama
killall ollama
ollama serve
```

### Port 8080 Already in Use
```properties
# Change port in application.properties
server.port=8081
```

### Maven Build Fails
```bash
# Clean and retry
mvn clean
mvn install -U
```

## 📞 Support

For buildathon support, contact the team lead or check project issues on GitHub.
