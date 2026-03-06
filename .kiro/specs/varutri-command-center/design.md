# Design Document: Varutri Command Center

## 1. System Architecture

### 1.1 Technology Stack

- **Backend Framework**: Spring Boot 17 (Java)
- **Database**: MongoDB (for evidence and session storage)
- **LLM Providers**: 
  - HuggingFace API (Llama 3.3 70B)
  - Ollama (local deployment option)
- **External Integrations**: WhatsApp Business API, Government Reporting APIs

### 1.2 Architectural Layers

The system follows a layered architecture pattern:

1. **Presentation Layer**: REST Controllers exposing API endpoints
2. **Service Layer**: Business logic and orchestration
3. **Data Layer**: MongoDB repositories and data access
4. **Integration Layer**: External service clients (LLM, WhatsApp, Government APIs)

### 1.3 Core Components

#### 1.3.1 Controller Layer
- **HoneypotController**: Main chat API and threat assessment endpoints
- **PersonaController**: Persona management and configuration
- **WhatsAppController**: WhatsApp webhook integration
- **ReportController**: Government reporting endpoints

#### 1.3.2 Service Layer

**AI Services**:
- **EnsembleThreatScorer**: Multi-layer threat detection pipeline
- **InformationExtractor**: Intelligence extraction from messages
- **ScamDetector**: Scam type classification
- **TextNormalizer**: Text normalization and obfuscation detection
- **AdvancedPatternMatcher**: Fuzzy matching and phonetic analysis
- **SemanticScamAnalyzer**: Semantic analysis and intent detection
- **PromptHardeningService**: LLM prompt security
- **ResponseValidationService**: AI response validation

**LLM Services**:
- **PersonaService**: Persona profile management
- **HuggingFaceService**: HuggingFace API integration
- **OllamaService**: Ollama local LLM integration

**Core Services**:
- **GovernmentReportService**: Report generation and submission
- **CallbackService**: External callback handling
- **WhatsAppService**: WhatsApp message sending

**Data Services**:
- **SessionStore**: Conversation session management
- **EvidenceCollector**: Evidence aggregation and storage

**Security Services**:
- **InputSanitizer**: Input validation and sanitization
- **RateLimitService**: API rate limiting

#### 1.3.3 Data Layer
- **SessionRepository**: Session entity persistence
- **EvidenceRepository**: Evidence entity persistence
- **ScamReportRepository**: Report entity persistence

## 2. Component Design

### 2.1 Multi-Layer Threat Detection Pipeline

The threat detection system uses a five-layer ensemble approach:

**Layer 1: Text Normalization**
- Detects and converts leetspeak (h3ll0 → hello)
- Normalizes homoglyphs (Cyrillic 'а' → Latin 'a')
- Removes zero-width and invisible characters
- Normalizes whitespace and formatting
- Preserves original text for evidence

**Layer 2: Regex-Based Keyword Matching**
- Pattern matching for known scam indicators
- UPI ID detection: [digits]@[provider]
- Bank account and IFSC code detection
- Phone number extraction (Indian format)
- URL and email extraction
- Suspicious keyword identification

**Layer 3: Advanced Pattern Matching**
- Fuzzy string matching for near-matches
- Phonetic analysis for sound-alike variations
- N-gram analysis for partial matches
- Configurable similarity thresholds
- Levenshtein distance calculations

**Layer 4: Semantic ML Analysis**
- Semantic embeddings for contextual understanding
- Intent classification for manipulation tactics
- Urgency indicator detection
- Trust exploitation pattern recognition
- Financial solicitation detection

**Layer 5: AI Phishing Model**
- Sophisticated phishing attempt detection
- Context-aware threat assessment
- Advanced manipulation tactic identification

**Ensemble Scoring**:
- Weighted scoring based on layer reliability
- Confidence calibration to reduce false positives
- Conflict resolution when layers disagree
- Final threat level: 0.0-1.0 normalized score
- Confidence intervals for assessments
- Layer-specific contribution tracking

### 2.2 AI Persona Management

**Persona Profile Structure**:
- Name, age, occupation
- City, country, living status
- Tech-savviness level
- Personality traits
- Language style characteristics
- Example phrases
- Common typing mistakes

**Persona Engine**:
- Maintains configurable persona profiles
- Generates contextually appropriate responses
- Incorporates persona characteristics consistently
- Supports multiple LLM backends
- Dynamic configuration without restart

**Preset Personas**:
- Elderly Indian male (default: Rajesh Kumar)
- Elderly Indian female (Kamala Devi)
- Young American student (Mike Johnson)
- Elderly British (Margaret Thompson)

### 2.3 Intelligence Extraction

**Extraction Capabilities**:
- **Payment Information**: UPI IDs in format [digits]@[provider]
- **Banking Information**: Account numbers, IFSC codes
- **Contact Information**: Phone numbers (Indian format)
- **Web References**: URLs, email addresses
- **Scam Indicators**: Suspicious keywords, pattern indicators

**Intelligence Association**:
- All extracted intelligence linked to originating session
- Traceability for investigation purposes
- Real-time extraction during conversation

### 2.4 Evidence Collection and Storage

**Evidence Package Structure**:
- Session identifier
- Complete conversation history with timestamps
- Sender identification for each message
- Threat level scores per message
- Scam type classification
- Ensemble scoring results
- Confidence calibration data
- Extracted intelligence summary

**Storage Requirements**:
- Persistent MongoDB storage
- Data integrity enforcement
- Tamper prevention mechanisms
- Query by session identifier
- Filter by threat level threshold
- High-threat evidence retrieval

### 2.5 Session Management

**Session Lifecycle**:
- Unique session per conversation thread
- Turn counting and limits (default: 20 turns)
- Conversation history tracking
- Intelligence status updates
- Session clearing after callback

**Session Triggers**:
- Max turns reached
- High threat detected
- Critical evidence collected
- Manual callback request

### 2.6 LLM Integration

**Provider Support**:
- HuggingFace API (cloud-based)
- Ollama (local deployment)
- Configurable provider selection
- Fallback handling

**Asynchronous Processing**:
- Non-blocking response generation
- CompletableFuture-based async pipeline
- Parallel task execution
- Graceful degradation on failures

**Prompt Engineering**:
- System prompt generation with persona context
- Threat-aware prompt adaptation
- Prompt injection detection and prevention
- Response validation and filtering

### 2.7 Security Architecture

**Authentication**:
- API key-based authentication
- Endpoint-level security (except health checks)
- HTTP 401 on invalid authentication

**Input Validation**:
- Input sanitization for all user input
- Prompt injection detection
- SQL/NoSQL injection prevention
- XSS prevention

**Rate Limiting**:
- Request rate limiting per API key
- Abuse prevention
- DoS attack mitigation
- Request queuing on limit exceeded

**Session Security**:
- Secure session management
- Appropriate timeout policies
- Authentication failure logging

### 2.8 WhatsApp Integration

**Webhook Handling**:
- Meta webhook verification
- Message receipt confirmation
- Event processing

**Message Processing**:
- Text message extraction
- Button interaction handling
- Scam report detection
- Phone-to-session mapping

**User Notifications**:
- Takeover notifications
- Intelligence extraction alerts
- Confirmation messages
- Button-based interactions

**Session Tracking**:
- Separate session per WhatsApp conversation
- Phone number to session ID mapping
- Session status retrieval

### 2.9 Government Reporting

**Report Generation**:
- Automatic report creation on session completion
- Manual report triggering
- Evidence package aggregation
- Threat level assessment

**Report Structure**:
- Unique report identifier
- Session reference
- Extracted intelligence (UPI IDs, bank accounts, phone numbers, URLs)
- Threat level and scam type
- Conversation summary
- Timestamp and metadata

**Report Submission**:
- External API integration
- Callback mechanism support
- Confirmation tracking
- Report archival

**Report Retrieval**:
- Query by report ID
- List all archived reports
- Statistical aggregation

## 3. API Design

### 3.1 Chat API

**POST /api/chat**
- Asynchronous message processing
- Parallel intelligence extraction and threat assessment
- Persona-based response generation
- Evidence collection
- Automatic callback triggering

**Response Format**:
```
{
  "status": "success",
  "reply": "<persona_response>"
}
```

### 3.2 Threat Assessment API

**POST /api/assess**
- Synchronous threat assessment
- Comprehensive ensemble analysis
- Detailed layer-by-layer results
- Confidence calibration

**Response Format**:
```
{
  "status": "success",
  "data": {
    "threatLevel": "HIGH|MEDIUM|LOW",
    "ensembleScore": 0.0-1.0,
    "confidencePercent": 0-100,
    "scamType": "INVESTMENT|LOTTERY|...",
    "triggeredLayers": 0-5,
    "layerResults": [...]
  }
}
```

### 3.3 Evidence API

**GET /api/evidence/{sessionId}**
- Retrieve session-specific evidence
- Complete evidence package

**GET /api/evidence/high-threat**
- Retrieve high-risk evidence (threat >= 0.7)
- Filtered evidence list

**GET /api/evidence**
- Retrieve all evidence packages
- Complete evidence archive

### 3.4 Persona API

**GET /api/persona**
- Current persona details

**PUT /api/persona**
- Update persona profile

**POST /api/persona/reset**
- Reset to default persona

**GET /api/persona/presets**
- List available preset personas

**POST /api/persona/presets/{presetName}**
- Apply preset persona

### 3.5 WhatsApp API

**GET /api/whatsapp/webhook**
- Webhook verification (Meta requirement)

**POST /api/whatsapp/webhook**
- Receive WhatsApp messages
- Process and respond

**POST /api/whatsapp/takeover**
- Manual takeover initiation

**GET /api/whatsapp/session/{phone}**
- Session status retrieval

### 3.6 Reporting API

**POST /api/report/manual**
- Manual report generation and submission

**GET /api/report/{reportId}**
- Retrieve specific report

**GET /api/report/all**
- List all archived reports

**GET /api/report/stats**
- Report statistics and aggregation

### 3.7 Health API

**GET /api/health**
- System health status
- Database connectivity check
- LLM service availability check
- No authentication required

## 4. Data Models

### 4.1 Core Entities

**SessionEntity**:
- Session ID (unique identifier)
- Conversation messages (list)
- Turn count
- Intelligence status
- Creation and update timestamps

**EvidenceEntity**:
- Session ID reference
- Extracted intelligence
- Threat level
- Scam type
- Conversation history
- Ensemble scoring data
- Timestamps

**ScamReportEntity**:
- Report ID (unique identifier)
- Session ID reference
- Extracted intelligence lists
- Threat level
- Scam type
- Report status
- Submission timestamp

### 4.2 DTOs

**ChatRequest**:
- Session ID
- Message (sender, text, timestamp)
- Conversation history
- Metadata

**ChatResponse**:
- Reply text
- (Internal: session ID, threat level, scam type)

**ThreatAssessmentResponse**:
- Threat level category
- Ensemble score
- Confidence percentage
- Scam type
- Triggered layers count
- Layer-specific results

**ExtractedInfo**:
- UPI IDs
- Bank account numbers
- IFSC codes
- Phone numbers
- URLs
- Email addresses
- Suspicious keywords

**PersonaProfile**:
- Name, age, occupation
- City, country, living status
- Tech level
- Personality traits
- Language style
- Example phrases
- Common mistakes

## 5. Configuration Management

### 5.1 Configuration Sources
- Environment variables
- Application properties files
- External configuration files

### 5.2 Configurable Parameters

**LLM Configuration**:
- Provider selection (huggingface/ollama)
- API keys and endpoints
- Model selection
- Timeout settings

**Security Configuration**:
- API keys
- Rate limiting thresholds
- Session timeout policies

**Threat Detection Configuration**:
- Sensitivity levels
- Layer weights
- Confidence thresholds

**Database Configuration**:
- MongoDB connection parameters
- Connection pooling settings

**Session Configuration**:
- Max turns per session
- Callback triggers

**WhatsApp Configuration**:
- Webhook verification token
- API credentials

### 5.3 Startup Validation
- Configuration validation on startup
- Clear error messages on invalid configuration
- Fail-fast behavior

## 6. Performance and Scalability

### 6.1 Asynchronous Processing
- CompletableFuture-based async pipeline
- Non-blocking chat endpoint
- Parallel intelligence extraction and threat assessment
- Background callback processing

### 6.2 Concurrent Processing
- Multiple session support
- Thread-safe session management
- Concurrent evidence collection

### 6.3 Database Optimization
- Connection pooling
- Indexed queries
- Efficient data retrieval

### 6.4 Horizontal Scaling
- Stateless API design
- Session data in MongoDB (shared state)
- Load balancer compatible

### 6.5 Degraded Mode Support
- Graceful handling of database failures
- LLM service fallback
- Continued operation with reduced functionality

## 7. Error Handling

### 7.1 Exception Hierarchy
- **ResourceNotFoundException**: 404 responses
- **RateLimitExceededException**: 429 responses
- **LLMServiceException**: 503 responses
- **GlobalExceptionHandler**: Centralized error handling

### 7.2 Error Response Format
```
{
  "status": "error",
  "message": "<error_description>",
  "errorCode": "<ERROR_CODE>"
}
```

### 7.3 Logging Strategy
- Structured logging with SLF4J
- Log levels: INFO, WARN, ERROR
- Security event logging
- Performance metrics logging

## 8. Testing Strategy

### 8.1 Unit Testing
- Service layer unit tests
- Mock external dependencies
- Test individual components

### 8.2 Integration Testing
- Controller integration tests
- Database integration tests
- LLM service integration tests

### 8.3 Property-Based Testing
- Threat detection property tests
- Intelligence extraction property tests
- Input validation property tests

### 8.4 Simulation Testing
- ScamSimulator for scenario testing
- End-to-end conversation simulation
- Intelligence extraction validation

## 9. Deployment Considerations

### 9.1 Environment Requirements
- Java 17 runtime
- MongoDB instance
- Network access to LLM providers
- WhatsApp Business API access

### 9.2 Configuration Management
- Environment-specific configuration
- Secrets management
- Configuration validation

### 9.3 Monitoring and Observability
- Health check endpoint
- Application metrics
- Log aggregation
- Alert configuration

### 9.4 Scaling Strategy
- Horizontal scaling with load balancer
- MongoDB replica set for high availability
- Rate limiting per instance

## 10. Security Considerations

### 10.1 Data Protection
- Sensitive data encryption at rest
- Secure transmission (HTTPS)
- PII handling compliance

### 10.2 Access Control
- API key authentication
- Role-based access (future enhancement)
- Audit logging

### 10.3 Input Validation
- Comprehensive input sanitization
- Injection attack prevention
- Prompt injection detection

### 10.4 Rate Limiting
- Per-API-key rate limits
- Global rate limits
- DDoS protection

## 11. Future Enhancements

### 11.1 Advanced Analytics
- Scam trend analysis
- Intelligence correlation
- Predictive threat modeling

### 11.2 Multi-Channel Support
- Telegram integration
- Email integration
- SMS integration

### 11.3 Enhanced Reporting
- Automated report scheduling
- Multi-agency reporting
- Report templates

### 11.4 Machine Learning Improvements
- Custom ML model training
- Adaptive threat detection
- Persona learning from interactions

## 12. Correctness Properties

### 12.1 Threat Detection Properties

**Property 1.1: Normalization Idempotence**
- **Validates**: Requirements 2.2, 14.1-14.4
- **Property**: Normalizing text twice produces the same result as normalizing once
- **Formal**: ∀ text: normalize(normalize(text)) = normalize(text)

**Property 1.2: Threat Score Bounds**
- **Validates**: Requirements 2.8, 13.5
- **Property**: All threat scores are within valid range [0.0, 1.0]
- **Formal**: ∀ message: 0.0 ≤ assessThreat(message).ensembleScore ≤ 1.0

**Property 1.3: Layer Monotonicity**
- **Validates**: Requirements 2.1, 13.1
- **Property**: Adding more triggered layers never decreases threat score
- **Formal**: ∀ message: triggeredLayers(message) ≥ n ⇒ threatScore(message) ≥ baseline

**Property 1.4: High Threat Consistency**
- **Validates**: Requirements 2.7, 13.5
- **Property**: Messages classified as HIGH threat have ensemble score ≥ 0.7
- **Formal**: ∀ message: threatLevel(message) = "HIGH" ⇒ ensembleScore(message) ≥ 0.7

### 12.2 Intelligence Extraction Properties

**Property 2.1: UPI ID Format Validity**
- **Validates**: Requirements 3.1
- **Property**: All extracted UPI IDs match the format [digits]@[provider]
- **Formal**: ∀ upiId ∈ extractedUPIs(message): upiId matches /\d+@[\w]+/

**Property 2.2: Extraction Completeness**
- **Validates**: Requirements 3.1-3.5
- **Property**: All valid intelligence patterns in message are extracted
- **Formal**: ∀ pattern ∈ message: isValid(pattern) ⇒ pattern ∈ extractedInfo(message)

**Property 2.3: No False Extractions**
- **Validates**: Requirements 3.1-3.5
- **Property**: Extracted intelligence items are actually present in the message
- **Formal**: ∀ item ∈ extractedInfo(message): item ⊆ message

### 12.3 Session Management Properties

**Property 3.1: Session Uniqueness**
- **Validates**: Requirements 4.1, 4.5
- **Property**: Each session ID is unique across all sessions
- **Formal**: ∀ session1, session2: session1 ≠ session2 ⇒ session1.id ≠ session2.id

**Property 3.2: Message Ordering**
- **Validates**: Requirements 4.1
- **Property**: Messages in a session are ordered by timestamp
- **Formal**: ∀ i, j in session.messages: i < j ⇒ timestamp(i) ≤ timestamp(j)

**Property 3.3: Turn Count Accuracy**
- **Validates**: Requirements 9.2
- **Property**: Turn count equals the number of user-assistant message pairs
- **Formal**: ∀ session: turnCount(session) = count(userMessages(session))

### 12.4 Evidence Storage Properties

**Property 4.1: Evidence Persistence**
- **Validates**: Requirements 4.1, 4.7
- **Property**: Stored evidence can be retrieved without modification
- **Formal**: ∀ evidence: retrieve(store(evidence)) = evidence

**Property 4.2: Session-Evidence Association**
- **Validates**: Requirements 3.6, 4.5
- **Property**: Evidence is correctly associated with its originating session
- **Formal**: ∀ evidence: evidence.sessionId ∈ activeSessions

**Property 4.3: High Threat Filtering**
- **Validates**: Requirements 4.6
- **Property**: High threat query returns only evidence with threat ≥ 0.7
- **Formal**: ∀ evidence ∈ getHighThreatEvidence(): evidence.threatLevel ≥ 0.7

### 12.5 API Security Properties

**Property 5.1: Authentication Enforcement**
- **Validates**: Requirements 8.1, 8.2
- **Property**: Protected endpoints reject requests without valid API key
- **Formal**: ∀ request to protectedEndpoint: !hasValidApiKey(request) ⇒ response.status = 401

**Property 5.2: Rate Limit Compliance**
- **Validates**: Requirements 8.3, 9.6
- **Property**: Requests exceeding rate limit are queued or rejected
- **Formal**: ∀ apiKey: requestCount(apiKey, timeWindow) > limit ⇒ request queued or rejected

**Property 5.3: Input Sanitization**
- **Validates**: Requirements 8.4, 8.5
- **Property**: All user input is sanitized before processing
- **Formal**: ∀ input: process(input) = process(sanitize(input))

### 12.6 Persona Consistency Properties

**Property 6.1: Persona Attribute Preservation**
- **Validates**: Requirements 1.1, 1.4
- **Property**: Persona characteristics remain consistent across responses
- **Formal**: ∀ response in session: extractPersonaTraits(response) ⊆ currentPersona.traits

**Property 6.2: Dynamic Configuration**
- **Validates**: Requirements 1.5
- **Property**: Persona updates take effect immediately without restart
- **Formal**: ∀ update: updatePersona(newPersona) ⇒ nextResponse uses newPersona

### 12.7 Scam Classification Properties

**Property 7.1: Classification Completeness**
- **Validates**: Requirements 10.1-10.6
- **Property**: Every detected threat is assigned a scam type
- **Formal**: ∀ message: threatLevel(message) > 0.5 ⇒ scamType(message) ∈ validScamTypes

**Property 7.2: Most Specific Classification**
- **Validates**: Requirements 10.7
- **Property**: Multi-category scams are assigned the most specific type
- **Formal**: ∀ message: matches(message, [type1, type2]) ⇒ scamType(message) = mostSpecific([type1, type2])

### 12.8 Asynchronous Processing Properties

**Property 8.1: Non-Blocking Chat**
- **Validates**: Requirements 9.1
- **Property**: Chat endpoint returns CompletableFuture immediately
- **Formal**: ∀ request: responseTime(chat(request)) < blockingThreshold

**Property 8.2: Parallel Task Completion**
- **Validates**: Requirements 9.2
- **Property**: Intelligence extraction and threat assessment complete independently
- **Formal**: ∀ message: extractionFuture(message) ∥ assessmentFuture(message)

### 12.9 WhatsApp Integration Properties

**Property 9.1: Webhook Verification**
- **Validates**: Requirements 6.1
- **Property**: Webhook verification succeeds only with correct token
- **Formal**: ∀ request: verifyWebhook(request) = true ⇔ request.token = configuredToken

**Property 9.2: Session Isolation**
- **Validates**: Requirements 6.4
- **Property**: Each WhatsApp phone number has a unique session
- **Formal**: ∀ phone1, phone2: phone1 ≠ phone2 ⇒ session(phone1) ≠ session(phone2)

### 12.10 Reporting Properties

**Property 10.1: Report Completeness**
- **Validates**: Requirements 7.2, 7.3
- **Property**: Reports contain all extracted intelligence from the session
- **Formal**: ∀ session: extractedInfo(report(session)) = extractedInfo(evidence(session))

**Property 10.2: Report Uniqueness**
- **Validates**: Requirements 7.5
- **Property**: Each report has a unique identifier
- **Formal**: ∀ report1, report2: report1 ≠ report2 ⇒ report1.id ≠ report2.id

## 13. Testing Framework

### 13.1 Property-Based Testing Framework
- **Framework**: JUnit 5 + jqwik (Java property-based testing)
- **Test Organization**: Co-located with source files using `.test.java` suffix
- **Annotation Format**: `// Validates: Requirements X.Y`

### 13.2 Test Generators
- **Message Generator**: Generates realistic scam messages with varying obfuscation
- **UPI ID Generator**: Generates valid and invalid UPI ID formats
- **Session Generator**: Generates conversation sessions with varying lengths
- **Persona Generator**: Generates persona profiles with valid attributes

### 13.3 Test Execution
- **Unit Tests**: Run on every build
- **Property Tests**: Run with configurable iteration count (default: 100)
- **Integration Tests**: Run in CI/CD pipeline
- **Simulation Tests**: Run for end-to-end validation

## 14. Compliance and Legal

### 14.1 Data Retention
- Evidence retention policy
- Automatic cleanup after reporting
- Compliance with data protection regulations

### 14.2 Government Reporting
- Mandatory reporting thresholds
- Report format compliance
- Submission confirmation tracking

### 14.3 Privacy Considerations
- Scammer data handling
- User data protection (WhatsApp integration)
- Data anonymization for analytics
