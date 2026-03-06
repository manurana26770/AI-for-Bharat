# Requirements Document: Varutri AI-Powered Active Defense & Threat Intelligence Ecosystem

## Introduction

Varutri is an AI-Powered Active Defense & Threat Intelligence Ecosystem that transforms cybersecurity from passive blocking to active engagement. Unlike traditional tools that only block attacks, Varutri invites and engages scammers through hyper-realistic AI personas acting as sophisticated digital decoys (Honeypots). The system wastes scammers' time, depletes their resources, and extracts valuable intelligence about their tactics, payment methods, and infrastructure.

### Problem Statement

1. **Rapid Evolution**: Scammers evolve faster than static filters (e.g., new UPI refund scams, AI voice cloning)
2. **Passive Defense Limitations**: Traditional blocking isn't enough; we need to understand the intent and methodology of attackers
3. **Resource Asymmetry**: Scammers jeopardize millions with low effort. We need to increase the cost of their attacks

### Solution

Varutri Command Center provides:
- **Defensive Deception**: An autonomous system that fights back by engaging scammers in endless, realistic conversations
- **Holistic Intelligence**: Combines real-time engagement data with web-scraped trend analysis
- **Situational Awareness**: A unified dashboard for monitoring active threats and global scam metrics

## Glossary

- **Varutri_System**: The complete AI-powered active defense and threat intelligence ecosystem
- **Persona_Engine**: The AI service that generates and manages realistic conversational personas
- **Threat_Detector**: The multi-layer threat detection pipeline that analyzes messages for scam indicators
- **Intelligence_Extractor**: The component that identifies and extracts actionable intelligence (UPI IDs, phone numbers, URLs, etc.)
- **Evidence_Store**: MongoDB-based persistent storage for conversation history and threat intelligence
- **Ensemble_Scorer**: The unified threat assessment system that combines all detection layers
- **Session**: A unique conversation thread between a persona and a potential scammer
- **Threat_Level**: A normalized score (0.0-1.0) indicating the likelihood of malicious intent
- **LLM**: Large Language Model used for persona generation (HuggingFace Llama 3.3 70B or Ollama)
- **UPI_ID**: Unified Payments Interface identifier used in Indian digital payments
- **IFSC_Code**: Indian Financial System Code for bank identification
- **Scam_Type**: Classification of scam methodology (INVESTMENT, LOTTERY, TECH_SUPPORT, PHISHING, JOB_SCAM)

## Requirements

### Requirement 1: AI Persona Management

**User Story:** As a cybersecurity defender, I want the system to generate and maintain realistic AI personas, so that scammers believe they are interacting with real victims and continue engaging.

#### Acceptance Criteria

1. THE Persona_Engine SHALL maintain configurable persona profiles with name, age, occupation, personality traits, language style, and tech-savviness level
2. WHEN a new conversation session starts, THE Persona_Engine SHALL generate contextually appropriate responses using the configured LLM
3. THE Persona_Engine SHALL support multiple LLM backends including HuggingFace API and Ollama
4. WHEN generating responses, THE Persona_Engine SHALL incorporate persona characteristics to maintain consistent personality and behavior patterns
5. THE Persona_Engine SHALL support dynamic persona configuration without requiring system restart

### Requirement 2: Multi-Layer Threat Detection Pipeline

**User Story:** As a threat analyst, I want the system to detect scam attempts through multiple detection layers, so that we can identify threats with high accuracy and low false positives.

#### Acceptance Criteria

1. WHEN a message is received, THE Threat_Detector SHALL process it through five sequential detection layers
2. THE Threat_Detector SHALL normalize text in Layer 1 by detecting and converting leetspeak, homoglyphs, and obfuscation techniques
3. THE Threat_Detector SHALL apply regex-based keyword matching in Layer 2 to identify known scam patterns
4. THE Threat_Detector SHALL perform advanced pattern matching in Layer 3 using fuzzy matching, phonetic analysis, and n-gram detection
5. THE Threat_Detector SHALL conduct semantic ML analysis in Layer 4 using embeddings, intent classification, and manipulation tactic detection
6. THE Threat_Detector SHALL apply AI phishing model detection in Layer 5 to identify sophisticated phishing attempts
7. THE Ensemble_Scorer SHALL combine results from all five layers to produce a unified threat assessment with calibrated confidence scores
8. WHEN threat detection completes, THE Varutri_System SHALL return a Threat_Level score between 0.0 and 1.0

### Requirement 3: Intelligence Extraction

**User Story:** As a law enforcement officer, I want the system to automatically extract actionable intelligence from scammer conversations, so that I can identify and track malicious actors.

#### Acceptance Criteria

1. WHEN a message contains payment information, THE Intelligence_Extractor SHALL identify and extract UPI IDs in the format [digits]@[provider]
2. WHEN a message contains banking information, THE Intelligence_Extractor SHALL extract bank account numbers and IFSC_Code values
3. WHEN a message contains contact information, THE Intelligence_Extractor SHALL extract phone numbers in Indian format
4. WHEN a message contains web references, THE Intelligence_Extractor SHALL extract URLs and email addresses
5. THE Intelligence_Extractor SHALL identify and extract suspicious keywords and scam pattern indicators
6. THE Intelligence_Extractor SHALL associate all extracted intelligence with the originating Session for traceability

### Requirement 4: Evidence Collection and Storage

**User Story:** As a cybersecurity investigator, I want the system to persistently store all conversation history and threat intelligence, so that I can analyze patterns and build cases against scammers.

#### Acceptance Criteria

1. THE Evidence_Store SHALL persist all conversation messages with timestamps, sender identification, and Session association
2. WHEN threat analysis completes, THE Evidence_Store SHALL store the calculated Threat_Level for each message
3. THE Evidence_Store SHALL classify and store the Scam_Type for each detected threat
4. THE Evidence_Store SHALL store ensemble scoring results with confidence calibration data
5. THE Evidence_Store SHALL support querying evidence by Session identifier
6. THE Evidence_Store SHALL support filtering evidence by Threat_Level threshold
7. WHEN evidence is stored, THE Varutri_System SHALL ensure data integrity and prevent tampering

### Requirement 5: RESTful API Integration

**User Story:** As a system integrator, I want the system to provide a secure RESTful API, so that I can integrate Varutri with external platforms and services.

#### Acceptance Criteria

1. THE Varutri_System SHALL expose a POST endpoint at /api/chat for asynchronous message processing
2. THE Varutri_System SHALL expose a POST endpoint at /api/assess for synchronous threat assessment
3. THE Varutri_System SHALL expose a GET endpoint at /api/health for system health monitoring
4. THE Varutri_System SHALL expose a GET endpoint at /api/evidence/{sessionId} for retrieving session-specific evidence
5. THE Varutri_System SHALL expose a GET endpoint at /api/evidence/high-threat for retrieving high-risk evidence
6. WHEN an API request is received, THE Varutri_System SHALL validate the API key before processing
7. WHEN an API request is invalid, THE Varutri_System SHALL return appropriate HTTP status codes and error messages
8. THE Varutri_System SHALL process chat requests asynchronously to prevent blocking

### Requirement 6: WhatsApp Integration

**User Story:** As a platform operator, I want the system to integrate with WhatsApp, so that we can engage scammers on their preferred communication channel.

#### Acceptance Criteria

1. THE Varutri_System SHALL expose a POST endpoint at /api/whatsapp/webhook for receiving WhatsApp messages
2. WHEN a WhatsApp message is received, THE Varutri_System SHALL extract the message content and sender information
3. WHEN a WhatsApp message is processed, THE Varutri_System SHALL generate a persona-based response
4. THE Varutri_System SHALL maintain separate Session tracking for each WhatsApp conversation
5. WHEN responding to WhatsApp messages, THE Varutri_System SHALL format responses according to WhatsApp API requirements

### Requirement 7: Government Reporting

**User Story:** As a compliance officer, I want the system to support manual reporting to government authorities, so that we can fulfill legal obligations and support law enforcement.

#### Acceptance Criteria

1. THE Varutri_System SHALL expose a POST endpoint at /api/report/manual for submitting manual reports
2. WHEN a manual report is submitted, THE Varutri_System SHALL validate the report content and format
3. THE Varutri_System SHALL associate manual reports with relevant Session and evidence data
4. THE Varutri_System SHALL support callback mechanisms for external reporting systems
5. WHEN a report is successfully submitted, THE Varutri_System SHALL return confirmation with report identifier

### Requirement 8: Security and Authentication

**User Story:** As a security administrator, I want the system to enforce strong authentication and security controls, so that only authorized users can access the API and sensitive data.

#### Acceptance Criteria

1. THE Varutri_System SHALL require API key authentication for all API endpoints except health checks
2. WHEN an API request lacks valid authentication, THE Varutri_System SHALL reject the request with HTTP 401 status
3. THE Varutri_System SHALL implement rate limiting to prevent abuse and denial-of-service attacks
4. WHEN input is received, THE Varutri_System SHALL sanitize and validate all user input to prevent injection attacks
5. THE Varutri_System SHALL detect and reject prompt injection attempts in LLM interactions
6. THE Varutri_System SHALL maintain secure session management with appropriate timeout policies
7. THE Varutri_System SHALL log all authentication failures for security monitoring

### Requirement 9: Performance and Scalability

**User Story:** As a system operator, I want the system to handle high message volumes efficiently, so that we can engage multiple scammers simultaneously without degradation.

#### Acceptance Criteria

1. WHEN processing chat requests, THE Varutri_System SHALL handle requests asynchronously to prevent blocking
2. THE Varutri_System SHALL support concurrent processing of multiple Session conversations
3. WHEN under load, THE Varutri_System SHALL maintain response times within acceptable thresholds
4. THE Varutri_System SHALL implement connection pooling for database operations
5. THE Varutri_System SHALL support horizontal scaling through stateless API design
6. WHEN rate limits are exceeded, THE Varutri_System SHALL queue requests rather than rejecting them

### Requirement 10: Scam Type Classification

**User Story:** As a threat analyst, I want the system to automatically classify scam types, so that I can understand attack patterns and trends.

#### Acceptance Criteria

1. WHEN a threat is detected, THE Varutri_System SHALL classify it into one of the defined Scam_Type categories
2. THE Varutri_System SHALL support classification of INVESTMENT scams
3. THE Varutri_System SHALL support classification of LOTTERY scams
4. THE Varutri_System SHALL support classification of TECH_SUPPORT scams
5. THE Varutri_System SHALL support classification of PHISHING scams
6. THE Varutri_System SHALL support classification of JOB_SCAM attempts
7. WHEN a scam matches multiple categories, THE Varutri_System SHALL assign the most specific applicable Scam_Type

### Requirement 11: System Health Monitoring

**User Story:** As a DevOps engineer, I want the system to provide health status information, so that I can monitor system availability and diagnose issues.

#### Acceptance Criteria

1. THE Varutri_System SHALL expose a GET endpoint at /api/health that returns system health status
2. WHEN the health endpoint is queried, THE Varutri_System SHALL verify database connectivity
3. WHEN the health endpoint is queried, THE Varutri_System SHALL verify LLM service availability
4. WHEN all components are operational, THE Varutri_System SHALL return HTTP 200 status
5. WHEN any critical component is unavailable, THE Varutri_System SHALL return HTTP 503 status with component details
6. THE Varutri_System SHALL not require authentication for health check endpoints

### Requirement 12: Configuration Management

**User Story:** As a system administrator, I want the system to support external configuration, so that I can adjust behavior without code changes.

#### Acceptance Criteria

1. THE Varutri_System SHALL load configuration from external sources (environment variables, configuration files)
2. THE Varutri_System SHALL support configuration of LLM provider selection (HuggingFace or Ollama)
3. THE Varutri_System SHALL support configuration of API keys and authentication credentials
4. THE Varutri_System SHALL support configuration of rate limiting thresholds
5. THE Varutri_System SHALL support configuration of threat detection sensitivity levels
6. THE Varutri_System SHALL support configuration of MongoDB connection parameters
7. WHEN configuration is invalid, THE Varutri_System SHALL fail startup with clear error messages

### Requirement 13: Ensemble Threat Scoring

**User Story:** As a threat analyst, I want the system to provide unified threat scores with confidence calibration, so that I can prioritize high-confidence threats.

#### Acceptance Criteria

1. THE Ensemble_Scorer SHALL combine threat scores from all five detection layers
2. THE Ensemble_Scorer SHALL apply weighted scoring based on layer reliability
3. THE Ensemble_Scorer SHALL calibrate confidence scores to reduce false positives
4. WHEN multiple layers disagree, THE Ensemble_Scorer SHALL apply conflict resolution logic
5. THE Ensemble_Scorer SHALL produce a final Threat_Level score between 0.0 and 1.0
6. THE Ensemble_Scorer SHALL provide confidence intervals for threat assessments
7. WHEN threat scoring completes, THE Ensemble_Scorer SHALL include layer-specific contributions in the result

### Requirement 14: Text Normalization and Obfuscation Detection

**User Story:** As a threat analyst, I want the system to detect and normalize obfuscated text, so that scammers cannot evade detection through text manipulation.

#### Acceptance Criteria

1. WHEN text contains leetspeak (e.g., "h3ll0"), THE Threat_Detector SHALL convert it to standard characters
2. WHEN text contains homoglyphs (e.g., Cyrillic 'а' instead of Latin 'a'), THE Threat_Detector SHALL normalize to standard Unicode
3. WHEN text contains zero-width characters or invisible obfuscation, THE Threat_Detector SHALL remove them
4. WHEN text contains excessive spacing or formatting, THE Threat_Detector SHALL normalize whitespace
5. THE Threat_Detector SHALL preserve original text for evidence while using normalized text for analysis

### Requirement 15: Advanced Pattern Matching

**User Story:** As a threat analyst, I want the system to detect scam patterns using fuzzy matching and phonetic analysis, so that we can identify variations and misspellings of known scam indicators.

#### Acceptance Criteria

1. WHEN analyzing text, THE Threat_Detector SHALL apply fuzzy string matching to detect near-matches of known scam keywords
2. THE Threat_Detector SHALL apply phonetic analysis to detect sound-alike variations of scam terms
3. THE Threat_Detector SHALL use n-gram analysis to detect partial matches and word fragments
4. WHEN a fuzzy match is detected, THE Threat_Detector SHALL calculate a similarity score
5. THE Threat_Detector SHALL support configurable similarity thresholds for pattern matching

### Requirement 16: Semantic Analysis and Intent Detection

**User Story:** As a threat analyst, I want the system to understand the semantic meaning and intent of messages, so that we can detect sophisticated scams that evade keyword-based detection.

#### Acceptance Criteria

1. WHEN analyzing text, THE Threat_Detector SHALL generate semantic embeddings for contextual understanding
2. THE Threat_Detector SHALL classify message intent to identify manipulation tactics
3. THE Threat_Detector SHALL detect urgency indicators and pressure tactics commonly used in scams
4. THE Threat_Detector SHALL identify trust exploitation patterns in message content
5. THE Threat_Detector SHALL detect financial solicitation patterns regardless of specific wording
