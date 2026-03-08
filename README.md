# Varutri Honeypot

Agentic scam-engagement platform built for India AI Impact Buildathon (Problem 2: Agentic Honey-Pot).

## Team
- Team Name: AITians
- Sahil Kumar Singh (Team Lead)
- Manu Rana 
- Ashutosh 

## Overview
Varutri engages scammers using a configurable AI persona, extracts actionable intelligence (UPI IDs, bank accounts, IFSC, phone numbers, URLs), performs multi-layer threat scoring, and generates reports for authorities.

## Current Repo Structure
```text
AI-for-Bharat/
  src/main/java/com/varutri/honeypot/
    controller/        # REST APIs (chat, persona, report, whatsapp, test)
    service/           # Core logic, LLM, ML integration, security, data
    config/            # Spring config (AWS, security, OpenAPI)
    dto/               # Request/response contracts
    entity/            # Persistence entities
    repository/        # Data repositories
  src/main/resources/
    application.properties
  ml-sidecar/
    app.py             # FastAPI ML service (/embed, /classify, /health)
    Dockerfile
    requirements.txt
  frontend/
    index.html, app.js, style.css
  docker-compose.yml
  Dockerfile           # Spring Boot app image
  DEPLOY.md            # EC2 deployment steps
```

## Tech Stack
- Backend: Spring Boot 3.2.2, Java 17
- ML Sidecar: FastAPI + sentence-transformers + transformers
- LLM Providers:
  - AWS Bedrock (Claude 3 Haiku) provision exists
  - Hugging Face API (active backup path)
- Security: API-key based auth (`X-API-Key`)
- Deployment: Docker Compose (app + ml-sidecar)

## AWS Services Used
- EC2: host application containers
- Bedrock Runtime: provisioned for Claude 3 Haiku integration
- DynamoDB: session/evidence/report persistence

## Important LLM Note (Bedrock vs Hugging Face)
Bedrock Haiku support is implemented in the codebase and configurable via `llm.provider=bedrock`.

At the moment, Bedrock model invocation has ongoing platform-side issues that multiple teams are seeing during the hackathon. Because of this, the project uses Hugging Face as backup (`llm.provider=huggingface`) to keep APIs operational.

Hugging Face free-tier limits apply: expect roughly **50-100 requests/hour** depending on model/account throttling.

## Authentication (`X-API-Key`)
All protected APIs require:

```http
X-API-Key: your_secure_api_key_here
```

Sample test value (if you set this in `.env`):

```http
X-API-Key: varutri_shield_2026
```

The value comes from `.env`:

```env
VARUTRI_API_KEY=your_secure_api_key_here
```

If you set a different value in `.env`, use that exact same value in request headers.

## Local Run
### Option A: Docker Compose (recommended)
```bash
docker-compose up -d --build
```

### Option B: Spring Boot directly
```bash
mvn clean install
mvn spring-boot:run
```

## Swagger / OpenAPI
- Swagger UI: `http://54.81.212.123:8080/swagger-ui/index.html`
- OpenAPI JSON: `http://54.81.212.123:8080/api-docs`

## Swagger APIs (Current)
These are the APIs exposed in Swagger.

### Health
- `GET /api/health`

### Chat and Threat
- `POST /api/chat`
- `POST /api/assess`
- `POST /api/callback/{sessionId}`
- `GET /api/evidence/{sessionId}`
- `GET /api/evidence/high-threat`
- `GET /api/evidence`

### Persona
- `GET /api/persona`
- `GET /api/persona/prompt`
- `PUT /api/persona`
- `POST /api/persona/reset`
- `GET /api/persona/presets`
- `POST /api/persona/presets/{presetName}`

### Reports
- `POST /api/report/manual`
- `GET /api/report/{reportId}`
- `GET /api/report/all`
- `GET /api/report/stats`

### Not Included in Swagger
- WhatsApp APIs (`/api/whatsapp/**`) are intentionally excluded.
- Test simulation APIs (`/api/test/**`) are intentionally excluded.

## Example Request
```bash
curl -X POST "http://localhost:8080/api/chat" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_secure_api_key_here" \
  -d '{
    "sessionId":"demo-session-001",
    "message":{
      "sender":"scammer",
      "text":"You won a prize. Share your UPI to claim now.",
      "timestamp":1700000000000
    },
    "conversationHistory":[]
  }'
```

## Key Environment Variables
See `.env.example` for full list.

Required:
- `VARUTRI_API_KEY`
- `HUGGINGFACE_API_KEY` (if using Hugging Face)
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` (for AWS integrations)

## Deployment
Use `DEPLOY.md` for EC2 setup and troubleshooting.
