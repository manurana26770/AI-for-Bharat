# Deployment Guide for AWS EC2

This guide deploys the current Varutri Honeypot application to an already-launched Ubuntu EC2 instance using Docker Compose.

## Prerequisites
- AWS account and running EC2 instance.
- EC2 key pair `.pem` file.
- Security Group inbound rules:
  - `SSH` (22) from `My IP` or `0.0.0.0/0`
  - `Custom TCP` (8080) from `0.0.0.0/0` (API access)
- Required secrets for `.env`:
  - `VARUTRI_API_KEY`
  - `HUGGINGFACE_API_KEY`
  - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
  - WhatsApp keys only if WhatsApp flow is used

---

## Step 3: Deploy on Your Existing EC2

1. Connect to the instance
```bash
# Linux/Mac only
chmod 400 honeypot-key.pem

# SSH into Ubuntu EC2
ssh -i "path/to/honeypot-key.pem" ubuntu@<YOUR_EC2_PUBLIC_IP>
```

2. Install Docker, Docker Compose, and Git
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2 git curl || sudo apt install -y docker.io docker-compose git curl

sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

docker --version
docker-compose --version
```

3. Re-login so docker group applies
```bash
exit
ssh -i "path/to/honeypot-key.pem" ubuntu@<YOUR_EC2_PUBLIC_IP>
```

4. Clone project
```bash
git clone https://github.com/SahilKumar75/Varutri-Honeypot.git
cd Varutri-Honeypot
```

5. Create `.env`
```bash
nano .env
```
Use at least:
```env
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1

VARUTRI_API_KEY=your_api_key
HUGGINGFACE_API_KEY=your_huggingface_key

WHATSAPP_API_TOKEN=
WHATSAPP_PHONE_NUMBER_ID=
WHATSAPP_VERIFY_TOKEN=
```

6. Build and run containers
```bash
docker-compose up -d --build
```

7. Check running services
```bash
docker-compose ps
docker-compose logs -f app
```

---

## Step 4: Verify Deployment

Open these URLs:
- Health: `http://<YOUR_EC2_PUBLIC_IP>:8080/api/health`  (used by Docker healthcheck)
- Swagger UI: `http://<YOUR_EC2_PUBLIC_IP>:8080/swagger-ui.html`
- OpenAPI JSON: `http://<YOUR_EC2_PUBLIC_IP>:8080/api-docs`

> After startup, `docker-compose ps` should show the `app` container as **healthy** once the endpoint responds.

Test chat API:
```bash
curl -X POST "http://<YOUR_EC2_PUBLIC_IP>:8080/api/chat" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <YOUR_VARUTRI_API_KEY>" \
  -d '{
    "sessionId":"ec2-test-001",
    "message":{
      "sender":"scammer",
      "text":"Hello, share your UPI for refund",
      "timestamp":1700000000000
    },
    "conversationHistory":[]
  }'
```

---

## Maintenance

Update and redeploy:
```bash
git pull origin main
docker-compose up -d --build
```

Logs:
```bash
docker-compose logs -f app
docker-compose logs -f ml-sidecar
```

Restart:
```bash
docker-compose restart
```

Stop:
```bash
docker-compose down
```
