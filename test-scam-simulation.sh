#!/bin/bash

# Test script to simulate scammer conversation with Varutri honeypot
# This creates a realistic scam scenario that you can monitor on the dashboard

API_URL="https://varutri-honeypot.onrender.com"
API_KEY="varutri_shield_2026"
SESSION_ID="live-demo-$(date +%s)"

echo "Starting scam simulation..."
echo "Session ID: $SESSION_ID"
echo "Open your dashboard to watch: file://$(pwd)/frontend/index.html"
echo ""
echo "Simulating lottery scam conversation..."
echo "========================================="
echo ""

# Message 1
echo "[SCAMMER] Congratulations! You won 10 lakh rupees!"
RESPONSE=$(curl -s -X POST "$API_URL/api/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"sessionId\": \"$SESSION_ID\",
    \"message\": {
      \"sender\": \"scammer\",
      \"text\": \"Congratulations! You won 10 lakh rupees in lucky draw!\",
      \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")\"
    }
  }")

echo "[VARUTRI] $(echo $RESPONSE | jq -r '.reply')"
echo ""
sleep 2

# Message 2
echo "[SCAMMER] Just send Rs 500 processing fee to 9876543210@paytm"
RESPONSE=$(curl -s -X POST "$API_URL/api/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"sessionId\": \"$SESSION_ID\",
    \"message\": {
      \"sender\": \"scammer\",
      \"text\": \"Just send Rs 500 processing fee to 9876543210@paytm to claim your prize\",
      \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")\"
    }
  }")

echo "[VARUTRI] $(echo $RESPONSE | jq -r '.reply')"
echo ""
sleep 2

# Message 3
echo "[SCAMMER] Very simple! Open Paytm and send to 9876543210"
RESPONSE=$(curl -s -X POST "$API_URL/api/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"sessionId\": \"$SESSION_ID\",
    \"message\": {
      \"sender\": \"scammer\",
      \"text\": \"Very simple madam! Just open Paytm app and send money to 9876543210\",
      \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")\"
    }
  }")

echo "[VARUTRI] $(echo $RESPONSE | jq -r '.reply')"
echo ""
sleep 2

# Message 4
echo "[SCAMMER] Also call this number for help: 9123456789"
RESPONSE=$(curl -s -X POST "$API_URL/api/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"sessionId\": \"$SESSION_ID\",
    \"message\": {
      \"sender\": \"scammer\",
      \"text\": \"If you have problem, call this number: 9123456789. They will help you.\",
      \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")\"
    }
  }")

echo "[VARUTRI] $(echo $RESPONSE | jq -r '.reply')"
echo ""
sleep 2

# Message 5
echo "[SCAMMER] Send to bank account 1234567890 if Paytm not working"
RESPONSE=$(curl -s -X POST "$API_URL/api/chat" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $API_KEY" \
  -d "{
    \"sessionId\": \"$SESSION_ID\",
    \"message\": {
      \"sender\": \"scammer\",
      \"text\": \"If Paytm not working, you can send directly to bank account 1234567890\",
      \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")\"
    }
  }")

echo "[VARUTRI] $(echo $RESPONSE | jq -r '.reply')"
echo ""

echo "========================================="
echo "Conversation complete!"
echo ""
echo "Now checking intelligence extracted..."
echo ""

# Get evidence
EVIDENCE=$(curl -s "$API_URL/api/evidence/$SESSION_ID" \
  -H "x-api-key: $API_KEY")

echo "Intelligence Report:"
echo "===================="
echo "$EVIDENCE" | jq '{
  threatLevel: .threatLevel,
  scamType: .scamType,
  intelligence: {
    upiIds: .extractedInfo.upiIds,
    phoneNumbers: .extractedInfo.phoneNumbers,
    bankAccounts: .extractedInfo.bankAccountNumbers,
    keywords: .extractedInfo.suspiciousKeywords
  }
}'

echo ""
echo "Session ID: $SESSION_ID"
echo "View on dashboard: Open frontend/index.html and look for this session!"
