#!/bin/bash

# Simple test script for Varutri Honeypot API

echo "Testing Varutri Honeypot API..."
echo ""

# Test 1: Health check
echo "1. Testing health endpoint..."
curl -s http://localhost:8080/health
echo -e "\n"

# Test 2: Chat API
echo "2. Testing chat endpoint..."
curl -X POST http://localhost:8080/api/chat \
  -H "x-api-key: varutri_shield_2026" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session",
    "message": "Hello",
    "conversationHistory": []
  }'
echo -e "\n"

echo "Test complete!"
