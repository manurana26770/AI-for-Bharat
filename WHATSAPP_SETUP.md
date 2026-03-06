# WhatsApp Integration Setup Guide

## Overview
This guide will help you set up WhatsApp integration with Varutri Honeypot using Meta's Cloud API (free tier: 1000 conversations/month).

---

## Step 1: Create Meta Business Account

1. Go to [Meta for Developers](https://developers.facebook.com/)
2. Click **"My Apps"** → **"Create App"**
3. Select **"Business"** as app type
4. Fill in details:
   - **App Name**: Varutri Honeypot
   - **Contact Email**: Your email
   - **Business Account**: Create new or select existing

---

## Step 2: Add WhatsApp Product

1. In your app dashboard, click **"Add Product"**
2. Find **"WhatsApp"** and click **"Set Up"**
3. You'll be taken to the WhatsApp setup page

---

## Step 3: Get API Credentials

### Get Phone Number ID
1. In WhatsApp setup, go to **"API Setup"**
2. You'll see a test phone number (starts with +1)
3. Copy the **Phone Number ID** (looks like: `123456789012345`)

### Get Access Token
1. In the same page, find **"Temporary Access Token"**
2. Click **"Copy"** (valid for 24 hours)
3. For production, generate a **Permanent Token**:
   - Go to **"System Users"** in Business Settings
   - Create system user → Generate token
   - Select permissions: `whatsapp_business_messaging`

---

## Step 4: Configure Varutri

Update `application.properties`:

```properties
whatsapp.api.token=YOUR_ACCESS_TOKEN_HERE
whatsapp.phone.number.id=YOUR_PHONE_NUMBER_ID_HERE
whatsapp.verify.token=varutri_webhook_2026
```

---

## Step 5: Set Up Webhook

### Deploy Your App
1. Make sure Varutri is deployed on Render:
   ```
   https://varutri-honeypot.onrender.com
   ```

### Configure Webhook in Meta
1. In WhatsApp setup, go to **"Configuration"**
2. Click **"Edit"** next to Webhook
3. Enter:
   - **Callback URL**: `https://varutri-honeypot.onrender.com/api/whatsapp/webhook`
   - **Verify Token**: `varutri_webhook_2026`
4. Click **"Verify and Save"**

### Subscribe to Webhook Fields
1. After verification, click **"Manage"**
2. Subscribe to:
   -  `messages`
   -  `message_status`

---

## Step 6: Test the Integration

### Test 1: Send Test Message
1. In Meta dashboard, find **"Send and receive messages"**
2. Add your phone number (you'll receive OTP)
3. Send a test message from your phone to the test number
4. Check Varutri logs - you should see the webhook received

### Test 2: Scam Report Flow
Send this message to your WhatsApp Business number:
```
Hello, you have won Rs 10 lakh! Send payment to claim.
```

Expected behavior:
1. Varutri receives message
2. AI responds with persona
3. You receive intelligence notifications

---

## Step 7: Production Setup

### Get Your Own Phone Number
1. In WhatsApp setup, go to **"Phone Numbers"**
2. Click **"Add Phone Number"**
3. Options:
   - **Use existing**: Link your WhatsApp Business number
   - **Get new**: Request a new number from Meta

### Business Verification
For higher limits (beyond 1000 conversations):
1. Complete **Business Verification** in Meta Business Settings
2. Submit business documents
3. Wait for approval (1-2 weeks)

---

## How Users Will Use It

### Option 1: Forward Scam Messages
1. User receives scam message
2. User forwards it to your WhatsApp Business number
3. Varutri takes over and handles the scammer

### Option 2: Button Integration (Future)
When you have message templates approved:
1. User receives scam
2. User taps "Report to Varutri" button
3. Varutri automatically engages

---

## API Endpoints

### Webhook Verification (GET)
```
GET /api/whatsapp/webhook?hub.mode=subscribe&hub.verify_token=varutri_webhook_2026&hub.challenge=CHALLENGE
```

### Receive Messages (POST)
```
POST /api/whatsapp/webhook
```

### Manual Takeover (POST)
```bash
curl -X POST https://varutri-honeypot.onrender.com/api/whatsapp/takeover \
  -H "Content-Type: application/json" \
  -H "x-api-key: varutri_shield_2026" \
  -d '{
    "phone": "919876543210",
    "message": "Scam message text here"
  }'
```

---

## Troubleshooting

### Webhook Not Verified
- Check Render logs for errors
- Ensure verify token matches: `varutri_webhook_2026`
- Verify URL is accessible: `curl https://varutri-honeypot.onrender.com/api/whatsapp/webhook`

### Messages Not Received
- Check webhook subscriptions (messages field)
- Verify access token is valid
- Check Render logs for incoming webhooks

### Messages Not Sent
- Verify phone number ID is correct
- Check access token has `whatsapp_business_messaging` permission
- Ensure recipient has messaged you first (24-hour window)

---

## Rate Limits (Free Tier)

- **1000 conversations/month**
- **Conversation** = 24-hour window after user messages you
- **Messages within conversation**: Unlimited

---

## Next Steps

1.  Complete Meta app setup
2.  Configure webhook
3.  Test with your phone
4.  Share WhatsApp Business number with users
5.  Monitor intelligence extraction

---

## Support

- **Meta Documentation**: https://developers.facebook.com/docs/whatsapp/cloud-api
- **Varutri Issues**: Check application logs on Render
