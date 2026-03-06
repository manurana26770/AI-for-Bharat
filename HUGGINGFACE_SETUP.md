# 🤗 Using Hugging Face Instead of Ollama

## Why Hugging Face?

 **No local installation** - Runs in the cloud  
 **Free tier available** - 30,000 requests/month  
 **Lighter on your laptop** - No GPU/RAM needed  
 **Fast setup** - Just need an API key  

## Setup Steps (5 minutes)

### 1. Get Your Hugging Face API Key

1. Go to https://huggingface.co/join
2. Create a free account (or login)
3. Go to https://huggingface.co/settings/tokens
4. Click "**New token**"
5. Name it: `varutri-honeypot`
6. Type: **Read**
7. Click "**Generate**"
8. **Copy the token** (starts with `hf_...`)

### 2. Update Configuration

Edit `application.properties`:

```properties
# Change this line:
llm.provider=huggingface

# Add your API key here:
huggingface.api-key=hf_YOUR_TOKEN_HERE
```

### 3. Run the Application

```bash
# No need to run Ollama!
# Just start the Spring Boot app in IntelliJ:
# Right-click VarutriHoneypotApplication.java → Run
```

### 4. Test It

```bash
curl -X POST http://localhost:8080/api/chat \
  -H "x-api-key: varutri_shield_2026" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-hf-001",
    "message": "Hello, I have a great investment opportunity!",
    "conversationHistory": []
  }'
```

You should get a response from Rajesh Kumar powered by Llama 3.2!

## Model Options

The default model is `meta-llama/Llama-3.2-3B-Instruct` (fast, free tier friendly).

Other options:
- `meta-llama/Llama-3.2-1B-Instruct` (faster, smaller)
- `mistralai/Mistral-7B-Instruct-v0.3` (alternative)
- `google/gemma-2b-it` (Google's model)

Change in `application.properties`:
```properties
huggingface.model=meta-llama/Llama-3.2-1B-Instruct
```

## Switching Back to Ollama

If you want to use Ollama later, just change:

```properties
llm.provider=ollama
```

The code automatically switches between providers!

## Free Tier Limits

- **30,000 requests/month** on free tier
- Rate limit: ~1000 requests/hour
- Perfect for the buildathon!

## Troubleshooting

**Error: "Model is currently loading"**
- Wait 20-30 seconds and try again
- First request "wakes up" the model

**Error: "Unauthorized"**
- Check your API key is correct
- Make sure it starts with `hf_`

**Error: "Rate limit exceeded"**
- You've hit the hourly limit
- Wait an hour or upgrade to Pro ($9/month for unlimited)

---

**Ready to go!** No Ollama needed, just get your HF token and you're set! 
