FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the models during build so startup is fast
RUN python -c "\
from sentence_transformers import SentenceTransformer; \
SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); \
print('MiniLM cached')"

RUN python -c "\
from transformers import pipeline; \
pipeline('zero-shot-classification', model='MoritzLaurer/deberta-v3-base-zeroshot-v1'); \
print('DeBERTa cached')"

COPY app.py .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
