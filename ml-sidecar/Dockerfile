FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (Docker layer caching)
COPY requirements.txt .
# Install CPU-only torch first to avoid pulling CUDA wheels on small EC2 disks
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.1.2

# Install remaining Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
