"""
Varutri ML Sidecar — FastAPI service for local ML inference.

Hosts two models:
1. MiniLM (sentence-transformers/all-MiniLM-L6-v2) → /embed
2. DeBERTa (MoritzLaurer/deberta-v3-base-zeroshot-v1) → /classify

Called by the Spring Boot application's LocalMLService via HTTP.
"""

import logging
from contextlib import asynccontextmanager
from typing import List

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from transformers import pipeline

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml-sidecar")

# ── Global model references ─────────────────────────────────────────────────
embedding_model = None
zeroshot_pipeline = None


# ── Startup / Shutdown ───────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models on startup, release on shutdown."""
    global embedding_model, zeroshot_pipeline

    logger.info("Loading MiniLM embedding model...")
    embedding_model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    logger.info(" MiniLM loaded (384-d embeddings)")

    logger.info("Loading DeBERTa zero-shot model...")
    zeroshot_pipeline = pipeline(
        "zero-shot-classification",
        model="MoritzLaurer/deberta-v3-base-zeroshot-v1",
        device="cpu",
    )
    logger.info(" DeBERTa loaded (zero-shot classification)")

    yield  # ── app is running ──

    logger.info("Shutting down — releasing model resources")
    del embedding_model, zeroshot_pipeline
    torch.cuda.empty_cache()


app = FastAPI(title="Varutri ML Sidecar", lifespan=lifespan)


# ── Request / Response schemas ───────────────────────────────────────────────
class EmbedRequest(BaseModel):
    text: str


class EmbedResponse(BaseModel):
    embedding: List[float]
    dimensions: int


class ClassifyRequest(BaseModel):
    text: str
    candidate_labels: List[str]


class ClassifyResponse(BaseModel):
    scores: dict  # label → probability


# ── Endpoints ────────────────────────────────────────────────────────────────
@app.post("/embed", response_model=EmbedResponse)
def embed(req: EmbedRequest):
    """Return a 384-dimensional sentence embedding for the given text."""
    if embedding_model is None:
        raise HTTPException(status_code=503, detail="Embedding model not loaded")

    vector = embedding_model.encode(req.text).tolist()
    return EmbedResponse(embedding=vector, dimensions=len(vector))


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    """Zero-shot classify text against candidate labels."""
    if zeroshot_pipeline is None:
        raise HTTPException(status_code=503, detail="Zero-shot model not loaded")

    result = zeroshot_pipeline(req.text, candidate_labels=req.candidate_labels)

    scores = {label: score for label, score in zip(result["labels"], result["scores"])}
    return ClassifyResponse(scores=scores)


@app.get("/health")
def health():
    """Health check — returns model readiness status."""
    return {
        "status": "ok",
        "embedding_model": embedding_model is not None,
        "zeroshot_model": zeroshot_pipeline is not None,
    }
