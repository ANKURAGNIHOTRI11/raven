"""Embedding service. Keeps the BERT-family encoder resident on the GPU so the
graph builder and the RAG engine share one copy of the weights."""
from __future__ import annotations

import os

import torch
from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

MODEL_NAME = os.environ.get("RAVEN_EMBEDDING_MODEL", "BAAI/bge-base-en-v1.5")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

app = FastAPI(title="RAVEN embedder")
model = SentenceTransformer(MODEL_NAME, device=DEVICE)


class Req(BaseModel):
    texts: list[str]
    normalize: bool = True


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": MODEL_NAME, "device": DEVICE,
            "dim": model.get_sentence_embedding_dimension()}


@app.post("/embed")
def embed(req: Req) -> dict:
    vecs = model.encode(
        req.texts, normalize_embeddings=req.normalize, batch_size=32, convert_to_numpy=True
    )
    return {"embeddings": [v.tolist() for v in vecs], "model": MODEL_NAME}
