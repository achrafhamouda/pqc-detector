"""
FastAPI backend for the PQC detector.

Endpoints:
  GET  /health             liveness probe
  POST /analyze            JSON body  {"code": "<source>", "filename": "..."}
  POST /analyze/upload     multipart/form-data, field name "file" (.py upload)

Both /analyze endpoints share the same pipeline (cli.analyze_source) and
return the same JSON shape:

  {
    "report":   { ... CLI report ... },
    "features": { ... AST features ... }
  }

Run locally:
    uvicorn api:app --reload --port 8000
"""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent))
from cli import analyze_source  # noqa: E402

MAX_SOURCE_BYTES = 256 * 1024  # 256 KB hard cap on submitted code
MODEL_DIR = Path(__file__).parent / "runs" / "codebert" / "final"

app = FastAPI(
    title="PQC Detector API",
    description="Static analyzer for post-quantum cryptography misuse in Python.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # frontend served separately during dev
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="Python source code to analyze")
    filename: str = Field("<pasted>", description="Display name for the report")


def _run_pipeline(source: str, filename: str) -> dict:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"source exceeds {MAX_SOURCE_BYTES} bytes",
        )

    model_dir = MODEL_DIR if MODEL_DIR.exists() else None
    result = analyze_source(source, filename=filename, model_dir=model_dir)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_available": MODEL_DIR.exists()}


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="empty source")
    return _run_pipeline(req.code, req.filename or "<pasted>")


@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)) -> dict:
    name = file.filename or "<upload>"
    if not name.endswith(".py"):
        raise HTTPException(status_code=400, detail="only .py files are accepted")
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="file is not valid UTF-8")
    return _run_pipeline(source, name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
