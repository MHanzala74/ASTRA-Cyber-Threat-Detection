"""
ASTRA - AI-Based Cyber Threat Detection and Response System
FastAPI Backend - Main Application Entry Point
"""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.logger import logger
from app.routers import predict, health, batch, blockchain_router


# ── Lifespan (replaces deprecated on_event) ─────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 ASTRA starting up — env=%s", settings.app_env)

    from app.models import model_manager
    from app.blockchain import blockchain

    try:
        model_manager.load()
        logger.info("✅ ML Models loaded successfully")
    except FileNotFoundError as e:
        logger.warning("⚠️  Model files not found: %s", e)
    except Exception as e:
        logger.error("❌ Model loading failed: %s", e)

    blockchain.connect()

    yield  # App runs here

    # Shutdown
    logger.info("🛑 ASTRA shutting down")


# ── App ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="ASTRA — Cyber Threat Detection API",
    description=(
        "AI-Based Cyber Threat Detection and Response System with Blockchain logging. "
        "Detects threats including DoS, DDoS, BruteForce, PortScan, and Infiltration "
        "using ensemble ML models (Random Forest + XGBoost)."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ── CORS ─────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins if settings.is_production else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# ── Request timing middleware ─────────────────────────────────────────
@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = round((time.perf_counter() - start) * 1000, 2)
    response.headers["X-Process-Time-Ms"] = str(duration)
    logger.debug("%s %s → %s (%sms)", request.method, request.url.path, response.status_code, duration)
    return response


# ── Global exception handler ──────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )


# ── Routers ───────────────────────────────────────────────────────────
app.include_router(health.router,            prefix=settings.api_prefix, tags=["Health"])
app.include_router(predict.router,           prefix=settings.api_prefix, tags=["Prediction"])
app.include_router(batch.router,             prefix=settings.api_prefix, tags=["Batch Prediction"])
app.include_router(blockchain_router.router, prefix=settings.api_prefix, tags=["Blockchain"])


# ── Root ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Root"])
def root():
    return {
        "project": "ASTRA",
        "description": "AI-Based Cyber Threat Detection and Response System",
        "version": settings.app_version,
        "environment": settings.app_env,
        "docs": "/docs",
        "health": f"{settings.api_prefix}/health",
    }
