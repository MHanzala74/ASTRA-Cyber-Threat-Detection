"""
ASTRA - AI-Based Cyber Threat Detection and Response System
FastAPI Backend - Main Application Entry Point
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.logging_config import configure_logging
from app.routers import batch, blockchain_router, health, predict

configure_logging(level=getattr(logging, settings.log_level, logging.INFO))

app = FastAPI(
    title=settings.app_title,
    description=settings.project_description,
    version=settings.app_version,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix=settings.api_prefix, tags=["Health"])
app.include_router(predict.router, prefix=settings.api_prefix, tags=["Prediction"])
app.include_router(batch.router, prefix=settings.api_prefix, tags=["Batch Prediction"])
app.include_router(blockchain_router.router, prefix=settings.api_prefix, tags=["Blockchain"])


@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def generic_exception_handler(_, exc: Exception):
    logging.getLogger("astra").exception("Unhandled application error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/", tags=["Root"])
def root():
    return {
        "project": settings.app_name,
        "description": settings.project_description,
        "docs": "/docs",
        "version": settings.app_version,
    }
