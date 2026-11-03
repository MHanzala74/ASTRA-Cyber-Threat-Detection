"""
ASTRA - Application Entry Point
Run with: python startup.py
Or with uvicorn: uvicorn startup:app --reload
"""

import uvicorn
from app.main import app  # noqa: F401 — needed for `uvicorn startup:app`
from app.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=not settings.is_production,
        log_level=settings.log_level.lower(),
    )
