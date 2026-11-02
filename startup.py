"""
ASTRA - Application Startup
Load models when the app starts.
"""

from app.blockchain import blockchain
from app.logging_config import logger
from app.models import model_manager


async def startup_event():
    logger.info("ASTRA starting up...")

    try:
        model_manager.load()
        logger.info("ML models loaded successfully.")
    except FileNotFoundError as exc:
        logger.warning("Model files not found: %s", exc)
    except Exception as exc:
        logger.exception("Model loading failed: %s", exc)

    blockchain.connect()
