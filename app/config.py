"""
ASTRA - Centralized Configuration
All settings are loaded from environment variables with safe defaults.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List
import os


def _get_env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _get_list(name: str, default: str) -> List[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    # ── App ──────────────────────────────────────────────
    app_name: str        = "ASTRA"
    app_version: str     = "2.0.0"
    app_env: str         = field(default_factory=lambda: _get_env("APP_ENV", "development"))
    api_prefix: str      = "/api/v1"

    # ── Server ───────────────────────────────────────────
    host: str            = field(default_factory=lambda: _get_env("APP_HOST", "0.0.0.0"))
    port: int            = field(default_factory=lambda: int(_get_env("APP_PORT", "8000")))
    workers: int         = field(default_factory=lambda: int(_get_env("APP_WORKERS", "1")))

    # ── Security ─────────────────────────────────────────
    allowed_origins: List[str] = field(
        default_factory=lambda: _get_list(
            "ALLOWED_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000"
        )
    )
    rate_limit: int      = field(default_factory=lambda: int(_get_env("RATE_LIMIT_PER_MINUTE", "60")))

    # ── Blockchain ───────────────────────────────────────
    ganache_url: str     = field(default_factory=lambda: _get_env("GANACHE_URL", "http://127.0.0.1:8545"))
    contract_address: str = field(default_factory=lambda: _get_env("CONTRACT_ADDRESS", ""))

    # ── Merkle batching (gas-efficient audit logging) ────
    # LOGGING_MODE: "per_record" (one tx per threat, original behaviour)
    #               "merkle"     (batch records, anchor only the Merkle root)
    logging_mode: str    = field(default_factory=lambda: _get_env("LOGGING_MODE", "per_record").lower())
    merkle_contract_address: str = field(default_factory=lambda: _get_env("MERKLE_CONTRACT_ADDRESS", ""))
    merkle_batch_size: int = field(default_factory=lambda: int(_get_env("MERKLE_BATCH_SIZE", "50")))
    merkle_flush_seconds: int = field(default_factory=lambda: int(_get_env("MERKLE_FLUSH_SECONDS", "30")))

    # ── Paths ────────────────────────────────────────────
    base_dir: Path       = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    abi_path: Path       = field(default_factory=lambda: Path(__file__).resolve().parent / "ThreatLog_abi.json")
    merkle_abi_path: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "MerkleAnchor_abi.json")

    @property
    def artifacts_dir(self) -> Path:
        custom = _get_env("ARTIFACTS_DIR", "")
        if custom:
            return Path(custom)
        return self.base_dir / "artifacts"

    @property
    def merkle_store_path(self) -> Path:
        custom = _get_env("MERKLE_STORE_PATH", "")
        return Path(custom) if custom else self.base_dir / "data" / "merkle_journal.jsonl"

    @property
    def merkle_enabled(self) -> bool:
        return self.logging_mode == "merkle"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def log_level(self) -> str:
        return _get_env("LOG_LEVEL", "INFO").upper()

    @property
    def log_file(self) -> str:
        return _get_env("LOG_FILE", "")


settings = Settings()
