from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _get_env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None else default


@dataclass(frozen=True)
class Settings:
    app_name: str = "ASTRA"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    project_description: str = (
        "AI-Based Cyber Threat Detection and Response System. "
        "Detects threats like DoS, DDoS, BruteForce, PortScan using ML models."
    )
    ganache_url: str = _get_env("GANACHE_URL", "http://127.0.0.1:8545")
    contract_address: str = _get_env("CONTRACT_ADDRESS", "")
    abi_path: Path = Path(__file__).resolve().parent / "ThreatLog_abi.json"
    artifacts_dir: Path = Path(__file__).resolve().parent.parent / "artifacts"
    log_level: str = _get_env("LOG_LEVEL", "INFO").upper()

    @property
    def app_title(self) -> str:
        return f"{self.app_name} - Cyber Threat Detection API"

    def validate(self) -> None:
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(
                f"Unsupported LOG_LEVEL '{self.log_level}'. "
                "Expected one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
            )
        if not self.ganache_url:
            raise ValueError("GANACHE_URL cannot be empty.")

    def to_dict(self) -> dict[str, str]:
        return {
            "app_name": self.app_name,
            "app_version": self.app_version,
            "api_prefix": self.api_prefix,
            "ganache_url": self.ganache_url,
            "contract_address": self.contract_address,
            "log_level": self.log_level,
        }


settings = Settings()
settings.validate()
