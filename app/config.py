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

    @property
    def app_title(self) -> str:
        return f"{self.app_name} - Cyber Threat Detection API"


settings = Settings()
