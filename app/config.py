from dataclasses import dataclass
from pathlib import Path
import os


def _get_env(name: str, default: str) -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    app_name: str = "ASTRA"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    ganache_url: str = _get_env("GANACHE_URL", "http://127.0.0.1:8545")
    contract_address: str = _get_env("CONTRACT_ADDRESS", "")
    abi_path: Path = Path(__file__).resolve().parent / "ThreatLog_abi.json"
    artifacts_dir: Path = Path(__file__).resolve().parent.parent / "artifacts"


settings = Settings()
