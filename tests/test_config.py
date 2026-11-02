from __future__ import annotations

from app.config import Settings


def test_settings_defaults(monkeypatch):
    monkeypatch.delenv("GANACHE_URL", raising=False)
    monkeypatch.delenv("CONTRACT_ADDRESS", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    settings = Settings()
    assert settings.ganache_url == "http://127.0.0.1:8545"
    assert settings.contract_address == ""
    assert settings.api_prefix == "/api/v1"


def test_settings_validate_accepts_degraded_mode():
    settings = Settings(contract_address="", ganache_url="http://127.0.0.1:8545")
    settings.validate()


def test_settings_validate_rejects_unknown_log_level():
    settings = Settings(log_level="VERBOSE")
    try:
        settings.validate()
        assert False, "Expected ValueError for unsupported LOG_LEVEL"
    except ValueError:
        pass
