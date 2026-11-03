"""
ASTRA — Blockchain Integration Module
Handles Web3 calls inside FastAPI.
Logs every detected threat to the blockchain (Ganache / any EVM node).
"""

import json
from typing import Optional

from web3 import Web3
from web3.exceptions import ContractLogicError
from dotenv import load_dotenv

from app.config import settings
from app.logger import logger

load_dotenv()


class BlockchainLogger:
    """
    Singleton — connect once, reuse for every request.
    Fails gracefully: if Ganache is not running, the API still works.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._ready = False
        return cls._instance

    def connect(self):
        """Call once at FastAPI startup."""
        if self._ready:
            return

        if not settings.contract_address:
            logger.warning("Blockchain: CONTRACT_ADDRESS missing in .env — logging disabled")
            return

        if not settings.abi_path.exists():
            logger.warning("Blockchain: ThreatLog_abi.json not found — run deploy_contract.py first")
            return

        try:
            self._w3 = Web3(Web3.HTTPProvider(settings.ganache_url))

            if not self._w3.is_connected():
                logger.warning("Blockchain: Cannot connect to %s — logging disabled", settings.ganache_url)
                return

            abi = json.loads(settings.abi_path.read_text())
            checksum_addr = Web3.to_checksum_address(settings.contract_address)

            self._contract = self._w3.eth.contract(address=checksum_addr, abi=abi)
            self._account  = self._w3.eth.accounts[0]
            self._ready    = True

            logger.info("Blockchain connected: %s", settings.ganache_url)
            logger.info("Contract : %s", checksum_addr)
            logger.info("Account  : %s", self._account)

        except Exception as e:
            logger.error("Blockchain init error: %s — logging disabled", e)

    def is_ready(self) -> bool:
        return self._ready

    def log_threat(self, prediction: dict) -> Optional[str]:
        """
        Store a threat prediction on the blockchain.

        Args:
            prediction: response dict from /predict endpoint

        Returns:
            tx_hash (hex string) if success, None if failed/disabled
        """
        if not self._ready:
            return None

        try:
            rf_conf  = int(prediction.get("rf_confidence",  0) * 10_000)
            xgb_conf = int(prediction.get("xgb_confidence", 0) * 10_000)

            tx_hash = self._contract.functions.logThreat(
                prediction.get("final_verdict",      "unknown"),
                prediction.get("severity",           "unknown"),
                prediction.get("rf_prediction",      "unknown"),
                prediction.get("xgb_prediction",     "unknown"),
                rf_conf,
                xgb_conf,
                prediction.get("recommended_action", ""),
                bool(prediction.get("is_threat",     False)),
            ).transact({
                "from": self._account,
                "gas":  500_000,
            })

            receipt  = self._w3.eth.wait_for_transaction_receipt(tx_hash)
            tx_str   = tx_hash.hex()

            logger.info("Blockchain log: %s... block=%s", tx_str[:20], receipt["blockNumber"])
            return tx_str

        except ContractLogicError as e:
            logger.error("Contract logic error: %s", e)
            return None
        except Exception as e:
            logger.error("Blockchain log error: %s", e)
            return None

    def get_all_logs(self) -> list[dict]:
        """Fetch all threat records stored on the blockchain."""
        if not self._ready:
            return []

        try:
            total = self._contract.functions.getTotalRecords().call()
            logs  = []

            for i in range(total):
                rec = self._contract.functions.getRecord(i).call()
                logs.append({
                    "record_id":          i,
                    "timestamp":          rec[0],
                    "threat_type":        rec[1],
                    "severity":           rec[2],
                    "rf_prediction":      rec[3],
                    "xgb_prediction":     rec[4],
                    "rf_confidence":      rec[5] / 10_000,
                    "xgb_confidence":     rec[6] / 10_000,
                    "recommended_action": rec[7],
                    "is_threat":          rec[8],
                })

            return logs

        except Exception as e:
            logger.error("Blockchain read error: %s", e)
            return []

    def get_stats(self) -> dict:
        """Return summary statistics from the blockchain."""
        if not self._ready:
            return {"enabled": False}

        try:
            total   = self._contract.functions.getTotalRecords().call()
            threats = self._contract.functions.getThreatCount().call()

            return {
                "enabled":       True,
                "total_records": total,
                "threat_count":  threats,
                "benign_count":  total - threats,
                "contract":      settings.contract_address,
                "node":          settings.ganache_url,
            }

        except Exception as e:
            logger.error("Blockchain stats error: %s", e)
            return {"enabled": False, "error": str(e)}


# ── Global singleton ──────────────────────────────────────────────────
blockchain = BlockchainLogger()
