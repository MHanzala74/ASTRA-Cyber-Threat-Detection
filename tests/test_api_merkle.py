"""End-to-end: real FastAPI app + real models + in-memory EVM running MerkleAnchor."""
import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester")
from fastapi.testclient import TestClient  # noqa: E402
from web3 import Web3, EthereumTesterProvider  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "threat_flows.json"
BUILD = Path(__file__).resolve().parent.parent / "build" / "contracts"


@pytest.fixture(scope="module")
def client():
    from app.main import app
    from app.blockchain import blockchain

    with TestClient(app) as c:
        w3 = Web3(EthereumTesterProvider())
        art = json.loads((BUILD / "MerkleAnchor.json").read_text())
        ctr = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        addr = w3.eth.wait_for_transaction_receipt(
            ctr.constructor().transact({"from": w3.eth.accounts[0]})).contractAddress
        blockchain._w3, blockchain._account = w3, w3.eth.accounts[0]
        blockchain._anchor = w3.eth.contract(address=addr, abi=art["abi"])
        blockchain._merkle_ready = True
        yield c


def _flows():
    return json.loads(FIX.read_text())


def test_threats_are_batched_and_anchored(client):
    flows = _flows()
    ids = []
    for name in ["dos", "ddos", "portscan"]:           # batch_size = 3 -> auto-seal
        r = client.post("/api/v1/predict", json=flows[name])
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["is_threat"]
        assert body["audit_record_id"] is not None
        ids.append(body["audit_record_id"])

    stats = client.get("/api/v1/blockchain/merkle/stats").json()
    assert stats["anchored_batches"] >= 1 and stats["avg_gas_per_record"]

    proof = client.get(f"/api/v1/blockchain/merkle/proof/{ids[1]}").json()
    assert proof["status"] == "anchored" and proof["root"]

    ok = client.post("/api/v1/blockchain/merkle/verify",
                     json={"record_id": ids[1], "record": proof["record"]}).json()
    assert ok["valid_local"] is True and ok["valid_onchain"] is True


def test_tampered_record_is_rejected_locally_and_on_chain(client):
    flows = _flows()
    ids = [client.post("/api/v1/predict", json=flows["dos"]).json()["audit_record_id"] for _ in range(3)]
    rec = client.get(f"/api/v1/blockchain/merkle/proof/{ids[0]}").json()["record"]
    rec["severity"] = "none"                              # attacker edits the log
    bad = client.post("/api/v1/blockchain/merkle/verify", json={"record_id": ids[0], "record": rec}).json()
    assert bad["valid_local"] is False and bad["valid_onchain"] is False


def test_manual_flush_seals_pending(client):
    r = client.post("/api/v1/predict", json=_flows()["bruteforce"]).json()
    rid = r["audit_record_id"]
    assert client.get(f"/api/v1/blockchain/merkle/proof/{rid}").json()["status"] == "pending"
    client.post("/api/v1/blockchain/merkle/flush")
    assert client.get(f"/api/v1/blockchain/merkle/proof/{rid}").json()["status"] == "anchored"


def test_unknown_record_404(client):
    assert client.get("/api/v1/blockchain/merkle/proof/999999").status_code == 404
