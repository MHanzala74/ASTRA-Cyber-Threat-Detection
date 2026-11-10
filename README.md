<div align="center">

# 🛡️ ASTRA
### AI-Based Cyber Threat Detection & Response System with Blockchain

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![Blockchain](https://img.shields.io/badge/Blockchain-Ethereum%2FSolidity-purple?logo=ethereum)](https://ethereum.org)
[![ML](https://img.shields.io/badge/ML-RandomForest%20%2B%20XGBoost-orange)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> **Final Year Project — BS Computer Science, AWKUM 2022–26**
> Real-time network threat detection using ensemble ML models with immutable blockchain audit logging.

</div>

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Architecture](#-architecture)
- [Threat Detection](#-threat-detection)
- [API Endpoints](#-api-endpoints)
- [Quick Start](#-quick-start)
- [Docker Deployment](#-docker-deployment)
- [Environment Variables](#-environment-variables)
- [Blockchain Setup](#-blockchain-setup)
- [Project Structure](#-project-structure)

---

## 🔍 Overview

ASTRA is a production-ready REST API that classifies network traffic flows into threat categories using a **dual-model ML ensemble** (Random Forest + XGBoost). Every detected threat is automatically logged as an **immutable record on an Ethereum-compatible blockchain** for tamper-proof audit trails.

### Key Features
| Feature | Details |
|---|---|
| 🤖 Dual ML Ensemble | Random Forest + XGBoost with confidence scores |
| ⛓️ Blockchain Logging | Immutable threat audit trail via Solidity smart contract |
| 📦 Batch Processing | JSON (up to 1,000 flows) + CSV upload (up to 5,000 rows) |
| 🔒 Production-Ready | CORS control, structured logging, error handling, Docker support |
| ⚡ Fast | Models loaded once at startup, singleton pattern |
| 📖 Auto Docs | Swagger UI at `/docs`, ReDoc at `/redoc` |

---

## 🔬 Novel Contributions

ASTRA goes beyond "classifier + blockchain log" with three research-oriented additions:

### 1. Merkle-batched, tamper-evident audit logging (`LOGGING_MODE=merkle`)
Writing every threat on-chain is expensive. ASTRA hashes records into a **Merkle tree** off-chain and anchors only the 32-byte **root** per batch in the `MerkleAnchor` smart contract. Any single record can later be proven (locally *and inside the contract*) with a logarithmic-size proof; changing any field of a stored record makes verification fail.

Measured on an in-memory EVM, 500 identical threat records (`python scripts/benchmark_gas.py`):

| Mode | Batch size | Gas / record | Reduction |
|---|---|---|---|
| Per-record (`ThreatLog`) | 1 | 281,739 | — |
| Merkle (`MerkleAnchor`) | 10 | 7,611 | 97.3% |
| Merkle (`MerkleAnchor`) | 50 | 1,550 | 99.5% |
| Merkle (`MerkleAnchor`) | 500 | 186 | 99.9% |

![Gas benchmark](docs/gas_benchmark.png)

Trade-off: records are buffered until a batch fills (or `MERKLE_FLUSH_SECONDS` passes), so on-chain anchoring is delayed; raw records live in an off-chain append-only journal (`data/merkle_journal.jsonl`) and the chain guarantees their integrity rather than storing them.

### 2. Explainable detection with a verifiable explanation hash
`POST /api/v1/predict/explain` returns the verdict **and why**: exact TreeSHAP contributions from XGBoost (`pred_contribs`, no extra dependency). The explanation is faithful by construction — summed contributions reproduce `predict_proba` exactly (unit-tested). Its keccak256 hash is committed inside the audit record, so the tamper-evident log also proves *why* a decision was made. The dashboard renders the top features as signed bars.

### 3. Generalization & robustness evaluation
`scripts/evaluate.py` evaluates the saved models on another CICFlowMeter dataset (e.g. CSE-CIC-IDS2018) with per-class metrics, confusion matrices, and robustness curves under evasion-like perturbations (raw-space jitter, Gaussian noise, feature masking). It excludes and counts unsupported labels and refuses to run when too many features are missing, so reported numbers are not silently inflated.

```bash
python scripts/evaluate.py --csv path/to/dataset.csv --name cic2018 --robustness
```

> Cross-dataset results depend on the data you run it on and are not included here; the script writes `docs/evaluation/<name>/report.md`.

* * *

## 🏗️ Architecture

![ASTRA Architecture](docs/architecture.svg)

---

## 🚨 Threat Detection

ASTRA classifies network flows into 6 categories using **51 CICFlowMeter features**:

| Threat Type | Severity | Automated Response |
|---|---|---|
| ✅ Benign | None | No action required |
| 🔴 DDoS | Critical | Activate DDoS mitigation. Rate-limit source. Alert NOC. |
| 🔴 DoS | Critical | Rate-limit traffic. Block offending IP. Alert security team. |
| 🟠 BruteForce | High | Block source IP. Enable account lockout policy. |
| 🟠 Infiltration | High | Isolate affected system. Conduct forensic analysis. |
| 🟡 PortScan | Medium | Flag source IP for monitoring. Review firewall rules. |

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | API info and links |
| `GET` | `/api/v1/health` | System health (models + blockchain) |
| `POST` | `/api/v1/predict` | Analyze a single network flow |
| `POST` | `/api/v1/predict/batch` | Analyze up to 1,000 flows (JSON) |
| `POST` | `/api/v1/predict/csv` | Analyze up to 5,000 flows (CSV upload) |
| `GET` | `/api/v1/blockchain/status` | Blockchain connection status |
| `GET` | `/api/v1/blockchain/logs` | All on-chain threat records |
| `GET` | `/api/v1/blockchain/logs/{id}` | Single on-chain record |

---

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- [Ganache](https://trufflesuite.com/ganache/) (for blockchain, optional)

### 1. Clone & Install

```bash
git clone https://github.com/MHanzala74/ASTRA-Cyber-Threat-Detection.git
cd ASTRA-Cyber-Threat-Detection

python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your values (see Environment Variables section)
```

### 3. (Optional) Deploy Blockchain Contract

```bash
# Start Ganache first, then:
python deploy_contract.py
# Copy the printed CONTRACT_ADDRESS into your .env
```

### 4. Run the Server

```bash
python startup.py
```

API is now live at **http://localhost:8000**
Interactive docs at **http://localhost:8000/docs**

---

## 🐳 Docker Deployment

```bash
# Build and start everything (API + Ganache)
docker compose up --build

# Run in background
docker compose up -d --build

# View logs
docker compose logs -f astra

# Stop
docker compose down
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development` or `production` |
| `APP_HOST` | `0.0.0.0` | Server bind address |
| `APP_PORT` | `8000` | Server port |
| `APP_WORKERS` | `1` | Uvicorn worker processes |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins |
| `GANACHE_URL` | `http://127.0.0.1:8545` | Ethereum node URL |
| `CONTRACT_ADDRESS` | *(empty)* | Deployed ThreatLog contract address |
| `LOG_LEVEL` | `INFO` | `DEBUG / INFO / WARNING / ERROR` |
| `LOG_FILE` | *(empty)* | Log file path (leave empty for console only) |

---

## ⛓️ Blockchain Setup

1. Install & start **Ganache** (GUI or CLI)
2. Make sure `GANACHE_URL` in `.env` points to it
3. Run `python deploy_contract.py` — deploys **ThreatLog** and **MerkleAnchor** and prints both addresses
4. Paste them into `.env` as `CONTRACT_ADDRESS` and `MERKLE_CONTRACT_ADDRESS`
5. (Optional) set `LOGGING_MODE=merkle` for gas-efficient batched anchoring
6. Restart the API — threats will now be logged on-chain

---

## 🧪 Tests & Benchmarks

```bash
pip install -r requirements-dev.txt
pytest -q                              # unit + end-to-end tests (in-memory EVM, real models)
python scripts/benchmark_gas.py        # per-record vs Merkle gas comparison
```

* * *

## 📁 Project Structure

```
ASTRA/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, middleware, lifespan
│   ├── config.py            # Centralized settings from env vars
│   ├── logger.py            # Structured logging
│   ├── models.py            # ML model singleton + feature config
│   ├── schemas.py           # Pydantic request/response models
│   ├── blockchain.py        # Web3 blockchain integration (ThreatLog + MerkleAnchor)
│   ├── merkle.py            # Merkle tree, proofs, persistent batcher
│   ├── event_logger.py      # per-record vs Merkle logging dispatcher
│   ├── explain.py           # TreeSHAP explanations + explanation hash
│   ├── ThreatLog_abi.json   # Smart contract ABI
│   └── routers/
│       ├── health.py        # GET /health
│       ├── predict.py       # POST /predict
│       ├── batch.py         # POST /predict/batch, /predict/csv
│       └── blockchain_router.py  # GET /blockchain/*
├── artifacts/
│   ├── rf_multiclass.pkl    # Random Forest model
│   ├── xgb_multiclass.pkl   # XGBoost model
│   ├── label_encoder.pkl    # Label encoder
│   └── scaler.pkl           # Feature scaler
├── ui/
│   └── astra_dashboard_1.html  # Frontend dashboard
├── ThreatLog.sol            # Per-record smart contract
├── MerkleAnchor.sol         # Merkle-root anchoring contract
├── build/contracts/         # Compiled ABI + bytecode (solc 0.8.19)
├── scripts/
│   ├── benchmark_gas.py     # Gas benchmark
│   └── evaluate.py          # Cross-dataset + robustness evaluation
├── tests/                   # pytest suite
├── deploy_contract.py       # Contract deployment script
├── startup.py               # Uvicorn entry point
├── Dockerfile               # Production Docker image
├── docker-compose.yml       # Multi-container setup
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
└── README.md
```

