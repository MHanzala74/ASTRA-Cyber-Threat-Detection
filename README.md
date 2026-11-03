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
git clone https://github.com/MHanzala74/Final-Year-Project-ASTRA-AI-Based-Cyber-Threat-Detection-Response-System-with-Blockchain-.git
cd Final-Year-Project-ASTRA-AI-Based-Cyber-Threat-Detection-Response-System-with-Blockchain-

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
3. Run `python deploy_contract.py` — it prints the contract address
4. Paste the address into `.env` as `CONTRACT_ADDRESS`
5. Restart the API — threats will now be logged on-chain

---

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
│   ├── blockchain.py        # Web3 blockchain integration
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
├── ThreatLog.sol            # Solidity smart contract
├── deploy_contract.py       # Contract deployment script
├── startup.py               # Uvicorn entry point
├── Dockerfile               # Production Docker image
├── docker-compose.yml       # Multi-container setup
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
└── README.md
```

