# ─────────────────────────────────────────────────────────────────────
#  ASTRA — Production Dockerfile
#  Multi-stage build: keeps the final image lean
# ─────────────────────────────────────────────────────────────────────

# Stage 1: Install dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps needed to compile some packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt


# Stage 2: Runtime image
FROM python:3.11-slim AS runtime

LABEL maintainer="ASTRA Team — BS CS AWKUM 2022-26"
LABEL description="ASTRA AI-Based Cyber Threat Detection System"

# Non-root user for security
RUN useradd --create-home --shell /bin/bash astra

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY app/        ./app/
COPY artifacts/  ./artifacts/
COPY startup.py  .
COPY deploy_contract.py .
COPY ThreatLog.sol .
COPY ThreatLog_abi.json .

# Create logs directory
RUN mkdir -p logs && chown -R astra:astra /app

USER astra

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')"

EXPOSE 8000

CMD ["python", "startup.py"]
