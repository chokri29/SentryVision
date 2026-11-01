# SentryVision production image
# FastAPI + Muse (Baseten) + Slither F1 (solc + slither-analyzer)
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ENABLE_SLITHER=true \
    SOLC_VERSION=0.8.20 \
    PORT=8000 \
    PATH="/home/appuser/.local/bin:$PATH" \
    SOLC_SELECT_INSTALL_DIR=/home/appuser/.solc-select

# OS deps for solc binaries (ssl/crypto) and git-based installs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install "solc-select>=1.0.4"

# Install compilers as appuser so artifacts land under SOLC_SELECT_INSTALL_DIR
USER appuser
RUN solc-select install 0.8.0 0.8.4 0.8.7 0.8.10 0.8.13 0.8.16 0.8.17 0.8.19 0.8.20 0.8.24 0.8.26 \
    && solc-select use 0.8.20 \
    && solc --version \
    && which solc \
    && slither --version \
    && echo "=== solc-select artifacts ===" \
    && ls -la /home/appuser/.solc-select/artifacts/ \
    && (find /home/appuser/.solc-select -type f -name 'solc*' | head -40) \
    && test -e /home/appuser/.solc-select/artifacts/solc-0.8.20 \
       -o -e /home/appuser/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 \
       -o -e /home/appuser/.solc-select/artifacts/solc-0.8.20/solc

USER root
COPY main.py slither_runner.py index.html ./
COPY examples ./examples
COPY vendor ./vendor
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Shell form so $PORT expands (Render injects PORT).
# Do NOT set a Start Command in the Render dashboard — leave it empty.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers
