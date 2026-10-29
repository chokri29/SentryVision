# SentryVision production image
# FastAPI + Muse (Baseten) + Slither F1 (solc + slither-analyzer)
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ENABLE_SLITHER=true \
    SOLC_VERSION=0.8.20 \
    PORT=8000 \
    PATH="/home/appuser/.local/bin:$PATH"

# Minimal OS deps for solc binaries and git-based installs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user EARLY, so solc-select installs into its home
RUN useradd -m -u 10001 appuser

WORKDIR /app

# Python deps first (better layer caching) - as root, installed system-wide
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install "solc-select>=1.0.4"

# Install compilers AS appuser - they land in /home/appuser/.solc-select
USER appuser
RUN solc-select install 0.8.20 0.8.19 0.8.17 0.8.0 \
    && solc-select use 0.8.20 \
    && solc --version \
    && slither --version

# Application source - back to root only to copy/chown
USER root
COPY main.py slither_runner.py index.html ./
COPY examples ./examples
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Shell form so $PORT expands (Render injects PORT).
# Do NOT set a Start Command in the Render dashboard - leave it empty.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'
