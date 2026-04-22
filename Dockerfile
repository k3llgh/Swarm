# ── Stage 1: build ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ───────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Nano Swarm Auditing System"
LABEL org.opencontainers.image.description="Self-educating blockchain security auditing"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry for Ethereum sandbox (https://getfoundry.sh)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup || true
ENV PATH="/root/.foundry/bin:${PATH}"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy project
COPY . .

# Create data directories
RUN mkdir -p data/{curriculum,patterns,pitfall_logs,reports}

# Non-root user for production
RUN useradd -m -u 1000 swarm && chown -R swarm:swarm /app
USER swarm

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-m", "nano_swarm.cli"]
CMD ["--help"]
