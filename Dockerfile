# Multi-stage Dockerfile for Security Automation Platform
# Provides zero-dependency deployment with CodeQL, Z3, and LLM patching

# ============================================
# Stage 1: CodeQL Base (lightweight)
# ============================================
FROM debian:bullseye-slim AS codeql-base

# Install only essential tools for downloading CodeQL
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install CodeQL CLI
ENV CODEQL_VERSION=2.15.3
ENV CODEQL_HOME=/opt/codeql

RUN mkdir -p ${CODEQL_HOME} && \
    cd /opt && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip && \
    unzip -q codeql-linux64.zip && \
    rm codeql-linux64.zip && \
    chmod +x ${CODEQL_HOME}/codeql

# Clone CodeQL queries repository
RUN git clone --depth 1 https://github.com/github/codeql.git /opt/codeql-repo

ENV PATH="${CODEQL_HOME}:${PATH}"


# ============================================
# Stage 2: Python Environment with Z3
# ============================================
FROM python:3.11-slim AS python-builder

# Install system dependencies for building Python packages
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY correlation-engine/requirements.txt /tmp/requirements.txt

# Install core dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    z3-solver==4.12.6.0 \
    fastapi==0.104.1 \
    uvicorn==0.24.0 \
    pydantic==2.5.0 \
    sqlalchemy==2.0.23 \
    pytest==7.4.3 \
    gitpython==3.1.40

# Install optional LLM dependencies (graceful failure if unavailable)
RUN pip install --no-cache-dir google-generativeai openai ollama || true


# ============================================
# Stage 3: Final Production Image (slim Python)
# ============================================
FROM python:3.11-slim AS final

LABEL maintainer="Security Automation Platform"
LABEL description="AI-powered security analysis and automated patching platform"
LABEL version="1.0.0"

# Install runtime system packages required for Java/CodeQL tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jdk \
    maven \
    git \
    curl \
    unzip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy CodeQL from builder stage
COPY --from=codeql-base /opt/codeql /opt/codeql
COPY --from=codeql-base /opt/codeql-repo /opt/codeql-repo

# Use system Python (python:3.11-slim). Install Python deps from requirements
WORKDIR /app
COPY correlation-engine/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt || true

# Copy application code (use build arg to bust cache when needed)
ARG CACHEBUST=1
COPY correlation-engine/ /app/

# Create directories for data persistence
RUN mkdir -p /data/codeql-databases /data/results /data/patches && \
    chmod -R 777 /data

# Set up environment
ENV CODEQL_HOME=/opt/codeql
ENV PATH="/usr/local/bin:${CODEQL_HOME}:${PATH}"
ENV PYTHONPATH="/app"
ENV CODEQL_QUERIES=/opt/codeql-repo

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command: Run FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
