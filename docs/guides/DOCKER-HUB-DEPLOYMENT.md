# 🐳 Docker Hub Deployment Guide

This guide shows how to build, tag, and push Docker images to Docker Hub for fully independent deployment.

---

## 📋 Prerequisites

1. **Docker Hub Account**: Create at https://hub.docker.com
2. **Docker Desktop**: Installed and running
3. **Docker Hub CLI**: Logged in via `docker login`

---

## 🏗️ Build Images for Docker Hub

### Step 1: Login to Docker Hub

```bash
docker login
# Enter your Docker Hub username and password
```

### Step 2: Build Images with Proper Tags

```bash
cd security-automation-platform

# Build Correlation Engine (API + LLM Integration)
docker build \
  -t yourusername/security-correlation-engine:latest \
  -t yourusername/security-correlation-engine:1.0.0 \
  -t yourusername/security-correlation-engine:1.0 \
  ./correlation-engine

# Build Vulnerable App (Optional - for testing)
docker build \
  -t yourusername/security-vulnerable-app:latest \
  -t yourusername/security-vulnerable-app:1.0.0 \
  ./vulnerable-app
```

**Tag Explanation:**
- `latest` - Always points to newest stable version
- `1.0.0` - Specific version for reproducibility
- `1.0` - Major.minor version (gets patch updates)

### Step 3: Push to Docker Hub

```bash
# Push Correlation Engine
docker push yourusername/security-correlation-engine:latest
docker push yourusername/security-correlation-engine:1.0.0
docker push yourusername/security-correlation-engine:1.0

# Push Vulnerable App (optional)
docker push yourusername/security-vulnerable-app:latest
docker push yourusername/security-vulnerable-app:1.0.0
```

**This will take 5-10 minutes depending on internet speed.**

---

## 📦 Updated docker-compose.yml (Docker Hub Version)

### For End Users (No Local Build Required)

```yaml
version: '3.8'

services:
  # Ollama LLM Service (DeepSeek Coder)
  ollama:
    image: ollama/ollama:latest
    container_name: security-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 12G
        reservations:
          memory: 8G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Correlation Engine API (FROM DOCKER HUB)
  correlation-engine:
    image: yourusername/security-correlation-engine:latest
    container_name: security-correlation
    environment:
      - OLLAMA_HOST=http://ollama:11434
      - LLM_PROVIDER=ollama
      - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
      - DATABASE_URL=sqlite:///./security.db
      # Optional: Add your notification configs
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - SMTP_SERVER=${SMTP_SERVER}
      - GITHUB_TOKEN=${GITHUB_TOKEN}
    depends_on:
      ollama:
        condition: service_healthy
    ports:
      - "8000:8000"
    volumes:
      # Mount your project for scanning
      - ./your-java-app:/app/target:ro
      # Data persistence
      - correlation_data:/app/data
    restart: unless-stopped
    command: >
      sh -c "
        echo 'Waiting for Ollama to be ready...' &&
        sleep 10 &&
        python -c 'import ollama; ollama.pull(\"deepseek-coder:6.7b-instruct\")' || true &&
        uvicorn app.main:app --host 0.0.0.0 --port 8000
      "

  # Vulnerable Java Application (Optional - for testing only)
  vulnerable-app:
    image: yourusername/security-vulnerable-app:latest
    container_name: security-vulnerable-app
    ports:
      - "8080:8080"
    restart: unless-stopped

volumes:
  ollama_data:
    name: security-ollama-models
  correlation_data:
    name: security-correlation-data

networks:
  default:
    name: security-automation-network
```

---

## 🌍 Public Docker Hub Deployment (Recommended Username: srinivas)

I'll use `srinivas` as the username for this example:

### Build & Push Commands

```bash
# Login
docker login

# Build with proper tags
docker build \
  -t srinivas/security-automation:latest \
  -t srinivas/security-automation:1.0.0 \
  -t srinivas/security-automation:phase3 \
  ./correlation-engine

# Push all tags
docker push srinivas/security-automation:latest
docker push srinivas/security-automation:1.0.0
docker push srinivas/security-automation:phase3
```

### Public docker-compose.yml

```yaml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: security-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 12G
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3

  correlation-engine:
    # FROM DOCKER HUB - No build required!
    image: srinivas/security-automation:latest
    container_name: security-correlation
    environment:
      - OLLAMA_HOST=http://ollama:11434
      - LLM_PROVIDER=ollama
      - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
    depends_on:
      ollama:
        condition: service_healthy
    ports:
      - "8000:8000"
    volumes:
      - correlation_data:/app/data
    restart: unless-stopped

volumes:
  ollama_data:
  correlation_data:

networks:
  default:
    name: security-automation-network
```

---

## 🚀 One-Command Deployment (For End Users)

Users can now deploy with **ONE COMMAND** without any source code:

```bash
# Create docker-compose.yml
curl -o docker-compose.yml https://raw.githubusercontent.com/yourusername/security-automation/main/docker-compose-hub.yml

# Start everything
docker-compose up -d

# Access dashboard
open http://localhost:8000/dashboard
```

**No source code needed! No builds! Fully independent!** 🎉

---

## 📝 Docker Hub Repository Setup

### 1. Create Repository on Docker Hub

1. Go to https://hub.docker.com
2. Click "Create Repository"
3. Repository Name: `security-automation`
4. Description: "AI-Powered Security Automation Platform with automated vulnerability patching using DeepSeek Coder"
5. Visibility: **Public** (so anyone can use it)
6. Click "Create"

### 2. Add README to Docker Hub

Create `README-DOCKERHUB.md`:

```markdown
# Security Automation Platform

AI-powered security vulnerability scanning and automated patching platform.

## Quick Start

```bash
# Pull image
docker pull srinivas/security-automation:latest

# Run standalone
docker run -d \
  -p 8000:8000 \
  -e LLM_PROVIDER=ollama \
  srinivas/security-automation:latest

# Access dashboard
open http://localhost:8000/dashboard
```

## Features

- 🤖 AI-powered patch generation (DeepSeek Coder)
- 📊 Interactive vulnerability dashboard
- 🔔 Multi-channel notifications (Slack/Email/GitHub)
- 🔌 REST API for integration
- 🐳 Fully containerized

## Full Stack Deployment

```yaml
version: '3.8'
services:
  ollama:
    image: ollama/ollama:latest
    ports: ["11434:11434"]
  
  security-platform:
    image: srinivas/security-automation:latest
    ports: ["8000:8000"]
    depends_on: [ollama]
```

## Documentation

- GitHub: https://github.com/yourusername/security-automation
- API Docs: http://localhost:8000/docs
- Dashboard: http://localhost:8000/dashboard

## Tags

- `latest` - Latest stable version
- `1.0.0` - Specific version
- `phase3` - Phase 3 complete (LLM patching)

## Support

- Issues: https://github.com/yourusername/security-automation/issues
- Docs: https://github.com/yourusername/security-automation/blob/main/README.md
```

---

## 🤖 Automated Docker Hub Deployment (CI/CD)

### GitHub Actions Workflow

Create `.github/workflows/docker-publish.yml`:

```yaml
name: Publish to Docker Hub

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]
  release:
    types: [ published ]

env:
  DOCKERHUB_USERNAME: srinivas
  IMAGE_NAME: security-automation

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ env.DOCKERHUB_USERNAME }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest,enable=${{ github.ref == 'refs/heads/main' }}
      
      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: ./correlation-engine
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=registry,ref=${{ env.DOCKERHUB_USERNAME }}/${{ env.IMAGE_NAME }}:buildcache
          cache-to: type=registry,ref=${{ env.DOCKERHUB_USERNAME }}/${{ env.IMAGE_NAME }}:buildcache,mode=max
      
      - name: Update Docker Hub description
        uses: peter-evans/dockerhub-description@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
          repository: ${{ env.DOCKERHUB_USERNAME }}/${{ env.IMAGE_NAME }}
          readme-filepath: ./README-DOCKERHUB.md
```

---

## 📊 Multi-Architecture Support

Build for multiple platforms (AMD64, ARM64):

```bash
# Create builder
docker buildx create --name multiarch --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t srinivas/security-automation:latest \
  -t srinivas/security-automation:1.0.0 \
  --push \
  ./correlation-engine
```

Now works on:
- ✅ Intel/AMD servers
- ✅ ARM servers (AWS Graviton, etc.)
- ✅ Apple Silicon Macs (M1/M2/M3)
- ✅ Raspberry Pi 4

---

## 🔐 Security Best Practices

### 1. Use Secrets for Sensitive Data

```yaml
services:
  correlation-engine:
    image: srinivas/security-automation:latest
    environment:
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
      - GITHUB_TOKEN=${GITHUB_TOKEN}
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    file: ./secrets/api_key.txt
```

### 2. Run as Non-Root User

Update Dockerfile:
```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 1000 security && \
    mkdir -p /app && \
    chown -R security:security /app

USER security
WORKDIR /app

# ... rest of Dockerfile
```

### 3. Scan Images for Vulnerabilities

```bash
# Using Docker Scout
docker scout cves srinivas/security-automation:latest

# Using Trivy
trivy image srinivas/security-automation:latest
```

---

## 📈 Image Size Optimization

### Current Size vs Optimized

```bash
# Before optimization
srinivas/security-automation:latest  →  1.2GB

# After optimization (multi-stage build)
srinivas/security-automation:slim    →  450MB
```

### Optimized Dockerfile

```dockerfile
# Builder stage
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application
WORKDIR /app
COPY . .

# Make sure scripts are in PATH
ENV PATH=/root/.local/bin:$PATH

EXPOSE 8000
HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 🎯 Usage Examples

### Example 1: Standalone API

```bash
docker run -d \
  --name security-api \
  -p 8000:8000 \
  -e LLM_PROVIDER=template \
  srinivas/security-automation:latest
```

### Example 2: With Ollama

```bash
# Start Ollama
docker run -d \
  --name ollama \
  -p 11434:11434 \
  ollama/ollama:latest

# Start Security Platform
docker run -d \
  --name security-api \
  -p 8000:8000 \
  -e OLLAMA_HOST=http://ollama:11434 \
  -e LLM_PROVIDER=ollama \
  --link ollama \
  srinivas/security-automation:latest
```

### Example 3: With Volume Mount

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/my-java-app:/app/target:ro \
  -v security-data:/app/data \
  srinivas/security-automation:latest
```

---

## ✅ Verification

After pushing to Docker Hub, verify:

```bash
# Pull and test
docker pull srinivas/security-automation:latest

# Run
docker run -d -p 8000:8000 srinivas/security-automation:latest

# Test API
curl http://localhost:8000/health

# Test LLM status
curl http://localhost:8000/api/llm/status

# Access dashboard
open http://localhost:8000/dashboard
```

---

## 📦 Alternative: GitHub Container Registry

For private or GitHub-integrated deployments:

```bash
# Login to GitHub
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Build and tag
docker build -t ghcr.io/username/security-automation:latest ./correlation-engine

# Push
docker push ghcr.io/username/security-automation:latest
```

Update docker-compose.yml:
```yaml
services:
  correlation-engine:
    image: ghcr.io/username/security-automation:latest
```

---

## 🎉 Summary

After Docker Hub deployment:

✅ **Fully Independent** - No source code needed
✅ **One-Command Deploy** - `docker-compose up -d`
✅ **Public or Private** - Your choice
✅ **Multi-Architecture** - Works on Intel, ARM, Apple Silicon
✅ **CI/CD Ready** - Auto-deploy on git push
✅ **Pluggable** - Any app can use it via API

**Next Steps:**
1. Push to Docker Hub: `docker push yourusername/security-automation:latest`
2. Share compose file: Users can deploy instantly
3. Document on Docker Hub: Add README with usage
4. Set up CI/CD: Auto-publish on releases

Your platform is now **truly independent and portable**! 🚀
