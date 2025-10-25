# Docker Deployment Guide

## 🐋 Quick Start with Docker Compose

This setup includes:
- **Ollama** with DeepSeek Coder 6.7B (local LLM)
- **Correlation Engine API** (FastAPI backend)
- **Vulnerable App** (Java Spring Boot test application)

### Prerequisites
- Docker Desktop installed (Windows/Mac)
- Or Docker Engine + Docker Compose (Linux)
- At least 12GB RAM available
- 15GB free disk space

### Step 1: Start Services
```bash
# From project root
docker-compose up -d

# Or to see logs
docker-compose up
```

### Step 2: Wait for Model Download
```bash
# The first time, Ollama will download DeepSeek Coder (8.5GB)
# This takes 5-15 minutes

# Check Ollama logs
docker logs -f security-ollama

# Wait for: "Model pulled successfully"
```

### Step 3: Verify Services
```bash
# Check all services are running
docker-compose ps

# Should show:
# security-ollama            running    11434/tcp
# security-correlation       running    8000/tcp
# security-vulnerable-app    running    8080/tcp

# Test Ollama
curl http://localhost:11434/api/tags

# Test API
curl http://localhost:8000/health
```

### Step 4: Generate Patches
```bash
# Test LLM provider detection
curl http://localhost:8000/api/llm/status

# Generate a patch
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_type": "SQL Injection",
    "severity": "high",
    "file_path": "/app/vulnerable-app/src/main/java/com/security/automation/controller/UserController.java",
    "line_number": 45,
    "vulnerable_code": "String sql = \"SELECT * FROM users WHERE username = \" + username;"
  }'
```

## 🔧 Configuration

### Environment Variables
Edit `docker-compose.yml` to customize:

```yaml
environment:
  # Ollama connection
  - OLLAMA_HOST=http://ollama:11434
  
  # LLM provider (ollama, openai, gemini, template)
  - LLM_PROVIDER=ollama
  
  # Model to use
  - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
  
  # Database
  - DATABASE_URL=sqlite:///./security.db
  
  # Optional: OpenAI fallback
  - OPENAI_API_KEY=sk-...
  
  # Optional: Gemini fallback
  - GEMINI_API_KEY=...
```

### Resource Limits
Adjust memory for Ollama based on your system:

```yaml
services:
  ollama:
    deploy:
      resources:
        limits:
          memory: 12G        # Adjust based on available RAM
        reservations:
          memory: 8G
```

### Using Different Models
To use a different model:

1. **Change in docker-compose.yml:**
```yaml
environment:
  - OLLAMA_MODEL=deepseek-coder:1.6b-instruct  # Smaller, faster
  # or
  - OLLAMA_MODEL=codellama:13b-instruct        # Larger, slower
```

2. **Pull the model:**
```bash
docker exec security-ollama ollama pull deepseek-coder:1.6b-instruct
```

3. **Restart correlation engine:**
```bash
docker-compose restart correlation-engine
```

## 🚀 Available Models for Docker

| Model | Size | RAM | Speed | Quality | Best For |
|-------|------|-----|-------|---------|----------|
| deepseek-coder:1.6b-instruct | 1.3GB | 4GB | ⚡⚡⚡ | ⭐⭐⭐ | CI/CD, Testing |
| **deepseek-coder:6.7b-instruct** | 8.5GB | 8GB | ⚡⚡ | ⭐⭐⭐⭐⭐ | **Production** |
| deepseek-coder:16b-instruct | 12GB | 16GB | ⚡ | ⭐⭐⭐⭐⭐ | High Accuracy |
| codellama:7b-instruct | 10GB | 10GB | ⚡⚡ | ⭐⭐⭐⭐ | Alternative |

**Recommendation:** Use `deepseek-coder:6.7b-instruct` (default) - best balance for Docker deployments.

## 📊 Monitoring

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f correlation-engine
docker-compose logs -f ollama

# Last 100 lines
docker-compose logs --tail=100 correlation-engine
```

### Check Resource Usage
```bash
# Docker stats
docker stats

# Should show:
# NAME                    CPU %    MEM USAGE / LIMIT
# security-ollama         25%      4GB / 12GB
# security-correlation    5%       512MB / 2GB
```

### Health Checks
```bash
# API health
curl http://localhost:8000/health

# Ollama health
curl http://localhost:11434/api/tags

# Vulnerable app health
curl http://localhost:8080/actuator/health
```

## 🛠️ Troubleshooting

### Issue: Ollama container keeps restarting
```bash
# Check logs
docker logs security-ollama

# Common causes:
# 1. Not enough RAM (need 8GB minimum)
# 2. Model not downloaded yet (wait 10 minutes)

# Manual model pull
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct
```

### Issue: "Model not found" error
```bash
# List available models
docker exec security-ollama ollama list

# Pull the model manually
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct

# Restart services
docker-compose restart
```

### Issue: Correlation engine can't connect to Ollama
```bash
# Check if Ollama is healthy
docker-compose ps
curl http://localhost:11434/api/tags

# Check network
docker network inspect security-automation-network

# Restart in correct order
docker-compose down
docker-compose up -d ollama
# Wait 30 seconds
docker-compose up -d correlation-engine
```

### Issue: Out of memory
```bash
# Use smaller model
docker exec security-ollama ollama pull deepseek-coder:1.6b-instruct

# Update docker-compose.yml
environment:
  - OLLAMA_MODEL=deepseek-coder:1.6b-instruct

# Restart
docker-compose restart correlation-engine
```

## 🔄 Updates and Maintenance

### Update Model
```bash
# Pull latest version
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct

# Restart to use new version
docker-compose restart correlation-engine
```

### Update Application
```bash
# Rebuild images
docker-compose build

# Restart services
docker-compose up -d
```

### Backup Data
```bash
# Backup database
docker cp security-correlation:/app/data/security.db ./backup/

# Backup Ollama models
docker run --rm -v security-ollama-models:/data -v $(pwd)/backup:/backup \
  alpine tar czf /backup/ollama-models.tar.gz -C /data .
```

### Clean Up
```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: deletes data)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

## 🌐 Production Deployment

### Using External Ollama Server
If you have a dedicated Ollama server:

```yaml
# docker-compose.yml
services:
  correlation-engine:
    environment:
      - OLLAMA_HOST=http://your-ollama-server:11434
      - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
  
  # Remove ollama service
  # ollama: ...
```

### GPU Support
For NVIDIA GPU acceleration:

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

### Kubernetes Deployment
```bash
# Convert docker-compose to k8s
kompose convert

# Or use provided k8s manifests (coming soon)
kubectl apply -f k8s/
```

## 📈 Performance Tuning

### For Development (Fast feedback)
```yaml
environment:
  - OLLAMA_MODEL=deepseek-coder:1.6b-instruct  # 1.3GB, fast
  - OLLAMA_NUM_PREDICT=1000                     # Shorter responses
```

### For Production (High quality)
```yaml
environment:
  - OLLAMA_MODEL=deepseek-coder:6.7b-instruct  # 8.5GB, balanced
  - OLLAMA_NUM_PREDICT=2000                     # Detailed responses
  - OLLAMA_NUM_THREAD=8                         # Adjust to CPU cores
```

### For CI/CD Pipeline
```yaml
environment:
  - OLLAMA_MODEL=deepseek-coder:1.6b-instruct  # Fast CI/CD
  - OLLAMA_NUM_PREDICT=500                      # Quick patches
```

## 🎯 Next Steps

1. ✅ Start services with `docker-compose up`
2. ✅ Wait for model download (10 minutes)
3. 🚀 Test API at http://localhost:8000/docs
4. 🔍 Scan vulnerable app for issues
5. 🤖 Generate LLM-powered patches
6. 📊 View dashboard at http://localhost:8000/dashboard
