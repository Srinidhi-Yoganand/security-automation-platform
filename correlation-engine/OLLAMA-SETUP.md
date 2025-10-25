# Ollama Setup Guide for Security Automation Platform

## Why DeepSeek Coder V2?
- **Docker-Friendly**: Smaller model sizes (1.6B-16B options)
- **Security-Aware**: Better trained on code security patterns
- **Recent Training**: More up-to-date code patterns (2024 data)
- **Quantized Versions**: Official Q4/Q8 quantization for containers
- **Cost-Effective**: Runs well on CPU with 8GB RAM

## Installation Steps (Windows)

### Step 1: Install Ollama
```bash
# Download and run:
https://ollama.com/download/OllamaSetup.exe

# Installer will:
# - Install Ollama service
# - Start automatically on system boot
# - Add to system PATH
# - Create system tray icon
```

### Step 2: Pull DeepSeek Coder Model
```bash
# After installation, open a NEW terminal and run:
ollama pull deepseek-coder:6.7b-instruct

# Model Details:
# - Size: 8.5GB download
# - RAM: 8GB minimum
# - Speed: ~10-20 tokens/sec on CPU
# - Quality: High for security patches
```

### Step 3: Verify Installation
```bash
# Check Ollama is running
ollama list

# Test generation
ollama run deepseek-coder:6.7b-instruct "Write a secure SQL query"
```

### Step 4: Test with Our Platform
```bash
cd correlation-engine
python test_llm_providers.py

# Should show:
# [INFO] Using Ollama (detected local server)
# [OK] Ollama initialized (model: deepseek-coder:6.7b-instruct)
```

## Docker Deployment Configuration

### Option 1: Ollama as Separate Service (Recommended)
```yaml
# docker-compose.yml
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
        reservations:
          memory: 8G
    
  correlation-engine:
    build: ./correlation-engine
    container_name: security-correlation
    environment:
      - OLLAMA_HOST=http://ollama:11434
      - LLM_PROVIDER=ollama
      - OLLAMA_MODEL=deepseek-coder:6.7b-instruct
    depends_on:
      - ollama
    ports:
      - "8000:8000"
    volumes:
      - ./test-data:/app/test-data
      - ./vulnerable-app:/app/vulnerable-app

volumes:
  ollama_data:
```

### Option 2: All-in-One Container (For Testing)
```dockerfile
# Dockerfile.allinone
FROM python:3.11-slim

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Copy application
WORKDIR /app
COPY correlation-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY correlation-engine/ .

# Start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
```

```bash
# start.sh
#!/bin/bash
set -e

# Start Ollama service
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
sleep 5

# Pull model if not exists
if ! ollama list | grep -q "deepseek-coder:6.7b-instruct"; then
    echo "Pulling DeepSeek Coder model..."
    ollama pull deepseek-coder:6.7b-instruct
fi

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Model Size Comparison for Docker

| Model | Size | RAM | Docker Best? |
|-------|------|-----|--------------|
| deepseek-coder:1.6b-instruct | 1.3GB | 4GB | ✅ CI/CD |
| deepseek-coder:6.7b-instruct | 8.5GB | 8GB | ✅ Production |
| deepseek-coder:16b-instruct | 12GB | 16GB | ⚠️ Heavy |
| codellama:7b-instruct | 10GB | 10GB | ❌ Older |

**Recommendation**: Use `deepseek-coder:6.7b-instruct` for production Docker deployments.

## Environment Variables

```bash
# For local development
export OLLAMA_HOST=http://localhost:11434
export LLM_PROVIDER=ollama
export OLLAMA_MODEL=deepseek-coder:6.7b-instruct

# For Docker deployment
OLLAMA_HOST=http://ollama:11434
LLM_PROVIDER=ollama
OLLAMA_MODEL=deepseek-coder:6.7b-instruct
```

## Performance Tuning

### CPU Only (Default)
```bash
# Works out of the box
# Speed: 10-20 tokens/sec
```

### With GPU (NVIDIA)
```yaml
# docker-compose.yml
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

## Testing After Setup

```bash
# 1. Start Ollama (if not already running)
ollama serve

# 2. Test model
cd correlation-engine
python test_llm_providers.py

# 3. Generate real patches
python test_patches.py

# 4. Test API
python run_server.py &
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_id": 1}'
```

## Troubleshooting

### "Ollama not found"
```bash
# Add to PATH
export PATH=$PATH:/usr/local/bin

# Or on Windows, reinstall from:
https://ollama.com/download/OllamaSetup.exe
```

### "Model not found"
```bash
# Pull the model
ollama pull deepseek-coder:6.7b-instruct

# List available models
ollama list
```

### "Connection refused"
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve
```

### Docker Container Issues
```bash
# Check Ollama logs
docker logs security-ollama

# Restart Ollama service
docker restart security-ollama

# Pull model inside container
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct
```

## Next Steps

1. ✅ Install Ollama on Windows
2. ✅ Pull DeepSeek Coder model
3. ✅ Test with `test_llm_providers.py`
4. 🚀 Generate patches with LLM
5. 🐋 Deploy with Docker
