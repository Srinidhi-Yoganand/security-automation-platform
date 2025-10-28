# 🐳 Docker Setup & Troubleshooting Guide

## Prerequisites

### 1. Install Docker Desktop

**Windows:**
- Download from: https://www.docker.com/products/docker-desktop/
- Install Docker Desktop for Windows
- **IMPORTANT:** Ensure Docker Desktop is running (check system tray for Docker icon)

**macOS:**
- Download from: https://www.docker.com/products/docker-desktop/
- Install Docker Desktop for Mac
- Start Docker Desktop from Applications

**Linux:**
- Install Docker Engine: https://docs.docker.com/engine/install/
- Install Docker Compose: `sudo apt install docker-compose-plugin`

### 2. Verify Docker Installation

```bash
# Check Docker is running
docker --version
docker ps

# Check Docker Compose
docker compose version
```

## 🚀 Quick Start

### Option 1: Use Pre-built Image (Recommended - Fastest)

```bash
# 1. Start Docker Desktop first!

# 2. Pull and run the platform
docker compose up -d

# 3. Wait for services to start (2-3 minutes)
docker compose ps

# 4. Check logs
docker compose logs -f correlation-engine

# 5. Access the platform
# Dashboard: http://localhost:8000/api/v1/e2e/dashboard
# API Docs: http://localhost:8000/docs
# Health: http://localhost:8000/health
```

### Option 2: Build from Source (For Development)

```bash
# 1. Start Docker Desktop

# 2. Build locally (takes 10-15 minutes first time)
docker compose -f docker-compose.local.yml build

# 3. Start services
docker compose -f docker-compose.local.yml up -d

# 4. Check status
docker compose -f docker-compose.local.yml ps
```

### Option 3: Quick Test Build

```bash
# Use the automated build script
bash build-with-progress.sh
```

## 🔧 Troubleshooting

### Issue 1: "Docker is not running"

**Error:**
```
error during connect: ... open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified
```

**Solution:**
1. **Start Docker Desktop** from Start Menu or Applications
2. Wait until you see the Docker icon in your system tray/menu bar
3. Click the icon - it should say "Docker Desktop is running"
4. Try your command again

### Issue 2: Port Already in Use

**Error:**
```
Bind for 0.0.0.0:8000 failed: port is already allocated
```

**Solution:**
```bash
# Find what's using port 8000
# Windows
netstat -ano | findstr :8000

# Linux/Mac
lsof -i :8000

# Stop the conflicting service or use a different port
docker compose up -d -e "PORT=8001"
```

### Issue 3: Container Fails to Start

**Check logs:**
```bash
docker compose logs correlation-engine
docker logs security-correlation-engine
```

**Common causes:**
1. Out of memory - Docker needs at least 4GB RAM
2. Missing environment variables - Check `.env` file
3. Volume mount issues - Check paths in `docker-compose.yml`

**Solution:**
```bash
# Restart with fresh state
docker compose down -v
docker compose up -d
```

### Issue 4: Health Check Failing

**Check endpoint:**
```bash
# Wait for container to fully start (30-60 seconds)
sleep 30

# Test health endpoint
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/status

# Check if server is running inside container
docker exec security-correlation-engine curl http://localhost:8000/health
```

### Issue 5: Build Fails

**Error:** Package installation failures

**Solution:**
```bash
# Clear Docker cache and rebuild
docker builder prune -a
docker compose -f docker-compose.local.yml build --no-cache
```

### Issue 6: Ollama LLM Not Working

**Check Ollama service:**
```bash
# Check if Ollama is running
docker compose ps ollama

# Pull the model (first time - takes ~10 minutes)
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct

# Test Ollama
curl http://localhost:11434/api/tags
```

## 📊 Verifying Everything Works

### Step 1: Check Services Status
```bash
docker compose ps

# Should show:
# - security-ollama (healthy)
# - security-correlation-engine (healthy)
```

### Step 2: Test Health Endpoints
```bash
# Main platform
curl http://localhost:8000/health
# Expected: {"status":"healthy","version":"0.2.0"}

# LLM status
curl http://localhost:8000/api/llm/status

# Ollama
curl http://localhost:11434/api/tags
```

### Step 3: Test API
```bash
# View API documentation
open http://localhost:8000/docs
# Or: start http://localhost:8000/docs (Windows)
```

### Step 4: Scan a Test Application
```bash
# Scan the included test app
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/target-app",
    "language": "java",
    "enable_patching": true
  }'
```

## 🎯 Running Tests on Your Own Application

### Method 1: Mount Your Application

**Edit `docker-compose.yml`:**
```yaml
services:
  correlation-engine:
    volumes:
      # Change this to YOUR app path
      - /path/to/your/app:/target-app:ro
```

**Scan your app:**
```bash
docker compose restart correlation-engine

curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/target-app",
    "language": "java",
    "enable_patching": true,
    "llm_provider": "ollama"
  }'
```

### Method 2: Copy Files into Container

```bash
# Copy your app into running container
docker cp /path/to/your/app security-correlation-engine:/workspace/my-app

# Scan it
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/workspace/my-app",
    "language": "python"
  }'
```

## 🛠️ Development Workflow

### Live Development with Hot Reload

```bash
# Use docker-compose.local.yml for development
docker compose -f docker-compose.local.yml up -d

# Watch logs
docker compose -f docker-compose.local.yml logs -f

# Make changes to code - they'll be reflected immediately
# (if you mounted the source directory)
```

### Running Tests Inside Container

```bash
# Enter container
docker exec -it security-correlation-engine bash

# Run tests
cd /app
pytest tests/ -v

# Run specific test
pytest tests/test_semantic_analyzer.py -v
```

### Debugging

```bash
# Check container filesystem
docker exec security-correlation-engine ls -la /app

# Check environment variables
docker exec security-correlation-engine env

# Check Python packages
docker exec security-correlation-engine pip list

# Interactive Python shell
docker exec -it security-correlation-engine python
```

## 🧹 Cleanup

### Stop Services
```bash
docker compose down
```

### Remove All Data (Fresh Start)
```bash
docker compose down -v  # Remove volumes too
docker system prune -a  # Clean up all unused Docker resources
```

### Remove Specific Container
```bash
docker stop security-correlation-engine
docker rm security-correlation-engine
```

## 📈 Performance Tuning

### Increase Docker Resources

**Docker Desktop → Settings → Resources:**
- **CPUs:** 4+ recommended
- **Memory:** 8GB minimum, 12GB recommended (for Ollama)
- **Disk:** 20GB+ for images and models

### Speed Up Builds

```bash
# Use BuildKit (faster builds)
export DOCKER_BUILDKIT=1

# Multi-stage caching
docker compose -f docker-compose.local.yml build --parallel
```

## 🔐 Security Notes

### Environment Variables

**Create `.env` file:**
```bash
# LLM Providers (optional)
GEMINI_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here

# GitHub Integration (for PR creation)
GITHUB_TOKEN=ghp_your_token_here
GITHUB_REPO=owner/repo

# Notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### Network Security

The platform runs on localhost by default. To expose externally:

```yaml
ports:
  - "0.0.0.0:8000:8000"  # Accessible from any IP
  # OR
  - "127.0.0.1:8000:8000"  # Localhost only (more secure)
```

## 📚 Additional Resources

- **Main README:** [README.md](./README.md)
- **Testing Guide:** [TESTING-SUMMARY.md](./TESTING-SUMMARY.md)
- **API Documentation:** http://localhost:8000/docs (when running)
- **Correlation Engine:** [correlation-engine/README.md](./correlation-engine/README.md)

## 🆘 Still Having Issues?

1. **Check Docker Desktop is running** (most common issue!)
2. Review logs: `docker compose logs -f`
3. Try a fresh start: `docker compose down -v && docker compose up -d`
4. Check system resources (RAM, disk space)
5. Verify network connectivity (for pulling images)

**For Windows users:**
- Ensure WSL2 is installed and up-to-date
- Docker Desktop should use WSL2 backend
- Check Windows Defender/Firewall isn't blocking Docker

**For Mac users:**
- Ensure you've granted Docker Desktop required permissions
- Check in System Preferences → Security & Privacy

## ✅ Success Checklist

- [ ] Docker Desktop installed and running
- [ ] Can run `docker ps` without errors
- [ ] Services start: `docker compose up -d`
- [ ] Health check passes: `curl http://localhost:8000/health`
- [ ] Dashboard loads: http://localhost:8000/api/v1/e2e/dashboard
- [ ] Can scan test app successfully

Once all items are checked, you're ready to scan your applications! 🎉
