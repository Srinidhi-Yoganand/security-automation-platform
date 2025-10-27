# 🚀 How to Run the Security Automation Platform

**Complete Guide to Setup, Run, and Use the Platform**

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Understanding the Platform](#understanding-the-platform)
4. [Running the Application](#running-the-application)
5. [Testing the System](#testing-the-system)
6. [Using Different Branches](#using-different-branches)
7. [API Usage](#api-usage)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Usage](#advanced-usage)

---

## Prerequisites

### Required Software

1. **Docker Desktop** (Windows/Mac) or **Docker Engine** (Linux)
   - Download: https://www.docker.com/products/docker-desktop
   - Minimum: 8GB RAM allocated to Docker
   - Recommended: 12GB RAM for optimal LLM performance

2. **Git**
   - Download: https://git-scm.com/downloads

3. **curl** (for API testing)
   - Usually pre-installed on Linux/Mac
   - Windows: Use Git Bash or install via Chocolatey

### Optional Tools

- **Postman** or **Insomnia** - For easier API testing
- **VS Code** - For code editing
- **Python 3.9+** - For local development (not needed for Docker usage)

---

## Quick Start

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Srinidhi-Yoganand/security-automation-platform.git
cd security-automation-platform
```

### 2️⃣ Start Docker Desktop

- **Windows/Mac**: Open Docker Desktop and wait for it to start (green icon in taskbar)
- **Linux**: `sudo systemctl start docker`

### 3️⃣ Start the Platform

```bash
# Start all services
docker-compose up -d

# First time: Takes 10-15 minutes (downloads ~6GB)
# Subsequent starts: 1-2 minutes
```

### 4️⃣ Verify It's Running

```bash
# Check services status
docker ps

# You should see 2 containers:
# - security-correlation (API server)
# - security-ollama (LLM service)

# Check API health
curl http://localhost:8000/health
# Expected: {"status":"healthy","version":"0.1.0"}
```

### 5️⃣ Access the Platform

- **API Documentation**: http://localhost:8000/docs (Swagger UI)
- **API Root**: http://localhost:8000/
- **Health Check**: http://localhost:8000/health
- **LLM Status**: http://localhost:8000/api/llm/status

---

## Understanding the Platform

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Environment                        │
│                                                              │
│  ┌──────────────────┐         ┌────────────────────┐       │
│  │  Ollama LLM      │         │  Correlation       │       │
│  │  (DeepSeek)      │◄────────┤  Engine (API)      │       │
│  │  Port: 11434     │         │  Port: 8000        │       │
│  └──────────────────┘         └────────────────────┘       │
│                                         │                    │
│                                         ▼                    │
│                              ┌──────────────────┐           │
│                              │  Your App        │           │
│                              │  (mounted)       │           │
│                              └──────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

### Components

1. **Correlation Engine** (`security-correlation`)
   - FastAPI-based REST API
   - Parses security scan results (Semgrep, CodeQL, ZAP)
   - Correlates findings across tools
   - Generates AI-powered patches
   - Creates interactive dashboards

2. **Ollama LLM Service** (`security-ollama`)
   - Runs DeepSeek Coder model locally
   - Provides AI capabilities for patch generation
   - No external API keys needed

3. **Your Application** (mounted volume)
   - Any application you want to scan
   - Mounted at `/target-app` in containers

---

## Running the Application

### Standard Workflow

#### Step 1: Start Services

```bash
cd security-automation-platform
docker-compose up -d
```

**Wait for services to be healthy:**
```bash
# Watch logs
docker-compose logs -f

# Wait for this message:
# "✅ Platform Ready!"
```

#### Step 2: Scan Your Application

**Option A: Scan the current directory (default)**
```bash
docker exec security-correlation python api_client.py scan /target-app
```

**Option B: Scan a specific application**
```bash
# Set path to YOUR application
export TARGET_APP_PATH=/path/to/your/java/app

# Restart to mount your app
docker-compose down
docker-compose up -d

# Scan it
docker exec security-correlation python api_client.py scan /target-app
```

**Option C: Use the API**
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/target-app", "tools": ["semgrep"]}'
```

#### Step 3: View Results

**View Dashboard:**
```bash
curl http://localhost:8000/api/dashboard > dashboard.html
open dashboard.html  # or double-click the file
```

**Get Vulnerabilities JSON:**
```bash
curl http://localhost:8000/api/vulnerabilities | python -m json.tool
```

#### Step 4: Generate Patches

**Generate patch for a specific vulnerability:**
```bash
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_id": "sql-injection-1"}'
```

**Response includes:**
- Original vulnerable code
- Patched code
- Explanation of the fix
- Confidence score

#### Step 5: Apply Patches

```bash
curl -X POST http://localhost:8000/api/patches/apply \
  -H "Content-Type: application/json" \
  -d '{"patch_id": "patch-123"}'
```

---

## Testing the System

### Quick Health Check

```bash
# API health
curl http://localhost:8000/health

# LLM status
curl http://localhost:8000/api/llm/status

# Check Ollama models
curl http://localhost:11434/api/tags
```

### Test with Example Vulnerable App

The platform includes test branches with vulnerable applications:

```bash
# Switch to test-examples branch
git checkout test-examples

# Restart with the vulnerable app
docker-compose down
docker-compose up -d

# Scan the sample vulnerable app
docker exec security-correlation python api_client.py scan /target-app

# View results
curl http://localhost:8000/api/dashboard > test-dashboard.html
```

### Run Automated Tests

```bash
cd correlation-engine

# Test API
python test_api.py

# Test patch generation
python test_patches.py

# Test LLM providers
python test_llm_providers.py

# Test all vulnerabilities
python test_all_vulnerabilities.py
```

---

## Using Different Branches

### Available Branches

1. **`main`** - Production-ready stable version
2. **`test-examples`** - Includes sample vulnerable Java app
3. **`docs`** - Extended documentation

### Switching Branches

```bash
# View all branches
git branch -a

# Switch to test-examples
git checkout test-examples

# Switch back to main
git checkout main

# Always restart containers after switching
docker-compose down
docker-compose up -d
```

---

## API Usage

### Core Endpoints

#### 1. Health Check
```bash
GET /health
curl http://localhost:8000/health
```

#### 2. Scan Application
```bash
POST /api/scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/target-app",
    "tools": ["semgrep", "codeql"],
    "severity_filter": "high"
  }'
```

#### 3. Get Vulnerabilities
```bash
GET /api/vulnerabilities
curl http://localhost:8000/api/vulnerabilities

# Filter by severity
curl "http://localhost:8000/api/vulnerabilities?severity=critical"

# Filter by tool
curl "http://localhost:8000/api/vulnerabilities?tool=semgrep"
```

#### 4. Generate Patch
```bash
POST /api/patches/generate
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_id": "sql-injection-1",
    "provider": "ollama"
  }'
```

#### 5. Apply Patch
```bash
POST /api/patches/apply
curl -X POST http://localhost:8000/api/patches/apply \
  -H "Content-Type: application/json" \
  -d '{
    "patch_id": "patch-123",
    "dry_run": false
  }'
```

#### 6. Get Dashboard
```bash
GET /api/dashboard
curl http://localhost:8000/api/dashboard > dashboard.html
```

#### 7. Compare Results
```bash
POST /api/compare
curl -X POST http://localhost:8000/api/compare \
  -H "Content-Type: application/json" \
  -d '{
    "before_scan_id": "scan-1",
    "after_scan_id": "scan-2"
  }'
```

### Using the Python Client

```python
from api_client import SecurityAutomationClient

# Initialize client
client = SecurityAutomationClient(base_url="http://localhost:8000")

# Health check
health = client.health_check()
print(health)

# Scan application
scan_result = client.scan_application(
    path="/target-app",
    tools=["semgrep"]
)

# Get vulnerabilities
vulns = client.get_vulnerabilities()

# Generate patch
patch = client.generate_patch(vuln_id="sql-injection-1")

# Apply patch
result = client.apply_patch(patch_id="patch-123")
```

---

## Troubleshooting

### Common Issues

#### 1. Services Not Starting

```bash
# Check Docker is running
docker info

# Check logs
docker-compose logs

# Restart services
docker-compose restart

# Clean restart
docker-compose down
docker-compose up -d
```

#### 2. Port Already in Use

```bash
# Check what's using port 8000
netstat -ano | findstr :8000  # Windows
lsof -i :8000                 # Linux/Mac

# Kill the process or change port in docker-compose.yml
```

#### 3. Ollama Models Not Loading

```bash
# Check Ollama logs
docker logs security-ollama

# Pull model manually
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct

# Check available models
docker exec security-ollama ollama list
```

#### 4. API Returns Errors

```bash
# Check correlation engine logs
docker logs security-correlation

# Restart the service
docker-compose restart correlation-engine

# Check health status
curl http://localhost:8000/health
```

#### 5. Out of Memory

```bash
# Check Docker memory allocation
docker stats

# Increase memory in Docker Desktop:
# Settings > Resources > Memory > 12GB (recommended)

# Or reduce Ollama memory in docker-compose.yml
```

#### 6. Slow Response Times

**First time starting:**
- Ollama needs to download the model (~4GB)
- Takes 10-15 minutes

**During patch generation:**
- LLM processing takes 30-60 seconds per patch
- This is normal for local AI models

```bash
# Check LLM status
curl http://localhost:8000/api/llm/status

# Monitor Ollama
docker logs -f security-ollama
```

---

## Advanced Usage

### Custom Configuration

#### Environment Variables

Create a `.env` file:

```bash
# Target application path
TARGET_APP_PATH=./my-java-app

# LLM Provider (ollama, openai, gemini)
LLM_PROVIDER=ollama

# Optional: API keys for cloud LLMs
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...

# Ollama configuration
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=deepseek-coder:6.7b-instruct
```

#### Custom Ollama Models

```bash
# Enter Ollama container
docker exec -it security-ollama bash

# List available models
ollama list

# Pull a different model
ollama pull codellama:7b

# Exit container
exit

# Update docker-compose.yml to use the new model
# environment:
#   - OLLAMA_MODEL=codellama:7b
```

### Scanning Different Languages

The platform supports multiple languages:

```yaml
# Java
tools: ["semgrep", "codeql"]

# Python
tools: ["semgrep", "bandit"]

# JavaScript/TypeScript
tools: ["semgrep", "eslint"]

# Multiple languages
tools: ["semgrep"]  # Supports 30+ languages
```

### CI/CD Integration

#### GitHub Actions

Add to `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start Security Platform
        run: |
          docker-compose up -d
          sleep 60  # Wait for services
      
      - name: Scan Application
        run: |
          docker exec security-correlation \
            python api_client.py scan /target-app
      
      - name: Generate Report
        run: |
          curl http://localhost:8000/api/dashboard \
            > security-report.html
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.html
```

### Local Development

#### Run Without Docker

```bash
cd correlation-engine

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Run server
python run_server.py

# Access at http://localhost:8000
```

#### Run Ollama Separately

```bash
# Install Ollama locally
# https://ollama.ai/download

# Pull model
ollama pull deepseek-coder:6.7b-instruct

# Run server (starts automatically on port 11434)
ollama serve

# Update environment
export OLLAMA_HOST=http://localhost:11434
```

---

## Maintenance

### Stop Services

```bash
# Stop all services
docker-compose down

# Stop but keep volumes (preserves data)
docker-compose stop
```

### Update Platform

```bash
# Pull latest code
git pull origin main

# Pull latest Docker images
docker-compose pull

# Restart services
docker-compose down
docker-compose up -d
```

### Clean Up

```bash
# Remove all containers and volumes
docker-compose down -v

# Remove all unused Docker data
docker system prune -a

# Free up space (removes everything!)
docker system prune -a --volumes
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker logs -f security-correlation
docker logs -f security-ollama

# Last N lines
docker logs --tail 100 security-correlation
```

---

## Performance Tips

1. **Allocate Sufficient RAM**
   - Minimum: 8GB
   - Recommended: 12GB
   - Optimal: 16GB+

2. **Use SSD Storage**
   - Models load faster
   - Better I/O performance

3. **Close Other Applications**
   - Free up RAM for Docker
   - Especially during first startup

4. **Pre-pull Models**
   ```bash
   docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct
   ```

5. **Use Smaller Models** (if needed)
   ```bash
   # Change in docker-compose.yml:
   OLLAMA_MODEL=deepseek-coder:1.3b-instruct  # Faster, less accurate
   ```

---

## Getting Help

### Documentation

- **Main README**: [README.md](./README.md)
- **Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)
- **API Docs**: [correlation-engine/API-DOCS.md](./correlation-engine/API-DOCS.md)
- **Quick Deploy**: [docs/guides/QUICK-DEPLOY.md](./docs/guides/QUICK-DEPLOY.md)

### Support Channels

- **GitHub Issues**: https://github.com/Srinidhi-Yoganand/security-automation-platform/issues
- **GitHub Discussions**: https://github.com/Srinidhi-Yoganand/security-automation-platform/discussions

### Debug Mode

```bash
# Enable debug logging
docker-compose down
export LOG_LEVEL=DEBUG
docker-compose up -d

# View detailed logs
docker logs -f security-correlation
```

---

## Summary Commands Cheat Sheet

```bash
# Quick Start
docker-compose up -d

# Health Check
curl http://localhost:8000/health

# Scan
docker exec security-correlation python api_client.py scan /target-app

# View Dashboard
curl http://localhost:8000/api/dashboard > dashboard.html

# Generate Patch
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_id": "YOUR_VULN_ID"}'

# Stop
docker-compose down

# Logs
docker-compose logs -f

# Clean Everything
docker-compose down -v && docker system prune -a
```

---

## Next Steps

1. ✅ Start the platform
2. ✅ Run a scan on your application
3. ✅ View the dashboard
4. ✅ Generate AI patches
5. ✅ Test patches in a branch
6. ✅ Integrate with CI/CD

**Happy Scanning! 🔒🤖**
