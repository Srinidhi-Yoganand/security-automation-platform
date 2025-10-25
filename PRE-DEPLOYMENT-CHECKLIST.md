# 🚀 Pre-Deployment Checklist

## Prerequisites

### 1. Docker Installation
- [ ] **Docker Desktop installed** (Windows/Mac) or Docker Engine (Linux)
- [ ] **Docker version**: 20.10+ recommended
- [ ] **Docker Compose version**: 2.0+ recommended
- [ ] **Docker daemon running**: `docker ps` should work

```bash
# Verify Docker
docker --version
docker-compose --version
docker ps
```

### 2. System Requirements
- [ ] **RAM**: Minimum 16GB (8GB for Ollama, 4GB for services, 4GB for OS)
- [ ] **Disk Space**: Minimum 20GB free (for Docker images + models)
- [ ] **CPU**: 4+ cores recommended
- [ ] **Internet**: Required for initial setup (downloading images/models)

### 3. Ports Available
- [ ] **Port 8000**: Correlation Engine API
- [ ] **Port 8080**: Vulnerable App (testing)
- [ ] **Port 11434**: Ollama LLM Service

```bash
# Check if ports are free (Windows)
netstat -ano | findstr "8000 8080 11434"

# Check if ports are free (Linux/Mac)
lsof -i :8000
lsof -i :8080
lsof -i :11434
```

---

## File Verification

### 1. Docker Configuration Files
```bash
# All these files must exist:
ls -lh docker-compose.yml
ls -lh correlation-engine/Dockerfile
ls -lh vulnerable-app/Dockerfile
ls -lh test-docker-deployment.sh
```

✅ **Expected**: All 4 files present

### 2. Application Code
```bash
# Core services must exist:
ls -lh correlation-engine/app/main.py
ls -lh correlation-engine/app/services/patcher/llm_patch_generator.py
ls -lh correlation-engine/app/services/notifications.py
ls -lh correlation-engine/app/services/dashboard_generator.py
```

✅ **Expected**: All files present (25KB+ each)

### 3. Dependencies
```bash
# Verify requirements.txt includes Phase 3 dependencies:
grep -E "(ollama|google-generativeai|javalang)" correlation-engine/requirements.txt
```

✅ **Expected Output**:
```
google-generativeai==0.8.5
ollama==0.6.0
javalang==0.13.0
diff-match-patch==20230430
```

### 4. Test Scripts
```bash
# Verify test files:
ls -1 correlation-engine/test_*.py | wc -l
```

✅ **Expected**: 11 test scripts

### 5. Documentation
```bash
# Verify documentation:
ls -1 *.md | grep -E "(PHASE3|DOCKER|NOTIFICATION)"
```

✅ **Expected**: 7+ markdown files

---

## Deployment Steps

### Step 1: Start Docker Desktop
**Windows/Mac**: Launch Docker Desktop application and wait for it to fully start

**Linux**: 
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

**Verify**:
```bash
docker ps
# Should show empty list or running containers (not an error)
```

### Step 2: Build Images
```bash
cd /path/to/security-automation-platform

# Build all images
docker-compose build

# Expected: 2-5 minutes
# Should complete without errors
```

✅ **Success Indicators**:
- ✅ `Successfully built` messages
- ✅ `Successfully tagged` messages
- ❌ No `ERROR` messages

### Step 3: Start Services
```bash
# Start all services in background
docker-compose up -d

# Watch logs (optional)
docker-compose logs -f
```

✅ **Expected Output**:
```
Creating network "security-automation-network" ... done
Creating volume "security-ollama-models" ... done
Creating volume "security-correlation-data" ... done
Creating security-ollama ... done
Creating security-vulnerable-app ... done
Creating security-correlation ... done
```

### Step 4: Wait for Services
```bash
# This takes 2-5 minutes on first run
# Ollama will download deepseek-coder:6.7b-instruct (3.8GB)

# Watch Ollama download progress:
docker logs -f security-ollama

# Watch Correlation Engine startup:
docker logs -f security-correlation
```

✅ **Ready when you see**:
- Ollama: `Listening on [::]:11434`
- Correlation Engine: `Uvicorn running on http://0.0.0.0:8000`
- Vulnerable App: `Started VulnerableAppApplication`

### Step 5: Verify Health
```bash
# Check all containers running:
docker ps

# Should show 3 containers:
# - security-ollama
# - security-correlation
# - security-vulnerable-app
```

### Step 6: Test Endpoints
```bash
# Test Ollama:
curl http://localhost:11434/api/tags

# Test API Health:
curl http://localhost:8000/health

# Test API Docs:
curl http://localhost:8000/docs

# Test Vulnerable App:
curl http://localhost:8080
```

✅ **All should return 200 OK**

### Step 7: Test LLM Integration
```bash
# Check LLM provider status:
curl http://localhost:8000/api/llm/status

# Should return:
# {
#   "provider": "ollama",
#   "status": "operational",
#   "ollama_models": ["deepseek-coder:6.7b-instruct"]
# }
```

### Step 8: Access Dashboard
Open browser to: **http://localhost:8000/dashboard**

✅ **Should see**: Security Dashboard with vulnerability findings

---

## Optional Configuration

### 1. Slack Notifications (Optional)
```bash
# Create .env file in correlation-engine/
cat > correlation-engine/.env << EOF
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
EOF
```

See `NOTIFICATION-SETUP.md` for complete setup.

### 2. Email Notifications (Optional)
```bash
# Add to .env:
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
NOTIFICATION_EMAIL=alerts@yourcompany.com
```

### 3. GitHub Integration (Optional)
```bash
# Add to .env:
GITHUB_TOKEN=ghp_YourPersonalAccessToken
GITHUB_REPO=owner/repo
```

---

## Troubleshooting

### Issue 1: Docker Daemon Not Running
**Error**: `Cannot connect to the Docker daemon`

**Solution**:
- **Windows/Mac**: Launch Docker Desktop application
- **Linux**: `sudo systemctl start docker`

### Issue 2: Port Already in Use
**Error**: `Bind for 0.0.0.0:8000 failed: port is already allocated`

**Solution**:
```bash
# Find process using port (Windows):
netstat -ano | findstr :8000

# Find process using port (Linux/Mac):
lsof -i :8000

# Kill process or change port in docker-compose.yml
```

### Issue 3: Out of Memory
**Error**: Container crashes or `docker: Error response from daemon: OCI runtime create failed`

**Solution**:
- Increase Docker memory limit in Docker Desktop settings
- Minimum 12GB allocated to Docker
- Close other memory-intensive applications

### Issue 4: Ollama Model Download Fails
**Error**: `failed to pull model` or connection timeout

**Solution**:
```bash
# Download model manually:
docker exec -it security-ollama ollama pull deepseek-coder:6.7b-instruct

# Or use alternative model:
docker exec -it security-ollama ollama pull codellama:7b-instruct
```

### Issue 5: Build Fails
**Error**: Various build errors

**Solution**:
```bash
# Clean rebuild:
docker-compose down -v
docker system prune -a
docker-compose build --no-cache
docker-compose up -d
```

---

## Verification Commands

### Quick Health Check
```bash
#!/bin/bash
echo "=== Docker Services ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo -e "\n=== API Health ==="
curl -s http://localhost:8000/health | jq

echo -e "\n=== LLM Status ==="
curl -s http://localhost:8000/api/llm/status | jq

echo -e "\n=== Ollama Models ==="
curl -s http://localhost:11434/api/tags | jq

echo -e "\n=== All systems operational! ==="
```

### Generate Test Report
```bash
# Run comprehensive tests:
docker exec security-correlation python test_all_vulnerabilities.py
```

---

## Production Readiness

### Before Going to Production:

- [ ] **Security**: Change all default passwords/keys
- [ ] **HTTPS**: Set up SSL/TLS certificates
- [ ] **Reverse Proxy**: Use Nginx/Traefik for load balancing
- [ ] **Monitoring**: Set up Prometheus/Grafana
- [ ] **Logging**: Configure centralized logging (ELK stack)
- [ ] **Backups**: Set up automated database backups
- [ ] **Updates**: Plan for regular security updates
- [ ] **Access Control**: Implement authentication/authorization
- [ ] **Rate Limiting**: Add API rate limiting
- [ ] **Secrets Management**: Use proper secrets management (Vault, AWS Secrets Manager)

### Production Deployment Options:

1. **Cloud Kubernetes** (AWS EKS, GCP GKE, Azure AKS)
2. **Docker Swarm** (simple orchestration)
3. **VM Deployment** (traditional approach)
4. **Serverless** (API Gateway + Lambda/Cloud Functions)

See documentation for deployment guides.

---

## Quick Start Commands

### Start Everything:
```bash
docker-compose up -d
```

### Stop Everything:
```bash
docker-compose down
```

### View Logs:
```bash
docker-compose logs -f
```

### Restart Service:
```bash
docker-compose restart correlation-engine
```

### Clean Everything:
```bash
docker-compose down -v
docker system prune -a
```

---

## Success Criteria

✅ **Deployment is successful when**:

1. ✅ All 3 containers running: `docker ps` shows 3 containers
2. ✅ Health checks passing: `curl http://localhost:8000/health` returns 200
3. ✅ LLM operational: Status shows `"provider": "ollama"`
4. ✅ Dashboard accessible: http://localhost:8000/dashboard loads
5. ✅ Patch generation works: Can generate patches from dashboard
6. ✅ No error logs: `docker-compose logs` shows no critical errors

---

## Support

- **Documentation**: See `DOCKER-DEPLOYMENT.md` for detailed guide
- **LLM Setup**: See `OLLAMA-SETUP.md` for Ollama configuration
- **Notifications**: See `NOTIFICATION-SETUP.md` for alert setup
- **Quick Start**: See `QUICKSTART-LLM-PATCHING.md` for usage guide
- **Complete Report**: See `PHASE3-COMPLETE-REPORT.md` for all features

---

**Estimated Time**:
- First deployment: 10-15 minutes (includes model download)
- Subsequent starts: 1-2 minutes
