# ⚡ Quick Reference Card - Security Automation Platform

**Everything you need on one page!**

---

## 🚀 Quick Start (Copy-Paste Ready)

```bash
# 1. Start the platform
cd security-automation-platform
docker-compose up -d

# 2. Wait and check health (wait 60 seconds)
sleep 60 && curl http://localhost:8000/health

# 3. Open in browser
open http://localhost:8000/docs
```

---

## 🌐 Key URLs

| Service | URL | Purpose |
|---------|-----|---------|
| **API Docs** | http://localhost:8000/docs | Interactive API documentation |
| **API Root** | http://localhost:8000/ | API information |
| **Health** | http://localhost:8000/health | System health check |
| **LLM Status** | http://localhost:8000/api/llm/status | AI model status |
| **Ollama** | http://localhost:11434/ | LLM service |

---

## 📖 Documentation Files

| File | What's Inside |
|------|---------------|
| **HOW-TO-RUN.md** | 📘 Complete guide (500+ lines) - **START HERE!** |
| **PROJECT-SUMMARY.md** | 📋 Quick overview and verification results |
| **SYSTEM-STATUS-REPORT.md** | 🔍 Technical verification report |
| **README.md** | 📖 Project overview and features |
| **ARCHITECTURE.md** | 🏗️ System architecture |

---

## ⚡ Essential Commands

### Docker Operations
```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Restart
docker-compose restart

# Logs
docker-compose logs -f

# Status
docker ps
```

### Health Checks
```bash
# API health
curl http://localhost:8000/health

# LLM status
curl http://localhost:8000/api/llm/status

# Container status
docker ps
```

### API Usage
```bash
# Scan application
docker exec security-correlation python api_client.py scan /target-app

# Get vulnerabilities
curl http://localhost:8000/api/vulnerabilities

# View dashboard
curl http://localhost:8000/api/dashboard > dashboard.html

# Generate patch
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_id": "YOUR_VULN_ID"}'
```

### Git Operations
```bash
# List branches
git branch -a

# Switch to test branch
git checkout test-examples

# Back to main
git checkout main
```

---

## 🎯 Common Tasks

### Task 1: Run a Scan
```bash
docker exec security-correlation python api_client.py scan /target-app
curl http://localhost:8000/api/vulnerabilities
```

### Task 2: Generate Patches
```bash
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_id": "sql-injection-1"}'
```

### Task 3: View Results
```bash
curl http://localhost:8000/api/dashboard > dashboard.html
open dashboard.html
```

### Task 4: Test with Example App
```bash
git checkout test-examples
docker-compose restart
docker exec security-correlation python api_client.py scan /target-app
```

---

## 🐛 Troubleshooting

### Problem: Services won't start
```bash
docker-compose down -v
docker-compose up -d
```

### Problem: API not responding
```bash
docker-compose restart correlation-engine
docker logs -f security-correlation
```

### Problem: Out of memory
```bash
# Check usage
docker stats

# Fix: Increase Docker memory to 12GB in Docker Desktop
# Settings > Resources > Memory > 12GB
```

### Problem: Port already in use
```bash
# Windows
netstat -ano | findstr :8000

# Linux/Mac
lsof -i :8000

# Then kill the process or change port in docker-compose.yml
```

---

## 📊 System Status

### Current Status ✅
- ✅ Docker services: Running
- ✅ API: Healthy (http://localhost:8000/health)
- ✅ LLM: Operational (DeepSeek Coder)
- ✅ Documentation: Complete

### Branches Available
- **main** ⭐ - Production ready
- **test-examples** - Sample vulnerable app
- **docs** - Extended documentation

---

## 💡 Quick Tips

1. **First time?** → Read `HOW-TO-RUN.md`
2. **Need help?** → Check troubleshooting section
3. **Want examples?** → `git checkout test-examples`
4. **API reference?** → http://localhost:8000/docs
5. **Something broken?** → `docker-compose restart`

---

## 🎓 What This Platform Does

- 🔍 **Scans** your code for vulnerabilities
- 🤖 **Generates** AI-powered patches using DeepSeek
- ✅ **Tests** patches automatically
- 📊 **Creates** interactive dashboards
- 🔄 **Integrates** with CI/CD pipelines
- 📢 **Notifies** via Slack/Email/GitHub

---

## 📞 Need More Help?

1. **Documentation:** Read `HOW-TO-RUN.md` (detailed guide)
2. **Logs:** `docker-compose logs -f` (see what's happening)
3. **Restart:** `docker-compose restart` (fix most issues)
4. **Reset:** `docker-compose down -v && docker-compose up -d` (nuclear option)

---

## ✅ Verification Checklist

Before asking for help, verify:
- [ ] Docker is running (`docker ps`)
- [ ] Services are up (`docker-compose ps`)
- [ ] API is healthy (`curl http://localhost:8000/health`)
- [ ] Logs show no errors (`docker-compose logs`)

---

**Keep this card handy! 📋**

*Last Updated: October 27, 2025*
