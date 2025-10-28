# 🚀 Quick Reference Guide

## Instant Commands

### Start Everything
```bash
docker-compose up -d
```

### Stop Everything
```bash
docker-compose down
```

### Check Status
```bash
docker-compose ps
bash verify-system-clean.sh
```

### Run Full Scan
```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/DVWA",
    "target_url": "http://dvwa-app/login.php",
    "correlation_threshold": 1,
    "generate_patches": true
  }' | jq '{
    SAST: .results.raw_findings.sast | length,
    DAST: .results.raw_findings.dast | length,
    IAST: .results.raw_findings.iast | length,
    HIGH_CONFIDENCE: .high_confidence_vulns,
    PATCHES: .patches_generated
  }'
```

---

## Container Management

```bash
# Restart a service
docker restart security-correlation-engine

# View logs
docker logs security-correlation-engine --tail 50

# Execute command in container
docker exec security-correlation-engine ls /app/data/patches

# Free memory (stop SonarQube)
docker stop security-sonarqube
```

---

## Model Management

```bash
# List available models
docker exec security-ollama ollama list

# Pull DeepSeek Coder
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct

# Pull smaller model
docker exec security-ollama ollama pull qwen2.5-coder:1.5b

# Test model
docker exec security-ollama ollama run deepseek-coder:6.7b-instruct "Fix SQL injection: SELECT * FROM users WHERE id = '\$id'"
```

---

## Common Scan Variations

### Quick Scan (No Patches)
```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{"source_path": "/tmp/DVWA", "target_url": "http://dvwa-app/login.php", "generate_patches": false}'
```

### Strict Correlation (Only Multi-Mode Confirmed)
```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{"source_path": "/tmp/DVWA", "target_url": "http://dvwa-app/login.php", "correlation_threshold": 2, "generate_patches": true}'
```

### Maximum Coverage
```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{"source_path": "/tmp/DVWA", "target_url": "http://dvwa-app/login.php", "max_vulnerabilities": 100, "correlation_threshold": 0, "generate_patches": true}'
```

---

## Test Scripts

```bash
# Verify everything works
python verify-everything-working.py

# Test DeepSeek patch generation
python test-deepseek-patch.py

# Test multiple vulnerability types
python test-all-vulnerability-types.py

# Full demo
python demo-all-patch-capabilities.py

# System health check
bash verify-system-clean.sh
```

---

## View Results

```bash
# View generated patches
docker exec security-correlation-engine ls -lh /app/data/patches/

# Read a patch file
docker exec security-correlation-engine cat /app/data/patches/llm_patch_SQL_INJECTION_*.patch

# Copy patches to host
docker cp security-correlation-engine:/app/data/patches ./local-patches/
```

---

## Troubleshooting Commands

```bash
# Check memory usage
docker stats --no-stream

# Restart everything
docker-compose restart

# Clean restart (preserves data)
docker-compose down && docker-compose up -d

# Full reset (deletes everything)
docker-compose down -v && docker-compose up -d

# View all logs
docker-compose logs --tail=100

# Check network
docker network inspect security-automation-network
```

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/e2e/combined-scan` | POST | Full scan (SAST+DAST+IAST) |
| `/api/v1/e2e/sast-scan` | POST | Static analysis only |
| `/api/v1/e2e/dast-scan` | POST | Dynamic analysis only |
| `/api/v1/e2e/iast-scan` | POST | Runtime testing only |
| `/api/v1/health` | GET | Health check |
| `/docs` | GET | Swagger UI |

---

## Expected Results (DVWA)

```
Total Vulnerabilities: 24
├─ SAST: 10 (code patterns)
├─ DAST: 10 (web security)
└─ IAST: 4 (confirmed exploits)

After Correlation:
├─ High Confidence (threshold=2): 1
├─ High Confidence (threshold=1): 18
└─ All findings (threshold=0): 24

Confirmed Exploits:
1. SQL Injection (CRITICAL)
2. XSS (HIGH)
3. Command Injection (CRITICAL)
4. Path Traversal (CRITICAL)

Patches Generated: 1-4 (depending on threshold)
False Positive Reduction: 95%
```

---

## URLs

- **Correlation Engine API**: http://localhost:8000
- **Swagger Docs**: http://localhost:8000/docs
- **DVWA**: http://localhost
- **OWASP ZAP**: http://localhost:8080
- **Ollama API**: http://localhost:11434

---

## File Locations

- **Patches**: `/app/data/patches/` (in correlation-engine container)
- **Scan Results**: `/app/data/monitoring/` (in correlation-engine container)
- **DVWA Source**: `/tmp/DVWA` (in correlation-engine container)
- **DVWA Web**: `/var/www/html` (in dvwa-app container)

---

## Performance Tips

1. **Memory**: Allocate 10-12 GB to Docker for best performance
2. **Stop SonarQube**: If memory constrained, stop SonarQube container
3. **Use Smaller Model**: qwen2.5-coder:1.5b uses only 1 GB
4. **Limit Vulns**: Set `max_vulnerabilities: 20` for faster scans
5. **Parallel Scans**: Don't run multiple scans simultaneously

---

## One-Liner Setup

```bash
git clone https://github.com/Srinidhi-Yoganand/security-automation-platform.git && \
cd security-automation-platform && \
docker-compose up -d && \
sleep 120 && \
docker exec security-ollama ollama pull deepseek-coder:6.7b-instruct && \
bash verify-system-clean.sh
```

---

## Success Indicators

✅ All containers show "Up (healthy)"  
✅ `verify-system-clean.sh` shows all green  
✅ Scan finds 24 vulnerabilities  
✅ IAST confirms 4 exploits  
✅ DeepSeek generates patches  
✅ No errors in `docker-compose logs`

---

**🎯 Everything working? You're ready to scan!**
