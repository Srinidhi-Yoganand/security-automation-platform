# 🎯 How to Add Vulnerable Applications for Scanning

This guide explains how to add new vulnerable applications to the security automation platform for comprehensive SAST + DAST + IAST scanning.

---

## 📋 Prerequisites

1. Docker and Docker Compose installed
2. Security automation platform running (`docker-compose up -d`)
3. Vulnerable application source code or running instance

---

## 🚀 Method 1: Add Docker-Based Vulnerable App

### Step 1: Add to docker-compose.yml

```yaml
services:
  # Add your vulnerable app
  your-app:
    image: vulnerable/app-image:latest
    # OR build from source:
    build: ./path-to-your-app
    container_name: your-app
    networks:
      - security-automation-network
    ports:
      - "8080:8080"
    environment:
      - APP_ENV=development
    volumes:
      - ./your-app-source:/app
```

**Key Requirements:**
- ✅ Must be on `security-automation-network` (for DAST/IAST access)
- ✅ Expose necessary ports
- ✅ Mount source code as volume (for SAST access)

### Step 2: Copy Source Code to Correlation Engine

```bash
# Start your app
docker-compose up -d your-app

# Copy source to correlation engine for SAST
docker cp ./your-app-source security-correlation-engine:/tmp/your-app
```

### Step 3: Run Combined Scan

```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/your-app",
    "target_url": "http://your-app:8080",
    "max_vulnerabilities": 50,
    "correlation_threshold": 2,
    "enable_sast": true,
    "enable_dast": true,
    "enable_iast": true,
    "generate_patches": true
  }'
```

---

## 🌐 Method 2: Add Remote Vulnerable App (External URL)

### Step 1: Copy Source Code Only

```bash
# Copy source code to correlation engine
docker cp /path/to/source security-correlation-engine:/tmp/remote-app
```

### Step 2: Run Scan with External URL

```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/remote-app",
    "target_url": "https://external-vulnerable-app.com",
    "max_vulnerabilities": 50,
    "correlation_threshold": 2,
    "enable_sast": true,
    "enable_dast": true,
    "enable_iast": true,
    "generate_patches": true
  }'
```

**Note:** IAST may have limited effectiveness without local access.

---

## 📦 Method 3: Add From Git Repository

### Step 1: Clone Inside Container

```bash
docker exec security-correlation-engine bash -c "
  cd /tmp && \
  git clone https://github.com/username/vulnerable-app.git
"
```

### Step 2: Run Scan

```bash
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/vulnerable-app",
    "target_url": "http://your-app:8080",
    "max_vulnerabilities": 50
  }'
```

---

## 🔧 Example: Adding OWASP Juice Shop

### docker-compose.yml Addition:

```yaml
  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: juice-shop
    networks:
      - security-automation-network
    ports:
      - "3000:3000"
```

### Clone Source and Scan:

```bash
# Start Juice Shop
docker-compose up -d juice-shop

# Clone source into correlation engine
docker exec security-correlation-engine bash -c "
  cd /tmp && \
  git clone https://github.com/juice-shop/juice-shop.git
"

# Run combined scan
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/juice-shop",
    "target_url": "http://juice-shop:3000",
    "max_vulnerabilities": 100,
    "correlation_threshold": 2
  }' | jq '.results.summary'
```

---

## 🎯 Example: Current DVWA Setup

```yaml
# docker-compose.yml (already configured)
services:
  dvwa-app:
    image: vulnerables/web-dvwa:latest
    container_name: dvwa-app
    networks:
      - security-automation-network
    ports:
      - "80:80"
```

```bash
# Source already copied to /tmp/DVWA in correlation-engine

# Scan command
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/tmp/DVWA",
    "target_url": "http://dvwa-app/login.php",
    "max_vulnerabilities": 30,
    "correlation_threshold": 2
  }'
```

---

## 📊 Understanding Scan Parameters

### Required Parameters:
- `source_path`: Path to source code inside correlation-engine container
- `target_url`: Running application URL (must be accessible from containers)

### Optional Parameters:
- `max_vulnerabilities`: Max vulns to process (default: 10, -1 for all)
- `correlation_threshold`: Min modes to detect vuln for high confidence (default: 2)
- `enable_sast`: Enable static analysis (default: true)
- `enable_dast`: Enable dynamic scanning (default: true)
- `enable_iast`: Enable runtime testing (default: true)
- `generate_patches`: Generate fixes for high-confidence vulns (default: true)

---

## 🔍 Verification Checklist

After adding a new app, verify:

1. **Network Connectivity**
   ```bash
   docker exec security-correlation-engine curl -I http://your-app:port
   ```

2. **Source Code Access**
   ```bash
   docker exec security-correlation-engine ls -la /tmp/your-app
   ```

3. **ZAP Can Reach App**
   ```bash
   docker exec security-zap-scanner curl -I http://your-app:port
   ```

4. **Run Test Scan**
   ```bash
   curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
     -H "Content-Type: application/json" \
     -d '{"source_path": "/tmp/your-app", "target_url": "http://your-app:port", "max_vulnerabilities": 5}'
   ```

---

## 🎓 Common Issues & Solutions

### Issue 1: "Source path not found"
**Solution:** Copy source code to correlation-engine:
```bash
docker cp ./source security-correlation-engine:/tmp/your-app
```

### Issue 2: "Connection refused" (DAST/IAST)
**Solution:** Ensure app is on correct network:
```bash
docker network connect security-automation-network your-app
```

### Issue 3: "IAST finds 0 vulnerabilities"
**Solution:** Check if app requires authentication. Update IAST code in `e2e_routes.py` with app-specific login credentials.

### Issue 4: "ZapUnknownHostException"
**Solution:** Verify hostname resolution:
```bash
docker exec security-zap-scanner ping -c 1 your-app
```

---

## 📁 Directory Structure

```
security-automation-platform/
├── docker-compose.yml          # Add your app here
├── vulnerable-apps/            # Store downloaded apps
│   ├── dvwa/
│   ├── juice-shop/
│   └── your-app/
└── correlation-engine/
    └── /tmp/                   # Apps copied here for scanning
        ├── DVWA/
        └── your-app/
```

---

## 🚀 Quick Start Template

```bash
#!/bin/bash
# add-vulnerable-app.sh

APP_NAME="your-app"
APP_PORT="8080"
APP_SOURCE="./vulnerable-apps/$APP_NAME"

# 1. Add to docker-compose (manual step)
echo "Add to docker-compose.yml:"
echo "
  $APP_NAME:
    image: your-image
    networks:
      - security-automation-network
    ports:
      - \"$APP_PORT:$APP_PORT\"
"

# 2. Start app
docker-compose up -d $APP_NAME

# 3. Copy source
docker cp $APP_SOURCE security-correlation-engine:/tmp/$APP_NAME

# 4. Verify connectivity
docker exec security-correlation-engine curl -I http://$APP_NAME:$APP_PORT

# 5. Run scan
curl -X POST http://localhost:8000/api/v1/e2e/combined-scan \
  -H "Content-Type: application/json" \
  -d "{
    \"source_path\": \"/tmp/$APP_NAME\",
    \"target_url\": \"http://$APP_NAME:$APP_PORT\",
    \"max_vulnerabilities\": 50,
    \"correlation_threshold\": 2
  }" | jq '.results.summary'
```

---

## 📈 Expected Results

After successful setup, you should see:

```json
{
  "total_vulnerabilities": 25,
  "sast_findings": 15,
  "dast_findings": 18,
  "iast_findings": 5,
  "very_high_confidence": 2,
  "high_confidence": 5,
  "medium_confidence": 8,
  "low_confidence": 10,
  "false_positive_reduction": "85.3%",
  "patches_generated": 7
}
```

✅ Multiple modes finding vulnerabilities
✅ Correlation reducing false positives
✅ High-confidence vulnerabilities identified
✅ Patches generated for confirmed issues

---

## 🎯 Next Steps

Once scanning works:
1. Review high-confidence vulnerabilities
2. Examine generated patches in `/app/data/patches/`
3. Test patches with validation endpoint
4. Create pull requests for fixes

See `PATCH-GENERATION-GUIDE.md` for next steps!
