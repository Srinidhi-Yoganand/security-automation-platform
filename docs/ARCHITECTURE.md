# 🏗️ Platform Architecture & Deployment

## What Gets Deployed vs What's for Testing

### ✅ **PRODUCTION DEPLOYMENT** (2 Services Only)

```
┌─────────────────────────────────────────────┐
│      PRODUCTION ARCHITECTURE                │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐    ┌──────────────────┐  │
│  │   Ollama     │    │  Correlation     │  │
│  │   (LLM)      │◄───┤  Engine          │  │
│  │              │    │  (Your Platform) │  │
│  │  Port: 11434 │    │  Port: 8000      │  │
│  └──────────────┘    └──────────────────┘  │
│                                             │
│  Volume: ollama_data (models)               │
│  Volume: correlation_data (database)        │
│                                             │
└─────────────────────────────────────────────┘
```

**Services to Deploy:**
1. **Ollama** - LLM service (DeepSeek Coder)
2. **Correlation Engine** - Your security automation platform

**What it does:**
- Scans **YOUR Java applications** (external)
- Generates AI-powered patches
- Provides dashboard and REST API
- Sends notifications

---

### 🧪 **TESTING ONLY** (NOT for Production)

```
┌─────────────────────────────────────────────┐
│      TESTING ARCHITECTURE (LOCAL ONLY)      │
├─────────────────────────────────────────────┤
│                                             │
│  ┌──────────────┐    ┌──────────────────┐  │
│  │   Ollama     │    │  Correlation     │  │
│  │   (LLM)      │◄───┤  Engine          │  │
│  │              │    │                  │  │
│  └──────────────┘    └──────────────────┘  │
│                                             │
│         ┌──────────────────────┐           │
│         │  Vulnerable App      │           │
│         │  (TEST TARGET)       │◄──────────┤
│         │  Port: 8080          │  Scanned  │
│         └──────────────────────┘           │
│                                             │
└─────────────────────────────────────────────┘
```

**Additional Service (LOCAL TESTING ONLY):**
3. **Vulnerable App** - Deliberately vulnerable Java app for testing

**Purpose:**
- Test vulnerability detection
- Test patch generation
- Demonstrate platform capabilities
- **NOT FOR PRODUCTION USE**

---

## 📦 Docker Hub Deployment Strategy

### What Gets Pushed to Docker Hub

**ONLY 1 Image:**
```bash
srinivas/security-automation:latest
```

This image contains:
- ✅ Correlation Engine (FastAPI API)
- ✅ LLM Patch Generator
- ✅ Notification Service
- ✅ Dashboard Generator
- ✅ All parsers (CodeQL, Semgrep, ZAP)
- ✅ Behavior analyzers

This image **DOES NOT** contain:
- ❌ Vulnerable test application
- ❌ Test data
- ❌ Development dependencies

---

## 🚀 Deployment Scenarios

### Scenario 1: Production (Scan External Apps)

**What you deploy:**
```yaml
services:
  ollama:
    image: ollama/ollama:latest
  
  correlation-engine:
    image: srinivas/security-automation:latest
    volumes:
      # Mount YOUR Java app here
      - /path/to/your/real/app:/app/target:ro
```

**How it works:**
1. Your real Java application sits on the host or another container
2. Security platform scans it via volume mount or API
3. Platform generates patches for YOUR code
4. You review and apply patches

### Scenario 2: Development/Testing

**What you deploy:**
```yaml
services:
  ollama:
    image: ollama/ollama:latest
  
  correlation-engine:
    build: ./correlation-engine  # Local build for dev
  
  vulnerable-app:
    build: ./vulnerable-app      # Test target
```

**How it works:**
1. Vulnerable app provides known vulnerabilities
2. Test patch generation on known issues
3. Validate platform features
4. NOT used in production

---

## 🔌 How "Pluggable" Works

### The Platform is Pluggable, NOT the Test App

**"Pluggable" means:**
- ✅ Your platform can scan **ANY external Java application**
- ✅ No need to include target app in Docker Compose
- ✅ Target app can be anywhere (same machine, network, cloud)

**Integration Methods:**

#### 1. Volume Mount (Same Machine)
```yaml
services:
  correlation-engine:
    image: srinivas/security-automation:latest
    volumes:
      - /path/to/customer/app:/app/target:ro
```

#### 2. REST API (Any Location)
```bash
# From customer's app
curl -X POST http://security-platform:8000/api/v1/scan \
  -F "file=@scan-results.sarif"
```

#### 3. Maven Plugin (Customer's Build)
```xml
<!-- Customer adds to their pom.xml -->
<plugin>
    <groupId>com.security.automation</groupId>
    <artifactId>security-maven-plugin</artifactId>
    <configuration>
        <apiEndpoint>http://your-platform:8000</apiEndpoint>
    </configuration>
</plugin>
```

#### 4. GitHub Actions (Customer's Repo)
```yaml
# Customer adds to their .github/workflows/
- name: Security Scan
  run: |
    curl http://your-platform:8000/api/v1/scan \
      -d @semgrep-results.sarif
```

#### 5. Sidecar Pattern (Kubernetes)
```yaml
# Customer's deployment
apiVersion: apps/v1
kind: Deployment
spec:
  containers:
    - name: customer-app
      image: customer/app:latest
    
    - name: security-scanner
      image: srinivas/security-automation:latest
```

---

## 📊 Comparison Table

| Component | Production | Testing | Docker Hub |
|-----------|------------|---------|------------|
| **Ollama** | ✅ Required | ✅ Required | ❌ Use official image |
| **Correlation Engine** | ✅ Required | ✅ Required | ✅ Push this |
| **Vulnerable App** | ❌ NOT included | ✅ For testing | ❌ Don't push |
| **Customer's App** | ✅ External | ❌ N/A | ❌ Not included |

---

## 🎯 What Gets Built & Pushed

### Build Command (ONE image only)
```bash
cd security-automation-platform

# Build ONLY the correlation engine
docker build -t srinivas/security-automation:latest \
  ./correlation-engine

# DO NOT build vulnerable-app for Docker Hub
# (it's only for local testing)
```

### Push Command
```bash
# Push ONLY the security platform
docker push srinivas/security-automation:latest

# DO NOT push vulnerable-app
# (users don't need it, it's YOUR test app)
```

---

## 🏢 Real-World Usage Example

### Company XYZ wants to use your platform:

**Step 1: They deploy your platform**
```bash
# Company XYZ runs:
docker-compose -f docker-compose-hub.yml up -d
```

**Step 2: They scan THEIR Java app**
```bash
# Company XYZ scans their own code:
curl -X POST http://localhost:8000/api/v1/scan \
  -F "source=@/their/app/src"
```

**Step 3: Platform generates patches for THEIR code**
```bash
# Platform analyzes THEIR vulnerabilities
# Generates patches for THEIR codebase
# They review and apply to THEIR code
```

**They never see or need:**
- ❌ Your vulnerable test app
- ❌ Your test data
- ❌ Your development setup

---

## 📝 docker-compose File Summary

### `docker-compose.yml` (Development)
```yaml
services:
  ollama: ✅ (for LLM)
  correlation-engine: ✅ (your platform)
  vulnerable-app: 🧪 (COMMENTED OUT - testing only)
```
- **Purpose:** Local development and testing
- **Include vulnerable-app?** Only when testing

### `docker-compose-hub.yml` (Production)
```yaml
services:
  ollama: ✅ (from Docker Hub)
  correlation-engine: ✅ (from Docker Hub)
  # NO vulnerable-app
```
- **Purpose:** Production deployment
- **Include vulnerable-app?** NO - never

---

## ✅ Verification Checklist

**Before Pushing to Docker Hub:**

- [ ] `docker-compose-hub.yml` has ONLY 2 services (Ollama + Correlation Engine)
- [ ] Vulnerable app is commented out in `docker-compose.yml`
- [ ] Only building `correlation-engine` for Docker Hub
- [ ] NOT building `vulnerable-app` for Docker Hub
- [ ] Documentation clarifies vulnerable app is test-only
- [ ] Users understand they scan their OWN applications

---

## 🎉 Summary

### What IS Pluggable:
✅ **Your Security Platform** - Can scan ANY external Java application
- Via REST API
- Via Maven/Gradle plugins
- Via GitHub Actions
- Via volume mounts
- Via sidecar pattern

### What is NOT Pluggable:
❌ **Vulnerable Test App** - This is YOUR internal test application
- Only for YOUR testing
- NOT deployed to production
- NOT pushed to Docker Hub
- Users scan THEIR OWN apps, not yours

### What to Push to Docker Hub:
✅ `srinivas/security-automation:latest` (Correlation Engine)
❌ `srinivas/vulnerable-app:*` (Don't push this!)

---

**Your platform is pluggable because it can scan ANY Java application via API/Maven/Gradle, NOT because it includes a test app in the deployment!** 🎯
