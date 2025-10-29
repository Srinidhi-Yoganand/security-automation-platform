# Security Platform Refactoring Architecture

**Date**: October 29, 2025  
**Purpose**: Document the modular, CPG-based architecture for flexible security testing

---

## 🎯 Refactoring Goals

### 1. **Decouple Vulnerable Application**
- **Before**: Vulnerable app mounted inside main security container
- **After**: Independent Docker container with standardized interface
- **Benefit**: Easy to swap target applications without changing security tooling

### 2. **Replace IAST with CPG Analysis**
- **Before**: IAST (Interactive) requires per-app configuration
- **After**: CPG-based static analysis (generic, no runtime instrumentation)
- **Benefit**: Works with any application without code changes

### 3. **Modular Testing Strategy**
- **Custom App**: Simple, controlled test application
- **External App**: DVWA as real-world validation
- **Benefit**: Validate against both simple and complex targets

---

## 🏗️ New Architecture Design

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DOCKER COMPOSE ORCHESTRATION                     │
└─────────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
                ▼               ▼               ▼
    ┌───────────────────┐ ┌──────────┐ ┌──────────────────┐
    │ SECURITY PLATFORM │ │   ZAP    │ │ TARGET APP       │
    │  (Correlation)    │ │  (DAST)  │ │ (Swappable)      │
    │                   │ │          │ │                  │
    │ • SAST (CodeQL)   │ └──────────┘ │ • Custom App     │
    │ • CPG Analysis    │               │   OR             │
    │ • Correlator      │               │ • DVWA           │
    │ • LLM Patcher     │               │   OR             │
    │ • API             │               │ • Any other app  │
    └───────────────────┘               └──────────────────┘
                │                                │
                └────────────┬───────────────────┘
                             │
                    ┌────────▼────────┐
                    │  SHARED NETWORK │
                    │  (security-net) │
                    └─────────────────┘
```

### Container Responsibilities

#### 1. Security Platform Container
**Name**: `security-correlation-engine`
**Purpose**: Core security scanning and analysis
**Technology**: Python, FastAPI, CodeQL, Joern
**Exposed**: Port 8000 (API)

**Capabilities**:
- SAST scanning with CodeQL
- CPG-based semantic analysis (Joern)
- Correlation of findings
- LLM-based patch generation
- Integration with ZAP for DAST results

**Does NOT**:
- Run or instrument target applications
- Require specific app frameworks

#### 2. ZAP Container
**Name**: `security-zap`
**Purpose**: Dynamic security testing
**Technology**: OWASP ZAP
**Exposed**: Port 8090 (API)

**Capabilities**:
- Spider web applications
- Active security scanning
- Passive scanning
- API testing

#### 3. Target Application Container (Generic)
**Name**: `target-app` (or `dvwa-app`, `custom-app`, etc.)
**Purpose**: Application under test
**Technology**: Any (Flask, Node.js, PHP, Java, etc.)
**Exposed**: Port 8888 (configurable)

**Requirements**:
- HTTP/HTTPS endpoint
- Health check endpoint
- Source code accessible via volume mount

---

## 🔄 CPG-Based Detection vs IAST

### Why Replace IAST?

| Aspect | IAST | CPG Analysis |
|--------|------|--------------|
| **Setup** | Requires instrumentation, runtime configuration | Zero configuration |
| **Language Support** | Java-specific (requires agent) | Multi-language (Java, Python, JS, PHP) |
| **Application Changes** | Needs JVM args, agent installation | No changes needed |
| **Detection Type** | Runtime exploitation confirmation | Static semantic + data flow |
| **Flexibility** | Tied to specific frameworks | Works with any codebase |
| **False Positives** | Very low (confirms exploits) | Low (semantic reasoning) |
| **Speed** | Slow (needs app execution) | Fast (static analysis) |

### What CPG Detects (That Pattern Matching Misses)

1. **Business Logic Flaws**
   ```javascript
   // Traditional SAST: ❌ Misses this
   // CPG: ✅ Detects missing validation
   
   app.post('/checkout', (req, res) => {
       const total = req.body.items.reduce((sum, item) => 
           sum + (item.price * item.quantity), 0);  // Price from client!
       processPayment(total);
   });
   ```

2. **Missing Authorization Checks**
   ```python
   # Traditional SAST: ❌ Looks fine
   # CPG: ✅ Detects data flow without auth
   
   @app.route('/api/user/<user_id>/profile')
   def get_profile(user_id):
       # No authorization check!
       return db.query(f"SELECT * FROM profiles WHERE id={user_id}")
   ```

3. **Complex Data Flow Issues**
   ```java
   // Traditional SAST: ❌ Doesn't trace across methods
   // CPG: ✅ Full data flow analysis
   
   String input = request.getParameter("data");
   String processed = processInput(input);  // Sanitizes in theory
   String final = transformData(processed); // But this removes sanitization
   executeQuery("SELECT * FROM t WHERE x=" + final); // SQL injection!
   ```

---

## 📦 Generic Target Application Interface

### Standardized Environment Variables

Every target application container must support:

```yaml
environment:
  # Application Configuration
  - APP_NAME=my-vulnerable-app
  - APP_LANGUAGE=python  # python, java, php, javascript
  - APP_FRAMEWORK=flask  # flask, django, spring, express
  
  # Source Code Location (for SAST)
  - SOURCE_PATH=/app/src
  - SOURCE_ENCODING=utf-8
  
  # Web Server Configuration
  - WEB_PORT=8888
  - WEB_PROTOCOL=http
  
  # Health Check
  - HEALTH_CHECK_PATH=/health
  - HEALTH_CHECK_TIMEOUT=30

# Required Volume Mounts
volumes:
  - ./my-app:/app/src:ro  # Source code (read-only for security platform)

# Required Network
networks:
  - security-network

# Required Health Check
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8888/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### Standardized API Contract

Every target application should expose:

```
GET /health
Response: {"status": "healthy", "app": "my-app", "version": "1.0"}

GET /api/info
Response: {
  "name": "my-vulnerable-app",
  "language": "python",
  "framework": "flask",
  "endpoints": [
    {"path": "/api/users", "methods": ["GET", "POST"]},
    {"path": "/api/users/{id}", "methods": ["GET", "PUT", "DELETE"]}
  ]
}
```

---

## 🔧 Implementation Steps

### Phase 1: Refactor Docker Compose

**New Structure**:
```yaml
# docker-compose.yml (Core Platform)
services:
  correlation-engine:
    # Security platform (unchanged)
  zap:
    # DAST tool (unchanged)
  ollama:
    # LLM service (unchanged)

# docker-compose.custom-app.yml (Custom Test App)
services:
  target-app:
    build: ./vulnerable-apps/custom-vulnerable-app
    environment:
      - APP_NAME=custom-vulnerable-app
      - APP_LANGUAGE=python
    volumes:
      - ./vulnerable-apps/custom-vulnerable-app:/app/src:ro

# docker-compose.dvwa.yml (DVWA Testing)
services:
  dvwa-db:
    # Database for DVWA
  dvwa-app:
    # DVWA application
```

**Usage**:
```bash
# Test with custom app
docker-compose -f docker-compose.yml -f docker-compose.custom-app.yml up

# Test with DVWA
docker-compose -f docker-compose.yml -f docker-compose.dvwa.yml up

# Test with your own app
docker-compose -f docker-compose.yml -f docker-compose.myapp.yml up
```

### Phase 2: Remove IAST Components

**Files to Remove**:
- `correlation-engine/app/services/iast_scanner.py`

**Files to Update**:
- `correlation-engine/app/api/e2e_routes.py` (remove IAST imports)
- `correlation-engine/app/core/correlator.py` (remove IAST logic)
- `correlation-engine/test_platform_comprehensive.py` (remove IAST tests)
- `docker-compose.yml` (remove IAST env vars)

**Environment Variables to Remove**:
- `IAST_PROVIDER`
- `IAST_AGENT_HOST`
- `CONTRAST_API_KEY`
- `CONTRAST_API_SERVICE_KEY`
- `CONTRAST_API_URL`

### Phase 3: Add CPG Analysis

**Tools to Integrate**:

1. **CodeQL** (Already installed)
   - Use for data flow queries
   - Add custom queries for logic flaws

2. **Joern** (New)
   - Install in Dockerfile
   - Use for CPG-based semantic analysis
   - Add queries for missing authorization, IDOR, etc.

**New Files**:
```
correlation-engine/app/services/
├── cpg_analyzer.py          # Main CPG analysis service
├── codeql_dataflow.py       # CodeQL data flow queries
└── joern_semantic.py        # Joern semantic analysis
```

**New Queries**:
```
codeql-queries/
├── business-logic-flaws.ql
├── missing-authorization.ql
├── idor-detection.ql
└── toctou-race-conditions.ql
```

### Phase 4: Update Correlator

**New Correlation Logic**:
```python
class SecurityCorrelator:
    TOOL_WEIGHTS = {
        "sast": 0.30,    # Basic pattern matching
        "dast": 0.25,    # Runtime testing
        "cpg": 0.45,     # Semantic + data flow (highest weight)
    }
    
    def correlate(self, sast_findings, dast_findings, cpg_findings):
        # Group by location
        # Match across tools
        # CPG confirmation increases confidence to HIGH
        # Return high-confidence findings only
```

**Confidence Levels**:
- SAST + CPG = HIGH (semantic confirmation)
- DAST + CPG = HIGH (runtime + semantic)
- SAST + DAST + CPG = VERY HIGH (all modes agree)
- SAST only = LOW (likely false positive)
- DAST only = MEDIUM (runtime issue, needs investigation)
- CPG only = MEDIUM-HIGH (semantic issue, likely real)

---

## 🧪 Testing Strategy

### Custom Vulnerable Application

**Purpose**: Controlled testing environment

**Features**:
- Simple Flask application (~200 lines)
- Known vulnerabilities:
  - SQL Injection (login form)
  - XSS (search functionality)
  - IDOR (user profile access)
  - Missing authorization (admin endpoints)
  - Business logic flaw (price manipulation)

**Benefits**:
- Fast to scan (< 1 minute)
- Easy to debug
- Clear ground truth
- Demonstrates CPG capabilities

### DVWA Integration

**Purpose**: Real-world validation

**Features**:
- Complex PHP application
- Multiple vulnerability categories
- Industry-standard test platform
- Comprehensive test suite

**Benefits**:
- Proves generalization
- Academic credibility
- Comparison baseline
- Complex code paths

---

## 📊 Expected Improvements

### Metrics Comparison

| Metric | Old (IAST-based) | New (CPG-based) | Improvement |
|--------|------------------|-----------------|-------------|
| **Setup Time** | 10 min (instrumentation) | 0 min (zero config) | ✅ 100% faster |
| **Scan Time** | 7 min (runtime required) | 3 min (static only) | ✅ 57% faster |
| **Language Support** | Java only | Java, Python, PHP, JS | ✅ 4x more |
| **Logic Flaw Detection** | 0% (needs patterns) | 60-80% (semantic) | ✅ New capability |
| **False Positives** | <3% (runtime confirmed) | <5% (semantic confirmed) | ⚠️ Slightly higher |
| **Application Coupling** | High (needs agent) | None (external scan) | ✅ Zero coupling |

### Research Contribution

**Old Approach**:
- ✅ Good: Multi-mode correlation (SAST + DAST + IAST)
- ❌ Limitation: Only detects known patterns + runtime exploits
- ❌ Limitation: Java-specific

**New Approach**:
- ✅ Good: Multi-mode correlation (SAST + DAST + CPG)
- ✅ Good: Detects logic flaws traditional tools miss
- ✅ Good: Language-agnostic
- ✅ Good: Zero-configuration (easier to adopt)
- ✅ Research novelty: CPG-based semantic analysis for complex vulnerabilities

---

## 🚀 Migration Path

### Step-by-Step Deployment

1. **Backup Current System** ✅ (Completed - commit 4ba6f63)

2. **Update Docker Compose** (Phase 1)
   - Separate target app into own service
   - Create generic interface
   - Test with custom app

3. **Remove IAST** (Phase 2)
   - Delete iast_scanner.py
   - Remove all IAST references
   - Update environment variables
   - Update tests

4. **Add CPG** (Phase 3)
   - Install Joern
   - Create CPG analyzer service
   - Add semantic queries
   - Test on custom app

5. **Update Correlation** (Phase 4)
   - Modify correlator logic
   - Adjust confidence scoring
   - Add CPG weighting

6. **Validate** (Phase 5)
   - Test custom app
   - Test DVWA
   - Compare results with baseline
   - Update documentation

### Rollback Plan

If issues occur, rollback to baseline commit:
```bash
git reset --hard 4ba6f63
docker-compose down -v
docker-compose up --build
```

---

## 📚 References

- **Joern Documentation**: https://joern.io/
- **CodeQL Documentation**: https://codeql.github.com/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **CPG Research Paper**: "Modeling and Discovering Vulnerabilities with Code Property Graphs" (Yamaguchi et al., 2014)

---

## ✅ Success Criteria

The refactoring is successful when:

1. ✅ Security platform runs independently of target app
2. ✅ Target app can be swapped with < 5 minutes configuration
3. ✅ CPG detects logic flaws that old system missed
4. ✅ Scan time is <= old system
5. ✅ False positive rate is < 5%
6. ✅ Custom app demonstrates all capabilities
7. ✅ DVWA validates real-world effectiveness
8. ✅ Documentation is updated
9. ✅ Tests pass with new architecture
10. ✅ Thesis argument is stronger (demonstrates research novelty)
