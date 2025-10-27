#!/bin/bash

# Practical Multi-Language Testing Script
# Tests platform with Java apps + attempts other languages

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "============================================"
echo "Multi-App Testing for Security Platform"
echo "============================================"
echo ""

# Create workspace
WORKSPACE="./test-workspace"
RESULTS="./multi-app-test-results"
mkdir -p "$WORKSPACE"
mkdir -p "$RESULTS"

echo -e "${BLUE}Phase 1: Download Test Applications${NC}"
echo ""

cd "$WORKSPACE"

# Java Applications (Primary - Should work!)
echo -e "${YELLOW}Java Applications:${NC}"

echo "1. WebGoat (OWASP) - Large Java app"
if [ ! -d "WebGoat" ]; then
    git clone --depth 1 https://github.com/WebGoat/WebGoat.git
    echo -e "${GREEN}✓${NC} WebGoat cloned"
else
    echo -e "${GREEN}✓${NC} WebGoat exists"
fi

echo "2. Java Sec Code (Vulnerable samples)"
if [ ! -d "java-sec-code" ]; then
    git clone --depth 1 https://github.com/JoyChou93/java-sec-code.git
    echo -e "${GREEN}✓${NC} java-sec-code cloned"
else
    echo -e "${GREEN}✓${NC} java-sec-code exists"
fi

echo "3. Benchmark Java (OWASP)"
if [ ! -d "benchmark" ]; then
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git benchmark
    echo -e "${GREEN}✓${NC} BenchmarkJava cloned"
else
    echo -e "${GREEN}✓${NC} BenchmarkJava exists"
fi

# Try other languages (Experimental)
echo ""
echo -e "${YELLOW}Experimental - Other Languages:${NC}"

echo "4. DVWA (PHP)"
if [ ! -d "DVWA" ]; then
    git clone --depth 1 https://github.com/digininja/DVWA.git
    echo -e "${YELLOW}⚠${NC} DVWA cloned (experimental)"
else
    echo -e "${YELLOW}⚠${NC} DVWA exists (experimental)"
fi

echo "5. NodeGoat (JavaScript)"
if [ ! -d "NodeGoat" ]; then
    git clone --depth 1 https://github.com/OWASP/NodeGoat.git
    echo -e "${YELLOW}⚠${NC} NodeGoat cloned (experimental)"
else
    echo -e "${YELLOW}⚠${NC} NodeGoat exists (experimental)"
fi

cd ..

echo ""
echo -e "${GREEN}✓ All applications downloaded${NC}"
echo ""

# Create simple test apps for other languages
echo -e "${BLUE}Phase 2: Create Simple Vulnerable Apps${NC}"
echo ""

# Simple vulnerable Python app
cat > "$WORKSPACE/vulnerable_python.py" << 'EOF'
# Simple Vulnerable Python App for Testing
import sqlite3
import os

# SQL Injection vulnerability
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# Command Injection vulnerability
def ping_server(hostname):
    # VULNERABLE: Command injection
    os.system(f"ping -c 1 {hostname}")

# Path Traversal vulnerability
def read_file(filename):
    # VULNERABLE: Path traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# XSS vulnerability (if used in web context)
def render_comment(comment):
    # VULNERABLE: XSS
    return f"<div>{comment}</div>"

if __name__ == "__main__":
    # Test functions
    get_user("1")
    ping_server("localhost")
EOF

echo -e "${GREEN}✓${NC} Created vulnerable_python.py"

# Simple vulnerable JavaScript app
cat > "$WORKSPACE/vulnerable_javascript.js" << 'EOF'
// Simple Vulnerable JavaScript/Node.js App for Testing
const express = require('express');
const sqlite3 = require('sqlite3');
const { exec } = require('child_process');

const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const db = new sqlite3.Database('users.db');
    // VULNERABLE: SQL injection
    const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
    db.get(query, (err, row) => {
        res.json(row);
    });
});

// Command Injection vulnerability
app.get('/ping/:host', (req, res) => {
    // VULNERABLE: Command injection
    exec(`ping -c 1 ${req.params.host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// XSS vulnerability
app.get('/comment/:text', (req, res) => {
    // VULNERABLE: XSS
    res.send(`<div>${req.params.text}</div>`);
});

// Path Traversal vulnerability
app.get('/file/:name', (req, res) => {
    const fs = require('fs');
    // VULNERABLE: Path traversal
    fs.readFile(`/var/data/${req.params.name}`, 'utf8', (err, data) => {
        res.send(data);
    });
});

app.listen(3000);
EOF

echo -e "${GREEN}✓${NC} Created vulnerable_javascript.js"

echo ""
echo -e "${GREEN}✓ Test applications ready${NC}"
echo ""

echo "============================================"
echo "Applications Ready for Testing:"
echo "============================================"
echo ""
echo "Java (Primary Target - Should Work):"
echo "  1. ✅ WebGoat           - $WORKSPACE/WebGoat"
echo "  2. ✅ java-sec-code     - $WORKSPACE/java-sec-code"
echo "  3. ✅ BenchmarkJava     - $WORKSPACE/benchmark"
echo ""
echo "Other Languages (Experimental):"
echo "  4. ⚠️  DVWA (PHP)       - $WORKSPACE/DVWA"
echo "  5. ⚠️  NodeGoat (JS)    - $WORKSPACE/NodeGoat"
echo "  6. ⚠️  Python app       - $WORKSPACE/vulnerable_python.py"
echo "  7. ⚠️  JavaScript app   - $WORKSPACE/vulnerable_javascript.js"
echo ""

echo "============================================"
echo "Next Steps:"
echo "============================================"
echo ""
echo "1. Run platform tests (existing):"
echo "   cd correlation-engine && python -m pytest -v"
echo ""
echo "2. Test with custom Java app (validated):"
echo "   ./run-e2e-test.sh"
echo ""
echo "3. Test Java applications:"
echo "   docker exec security-correlation python api_client.py scan /test-workspace/WebGoat"
echo ""
echo "4. Try experimental (other languages):"
echo "   docker exec security-correlation python api_client.py scan /test-workspace/vulnerable_python.py"
echo ""
echo "5. Collect all metrics:"
echo "   python test-all-apps.py"
echo ""

# Create results template
cat > "$RESULTS/TEST-PLAN.md" << 'EOF'
# Multi-Application Test Results

## Test Date
$(date)

## Applications

### Java Applications (Primary - Expected to Work)

#### 1. Custom Vulnerable App ✅
- **Status**: TESTED
- **LOC**: 78
- **Findings**: 7 (4-tool scan)
- **Correlated**: 1 (unanimous)
- **FP Rate**: 1.0%
- **Result**: SUCCESS

#### 2. WebGoat
- **Status**: TO TEST
- **LOC**: ~50,000
- **Expected**: Should work (Java)

#### 3. java-sec-code
- **Status**: TO TEST
- **LOC**: ~10,000
- **Expected**: Should work (Java)

#### 4. BenchmarkJava
- **Status**: TO TEST
- **LOC**: ~15,000
- **Expected**: Should work (Java)

### Other Languages (Experimental)

#### 5. Python (vulnerable_python.py)
- **Status**: TO TEST
- **LOC**: 50
- **Expected**: May work (CodeQL supports Python)

#### 6. JavaScript (vulnerable_javascript.js)
- **Status**: TO TEST
- **LOC**: 60
- **Expected**: May work (CodeQL supports JavaScript)

#### 7. DVWA (PHP)
- **Status**: TO TEST
- **LOC**: ~5,000
- **Expected**: Unknown (limited PHP support)

#### 8. NodeGoat (Node.js)
- **Status**: TO TEST
- **LOC**: ~3,000
- **Expected**: May work (JavaScript)

## Testing Strategy

1. **Validate Java support** (3-4 apps)
2. **Attempt Python** (1 simple app)
3. **Attempt JavaScript** (1-2 apps)
4. **Document what works**
5. **Be honest about limitations**

## Expected Thesis Claims

### If Java apps work:
- "Platform validated on multiple Java applications"
- "Tested across 50,000+ lines of Java code"
- "Consistent results across diverse Java codebases"

### If Python/JS work:
- "Extended validation to multiple languages"
- "Architecture supports polyglot analysis"

### If Python/JS don't work:
- "Implemented for Java applications"
- "Architecture designed for multi-language (future work)"
- "Tool integration supports multiple languages"

EOF

echo -e "${GREEN}✓ Test plan created: $RESULTS/TEST-PLAN.md${NC}"
echo ""
