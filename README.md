# Security Automation Platform

An **intelligent security testing and remediation platform** that correlates SAST, DAST, and CodeQL findings to identify vulnerabilities and **automatically generates secure patches using AI/LLM**.

## ✨ Key Features

- 🔍 **Multi-Tool Correlation**: Integrates Semgrep, CodeQL, OWASP ZAP
- 🧠 **Behavioral Analysis**: Tracks vulnerability lifecycles and patterns
- 🤖 **LLM-Powered Patching**: Generates secure fixes for **ANY vulnerability type** using GPT-4
- 🧪 **Automated Testing**: Tests patches in isolated git branches
- ✅ **Human-in-the-Loop**: Approval workflow for safety
- 📊 **Rich Dashboards**: Interactive vulnerability tracking and trends
- 🚀 **Production-Ready**: RESTful API, database persistence, git integration

## Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Security Tools │───▶│  Correlation │───▶│   LLM Patch     │
│ Semgrep/ZAP/    │    │    Engine    │    │   Generator     │
│    CodeQL       │    │ (Phase 1+2)  │    │   (Phase 3)     │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              │                      │
                              ▼                      ▼
                       ┌──────────────┐    ┌─────────────────┐
                       │   Database   │    │  Test Branch    │
                       │ (SQLAlchemy) │    │  (Git Repo)     │
                       └──────────────┘    └─────────────────┘
                              │                      │
                              ▼                      ▼
                       ┌──────────────┐    ┌─────────────────┐
                       │  Dashboard   │    │  Apply Patch    │
                       │    (HTML)    │    │   (Approved)    │
                       └──────────────┘    └─────────────────┘
```

## Project Structure

```
security-automation-platform/
├── vulnerable-app/          # Spring Boot application with vulnerabilities
│   └── src/main/java/       # Intentional security flaws for testing
├── correlation-engine/      # Python FastAPI service
│   ├── app/
│   │   ├── core/            # Correlation logic
│   │   ├── services/
│   │   │   ├── behavior/    # Lifecycle tracking, risk scoring
│   │   │   └── patcher/     # LLM patch generation
│   │   └── main.py          # REST API
│   └── test-data/           # Sample scan results & dashboards
├── test-data/               # Test inputs and outputs
└── docs/                    # Comprehensive documentation
```

## Implementation Status

### ✅ Phase 1: Foundation & Correlation (COMPLETE)
- Vulnerable Spring Boot application with SQLi, IDOR, XSS, Path Traversal
- Integration of Semgrep (SAST), OWASP ZAP (DAST), CodeQL
- Correlation engine with data flow analysis
- Multi-tool vulnerability deduplication

### ✅ Phase 2: Behavioral Intelligence (COMPLETE)
- Database persistence (SQLAlchemy + SQLite)
- Git integration for code history analysis
- Vulnerability lifecycle tracking
- Risk scoring algorithm
- Pattern detection (recurring vulnerabilities)
- Enhanced dashboard with charts and trends
- RESTful API (6 endpoints)

### ✅ Phase 3: LLM-Powered Patching (IN PROGRESS - 40% COMPLETE)
- 🤖 **LLM Integration**: GPT-4 for intelligent patch generation
- 🎯 **Universal Support**: Works with ANY vulnerability type (not just templates)
- 🧪 **Automated Testing**: Patches tested in isolated git branches
- ✅ **Approval Workflow**: Generate → Test → Review → Apply
- 📋 **API Endpoints**: 4 new endpoints for patch management
- 🔄 **Git Workflow**: Branch creation, testing, merging

## Quick Start

### 1. Setup

```bash
# Clone repository
git clone <repo-url>
cd security-automation-platform

# Install Python dependencies
cd correlation-engine
python -m venv venv
source venv/Scripts/activate  # Windows
pip install -r requirements.txt

# Install LLM dependencies
pip install openai javalang diff-match-patch

# Configure OpenAI API key
export OPENAI_API_KEY="sk-..."
```

### 2. Run Vulnerability Scanning (Phase 1 & 2)

```bash
cd correlation-engine

# Run correlation with behavior analysis
python -m app.main correlate \
  --codeql ../test-data/codeql-results/results.csv \
  --semgrep ../test-data/semgrep-results.sarif \
  --zap ../test-data/zap-results.json \
  --repo ../vulnerable-app \
  --output ../test-data/correlation-results.json

# Generate enhanced dashboard
python -m app.main dashboard \
  --input ../test-data/correlation-results.json \
  --output ../test-data/dashboard.html
```

### 3. Generate Patches with LLM (Phase 3)

```bash
# Start API server
python -m uvicorn app.main:app --reload --port 8000

# Generate patches for all vulnerabilities
curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches?limit=10" \
  -H "Content-Type: application/json"
```

**See [`QUICKSTART-LLM-PATCHING.md`](QUICKSTART-LLM-PATCHING.md) for detailed instructions.**

## Getting Started

### Prerequisites
- Java 17+
- Maven 3.8+
- Python 3.10+
- Docker (for ZAP and deployment)

### Running the Vulnerable Application

```bash
cd vulnerable-app
mvn spring-boot:run
```

### Running the Correlation Engine

```bash
cd correlation-engine
pip install -r requirements.txt
uvicorn main:app --reload
```

## Development Phases

### ✅ Phase 1: Foundation & Basic Intelligence (COMPLETED)
- [x] **Phase 1.1:** Vulnerable Spring Boot Application
  - SQLi, Simple IDOR, Complex IDOR vulnerabilities
  - Test data with users, companies, and orders
- [x] **Phase 1.2:** CI/CD Orchestrator
  - GitHub Actions workflow with parallel scanning
  - Automated PR comments and artifact management
- [x] **Phase 1.3:** Scanner Integration
  - Semgrep SAST (security-audit, OWASP Top 10)
  - CodeQL SAST (security-extended queries)
  - OWASP ZAP DAST (baseline + full scans)
- [x] **Phase 1.4:** Correlation Engine Core
  - FastAPI service with REST API and CLI
  - Multi-format parsers (SARIF, JSON, CSV)
  - Location-based correlation algorithm
  - Interactive HTML dashboard generator

**See [PHASE1-SUMMARY.md](./PHASE1-SUMMARY.md) for detailed implementation notes.**

### 🚧 Phase 2: Security Behavior Analysis (NEXT)
- [ ] Security Policy Extractor from @PreAuthorize annotations
- [ ] URL-to-Controller mapping analysis
- [ ] Behavioral DAST scripts for authorization testing
- [ ] Specification vs. Implementation gap detection

### 📋 Phase 3: Advanced Patch Generation (PLANNED)
- [ ] Context Assembler for vulnerability analysis
- [ ] LLM-powered patch generation
- [ ] Automated code validation and testing
- [ ] Pull Request creation automation

### 🎯 Phase 4: Demonstration & Evaluation (PLANNED)
- [ ] End-to-end testing scenarios
- [ ] Performance benchmarking
- [ ] Documentation and video demos
- [ ] Production readiness assessment

## License

MIT
