# Security Automation Platform

An intelligent security testing platform that correlates SAST, DAST, and CodeQL findings to identify and automatically patch vulnerabilities.

## Architecture

The platform consists of:
- **Vulnerable Spring Boot App**: Test application with intentional security flaws
- **CI/CD Pipeline**: GitHub Actions orchestration
- **Security Scanners**: Semgrep (SAST), OWASP ZAP (DAST), CodeQL
- **Correlation Engine**: Python/FastAPI service for intelligent analysis
- **Patch Generator**: LLM-powered automated remediation

## Project Structure

```
security-automation-platform/
├── vulnerable-app/          # Spring Boot application with vulnerabilities
├── correlation-engine/      # Python FastAPI service
├── .github/workflows/       # CI/CD pipelines
├── scripts/                 # Helper scripts
└── docs/                    # Documentation
```

## Phase 1: Foundation & Basic Intelligence

Current implementation includes:
- Vulnerable Spring Boot application with SQLi, IDOR, and complex logic flaws
- CI/CD orchestration with GitHub Actions
- Integration of Semgrep, ZAP, and CodeQL
- Basic correlation engine with data flow analysis

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
