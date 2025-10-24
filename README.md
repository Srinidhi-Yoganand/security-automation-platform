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

- [x] Phase 1.1: Vulnerable Spring Boot Application
- [ ] Phase 1.2: CI/CD Orchestrator
- [ ] Phase 1.3: Scanner Integration
- [ ] Phase 1.4: Correlation Engine Core
- [ ] Phase 2: Security Behavior Analysis
- [ ] Phase 3: Advanced Patch Generation
- [ ] Phase 4: Demonstration & Evaluation

## License

MIT
