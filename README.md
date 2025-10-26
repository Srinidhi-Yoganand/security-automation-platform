# 🔒 AI-Powered Security Automation Platform

[![Docker Hub](https://img.shields.io/docker/v/srinidhiyoganand/security-automation?label=Docker%20Hub)](https://hub.docker.com/r/srinidhiyoganand/security-automation)
[![CI/CD](https://img.shields.io/github/actions/workflow/status/yourusername/security-automation-platform/security-pipeline.yml?branch=main)](https://github.com/yourusername/security-automation-platform/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An intelligent security automation platform that correlates findings from multiple security scanning tools and uses AI to automatically generate, test, and apply security patches.

## ✨ Key Features

- 🔍 **Multi-Tool Correlation** - Integrates Semgrep, CodeQL, and OWASP ZAP findings
- 🤖 **AI-Powered Patching** - Generates fixes using LLM models (DeepSeek, OpenAI, Gemini)
- 🔄 **Automated Testing** - Tests patches before applying them
- 📊 **Interactive Dashboards** - Real-time vulnerability tracking with risk scoring
- 🔌 **Pluggable Architecture** - Works with any Java application via REST API
- 🚀 **CI/CD Integration** - GitHub Actions workflow with automated PR creation
- 🐳 **Docker Deployment** - Available on Docker Hub, no local dependencies

## 🚀 Quick Start

### Using Docker Hub (Recommended)

```bash
# Pull and start the platform
docker-compose -f docker-compose-hub.yml up -d

# Wait for Ollama to download the model (~2-5 minutes)
docker logs -f security-ollama

# Access the API
curl http://localhost:8000/health
```

### Using API Client

```python
from correlation_engine.api_client import SecurityAutomationClient

# Initialize client
client = SecurityAutomationClient("http://localhost:8000")

# Scan your project
results = client.scan_project(
    project_path="/path/to/your/app",
    tools=["semgrep", "zap"]
)

# Generate and apply patches
for vuln in results["high_severity"]:
    patch = client.generate_patch(vuln["id"], auto_apply=False)
    print(f"Generated patch for {vuln['type']}: {patch['confidence']}")
```

## 🏗️ Architecture

```
┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│   Security   │───▶│  Correlation  │───▶│  LLM Patch   │
│    Tools     │    │    Engine     │    │  Generator   │
└──────────────┘    └───────────────┘    └──────────────┘
                           │                     │
                           ▼                     ▼
                    ┌─────────────┐      ┌──────────────┐
                    │  Dashboard  │      │ Test & Apply │
                    │  (FastAPI)  │      │    Patches   │
                    └─────────────┘      └──────────────┘
```

## 📋 Prerequisites

- **Docker** & Docker Compose
- **Python 3.11+** (for local development)
- **Maven 3.8+** (for building test app)

## 🛠️ Installation

### Option 1: Docker Hub (Production)

```bash
# Clone repository
git clone https://github.com/yourusername/security-automation-platform.git
cd security-automation-platform

# Start services
docker-compose -f docker-compose-hub.yml up -d

# Verify deployment
curl http://localhost:8000/api/health
```

### Option 2: Local Development

```bash
# Clone repository
git clone https://github.com/yourusername/security-automation-platform.git
cd security-automation-platform

# Setup Python environment
cd correlation-engine
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Setup Ollama
./setup-ollama.sh  # or setup-ollama.ps1 on Windows

# Start the server
python run_server.py
```

## 📖 Usage

### 1. Scan Your Application

```bash
# Using curl
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "project_path": "/path/to/app",
    "tools": ["semgrep", "zap"]
  }'

# Using Python API client
python correlation-engine/api_client.py scan /path/to/app
```

### 2. Generate Patches

```bash
# Generate patch for specific vulnerability
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{
    "vuln_id": "sql-injection-001",
    "auto_apply": false
  }'
```

### 3. View Dashboard

```bash
# Generate HTML dashboard
curl http://localhost:8000/api/dashboard > dashboard.html
open dashboard.html
```

### 4. Integration Methods

The platform supports 6 integration methods:

1. **REST API** (Universal)
2. **Maven Plugin** (Java)
3. **Gradle Plugin** (Java)
4. **GitHub Actions** (CI/CD)
5. **CLI Tool** (Command-line)
6. **Docker Sidecar** (Kubernetes)

See [SDK.md](correlation-engine/SDK.md) for detailed integration guides.

## 🔧 Configuration

### Environment Variables

```bash
# LLM Providers
OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=sk-...                 # Optional
GEMINI_API_KEY=...                    # Optional

# Database
DATABASE_URL=sqlite:///security_behavior.db

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
EMAIL_SMTP_HOST=smtp.gmail.com
GITHUB_TOKEN=ghp_...
```

### docker-compose-hub.yml

```yaml
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama-models:/root/.ollama
  
  correlation-engine:
    image: srinidhiyoganand/security-automation:latest
    ports:
      - "8000:8000"
    depends_on:
      - ollama
    environment:
      - OLLAMA_HOST=http://ollama:11434
```

## 🧪 Testing

### Run All Tests

```bash
cd correlation-engine
source venv/bin/activate

# Test vulnerability detection (10+ types)
python test_all_vulnerabilities.py

# Test patch generation
python test_llm_patches.py

# Test API endpoints
python test_api_direct.py
```

### CI/CD Pipeline

The GitHub Actions workflow automatically:

1. **Scans** code with Semgrep, CodeQL, and ZAP
2. **Correlates** findings across tools
3. **Generates** AI-powered patches
4. **Tests** patches in isolated branch
5. **Creates PR** if patches improve security
6. **Deploys** to Docker Hub on merge

## 📊 Supported Vulnerabilities

The platform can detect and patch:

- SQL Injection
- XSS (Cross-Site Scripting)
- Path Traversal
- Command Injection
- XXE (XML External Entity)
- Insecure Deserialization
- SSRF (Server-Side Request Forgery)
- Hardcoded Secrets
- Weak Cryptography
- Authentication Bypass
- **...and more!**

## 🔐 Security

- **Human-in-the-Loop**: All patches require review before merge
- **Isolated Testing**: Patches tested in separate git branches
- **Confidence Scoring**: Each patch rated by AI confidence
- **Rollback Support**: Easy revert if issues detected

## 📚 Documentation

- **[Architecture](ARCHITECTURE.md)** - System design and components
- **[API Documentation](correlation-engine/API-DOCS.md)** - REST API reference
- **[SDK Guide](correlation-engine/SDK.md)** - Integration methods
- **[Deployment Guide](docs/guides/DOCKER-HUB-DEPLOYMENT.md)** - Production deployment
- **[Reports](docs/reports/)** - Phase implementation reports

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Ollama** for local LLM runtime
- **DeepSeek** for code generation models
- **Semgrep**, **CodeQL**, **OWASP ZAP** for security scanning
- **FastAPI** for the web framework

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/security-automation-platform/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/security-automation-platform/discussions)
- **Docker Hub**: [srinidhiyoganand/security-automation](https://hub.docker.com/r/srinidhiyoganand/security-automation)

---

**Built with ❤️ for secure software development**
