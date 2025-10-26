# Security Automation Platform 🔒

**AI-Powered Security Scanning and Automated Patching for ANY Application**

[![Docker Hub](https://img.shields.io/docker/pulls/srinidhiyoganand/security-automation)](https://hub.docker.com/r/srinidhiyoganand/security-automation)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What Is This?

A **pluggable security automation platform** that:
- 🔍 Scans your application for vulnerabilities (SAST)
- 🤖 Generates AI-powered patches using LLMs (DeepSeek, OpenAI, Gemini)
- ✅ Tests patches automatically
- 📝 Creates Pull Requests with fixes

**Works with ANY application** - not tied to a specific codebase!

## Quick Start

### Option 1: Docker Compose (Local)

Scan your own application:

```bash
# Set path to YOUR application
export TARGET_APP_PATH=/path/to/your/app

# Start the platform
docker-compose up -d

# Scan your app
docker exec security-correlation python api_client.py scan /target-app

# View dashboard
open http://localhost:8000/api/dashboard
```

### Option 2: GitHub Actions (CI/CD)

Add to your repository's workflow:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    uses: Srinidhi-Yoganand/security-automation-platform/.github/workflows/security-pipeline.yml@main
    with:
      target_repository: your-org/your-repo
      target_ref: main
      auto_apply_patches: true
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The platform will:
1. Scan your repository
2. Generate AI patches for vulnerabilities
3. Create a test branch with patches applied
4. Verify vulnerabilities are fixed
5. Create a PR for you to review

## Architecture

```
┌─────────────────────┐
│   Your Application  │ ← Pluggable target
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Security Scanner   │ ← Semgrep, CodeQL
│  (Correlation Engine)│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   AI Patch Gen      │ ← DeepSeek/OpenAI/Gemini
│   (LLM-powered)     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Patch Testing      │ ← Automatic verification
│  & PR Creation      │
└─────────────────────┘
```

## Features

### 🔍 Multi-Tool Security Scanning
- **Semgrep** - Fast SAST for multiple languages
- **CodeQL** - Deep semantic analysis
- **OWASP ZAP** - DAST for running applications

### 🤖 AI-Powered Patching
- **DeepSeek Coder** - Primary LLM (local, free)
- **OpenAI GPT-4** - Fallback option
- **Google Gemini** - Alternative provider
- **Template-based** - Fallback for common patterns

### ✅ Automated Validation
- Apply patches to test branch
- Re-scan to verify fixes
- Compare before/after results
- Auto-create PR if successful

### 📊 Comprehensive Dashboard
- Vulnerability correlation across tools
- Patch confidence scores
- Risk assessment
- Trend analysis

## Usage Examples

### Scan a Java Application

```bash
TARGET_APP_PATH=./my-java-app docker-compose up -d
docker exec security-correlation python api_client.py scan /target-app --tools semgrep,codeql
```

### Scan via API

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/target-app", "tools": ["semgrep"]}'
```

### Generate Patches

```bash
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_ids": ["sql-injection-1", "xss-2"]}'
```

### Use in CI/CD

See `.github/workflows/security-pipeline.yml` for the full workflow.

**Manual Trigger:**
1. Go to Actions tab in your repo
2. Select "Security Automation Platform"
3. Click "Run workflow"
4. Enter target repository
5. Enable auto-apply patches
6. Run!

## Configuration

### Environment Variables

```bash
# LLM Providers (optional, falls back to DeepSeek)
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...

# Target Application
TARGET_APP_PATH=/path/to/your/app

# Ollama (local LLM)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=deepseek-coder:6.7b-instruct
```

### Docker Compose

See `docker-compose.yml` - mount YOUR application:

```yaml
services:
  correlation-engine:
    volumes:
      - ${TARGET_APP_PATH:-.}:/target-app:ro
```

## Test Example

Want to see it in action? Check out the `test-examples` branch which contains a vulnerable Java app:

```bash
git checkout test-examples
TARGET_APP_PATH=./vulnerable-app docker-compose up -d
```

## API Documentation

Full API docs available at: `http://localhost:8000/docs` when running

Key endpoints:
- `POST /api/scan` - Scan application
- `POST /api/patches/generate` - Generate patches
- `POST /api/patches/apply` - Apply patches
- `GET /api/dashboard` - View dashboard
- `GET /api/metrics` - Get statistics

## Contributing

1. Fork the repository
2. Create your feature branch
3. Test with the example app in `test-examples` branch
4. Submit a pull request

## Architecture Details

- **Correlation Engine** - Python FastAPI application
- **Scanner Integration** - Semgrep, CodeQL, ZAP parsers
- **LLM Integration** - Multi-provider support
- **Patch Generator** - Template + AI hybrid approach
- **Docker** - Containerized deployment

## License

MIT License - see LICENSE file

## Support

- 📖 Documentation: See `docs/` directory
- 🐛 Issues: [GitHub Issues](https://github.com/Srinidhi-Yoganand/security-automation-platform/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Srinidhi-Yoganand/security-automation-platform/discussions)

---

**Made with ❤️ by the Security Automation Team**
