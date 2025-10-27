# 🔒 Security Automation Platform# Security Automation Platform 🔒



**AI-Powered Automated Vulnerability Detection and Patching****AI-Powered Security Scanning and Automated Patching for ANY Application**



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)[![Docker Hub](https://img.shields.io/docker/pulls/srinidhiyoganand/security-automation)](https://hub.docker.com/r/srinidhiyoganand/security-automation)

[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-green.svg)](./action.yml)

## What Is This?

A production-ready security platform that combines **CodeQL semantic analysis**, **Z3 symbolic execution**, and **LLM-powered patching** to automatically detect, verify, and fix security vulnerabilities in your code.

A **pluggable security automation platform** that:

## ✨ Features- 🔍 Scans your application for vulnerabilities (SAST)

- 🤖 Generates AI-powered patches using LLMs (DeepSeek, OpenAI, Gemini)

- 🔍 **Automated Vulnerability Detection** - CodeQL semantic analysis with data flow tracking- ✅ Tests patches automatically

- 🧮 **Formal Verification** - Z3 symbolic execution proves exploitability- 📝 Creates Pull Requests with fixes

- 🤖 **AI-Powered Patching** - LLM-generated security fixes with validation

- ✅ **Automatic PR Creation** - Patches submitted as pull requests**Works with ANY application** - not tied to a specific codebase!

- 📊 **Interactive Dashboard** - Real-time security metrics

- 🐳 **Zero Dependencies** - Fully containerized deployment## Quick Start

- 🔌 **Plug & Play** - Add to any project with one workflow file

### Option 1: Docker Compose (Local)

## 🚀 Quick Start

Scan your own application:

### Option 1: GitHub Action (Recommended)

```bash

Add `.github/workflows/security.yml` to your repository:# Set path to YOUR application

export TARGET_APP_PATH=/path/to/your/app

```yaml

name: Security Scan# Start the platform

docker-compose up -d

on: [pull_request, push]

# Scan your app

jobs:docker exec security-correlation python api_client.py scan /target-app

  security:

    runs-on: ubuntu-latest# View dashboard

    steps:open http://localhost:8000/api/dashboard

      - uses: actions/checkout@v4```

      

      - uses: Srinidhi-Yoganand/security-automation-platform@main### Option 2: GitHub Actions (CI/CD)

        with:

          language: 'java'Add to your repository's workflow:

          github_token: ${{ secrets.GITHUB_TOKEN }}

``````yaml

name: Security Scan

**That's it!** The platform will automatically scan, detect, patch, and create PRs.

on: [push, pull_request]

### Option 2: Docker Compose

jobs:

```bash  security:

# Start platform    uses: Srinidhi-Yoganand/security-automation-platform/.github/workflows/security-pipeline.yml@main

export TARGET_APP_PATH=./your-app    with:

docker-compose up -d      target_repository: your-org/your-repo

      target_ref: main

# Run analysis      auto_apply_patches: true

curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \    secrets:

  -H "Content-Type: application/json" \      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

  -d '{"source_path": "/target-app", "language": "java"}'```

```

The platform will:

### Option 3: Quick Test1. Scan your repository

2. Generate AI patches for vulnerabilities

```bash3. Create a test branch with patches applied

./run-e2e-test.sh4. Verify vulnerabilities are fixed

```5. Create a PR for you to review



## 📖 Documentation## Architecture



- **[Quick Start Guide](./QUICKSTART.md)** - 3-step setup```

- **[GitHub Action Usage](./docs/guides/GITHUB-ACTION-USAGE.md)** - Plug into any repo┌─────────────────────┐

- **[Full Integration Guide](./docs/guides/END-TO-END-INTEGRATION.md)** - Complete documentation│   Your Application  │ ← Pluggable target

- **[API Reference](./correlation-engine/README.md)** - REST API docs└──────────┬──────────┘

           │

## 🎯 How It Works           ▼

┌─────────────────────┐

1. **Detection** → CodeQL finds vulnerabilities with data flow analysis│  Security Scanner   │ ← Semgrep, CodeQL

2. **Verification** → Z3 proves they're exploitable│  (Correlation Engine)│

3. **Patching** → LLM generates fixes with CVE references└──────────┬──────────┘

4. **Validation** → Multi-level verification (syntax, security, symbolic)           │

5. **Integration** → Auto-creates PR with patches           ▼

┌─────────────────────┐

## 🛠️ Supported│   AI Patch Gen      │ ← DeepSeek/OpenAI/Gemini

│   (LLM-powered)     │

| Feature | Status |└──────────┬──────────┘

|---------|--------|           │

| Java | ✅ Full Support |           ▼

| IDOR Detection | ✅ |┌─────────────────────┐

| Missing Authorization | ✅ |│  Patch Testing      │ ← Automatic verification

| SQL Injection | ✅ |│  & PR Creation      │

| XSS, CSRF | ✅ |└─────────────────────┘

| Auto PR Creation | ✅ |```

| Dashboard | ✅ |

| GitHub Security | ✅ |## Features



## 📊 Example### 🔍 Multi-Tool Security Scanning

- **Semgrep** - Fast SAST for multiple languages

```bash- **CodeQL** - Deep semantic analysis

$ ./run-e2e-test.sh- **OWASP ZAP** - DAST for running applications



🔍 Found 5 vulnerabilities### 🤖 AI-Powered Patching

✅ Generated 5 patches  - **DeepSeek Coder** - Primary LLM (local, free)

✅ Validation: 95/100 average score- **OpenAI GPT-4** - Fallback option

✅ PR created: https://github.com/org/repo/pull/123- **Google Gemini** - Alternative provider

```- **Template-based** - Fallback for common patterns



## 🏗️ Architecture### ✅ Automated Validation

- Apply patches to test branch

```- Re-scan to verify fixes

GitHub Action → CodeQL → Z3 → LLM → Validator → GitHub PR- Compare before/after results

```- Auto-create PR if successful



## 🧪 Testing### 📊 Comprehensive Dashboard

- Vulnerability correlation across tools

```bash- Patch confidence scores

cd correlation-engine- Risk assessment

python -m pytest test_end_to_end.py -v- Trend analysis

```

## Usage Examples

## 📄 License

### Scan a Java Application

MIT License - See [LICENSE](./LICENSE)

```bash

## 🎓 ResearchTARGET_APP_PATH=./my-java-app docker-compose up -d

docker exec security-correlation python api_client.py scan /target-app --tools semgrep,codeql

Novel hybrid approach combining semantic + symbolic + LLM analysis.  ```

[Read Implementation Summary →](./docs/reports/IMPLEMENTATION-SUMMARY.md)

### Scan via API

---

```bash

**[Get Started →](./QUICKSTART.md)** | **[Documentation →](./docs/)** | **[Report Issues →](https://github.com/Srinidhi-Yoganand/security-automation-platform/issues)**curl -X POST http://localhost:8000/api/scan \

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
