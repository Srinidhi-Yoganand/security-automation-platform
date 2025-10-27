# Pluggable Usage Guide

## The Security Automation Platform is Now Fully Pluggable!

The **correlation engine** is the main product. You can scan **ANY application** with it.

## What Changed?

### Before ❌
- `vulnerable-app` was in main branch
- Looked like it was part of the product
- Confusing architecture

### After ✅
- `vulnerable-app` moved to `test-examples` branch (example only)
- Clean separation: **correlation-engine** = product, **vulnerable-app** = test target
- Works with ANY application

## Usage Options

### 1. Local Scanning with Docker Compose

Scan your own Java/Python/Node.js application:

```bash
# Point to YOUR application
export TARGET_APP_PATH=/path/to/your/application

# Start the platform
docker-compose up -d

# The platform mounts your app at /target-app inside the container
docker exec security-correlation python api_client.py scan /target-app
```

**How it works:**
- `docker-compose.yml` mounts `$TARGET_APP_PATH` to `/target-app` in the container
- Platform scans files in `/target-app`
- Generates patches for vulnerabilities found
- Stores results in `/app/data`

### 2. GitHub Actions CI/CD

Scan ANY GitHub repository automatically:

```yaml
# In YOUR repository's .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    uses: Srinidhi-Yoganand/security-automation-platform/.github/workflows/security-pipeline.yml@main
    with:
      target_repository: your-org/your-repo  # YOUR repo
      target_ref: main
      auto_apply_patches: true
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

**What happens:**
1. Workflow checks out YOUR repository
2. Runs security scans (Semgrep)
3. Generates AI patches using LLMs
4. Creates a test branch with patches applied
5. Re-scans to verify vulnerabilities are fixed
6. Creates a PR if successful

### 3. Manual Workflow Dispatch

Scan any repository on-demand:

1. Go to [Actions tab](https://github.com/Srinidhi-Yoganand/security-automation-platform/actions)
2. Select "Security Automation Platform - Pluggable Scanner"
3. Click "Run workflow"
4. Fill in:
   - **target_repository**: `owner/repo` (e.g., `facebook/react`)
   - **target_ref**: `main` (or any branch)
   - **auto_apply_patches**: ✅ (to create PR with fixes)
5. Click "Run workflow"

The platform will scan the specified repository and create a PR with patches!

## Architecture

```
┌────────────────────────────────────────┐
│  Correlation Engine (The Product)      │
│  ├── Security scanners                 │
│  ├── AI patch generator                │
│  ├── Patch validator                   │
│  └── API + Dashboard                   │
└────────────┬───────────────────────────┘
             │
             │ scans
             ▼
   ┌─────────────────────┐
   │   YOUR Application  │ ← Pluggable!
   │   (any repo/path)   │
   └─────────────────────┘
```

## Test with Example

Want to see it in action first?

```bash
# Check out the test-examples branch
git checkout test-examples

# Run with the example vulnerable app
TARGET_APP_PATH=./vulnerable-app docker-compose up -d

# Scan it
docker exec security-correlation python api_client.py scan /target-app
```

## API Usage

Once running (`docker-compose up`), use the REST API:

```bash
# Scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/target-app"}'

# Generate patches
curl -X POST http://localhost:8000/api/patches/generate \
  -H "Content-Type: application/json" \
  -d '{"vuln_ids": ["vuln-1", "vuln-2"]}'

# View dashboard
curl http://localhost:8000/api/dashboard
```

## Configuration

### Environment Variables

```bash
# Required
TARGET_APP_PATH=/path/to/your/app

# Optional LLM providers (falls back to DeepSeek)
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...

# Ollama config
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=deepseek-coder:6.7b-instruct
```

### Docker Compose Customization

Edit `docker-compose.yml` to:
- Change memory limits
- Add more volumes
- Configure networks
- Set additional environment variables

## Benefits

✅ **No code changes** to your application
✅ **Works with any language** (Java, Python, JavaScript, Go, etc.)
✅ **Local or CI/CD** deployment
✅ **Automated patching** with AI
✅ **PR creation** for easy review
✅ **Free to use** (with local DeepSeek LLM)

## Examples

### Scan a Java Spring Boot App
```bash
TARGET_APP_PATH=./my-spring-app docker-compose up -d
```

### Scan a Python Flask App
```bash
TARGET_APP_PATH=./my-flask-app docker-compose up -d
```

### Scan a Node.js Express App
```bash
TARGET_APP_PATH=./my-express-app docker-compose up -d
```

### Scan ANY GitHub Repo (via Actions)
Just set `target_repository` in workflow dispatch!

## Next Steps

1. ✅ Commit these changes
2. ✅ Push to GitHub
3. ✅ Test with your own application
4. ✅ Try the GitHub Actions workflow
5. ⭐ Star the repo if it helps!

---

**Questions?** Open an issue or discussion on GitHub!
