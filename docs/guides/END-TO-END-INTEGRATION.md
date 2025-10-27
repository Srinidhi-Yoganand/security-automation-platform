# End-to-End Integration & Deployment Guide

Complete guide for deploying and integrating the Security Automation Platform into any project.

## 🎯 Overview

The Security Automation Platform provides **zero-dependency** automated security analysis and patching using:

- **CodeQL Semantic Analysis** - Deep code understanding with data flow tracking
- **Z3 Symbolic Execution** - Formal verification of exploitability  
- **LLM-Powered Patching** - AI-generated security fixes
- **Automated Validation** - Multi-level patch verification

## 🚀 Quick Start (Docker)

### Prerequisites

- Docker & Docker Compose
- 8GB+ RAM (for LLM models)
- Internet connection (for pulling models)

### 1. Deploy with Docker Compose

```bash
# Clone the repository
git clone https://github.com/your-org/security-automation-platform.git
cd security-automation-platform

# Set your target application path
export TARGET_APP_PATH=./path/to/your/java/app

# Start the platform
docker-compose up -d

# Wait for services to be ready
docker-compose logs -f correlation-engine
```

### 2. Run End-to-End Analysis

```bash
# Via REST API
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/target-app",
    "language": "java",
    "create_database": true,
    "generate_patches": true,
    "validate_patches": true,
    "llm_provider": "ollama"
  }'

# Via CLI (inside container)
docker exec security-correlation python -m pytest test_end_to_end.py -v
```

### 3. View Results

```bash
# Check API status
curl http://localhost:8000/api/v1/e2e/status

# Access Swagger UI
open http://localhost:8000/docs

# View logs
docker-compose logs correlation-engine
```

## 📦 GitHub Actions Integration

### Add to Your Repository

Create `.github/workflows/security-analysis.yml`:

```yaml
name: Security Analysis

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Analysis
        uses: your-org/security-automation-platform/.github/workflows/security-analysis.yml@main
        with:
          target_path: '.'
          language: 'java'
          generate_patches: true
        secrets:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

### Configure Secrets

Add to your repository settings → Secrets:

- `GEMINI_API_KEY` - Google Gemini API key (optional)
- `OPENAI_API_KEY` - OpenAI API key (optional)

### What It Does

1. ✅ Runs on every PR and push to main
2. 🔍 Analyzes code with CodeQL + Z3
3. 🤖 Generates patches for vulnerabilities
4. 📊 Comments results on PR
5. 🚨 Creates issues for critical vulnerabilities
6. 📦 Uploads SARIF results to GitHub Security

## 🔌 Pluggable Integration

### Option 1: Docker Volume Mount

```bash
# Analyze any application
docker run -v /path/to/your/app:/target-app:ro \
  -p 8000:8000 \
  security-automation-platform:latest

# Then call API
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -d '{"source_path": "/target-app", "language": "java"}'
```

### Option 2: Standalone Binary

```bash
# Build standalone image
docker build -t my-security-scanner .

# Export binary
docker create --name extract my-security-scanner
docker cp extract:/opt/codeql/codeql ./codeql-cli
docker rm extract

# Use in CI/CD
./codeql-cli database create --language=java mydb
./codeql-cli database analyze mydb
```

### Option 3: Python SDK

```python
from app.api.e2e_routes import analyze_and_fix
from app.api.e2e_routes import AnalyzeAndFixRequest

# Programmatic usage
request = AnalyzeAndFixRequest(
    source_path="./my-java-app",
    language="java",
    generate_patches=True,
    validate_patches=True
)

result = await analyze_and_fix(request)
print(f"Found {result.vulnerabilities_found} vulnerabilities")
print(f"Fixed {result.vulnerabilities_fixed} vulnerabilities")
```

## 🧪 End-to-End Testing

### Run Complete Test Suite

```bash
cd correlation-engine

# Run all E2E tests
python -m pytest test_end_to_end.py -v -s

# Run specific test
python -m pytest test_end_to_end.py::TestEndToEnd::test_complete_pipeline_integration -v -s
```

### Test Output

The test suite verifies:

1. ✅ **Phase 1: CodeQL Analysis** - Detects vulnerabilities
2. ✅ **Phase 2: Symbolic Execution** - Verifies exploitability
3. ✅ **Phase 3: Context Building** - Combines semantic + symbolic data
4. ✅ **Phase 4: Patch Generation** - Creates security fixes
5. ✅ **Phase 5: Validation** - Verifies patches work

Results saved to `test-data/`:
- `e2e-codeql-results.json`
- `e2e-symbolic-results.json`
- `e2e-enhanced-context.json`
- `e2e-generated-patch.java`
- `e2e-validation-results.json`

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Actions / CI/CD                    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│              REST API (/api/v1/e2e/analyze-and-fix)         │
└────────────────────────────┬────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────┐
│   CodeQL     │   │   Z3 Symbolic    │   │  LLM Patch   │
│   Semantic   │──▶│   Execution      │──▶│  Generator   │
│   Analysis   │   │                  │   │              │
└──────────────┘   └──────────────────┘   └──────┬───────┘
                                                  │
                                                  ▼
                                           ┌──────────────┐
                                           │    Patch     │
                                           │  Validator   │
                                           └──────────────┘
```

## 🔧 Configuration

### Environment Variables

```bash
# LLM Provider Configuration
LLM_PROVIDER=ollama              # ollama, gemini, openai, template
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=deepseek-coder:6.7b-instruct
GEMINI_API_KEY=your-key-here
OPENAI_API_KEY=your-key-here

# CodeQL Configuration
CODEQL_HOME=/opt/codeql
CODEQL_QUERIES=/opt/codeql-repo

# Database
DATABASE_URL=sqlite:////data/security.db

# Target Application
TARGET_APP_PATH=/target-app
```

### Docker Compose Variables

Create `.env` file:

```env
TARGET_APP_PATH=./my-java-app
LLM_PROVIDER=ollama
GEMINI_API_KEY=your-api-key
OPENAI_API_KEY=your-api-key
```

## 📊 API Endpoints

### End-to-End Pipeline

```bash
POST /api/v1/e2e/analyze-and-fix
```

Request:
```json
{
  "source_path": "/target-app",
  "language": "java",
  "create_database": true,
  "generate_patches": true,
  "validate_patches": true,
  "llm_provider": "ollama"
}
```

Response:
```json
{
  "success": true,
  "source_path": "/target-app",
  "vulnerabilities_found": 5,
  "vulnerabilities_fixed": 5,
  "results": [
    {
      "vulnerability": {
        "type": "IDOR",
        "file": "UserController.java",
        "line": 26,
        "method": "getUserById",
        "severity": "high",
        "data_flows": [...],
        "symbolic_proof": {...}
      },
      "patch": {
        "original_code": "...",
        "patched_code": "...",
        "explanation": "...",
        "validation": {
          "is_valid": true,
          "vulnerability_fixed": true,
          "score": 95
        }
      }
    }
  ]
}
```

### Pipeline Status

```bash
GET /api/v1/e2e/status
```

Response:
```json
{
  "pipeline": "ready",
  "stages": {
    "codeql": {"available": true, "version": "2.15.3"},
    "z3_symbolic": {"available": true},
    "llm_patching": {
      "available": true,
      "providers": ["gemini", "ollama", "template"]
    },
    "patch_validation": {"available": true}
  }
}
```

## 🎨 Customization

### Add Custom CodeQL Queries

```bash
# Create custom query
cat > custom-query.ql << 'EOF'
import java

from MethodAccess call
where call.getMethod().getName() = "execute"
select call, "Potential SQL injection"
EOF

# Mount into container
docker run -v ./custom-query.ql:/opt/custom-queries/custom.ql \
  security-automation-platform:latest
```

### Add Custom Patch Templates

```python
# In app/services/patcher/semantic_patch_generator.py
from app.services.patcher.semantic_patch_generator import PatchTemplate

custom_template = PatchTemplate(
    name="custom-validation",
    pattern=r"public.*getData\(.*\)",
    fix_template="""
    // Add validation
    if (data == null || !isValid(data)) {
        throw new ValidationException("Invalid data");
    }
    {original_code}
    """,
    imports=["ValidationException"],
    explanation="Added input validation"
)

generator.templates["CUSTOM_VULN"] = [custom_template]
```

## 🐛 Troubleshooting

### Common Issues

**CodeQL database creation fails**

```bash
# Check Java version
docker exec security-correlation java -version

# Manually create database
docker exec security-correlation codeql database create \
  --language=java \
  /data/codeql-databases/mydb \
  --source-root=/target-app
```

**LLM provider not available**

```bash
# Check Ollama connectivity
curl http://localhost:11434/api/tags

# Use template-based fallback
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -d '{"source_path": "/target-app", "llm_provider": "template"}'
```

**Out of memory**

```bash
# Increase Docker memory
docker-compose down
docker-compose up -d --scale correlation-engine=1 \
  --memory=8g
```

## 📈 Performance

### Benchmarks

- **Small project** (<1K LOC): ~2 minutes
- **Medium project** (1K-10K LOC): ~5-10 minutes
- **Large project** (10K-100K LOC): ~20-30 minutes

### Optimization Tips

1. **Reuse CodeQL databases** - Set `create_database: false`
2. **Use template-based patching** - Faster than LLM
3. **Disable validation** - Set `validate_patches: false`
4. **Parallel processing** - Run multiple instances

## 🔐 Security Considerations

1. **API Keys** - Store in secrets, never commit
2. **Code Access** - Platform reads code, ensure proper access controls
3. **Patch Review** - Always review generated patches before applying
4. **Network Security** - Use HTTPS in production

## 📚 Additional Resources

- [API Documentation](http://localhost:8000/docs) - Swagger UI
- [Phase 3 Implementation Report](../docs/reports/PHASE3-IMPLEMENTATION-COMPLETE.md)
- [Architecture Overview](../ARCHITECTURE.md)
- [Docker Deployment Guide](./DOCKER-DEPLOYMENT.md)

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.

## 📄 License

MIT License - See [LICENSE](../LICENSE) for details.

---

**Questions?** Open an issue on [GitHub](https://github.com/your-org/security-automation-platform/issues)
