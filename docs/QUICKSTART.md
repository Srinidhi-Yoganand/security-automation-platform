# 🚀 Quick Start - Security Automation Platform

## Get Started in 3 Steps

### Step 1: Deploy the Platform

```bash
# Clone the repository
git clone https://github.com/your-org/security-automation-platform.git
cd security-automation-platform

# Set your target application
export TARGET_APP_PATH=./test-vuln-app

# Start services
docker-compose up -d
```

### Step 2: Run Security Analysis

```bash
# Wait for services to be ready (30 seconds)
sleep 30

# Run end-to-end analysis
curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{
    "source_path": "/target-app",
    "language": "java",
    "generate_patches": true,
    "validate_patches": true
  }' | jq '.'
```

### Step 3: View Results

```bash
# Access Swagger UI
open http://localhost:8000/docs

# Or run quick test
./run-e2e-test.sh
```

## 🎯 What You Get

✅ **Automatic Vulnerability Detection** - CodeQL semantic analysis  
✅ **Exploitability Verification** - Z3 symbolic execution  
✅ **AI-Powered Patches** - LLM-generated security fixes  
✅ **Patch Validation** - Multi-level verification  
✅ **GitHub Integration** - Automatic PR comments and SARIF upload  

## 📚 Full Documentation

- [End-to-End Integration Guide](./docs/guides/END-TO-END-INTEGRATION.md)
- [Implementation Summary](./IMPLEMENTATION-SUMMARY.md)
- [Phase 4 Complete Report](./docs/reports/PHASE4-INTEGRATION-COMPLETE.md)

## 🐳 Docker Commands

```bash
# View logs
docker-compose logs -f correlation-engine

# Stop services
docker-compose down

# Restart
docker-compose restart

# Shell access
docker exec -it security-correlation bash
```

## 🔧 Environment Variables

Create `.env` file:
```bash
TARGET_APP_PATH=./your-java-app
LLM_PROVIDER=ollama                    # or gemini, openai, template
GEMINI_API_KEY=your-key-here          # optional
OPENAI_API_KEY=your-key-here          # optional
```

## 🧪 Testing

```bash
# Run end-to-end tests
cd correlation-engine
python -m pytest test_end_to_end.py -v

# Or use quick start script
./run-e2e-test.sh
```

## 📊 API Endpoints

- `GET /api/v1/status` - Platform health
- `GET /api/v1/e2e/status` - Pipeline status
- `POST /api/v1/e2e/analyze-and-fix` - Full analysis
- `GET /docs` - Swagger UI

## 🎓 Research

This platform implements a novel hybrid approach combining:
- CodeQL semantic analysis
- Z3 symbolic execution
- LLM-powered patching
- Automated validation

**Ready for thesis defense and publication!**

For more details, see [IMPLEMENTATION-SUMMARY.md](./IMPLEMENTATION-SUMMARY.md)
