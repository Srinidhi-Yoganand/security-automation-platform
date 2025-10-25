# Quick Start: LLM-Powered Automated Patching

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies (1 minute)

```bash
cd correlation-engine

# Activate virtual environment
source venv/Scripts/activate  # Windows Git Bash
# or
source venv/bin/activate       # Linux/Mac

# Install LLM dependencies
pip install openai==1.3.7 javalang==0.13.0 diff-match-patch==20230430
```

### Step 2: Configure OpenAI API Key (1 minute)

```bash
# Get API key from https://platform.openai.com/api-keys

# Set environment variable
export OPENAI_API_KEY="sk-proj-..."

# Verify it's set
echo $OPENAI_API_KEY
```

### Step 3: Start the API Server (30 seconds)

```bash
cd correlation-engine
python -m uvicorn app.main:app --reload --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
```

### Step 4: Generate Your First Patch! (2 minutes)

Open a new terminal and run:

```bash
# Generate patches for all vulnerabilities in scan ID 1
curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches?limit=5&test_patches=false" \
  -H "Content-Type: application/json" | json_pp
```

Or for a single vulnerability:

```bash
# Generate patch for vulnerability ID 1
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch?test_patch=false" \
  -H "Content-Type: application/json" | json_pp
```

### Step 5: Review the Patch

The response will include:

```json
{
  "success": true,
  "vulnerability": {
    "id": 1,
    "type": "SQL Injection",
    "file": "src/main/java/.../UserController.java",
    "line": 45,
    "severity": "high"
  },
  "patch": {
    "original_code": "String query = \"SELECT * FROM users WHERE id=\" + userId;",
    "fixed_code": "PreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE id=?\");\nstmt.setString(1, userId);",
    "explanation": "Replaced string concatenation with PreparedStatement to prevent SQL injection...",
    "confidence": "high",
    "status": "generated",
    "manual_review_needed": false,
    "diff": "--- a/src/...\n+++ b/src/...\n..."
  }
}
```

## 🧪 Test with Real Vulnerabilities

### Option 1: Use Test Script

```bash
cd correlation-engine

# Run demo with sample vulnerabilities
python test_llm_patches.py
```

This will:
- ✅ Test SQL Injection patching
- ✅ Test IDOR patching
- ✅ Test Race Condition patching (novel vulnerability)
- ✅ Test with actual database vulnerabilities (if Phase 2 ran)

### Option 2: Use API

```bash
# Make sure Phase 2 ran and database has vulnerabilities
# Then generate patches for a scan

curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches" \
  -H "Content-Type: application/json"
```

## 🔀 Test Patch in Branch (Optional)

If you want to test patches in isolated git branches:

```bash
# Enable testing (takes longer due to Maven build)
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch?test_patch=true" \
  -H "Content-Type: application/json"
```

This will:
1. Create a test branch (e.g., `security-patch-sql-injection-line-45`)
2. Apply the fix
3. Run `mvn clean test`
4. Return test results

Then you can manually review:

```bash
cd ../vulnerable-app
git branch  # See test branches
git checkout security-patch-sql-injection-line-45
git diff main
mvn clean test  # Run tests yourself
```

## ✅ Apply Approved Patch

After reviewing the patch and test results:

```bash
curl -X POST "http://localhost:8000/api/v1/patches/apply" \
  -H "Content-Type: application/json" \
  -d '{
    "test_branch": "security-patch-sql-injection-line-45",
    "target_branch": "main",
    "repo_path": "../vulnerable-app"
  }'
```

## 💡 Tips

### Save API Responses

```bash
# Save patch to file for review
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch" \
  -H "Content-Type: application/json" > patch-vuln-1.json

# View nicely formatted
cat patch-vuln-1.json | json_pp
```

### Generate Multiple Patches

```bash
# Generate patches for top 10 vulnerabilities
curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches?limit=10" \
  -H "Content-Type: application/json" > patches-scan-1.json
```

### Use GPT-3.5 for Faster/Cheaper

Edit `app/services/patcher/llm_patch_generator.py`:

```python
# Line ~200, change model to:
model="gpt-3.5-turbo"  # 10x cheaper than GPT-4
```

## 🐛 Troubleshooting

### "OpenAI API key not configured"

```bash
# Set the environment variable
export OPENAI_API_KEY="sk-..."

# Restart the server
```

### "Vulnerability not found"

```bash
# Make sure Phase 2 ran and populated the database
cd correlation-engine
python test_phase2.py

# This will create scan and vulnerabilities
```

### "Git repository not available"

```bash
# Make sure you're running from correct directory
cd correlation-engine
pwd  # Should be: .../security-automation-platform/correlation-engine

# Check repo path parameter
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch?repo_path=../vulnerable-app"
```

### Maven build fails during testing

```bash
# Test manually first
cd ../vulnerable-app
mvn clean test

# If that works, try again
# If not, disable testing:
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch?test_patch=false"
```

## 📊 Check API Documentation

Visit: http://localhost:8000/docs

This shows:
- All available endpoints
- Request/response schemas
- Interactive testing interface

## 🎓 Learn More

- **Full Documentation**: See `PHASE3-LLM-PATCHING.md`
- **Implementation Details**: See `PHASE3-IMPLEMENTATION-SUMMARY.md`
- **API Reference**: See `correlation-engine/API-DOCS.md`

## 🚀 What's Next?

1. ✅ Generate patches for all vulnerabilities
2. 📝 Review and approve patches
3. 🔀 Test in isolated branches
4. ✅ Apply approved patches to main
5. 🎉 Deploy secure code!

---

**Questions?** Check the full documentation or review the test scripts for more examples.

**Ready for Production?** The system is designed for safety with isolated testing and human approval workflows.
