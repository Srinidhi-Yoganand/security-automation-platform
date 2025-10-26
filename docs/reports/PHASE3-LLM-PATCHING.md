# LLM-Powered Automated Security Patching

## Overview

The security automation platform now uses **LLM (Large Language Models)** to generate intelligent, context-aware security patches for **ANY vulnerability type** found in Phase 1 and Phase 2.

## Key Features

### 🤖 **LLM-Powered Patch Generation**
- Uses GPT-4 (or GPT-3.5) to generate contextually appropriate fixes
- **Not limited to specific vulnerability types** - handles ANY security issue
- Analyzes full code context, method signatures, class structure
- Follows best practices and coding standards
- Includes proper error handling

### 🧪 **Automated Testing in Isolated Branches**
- Each patch is tested in a separate git branch
- Runs Maven/Gradle build and tests automatically
- Verifies compilation and test success before approval
- No risk to main codebase

### ✅ **Human Approval Workflow**
- Patches are generated and tested automatically
- Human reviews test results before applying
- Breaking changes and prerequisites clearly documented
- Manual review flag for critical changes

### 🔄 **Complete Workflow**
1. **Generate** → LLM creates fix with full context
2. **Test** → Patch applied in isolated branch, tests run
3. **Review** → Human reviews patch and test results
4. **Apply** → Approved patch merged to main branch

## API Endpoints

### 1. Generate Patch for Single Vulnerability

```bash
POST /api/v1/vulnerabilities/{vuln_id}/generate-patch
```

**Parameters:**
- `vuln_id` (int): Vulnerability ID from database
- `repo_path` (string, optional): Path to repository (default: ../vulnerable-app)
- `test_patch` (bool, optional): Test patch in branch (default: true)

**Response:**
```json
{
  "success": true,
  "vulnerability": {
    "id": 1,
    "type": "SQL Injection",
    "file": "src/main/java/com/security/automation/controller/UserController.java",
    "line": 45,
    "severity": "high",
    "risk_score": 85
  },
  "patch": {
    "original_code": "String query = \"SELECT * FROM users WHERE id=\" + userId;",
    "fixed_code": "PreparedStatement stmt = connection.prepareStatement(\"SELECT * FROM users WHERE id=?\");\nstmt.setString(1, userId);",
    "explanation": "Replaced string concatenation with PreparedStatement to prevent SQL injection...",
    "confidence": "high",
    "status": "tested",
    "test_branch": "security-patch-sql-injection-line-45",
    "test_results": {
      "success": true,
      "compilation_success": true,
      "tests_passed": true,
      "build_output": "..."
    },
    "breaking_changes": [],
    "prerequisites": [],
    "manual_review_needed": false,
    "diff": "--- a/src/main/java/...\n+++ b/src/main/java/...\n..."
  }
}
```

### 2. Generate Patches for Entire Scan

```bash
POST /api/v1/scans/{scan_id}/generate-patches
```

**Parameters:**
- `scan_id` (int): Scan ID from database
- `repo_path` (string, optional): Path to repository
- `limit` (int, optional): Max patches to generate (default: 20)
- `test_patches` (bool, optional): Test all patches (default: true)

**Response:**
```json
{
  "scan_id": 1,
  "commit_hash": "abc123",
  "patches_generated": 5,
  "vulnerabilities_skipped": 2,
  "patches": [
    {
      "vulnerability_id": 1,
      "type": "SQL Injection",
      "file": "...",
      "line": 45,
      "risk_score": 85,
      "original_code": "...",
      "fixed_code": "...",
      "explanation": "...",
      "confidence": "high",
      "status": "tested",
      "test_branch": "security-patch-sql-injection-line-45",
      "test_results": {...},
      "breaking_changes": [],
      "prerequisites": [],
      "manual_review_needed": false,
      "diff": "..."
    }
  ],
  "skipped": [
    {
      "vulnerability_id": 7,
      "type": "Information Disclosure",
      "reason": "Patch generation failed or not applicable"
    }
  ],
  "note": "Test patches in their respective branches before approving and applying"
}
```

### 3. Test Patch in Branch

```bash
POST /api/v1/patches/{vuln_id}/test
```

Re-test an existing patch to verify it still works.

### 4. Apply Approved Patch

```bash
POST /api/v1/patches/apply
```

**Parameters:**
- `test_branch` (string): Name of test branch with approved patch
- `target_branch` (string, optional): Branch to merge into (default: main)
- `repo_path` (string, optional): Path to repository

**Response:**
```json
{
  "success": true,
  "message": "Patch from 'security-patch-sql-injection-line-45' applied to 'main'",
  "target_branch": "main",
  "merged_branch": "security-patch-sql-injection-line-45"
}
```

## Setup

### 1. Install Dependencies

```bash
cd correlation-engine
pip install openai==1.3.7 javalang==0.13.0 diff-match-patch==20230430
```

### 2. Configure OpenAI API Key

```bash
# Option 1: Environment variable
export OPENAI_API_KEY="sk-..."

# Option 2: In code (llm_patch_generator.py)
# Will use environment variable if available
```

### 3. Start the Server

```bash
cd correlation-engine
source venv/Scripts/activate  # Windows Git Bash
python -m uvicorn app.main:app --reload --port 8000
```

## Usage Examples

### Example 1: Generate and Test Single Patch

```bash
# Generate patch for vulnerability ID 1
curl -X POST "http://localhost:8000/api/v1/vulnerabilities/1/generate-patch?test_patch=true" \
  -H "Content-Type: application/json"
```

### Example 2: Generate Patches for All Vulnerabilities

```bash
# Generate patches for scan ID 1
curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches?limit=10&test_patches=true" \
  -H "Content-Type: application/json"
```

### Example 3: Apply Approved Patch

```bash
# After reviewing test results, apply patch
curl -X POST "http://localhost:8000/api/v1/patches/apply" \
  -H "Content-Type: application/json" \
  -d '{
    "test_branch": "security-patch-sql-injection-line-45",
    "target_branch": "main",
    "repo_path": "../vulnerable-app"
  }'
```

## Workflow Steps

### Step 1: Phase 1 & 2 - Find Vulnerabilities

```bash
# Run correlation and behavior analysis (Phase 1 & 2)
cd correlation-engine
python -m app.main correlate \
  --codeql ../test-data/codeql-results/results.csv \
  --semgrep ../test-data/semgrep-results.sarif \
  --zap ../test-data/zap-results.json \
  --repo ../vulnerable-app \
  --output ../test-data/correlation-results.json

# This populates database with vulnerabilities
```

### Step 2: Generate Patches with LLM

```bash
# Generate patches for all vulnerabilities in latest scan
curl -X POST "http://localhost:8000/api/v1/scans/1/generate-patches" \
  -H "Content-Type: application/json"
```

The LLM will:
1. Analyze each vulnerability's context
2. Generate a secure fix
3. Create a test branch
4. Apply the fix in the branch
5. Run Maven/Gradle build and tests
6. Return results with test status

### Step 3: Review Patches

Review the response to check:
- ✅ `status`: "tested" (vs "failed")
- ✅ `test_results.success`: true
- ✅ `test_results.compilation_success`: true
- ✅ `test_results.tests_passed`: true
- ⚠️ `breaking_changes`: [] (none expected)
- ⚠️ `manual_review_needed`: false
- 📝 `explanation`: Understand what the fix does

### Step 4: Test in Branch (Optional)

```bash
# Checkout the test branch and manually verify
cd ../vulnerable-app
git checkout security-patch-sql-injection-line-45

# Run your own tests
mvn clean test

# Review the changes
git diff main
```

### Step 5: Apply Approved Patches

```bash
# Apply patch to main branch
curl -X POST "http://localhost:8000/api/v1/patches/apply" \
  -H "Content-Type: application/json" \
  -d '{
    "test_branch": "security-patch-sql-injection-line-45",
    "target_branch": "main"
  }'
```

## Supported Vulnerability Types

The LLM can generate patches for **ANY vulnerability type**, including:

### Common Types (Tested)
- ✅ SQL Injection
- ✅ Cross-Site Scripting (XSS)
- ✅ Insecure Direct Object Reference (IDOR)
- ✅ Path Traversal
- ✅ Command Injection
- ✅ Cross-Site Request Forgery (CSRF)
- ✅ Weak Cryptography
- ✅ Insecure Deserialization
- ✅ XML External Entity (XXE)
- ✅ Server-Side Request Forgery (SSRF)

### Advanced Types
- ✅ Race Conditions
- ✅ Authentication Bypass
- ✅ Authorization Flaws
- ✅ Information Disclosure
- ✅ Denial of Service
- ✅ Business Logic Vulnerabilities
- ✅ API Security Issues
- ✅ **And literally ANY other type!**

The LLM understands security concepts and can generate appropriate fixes for novel or complex vulnerability types.

## Advantages Over Template-Based Patching

| Feature | Template-Based | LLM-Powered |
|---------|---------------|-------------|
| **Vulnerability Coverage** | 5-10 types | ♾️ UNLIMITED |
| **Code Understanding** | Pattern matching only | Full semantic analysis |
| **Context Awareness** | Limited | Complete (class, method, dependencies) |
| **Fix Quality** | Generic | Contextually appropriate |
| **Best Practices** | Hardcoded | Adaptive (Spring Boot, security patterns) |
| **Novel Vulnerabilities** | ❌ Cannot handle | ✅ Adapts automatically |
| **Breaking Changes** | Unknown | Documented |
| **Explanation** | Generic | Detailed and specific |

## Configuration

### OpenAI Model Selection

Edit `llm_patch_generator.py`:

```python
# For best quality (recommended)
model="gpt-4-turbo-preview"

# For faster/cheaper option
model="gpt-3.5-turbo"
```

### LLM Parameters

```python
temperature=0.3  # Lower = more consistent code
max_tokens=2000  # Adjust for longer/shorter fixes
```

### Testing Timeout

```python
timeout=300  # 5 minutes for build/test
```

## Troubleshooting

### Issue: "OpenAI API key not configured"

**Solution:**
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

### Issue: Patch generation fails

**Fallback:** The system automatically falls back to template-based patching if LLM is unavailable.

### Issue: Build tests fail

**Check:**
1. Is Maven/Gradle installed?
2. Does the project build successfully on main branch?
3. Review `test_results.build_output` for errors

### Issue: Git branch conflicts

**Solution:**
```bash
cd vulnerable-app
git checkout main
git branch -D security-patch-*  # Clean up test branches
```

## Security Considerations

1. **API Key Security**: Never commit OpenAI API keys to git
2. **Code Review**: Always review LLM-generated code before applying
3. **Test First**: Always test patches in isolated branches
4. **Cost Control**: Set OpenAI usage limits to avoid unexpected charges
5. **Fallback**: Template-based patching used when LLM unavailable

## Cost Estimation

### OpenAI API Costs (GPT-4 Turbo)

- **Input**: ~$0.01 per 1K tokens
- **Output**: ~$0.03 per 1K tokens
- **Average patch**: ~2K input + 1K output = ~$0.05 per patch
- **For 20 vulnerabilities**: ~$1.00

### Cost Optimization

1. Use GPT-3.5 Turbo for lower costs (~10x cheaper)
2. Generate patches in batches
3. Cache similar vulnerability fixes
4. Set monthly spending limits in OpenAI dashboard

## Next Steps

1. ✅ **Done**: LLM-powered patch generation
2. ✅ **Done**: Automated testing in branches
3. 🔲 **TODO**: Developer notifications (Slack/Email)
4. 🔲 **TODO**: GitHub Action integration
5. 🔲 **TODO**: Dashboard UI for patch approval
6. 🔲 **TODO**: Batch patch application

## References

- [OpenAI API Documentation](https://platform.openai.com/docs/api-reference)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
