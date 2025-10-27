# 🌐 Semantic Analysis API Documentation

**Version:** 2.0.0  
**Last Updated:** October 27, 2025  
**Base URL:** `http://localhost:8000`

---

## 📋 Overview

The Semantic Analysis API provides endpoints for performing deep code analysis using CodeQL and symbolic execution. It enables:
- Creating CodeQL databases from Java projects
- Running security queries to detect logic flaws
- **Symbolic execution verification with Z3 (NEW)**
- Parsing and enriching SARIF results
- Extracting security context (authentication/authorization)
- Building Code Property Graphs (CPGs)
- **Generating exploit PoCs (NEW)**

---

## 🔐 Endpoints

### 1. Complete Semantic Analysis

**POST** `/api/v1/semantic/analyze`

Performs complete semantic analysis including database creation, query execution, and result parsing.

**Request Body:**
```json
{
  "project_path": "/path/to/java/project",
  "force_refresh": false,
  "run_queries": true,
  "enable_symbolic_verification": false
}
```

**Parameters:**
- `project_path` (string, required): Absolute path to Java project
- `force_refresh` (boolean, optional): Force database recreation. Default: `false`
- `run_queries` (boolean, optional): Run queries after DB creation. Default: `true`
- `enable_symbolic_verification` (boolean, optional): **NEW** - Verify findings with Z3. Default: `false`

**Response:**
```json
{
  "status": "success",
  "project_path": "/path/to/java/project",
  "database_path": "/path/to/codeql-databases/project-db",
  "results_file": "/path/to/results.sarif",
  "total_findings": 15,
  "vulnerabilities": [
    {
      "vulnerability_type": "IDOR",
      "source_location": {
        "file_path": "src/main/java/UserController.java",
        "start_line": 45,
        "end_line": 45,
        "start_column": 20,
        "end_column": 35
      },
      "sink_location": {
        "file_path": "src/main/java/UserController.java",
        "start_line": 52,
        "end_line": 52,
        "start_column": 12,
        "end_column": 28
      },
      "flow_path": [
        {
          "file_path": "src/main/java/UserController.java",
          "start_line": 45,
          "description": "User input from request parameter"
        },
        {
          "file_path": "src/main/java/UserController.java",
          "start_line": 52,
          "description": "Used in database query without authorization check"
        }
      ],
      "confidence_score": 0.85,
      "severity": "high",
      "security_context": {
        "has_authentication": true,
        "has_authorization": false,
        "authentication_type": "@PreAuthorize",
        "authorization_check": null
      }
    }
  ],
  "statistics": {
    "total_findings": 15,
    "by_type": {
      "IDOR": 5,
      "MissingAuthorization": 3,
      "PathTraversal": 2,
      "SQLInjection": 5
    },
    "by_severity": {
      "high": 8,
      "medium": 5,
      "low": 2
    },
    "database_creation_time": "10.5s",
    "query_execution_time": "23.2s"
  }
}
```

**Error Responses:**
- `404 Not Found`: Project path doesn't exist
- `500 Internal Server Error`: Analysis failed

---

### 2. Create CodeQL Database

**POST** `/api/v1/semantic/database/create`

Creates a CodeQL database from a Java project without running queries.

**Request Body:**
```json
{
  "project_path": "/path/to/java/project",
  "db_name": "my-project-db",
  "force": false
}
```

**Parameters:**
- `project_path` (string, required): Absolute path to Java project
- `db_name` (string, optional): Custom database name. Default: auto-generated
- `force` (boolean, optional): Overwrite existing database. Default: `false`

**Response:**
```json
{
  "success": true,
  "database_path": "/path/to/codeql-databases/my-project-db",
  "message": "Database created successfully"
}
```

**Use Cases:**
- CI/CD pipeline database creation
- Batch processing multiple projects
- Database creation for later query execution

---

### 3. Run CodeQL Queries

**POST** `/api/v1/semantic/queries/run`

Runs CodeQL security queries on an existing database.

**Request Body:**
```json
{
  "database_path": "/path/to/codeql-databases/project-db",
  "query_path": "/path/to/custom-queries/"
}
```

**Parameters:**
- `database_path` (string, required): Path to CodeQL database
- `query_path` (string, optional): Path to custom queries. Default: built-in queries

**Response:**
```json
{
  "success": true,
  "results_file": "/path/to/results.sarif",
  "findings_count": 15,
  "message": "Found 15 potential vulnerabilities"
}
```

**Built-in Queries:**
- `idor-detection.ql`: IDOR vulnerability detection
- `missing-authorization.ql`: Missing authorization checks
- `advanced-dataflow.ql`: Multi-vulnerability data flow analysis

---

### 4. Get Analysis Results

**GET** `/api/v1/semantic/results/{results_file}`

Retrieves parsed and enhanced results from a SARIF file.

**Path Parameters:**
- `results_file` (string, required): Path to SARIF results file

**Response:**
```json
{
  "results_file": "/path/to/results.sarif",
  "total_findings": 15,
  "vulnerabilities": [
    {
      "vulnerability_type": "IDOR",
      "source_location": { ... },
      "sink_location": { ... },
      "flow_path": [ ... ],
      "confidence_score": 0.85,
      "security_context": {
        "has_authentication": true,
        "has_authorization": false,
        "authentication_type": "@PreAuthorize",
        "authorization_check": null
      }
    }
  ]
}
```

**Enhancement Features:**
- Security context extraction (authentication/authorization)
- Confidence scoring based on data flow analysis
- CPG node enrichment
- Severity classification

---

### 5. Get Statistics

**GET** `/api/v1/semantic/stats`

Returns statistics about semantic analysis operations.

**Response:**
```json
{
  "active_analyzers": 3,
  "projects": [
    "/path/to/project1",
    "/path/to/project2",
    "/path/to/project3"
  ]
}
```

---

## 🔧 Integration Examples

### Python Client Example

```python
import requests

# Complete analysis
response = requests.post(
    "http://localhost:8000/api/v1/semantic/analyze",
    json={
        "project_path": "/path/to/vulnerable-app",
        "force_refresh": False
    }
)

results = response.json()
print(f"Found {results['total_findings']} vulnerabilities")

for vuln in results['vulnerabilities']:
    print(f"- {vuln['vulnerability_type']} at {vuln['sink_location']['file_path']}:{vuln['sink_location']['start_line']}")
```

### cURL Example

```bash
# Create database
curl -X POST http://localhost:8000/api/v1/semantic/database/create \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/path/to/project"}'

# Run queries
curl -X POST http://localhost:8000/api/v1/semantic/queries/run \
  -H "Content-Type: application/json" \
  -d '{"database_path": "/path/to/codeql-databases/project-db"}'

# Get results
curl http://localhost:8000/api/v1/semantic/results/path/to/results.sarif
```

---

## 📊 Data Models

### CodeLocation
```python
{
  "file_path": str,
  "start_line": int,
  "end_line": int,
  "start_column": int,
  "end_column": int
}
```

### DataFlowPath
```python
{
  "vulnerability_type": str,
  "source_location": CodeLocation,
  "sink_location": CodeLocation,
  "flow_path": List[CodeLocation],
  "confidence_score": float,  # 0.0 - 1.0
  "severity": str  # "low", "medium", "high", "critical"
}
```

### SecurityContext
```python
{
  "has_authentication": bool,
  "has_authorization": bool,
  "authentication_type": Optional[str],  # "@PreAuthorize", "@Secured", etc.
  "authorization_check": Optional[str],  # Method name or annotation
  "context_variables": Dict[str, Any]
}
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# CodeQL CLI path
CODEQL_CLI=/path/to/codeql/codeql

# Default query path
CODEQL_QUERIES=/path/to/codeql-queries

# Database storage
CODEQL_DATABASES=/path/to/codeql-databases

# Cache directory
SEMANTIC_CACHE=/path/to/.cache

# Timeouts (seconds)
DB_CREATE_TIMEOUT=600
QUERY_RUN_TIMEOUT=900
```

---

## 🐛 Error Handling

### Common Errors

**Database Creation Failed**
```json
{
  "status": "error",
  "error": "Failed to create CodeQL database: build command failed"
}
```
**Solution:** Check that project compiles correctly

**Query Execution Timeout**
```json
{
  "status": "error",
  "error": "Query execution timed out after 900s"
}
```
**Solution:** Use more specific queries or increase timeout

**SARIF Parse Error**
```json
{
  "status": "error",
  "error": "Failed to parse SARIF: invalid JSON"
}
```
**Solution:** Check CodeQL query output format

---

## 📈 Performance

### Typical Timings

| Project Size | DB Creation | Query Execution | Total Time |
|--------------|-------------|-----------------|------------|
| Small (1K LOC) | 5-10s | 10-15s | 15-25s |
| Medium (10K LOC) | 15-30s | 30-60s | 45-90s |
| Large (100K LOC) | 60-120s | 120-300s | 3-7 min |

### Optimization Tips

1. **Use Caching**: Set `force_refresh=false` to reuse databases
2. **Targeted Queries**: Run specific queries instead of all
3. **Incremental Analysis**: Analyze changed files only
4. **Parallel Execution**: Analyze multiple projects concurrently

---

## 🔬 Symbolic Execution (NEW)

### Overview

Symbolic execution uses Z3 theorem prover to verify CodeQL findings. Instead of pattern matching alone, it proves vulnerabilities are exploitable by solving constraints.

### Enable Symbolic Verification

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/semantic/analyze",
    json={
        "project_path": "/path/to/project",
        "enable_symbolic_verification": True  # Enable Z3 verification
    }
)

results = response.json()

# Only symbolically verified findings included
for vuln in results['vulnerabilities']:
    if vuln['symbolically_verified']:
        print(f"Confirmed: {vuln['vulnerability_type']}")
        print(f"Exploit: {vuln['exploit_proof']}")
```

### Exploit Proof Structure

When symbolic verification is enabled, findings include exploit proofs:

```json
{
  "vulnerability_type": "idor",
  "symbolically_verified": true,
  "confidence": 0.95,
  "exploit_proof": {
    "vulnerability_type": "idor",
    "exploitable": true,
    "attack_vector": {
      "endpoint": "/api/users",
      "attacker_value": 42,
      "attacker_logged_in_as": 1,
      "explanation": "User 1 can access user 42's data"
    },
    "proof": "IDOR vulnerability confirmed through symbolic execution...",
    "satisfying_constraints": [
      "userId = 42",
      "currentUserId = 1",
      "userId ≠ currentUserId (no authorization check)"
    ],
    "missing_check": "Authorization check: verify current user owns the requested resource",
    "confidence": 0.95
  }
}
```

### Generate PoC Exploits

```bash
# Save analysis results
curl -X POST http://localhost:8000/api/v1/semantic/analyze \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/path/to/project", "enable_symbolic_verification": true}' \
  > results.json

# Generate JUnit tests and curl commands
python correlation-engine/tools/generate_pocs.py results.json --output-dir ./pocs --curl
```

Output:
- `./pocs/testIDOR_0.java` - Runnable JUnit test
- `./pocs/testMissingAuth_1.java` - Another test
- Curl commands printed to console

### Benefits

- **False Positive Reduction**: Only confirmed exploits reported
- **Higher Confidence**: Proven with constraint solving
- **Exploit Generation**: Automatic PoC creation
- **Minimal Overhead**: <10ms per finding verification

See [Symbolic Execution Guide](../../docs/guides/SYMBOLIC-EXECUTION.md) for detailed documentation.

---

## 🧪 Testing

### Unit Tests

```bash
# Run semantic analyzer tests
cd correlation-engine
python -m pytest test_semantic_analyzer.py -v

# Run symbolic execution tests
python -m pytest tests/test_symbolic_idor.py -v
python -m pytest tests/test_symbolic_auth.py -v
python -m pytest tests/test_integration_semantic_symbolic.py -v
python -m pytest tests/test_poc_generation.py -v

# Run with coverage
python -m pytest tests/ --cov=app.core
```

### Integration Tests

```bash
# Test with sample vulnerable app
python test_semantic_analyzer.py
```

---

## 📝 Changelog

### Version 2.0.0 (2025-10-27)
- ✅ **NEW**: Symbolic execution with Z3 solver
- ✅ **NEW**: IDOR verification via constraint solving
- ✅ **NEW**: Missing authentication detection
- ✅ **NEW**: Exploit PoC generation tool
- ✅ **NEW**: Integration with semantic analyzer pipeline
- ✅ False positive reduction through symbolic verification
- ✅ 27 total unit tests (all passing)

### Version 1.0.0 (2025-10-27)
- ✅ Initial release
- ✅ Complete semantic analysis workflow
- ✅ SARIF parsing with security context
- ✅ CPG building
- ✅ Caching system
- ✅ 5 REST API endpoints
- ✅ Comprehensive unit tests

---

## 🤝 Contributing

For questions or issues, please contact the development team or open an issue on the repository.

---

## 📚 References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Z3 Theorem Prover](https://github.com/Z3Prover/z3)
- [Symbolic Execution Guide](../../docs/guides/SYMBOLIC-EXECUTION.md)
