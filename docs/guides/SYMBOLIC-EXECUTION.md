# Symbolic Execution Guide

## Overview

Symbolic execution uses the Z3 constraint solver to verify security vulnerabilities discovered by CodeQL. Instead of relying solely on pattern matching, symbolic execution proves that a vulnerability is exploitable by solving constraints that model attack scenarios.

## Key Features

- **IDOR Verification**: Proves that an attacker logged in as user A can access user B's data
- **Missing Authentication Detection**: Verifies that sensitive endpoints are accessible without authentication
- **False Positive Reduction**: Filters CodeQL findings that cannot be symbolically confirmed
- **Exploit Generation**: Automatically creates JUnit tests and curl commands demonstrating the vulnerability

## How It Works

### IDOR Detection

1. Create symbolic variables:
   - `userId` = user-controlled input (from request parameter)
   - `currentUserId` = authenticated user
2. Add constraint: `userId != currentUserId` (attacker tries different user's data)
3. Check if authorization check exists in code path
4. If satisfiable without authorization, vulnerability confirmed

### Missing Authentication Detection

1. Create symbolic boolean: `isAuthenticated`
2. Check for authentication annotations (`@PreAuthorize`, `@Secured`)
3. Check for authentication checks in method body
4. If endpoint accessible with `isAuthenticated = false`, vulnerability confirmed

## Usage

### Via Semantic Analyzer

```python
from app.core.semantic_analyzer_complete import SemanticAnalyzer

analyzer = SemanticAnalyzer("/path/to/project")
results = analyzer.analyze_project(
    "/path/to/project",
    enable_symbolic_verification=True  # Enable verification
)

# Only symbolically verified findings are included
for vuln in results['vulnerabilities']:
    if vuln['symbolically_verified']:
        print(f"Confirmed: {vuln['vulnerability_type']}")
        print(f"Confidence: {vuln['confidence']}")
        print(f"Proof: {vuln['exploit_proof']['proof']}")
```

### Direct Symbolic Executor

```python
from app.core.symbolic_executor import SymbolicExecutor
from app.core.semantic_analyzer_complete import DataFlowPath, SecurityContext, CodeLocation

executor = SymbolicExecutor()

# Create data flow (from CodeQL)
source_loc = CodeLocation("UserController.java", 42, 42, 10, 25)
sink_loc = CodeLocation("UserController.java", 45, 45, 8, 30)

dataflow = DataFlowPath(
    source="@PathVariable userId",
    sink="userRepository.findById(userId)",
    source_location=source_loc,
    sink_location=sink_loc,
    vulnerability_type="idor"
)

context = SecurityContext(
    file_path="UserController.java",
    line_number=42,
    authentication_present=True,
    authorization_present=False
)

# Verify with symbolic execution
proof = executor.verify_codeql_finding(dataflow, context)

if proof:
    print(f"Vulnerability confirmed: {proof.vulnerability_type}")
    print(f"Attack vector: {proof.attack_vector}")
else:
    print("False positive - no exploit found")
```

### Generate PoC Exploits

```bash
# Generate JUnit tests and curl commands from analysis results
python correlation-engine/tools/generate_pocs.py results.json --output-dir ./pocs --curl
```

Output:
- `./pocs/testIDOR_0.java` - JUnit test demonstrating IDOR
- `./pocs/testMissingAuth_1.java` - JUnit test for missing auth
- Curl commands printed to console

## Configuration

### Z3 Solver

Z3 is automatically installed via `requirements.txt`:
```
z3-solver==4.12.2.0
```

Verify installation:
```python
from z3 import Solver, Int, sat
s = Solver()
x = Int('x')
s.add(x > 0)
print(s.check())  # Should print 'sat'
```

### Timeouts

Symbolic execution typically completes in milliseconds but can be configured:

```python
# In symbolic_executor.py
self.solver.set("timeout", 5000)  # 5 seconds
```

## Integration with Semantic Analyzer

When `enable_symbolic_verification=True`:

1. CodeQL finds potential vulnerabilities
2. For each finding, semantic analyzer:
   - Extracts security context (auth/authz annotations)
   - Calls `SymbolicExecutor.verify_codeql_finding()`
3. Symbolic executor:
   - Models attack scenario with Z3 constraints
   - Attempts to find satisfying assignment
   - Returns `ExploitProof` if successful, `None` otherwise
4. Only verified findings are included in results
5. Unverified findings are logged but excluded (false positive reduction)

## Examples

### Example 1: IDOR Vulnerability

**Code:**
```java
@GetMapping("/api/users/{userId}")
public User getUser(@PathVariable Long userId) {
    return userRepository.findById(userId).orElse(null);
}
```

**Symbolic Analysis:**
- User input: `userId` (PathVariable)
- Authenticated user: `currentUserId` (from SecurityContext)
- Constraint: `userId != currentUserId`
- Authorization check: **MISSING**
- Result: **SAT** → Vulnerability confirmed

**Exploit Proof:**
```json
{
  "vulnerability_type": "idor",
  "exploitable": true,
  "attack_vector": {
    "attacker_value": 42,
    "attacker_logged_in_as": 1,
    "explanation": "User 1 can access user 42's data"
  },
  "confidence": 0.95
}
```

### Example 2: Secure Implementation

**Code:**
```java
@GetMapping("/api/users/{userId}")
@PreAuthorize("@userSecurity.isOwner(#userId)")
public User getUser(@PathVariable Long userId) {
    return userRepository.findById(userId).orElse(null);
}
```

**Symbolic Analysis:**
- Same setup as Example 1
- Authorization check: `@PreAuthorize` annotation found
- Additional constraint: `userId == currentUserId` (enforced by annotation)
- Result: **UNSAT** → No vulnerability (false positive filtered)

### Example 3: Missing Authentication

**Code:**
```java
@PostMapping("/api/admin/delete")
public void deleteUser(@RequestParam Long userId) {
    userRepository.deleteById(userId);
}
```

**Symbolic Analysis:**
- Authentication required: **NO**
- Sensitive operation: **YES** (delete)
- Constraint: `isAuthenticated = false`
- Result: **SAT** → Vulnerability confirmed

**Fix:**
```java
@PostMapping("/api/admin/delete")
@PreAuthorize("hasRole('ADMIN')")  // Add this
public void deleteUser(@RequestParam Long userId) {
    userRepository.deleteById(userId);
}
```

## Testing

### Run Unit Tests

```bash
cd correlation-engine

# IDOR tests
python tests/test_symbolic_idor.py

# Authentication tests
python tests/test_symbolic_auth.py

# Integration tests
python tests/test_integration_semantic_symbolic.py

# PoC generation tests
python tests/test_poc_generation.py

# All tests
python -m pytest tests/ -v
```

### Test Coverage

- **IDOR Detection**: 9 tests
- **Missing Auth**: 8 tests
- **Integration**: 5 tests
- **PoC Generation**: 5 tests
- **Total**: 27 tests, all passing

## Performance

| Operation | Typical Time |
|-----------|--------------|
| Single IDOR verification | <10ms |
| Single auth verification | <5ms |
| 10 findings verification | ~50ms |
| PoC generation | ~100ms per PoC |

Symbolic execution adds minimal overhead (~5-10%) to overall analysis time.

## Limitations

1. **Path Explosion**: Complex code paths may cause solver timeouts (rare in practice)
2. **Framework-Specific**: Currently optimized for Spring Boot annotations
3. **Simple Constraints**: Models basic access control; complex business logic requires manual review
4. **No Runtime State**: Symbolic execution is static; doesn't account for runtime configuration

## Best Practices

1. **Enable for High-Value Targets**: Use symbolic verification on critical endpoints
2. **Review Filtered Results**: Occasionally check false positives to tune filters
3. **Combine with Manual Review**: Symbolic execution reduces but doesn't eliminate manual security review
4. **Use Generated PoCs**: Run generated JUnit tests in your test suite

## Troubleshooting

### Z3 Import Error

```python
ImportError: No module named 'z3'
```

**Solution:**
```bash
pip install z3-solver==4.12.2.0
```

### Solver Timeout

```
Z3 solver timed out
```

**Solution:**
- Increase timeout: `self.solver.set("timeout", 10000)`
- Simplify constraints
- Break complex flows into smaller units

### No Proofs Generated

All findings marked as "symbolically_verified: false"

**Possible causes:**
- Authorization checks present (working as expected)
- Adapter not recognizing security annotations
- Check logs for verification attempts

## References

- [Z3 Theorem Prover](https://github.com/Z3Prover/z3)
- [Z3 Python API](https://z3prover.github.io/api/html/namespacez3py.html)
- [Symbolic Execution Wikipedia](https://en.wikipedia.org/wiki/Symbolic_execution)
