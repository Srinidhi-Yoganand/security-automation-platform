"""
Phase 1 Validation Script
Tests that all components are ready for implementation
"""

import sys
import subprocess
from pathlib import Path

print("="*60)
print("PHASE 1 VALIDATION - Pre-Implementation Checks")
print("="*60)
print()

# Track results
tests_passed = 0
tests_failed = 0

def test(name, fn):
    """Run a test and track results"""
    global tests_passed, tests_failed
    print(f"Testing: {name}...", end=" ")
    try:
        fn()
        print("✅ PASS")
        tests_passed += 1
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        tests_failed += 1
        return False

# Test 1: Python environment
def check_python():
    assert sys.version_info >= (3, 9), "Python 3.9+ required"

test("Python version", check_python)

# Test 2: Required files exist
def check_files():
    required_files = [
        "correlation-engine/app/core/semantic_analyzer.py",
        "correlation-engine/app/core/symbolic_executor.py",
        "setup-codeql.sh",
        "setup-codeql.ps1",
        "IMPLEMENTATION-ROADMAP.md",
        "THESIS-IMPLEMENTATION-PLAN.md"
    ]
    for file in required_files:
        assert Path(file).exists(), f"Missing {file}"

test("Required files exist", check_files)

# Test 3: Can import new modules
def check_imports():
    sys.path.insert(0, 'correlation-engine')
    from app.core.semantic_analyzer import SemanticAnalyzer, DataFlowPath
    from app.core.symbolic_executor import SymbolicExecutor, ExploitProof

test("Import new modules", check_imports)

# Test 4: Check if vulnerable app exists
def check_vuln_app():
    vuln_app_paths = [
        "sample-vuln-app",
        "vulnerable-app",
        "test-data"
    ]
    found = any(Path(p).exists() for p in vuln_app_paths)
    assert found, "No vulnerable app found for testing"

test("Vulnerable app for testing", check_vuln_app)

# Test 5: Check Git status
def check_git():
    result = subprocess.run(
        ["git", "status"],
        capture_output=True,
        text=True,
        check=True
    )
    assert "On branch main" in result.stdout or "On branch" in result.stdout

test("Git repository", check_git)

# Test 6: Check Docker status
def check_docker():
    result = subprocess.run(
        ["docker", "ps"],
        capture_output=True,
        text=True,
        check=True
    )
    # Docker should be running
    assert "CONTAINER ID" in result.stdout

test("Docker running", check_docker)

# Test 7: Check if API is accessible
def check_api():
    import requests
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        assert response.status_code == 200
    except requests.exceptions.RequestException:
        raise Exception("API not running. Start with: docker-compose up -d")

test("API accessible", check_api)

print()
print("="*60)
print(f"Results: {tests_passed} passed, {tests_failed} failed")
print("="*60)
print()

if tests_failed == 0:
    print("🎉 All checks passed! Ready to start Phase 1.")
    print()
    print("Next steps:")
    print("1. Run CodeQL setup: ./setup-codeql.ps1 (Windows) or ./setup-codeql.sh (Linux/Mac)")
    print("2. Install new dependencies: cd correlation-engine && pip install -r requirements.txt")
    print("3. Start building!")
    sys.exit(0)
else:
    print("⚠️  Some checks failed. Please fix issues before proceeding.")
    print()
    print("Common fixes:")
    print("- Install missing dependencies: pip install -r correlation-engine/requirements.txt")
    print("- Start Docker: docker-compose up -d")
    print("- Ensure you're in the project root directory")
    sys.exit(1)
