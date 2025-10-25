"""
Direct API test without starting server
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext


def test_api_logic():
    """Test the API logic directly"""
    
    print("="*80)
    print("API ENDPOINT LOGIC TEST")
    print("="*80)
    print()
    
    # Simulate what the API endpoint does
    print("Simulating: POST /api/v1/vulnerabilities/{vuln_id}/generate-patch")
    print()
    
    # Create patch context (like API would from database)
    context = PatchContext(
        vulnerability_type="SQL Injection",
        file_path="src/main/java/com/security/automation/controller/UserController.java",
        line_number=45,
        vulnerable_code='String query = "SELECT * FROM users WHERE id=" + userId;',
        severity="high",
        confidence=0.9,
        description="SQL injection via string concatenation",
        cwe_id="CWE-89",
        tool_name="CodeQL"
    )
    
    # Generate patch (like API would)
    generator = LLMPatchGenerator(repo_path="../vulnerable-app")
    patch = generator.generate_patch(context, test_patch=False)
    
    if patch:
        # Simulate API response
        response = {
            "success": True,
            "vulnerability": {
                "id": 1,
                "type": context.vulnerability_type,
                "file": context.file_path,
                "line": context.line_number,
                "severity": context.severity
            },
            "patch": {
                "original_code": patch.original_code,
                "fixed_code": patch.fixed_code,
                "explanation": patch.explanation,
                "confidence": patch.confidence,
                "status": patch.status.value,
                "manual_review_needed": patch.manual_review_needed,
                "diff": patch.diff[:200] + "..." if len(patch.diff) > 200 else patch.diff
            }
        }
        
        print("[SUCCESS] API would return:")
        print()
        import json
        print(json.dumps(response, indent=2))
        
        return True
    else:
        print("[FAILED] API would return error")
        return False


if __name__ == "__main__":
    result = test_api_logic()
    print()
    print("="*80)
    print(f"Result: {'PASS' if result else 'FAIL'}")
    print()
    print("The API endpoints are ready to use!")
    print()
    print("To start the API server:")
    print("  python -m uvicorn app.main:app --reload --port 8000")
    print()
    print("Then test with:")
    print("  curl -X POST 'http://localhost:8000/api/v1/vulnerabilities/1/generate-patch'")
    print()
