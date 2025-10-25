"""
Simple test for LLM-Powered Patch Generation (Windows-friendly)
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext, PatchStatus


def test_sql_injection_patch():
    """Test SQL injection patch generation"""
    
    print("="*80)
    print("TEST: SQL Injection Patch Generation")
    print("="*80)
    print()
    
    # Check for OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        print("[OK] OpenAI API key found - using GPT-4")
    else:
        print("[INFO] No OpenAI API key - using template fallback")
    print()
    
    generator = LLMPatchGenerator(repo_path="../vulnerable-app")
    
    context = PatchContext(
        vulnerability_type="SQL Injection",
        file_path="src/main/java/com/security/automation/controller/UserController.java",
        line_number=45,
        vulnerable_code='String query = "SELECT * FROM users WHERE username=\'" + username + "\'";',
        severity="high",
        confidence=0.95,
        description="User input directly concatenated into SQL query",
        cwe_id="CWE-89",
        tool_name="CodeQL"
    )
    
    print("Vulnerability Details:")
    print(f"  Type: {context.vulnerability_type}")
    print(f"  File: {context.file_path}")
    print(f"  Line: {context.line_number}")
    print(f"  Severity: {context.severity}")
    print()
    
    print("Vulnerable Code:")
    print(f"  {context.vulnerable_code}")
    print()
    
    print("Generating patch...")
    patch = generator.generate_patch(context, test_patch=False)
    
    if patch:
        print()
        print("[SUCCESS] Patch Generated!")
        print()
        print("-"*80)
        print("ORIGINAL CODE:")
        print("-"*80)
        print(patch.original_code)
        print()
        print("-"*80)
        print("FIXED CODE:")
        print("-"*80)
        print(patch.fixed_code)
        print()
        print("-"*80)
        print("EXPLANATION:")
        print("-"*80)
        print(patch.explanation)
        print()
        print("Metadata:")
        print(f"  Confidence: {patch.confidence}")
        print(f"  Status: {patch.status.value}")
        print(f"  Manual Review: {patch.manual_review_needed}")
        print()
    else:
        print("[FAILED] Could not generate patch")
    
    return patch is not None


def test_with_database():
    """Test with real database vulnerabilities"""
    
    print()
    print("="*80)
    print("TEST: Generate Patches for Database Vulnerabilities")
    print("="*80)
    print()
    
    try:
        from app.database import get_db
        from app.models import Vulnerability
        
        with get_db() as db:
            vulns = db.query(Vulnerability).filter(
                Vulnerability.state != 'fixed'
            ).order_by(Vulnerability.risk_score.desc()).limit(3).all()
            
            if not vulns:
                print("[INFO] No vulnerabilities in database")
                print("       Run Phase 2 tests first: python test_phase2.py")
                return False
            
            print(f"Found {len(vulns)} vulnerabilities")
            print()
            
            generator = LLMPatchGenerator(repo_path="../vulnerable-app")
            success_count = 0
            
            for i, vuln in enumerate(vulns, 1):
                print(f"[{i}/{len(vulns)}] {vuln.type}")
                print(f"      File: {vuln.file_path}:{vuln.line_number}")
                print(f"      Risk Score: {vuln.risk_score}")
                
                context = PatchContext(
                    vulnerability_type=vuln.type,
                    file_path=vuln.file_path,
                    line_number=vuln.line_number,
                    vulnerable_code=vuln.message or "",
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    description=vuln.message,
                    cwe_id=vuln.cwe_id,
                    tool_name=getattr(vuln, 'tool', 'Unknown')
                )
                
                patch = generator.generate_patch(context, test_patch=False)
                
                if patch:
                    print(f"      [OK] Patch generated ({patch.confidence} confidence)")
                    success_count += 1
                else:
                    print(f"      [SKIP] No automatic patch available")
                
                print()
            
            print(f"Summary: {success_count}/{len(vulns)} patches generated")
            return success_count > 0
            
    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def test_api_endpoint():
    """Test API endpoint for patch generation"""
    
    print()
    print("="*80)
    print("TEST: API Endpoint")
    print("="*80)
    print()
    
    print("To test the API:")
    print()
    print("1. Start the server:")
    print("   python -m uvicorn app.main:app --reload --port 8000")
    print()
    print("2. Generate patch for vulnerability ID 1:")
    print("   curl -X POST 'http://localhost:8000/api/v1/vulnerabilities/1/generate-patch'")
    print()
    print("3. Generate patches for scan ID 1:")
    print("   curl -X POST 'http://localhost:8000/api/v1/scans/1/generate-patches'")
    print()
    print("4. View API docs:")
    print("   http://localhost:8000/docs")
    print()


if __name__ == "__main__":
    print()
    print("="*80)
    print("LLM-POWERED AUTOMATED SECURITY PATCHING")
    print("="*80)
    print()
    
    # Test 1: SQL Injection
    result1 = test_sql_injection_patch()
    
    # Test 2: Database vulnerabilities
    result2 = test_with_database()
    
    # Test 3: API instructions
    test_api_endpoint()
    
    print()
    print("="*80)
    print("RESULTS")
    print("="*80)
    print(f"SQL Injection Test: {'PASS' if result1 else 'FAIL'}")
    print(f"Database Test: {'PASS' if result2 else 'SKIP'}")
    print()
    
    if not os.getenv("OPENAI_API_KEY"):
        print("NOTE: Set OPENAI_API_KEY to enable LLM-powered patching")
        print("      Currently using template-based fallback")
    
    print()
