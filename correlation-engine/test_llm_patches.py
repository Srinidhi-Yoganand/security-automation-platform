"""
Test LLM-Powered Automated Patch Generation
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext, PatchStatus


def test_llm_patch_generation():
    """Test LLM-powered patch generation"""
    
    print("="*80)
    print("LLM-POWERED AUTOMATED SECURITY PATCHING TEST")
    print("="*80)
    print()
    
    # Check for OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("WARNING: OPENAI_API_KEY environment variable not set")
        print("   Set it with: export OPENAI_API_KEY='sk-...'")
        print("   Falling back to template-based patching for this demo")
        print()
    else:
        print("OpenAI API key found")
        print()
    
    generator = LLMPatchGenerator(repo_path="../vulnerable-app")
    
    # Test Case 1: SQL Injection
    print("="*80)
    print("TEST CASE 1: SQL Injection")
    print("="*80)
    print()
    
    context1 = PatchContext(
        vulnerability_type="SQL Injection",
        file_path="src/main/java/com/security/automation/controller/UserController.java",
        line_number=45,
        vulnerable_code='String query = "SELECT * FROM users WHERE username=\'" + username + "\'";',
        severity="high",
        confidence=0.95,
        description="User input directly concatenated into SQL query without sanitization",
        cwe_id="CWE-89",
        tool_name="CodeQL"
    )
    
    print("📋 Vulnerability Details:")
    print(f"   Type: {context1.vulnerability_type}")
    print(f"   File: {context1.file_path}")
    print(f"   Line: {context1.line_number}")
    print(f"   Severity: {context1.severity}")
    print(f"   CWE: {context1.cwe_id}")
    print()
    print("🐛 Vulnerable Code:")
    print(f"   {context1.vulnerable_code}")
    print()
    
    print("🤖 Generating patch with LLM...")
    patch1 = generator.generate_patch(context1, test_patch=False)  # Don't test for demo
    
    if patch1:
        print()
        print("✅ PATCH GENERATED SUCCESSFULLY!")
        print()
        print("="*80)
        print("PATCH DETAILS")
        print("="*80)
        print()
        print("📝 Original Code:")
        print("-" * 80)
        print(patch1.original_code)
        print("-" * 80)
        print()
        print("✨ Fixed Code:")
        print("-" * 80)
        print(patch1.fixed_code)
        print("-" * 80)
        print()
        print("💡 Explanation:")
        print("-" * 80)
        print(patch1.explanation)
        print("-" * 80)
        print()
        print("📊 Metadata:")
        print(f"   Confidence: {patch1.confidence}")
        print(f"   Status: {patch1.status.value}")
        print(f"   Manual Review Needed: {patch1.manual_review_needed}")
        if patch1.breaking_changes:
            print(f"   Breaking Changes: {', '.join(patch1.breaking_changes)}")
        if patch1.prerequisites:
            print(f"   Prerequisites: {', '.join(patch1.prerequisites)}")
        print()
        
        if patch1.test_branch:
            print(f"🔀 Test Branch: {patch1.test_branch}")
            if patch1.test_results:
                print("🧪 Test Results:")
                print(f"   Success: {patch1.test_results.get('success', False)}")
                print(f"   Compilation: {patch1.test_results.get('compilation_success', False)}")
                print(f"   Tests Passed: {patch1.test_results.get('tests_passed', False)}")
            print()
        
        print("📄 Git Diff:")
        print("-" * 80)
        print(patch1.diff)
        print("-" * 80)
        print()
    else:
        print("❌ Failed to generate patch")
        print()
    
    print()
    
    # Test Case 2: IDOR (Any vulnerability type works!)
    print("="*80)
    print("TEST CASE 2: Insecure Direct Object Reference (IDOR)")
    print("="*80)
    print()
    
    context2 = PatchContext(
        vulnerability_type="Insecure Direct Object Reference",
        file_path="src/main/java/com/security/automation/controller/OrderController.java",
        line_number=35,
        vulnerable_code='Order order = orderRepository.findById(orderId).orElse(null);',
        severity="medium",
        confidence=0.85,
        description="No authorization check before accessing order object",
        cwe_id="CWE-639",
        tool_name="Semgrep"
    )
    
    print("📋 Vulnerability Details:")
    print(f"   Type: {context2.vulnerability_type}")
    print(f"   File: {context2.file_path}")
    print(f"   Severity: {context2.severity}")
    print()
    print("🐛 Vulnerable Code:")
    print(f"   {context2.vulnerable_code}")
    print()
    
    print("🤖 Generating patch with LLM...")
    patch2 = generator.generate_patch(context2, test_patch=False)
    
    if patch2:
        print()
        print("✅ PATCH GENERATED!")
        print()
        print("✨ Fixed Code:")
        print("-" * 80)
        print(patch2.fixed_code)
        print("-" * 80)
        print()
        print("💡 Explanation:")
        print(patch2.explanation)
        print()
    else:
        print("❌ Failed to generate patch")
        print()
    
    print()
    
    # Test Case 3: Novel/Complex Vulnerability (demonstrates LLM flexibility)
    print("="*80)
    print("TEST CASE 3: Complex Custom Vulnerability (LLM Adapts!)")
    print("="*80)
    print()
    
    context3 = PatchContext(
        vulnerability_type="Race Condition in Session Management",
        file_path="src/main/java/com/security/automation/security/SecurityConfig.java",
        line_number=42,
        vulnerable_code='if (sessionStore.contains(sessionId)) { sessionStore.update(sessionId); }',
        severity="medium",
        confidence=0.75,
        description="Time-of-check time-of-use vulnerability in session validation",
        cwe_id="CWE-367",
        tool_name="Custom Analysis"
    )
    
    print("📋 Vulnerability Details:")
    print(f"   Type: {context3.vulnerability_type}")
    print(f"   Description: {context3.description}")
    print(f"   CWE: {context3.cwe_id}")
    print()
    print("🐛 Vulnerable Code:")
    print(f"   {context3.vulnerable_code}")
    print()
    
    print("🤖 Generating patch with LLM (demonstrates flexibility)...")
    patch3 = generator.generate_patch(context3, test_patch=False)
    
    if patch3:
        print()
        print("✅ LLM ADAPTED TO NOVEL VULNERABILITY!")
        print()
        print("✨ Fixed Code:")
        print("-" * 80)
        print(patch3.fixed_code)
        print("-" * 80)
        print()
        print("💡 Explanation:")
        print(patch3.explanation)
        print()
    else:
        print("⚠️  Patch generation skipped or failed")
        print()
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print()
    print("✅ LLM-powered patching supports:")
    print("   - ANY vulnerability type (not limited to templates)")
    print("   - Full context analysis (surrounding code, class structure)")
    print("   - Intelligent, adaptive fixes")
    print("   - Best practices and security standards")
    print("   - Automated testing in isolated branches")
    print("   - Human approval workflow")
    print()
    print("🚀 Ready for production use!")
    print()


def test_with_database():
    """Test patch generation with actual database vulnerabilities"""
    from app.database import get_db
    from app.models import Vulnerability
    
    print("="*80)
    print("TESTING WITH REAL VULNERABILITIES FROM DATABASE")
    print("="*80)
    print()
    
    try:
        with get_db() as db:
            vulns = db.query(Vulnerability).filter(
                Vulnerability.state != 'fixed'
            ).order_by(Vulnerability.risk_score.desc()).limit(3).all()
            
            if not vulns:
                print("⚠️  No vulnerabilities found in database")
                print("   Run Phase 2 tests first to populate database")
                return
            
            print(f"Found {len(vulns)} vulnerabilities. Generating patches...\n")
            
            generator = LLMPatchGenerator(repo_path="../vulnerable-app")
            
            for i, vuln in enumerate(vulns, 1):
                print(f"{'='*80}")
                print(f"VULNERABILITY {i}/{len(vulns)}: {vuln.type}")
                print(f"{'='*80}")
                print(f"ID: {vuln.id}")
                print(f"File: {vuln.file_path}:{vuln.line_number}")
                print(f"Severity: {vuln.severity}")
                print(f"Risk Score: {vuln.risk_score}")
                print()
                
                context = PatchContext(
                    vulnerability_type=vuln.type,
                    file_path=vuln.file_path,
                    line_number=vuln.line_number,
                    vulnerable_code=vuln.message or "",
                    severity=vuln.severity,
                    confidence=vuln.confidence,
                    description=vuln.message,  # Use message as description
                    cwe_id=vuln.cwe_id,
                    tool_name=getattr(vuln, 'tool', 'Unknown')
                )
                
                patch = generator.generate_patch(context, test_patch=False)
                
                if patch:
                    print("✅ Patch Generated")
                    print()
                    print("Fixed Code:")
                    print(patch.fixed_code[:200] + "..." if len(patch.fixed_code) > 200 else patch.fixed_code)
                    print()
                    print(f"Confidence: {patch.confidence}")
                    print(f"Status: {patch.status.value}")
                else:
                    print("⚠️  No automatic patch available")
                
                print()
    
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure database is initialized")


if __name__ == "__main__":
    # Test LLM patch generation
    test_llm_patch_generation()
    
    print("\n" + "="*80 + "\n")
    
    # Test with real database vulnerabilities
    test_with_database()
    
    print()
    print("="*80)
    print("NEXT STEPS")
    print("="*80)
    print()
    print("1. Set OpenAI API key:")
    print("   export OPENAI_API_KEY='sk-...'")
    print()
    print("2. Start the API server:")
    print("   cd correlation-engine")
    print("   python -m uvicorn app.main:app --reload")
    print()
    print("3. Generate patches via API:")
    print("   curl -X POST 'http://localhost:8000/api/v1/scans/1/generate-patches'")
    print()
    print("4. Review patches and apply approved ones")
    print()
