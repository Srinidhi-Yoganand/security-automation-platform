"""
Test automated patch generation for vulnerabilities found in Phase 1 and Phase 2
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.patcher import PatchGenerator, PatchContext
from app.database import get_db
from app.models import Vulnerability

def test_patch_generation():
    """Test patch generation for existing vulnerabilities in database"""
    
    print("="*70)
    print("AUTOMATED PATCH GENERATION TEST")
    print("="*70)
    print()
    
    generator = PatchGenerator(repo_path="../vulnerable-app")
    
    # Test cases based on our known vulnerabilities
    test_cases = [
        {
            "name": "SQL Injection in UserController",
            "context": PatchContext(
                vulnerability_type="SQL Injection",
                file_path="src/main/java/com/security/automation/controller/UserController.java",
                line_number=45,
                vulnerable_code='String query = "SELECT * FROM users WHERE id=" + userId;',
                severity="high",
                confidence=0.9
            )
        },
        {
            "name": "IDOR in OrderController",
            "context": PatchContext(
                vulnerability_type="IDOR",
                file_path="src/main/java/com/security/automation/controller/OrderController.java",
                line_number=35,
                vulnerable_code="Order order = orderRepository.findById(orderId);",
                severity="medium",
                confidence=0.85
            )
        },
        {
            "name": "IDOR in Authorization Service",
            "context": PatchContext(
                vulnerability_type="Insecure Direct Object Reference",
                file_path="src/main/java/com/security/automation/security/AuthorizationService.java",
                line_number=28,
                vulnerable_code="Company company = companyRepository.findById(companyId);",
                severity="medium",
                confidence=0.85
            )
        }
    ]
    
    patches_generated = 0
    patches_failed = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}: {test_case['name']}")
        print("-" * 70)
        
        patch = generator.generate_patch(test_case['context'])
        
        if patch:
            patches_generated += 1
            print(f"[SUCCESS] Patch generated!")
            print()
            print(f"Vulnerability: {patch.vulnerability_type}")
            print(f"File: {patch.file_path}")
            print(f"Line: {patch.line_number}")
            print(f"Confidence: {patch.confidence}")
            print(f"Manual Review Needed: {patch.manual_review_needed}")
            print()
            print("ORIGINAL CODE:")
            print("  " + patch.original_code.replace("\n", "\n  "))
            print()
            print("FIXED CODE:")
            print("  " + patch.fixed_code.replace("\n", "\n  "))
            print()
            print("EXPLANATION:")
            print("  " + patch.explanation)
            print()
            print("REMEDIATION GUIDE:")
            print("  " + patch.remediation_guide)
            print()
            print("GIT DIFF:")
            print(patch.diff)
            print()
        else:
            patches_failed += 1
            print(f"[FAILED] Could not generate patch")
            print(f"Reason: Pattern not recognized or file not found")
            print()
        
        print()
    
    print("="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total Test Cases: {len(test_cases)}")
    print(f"Patches Generated: {patches_generated}")
    print(f"Patches Failed: {patches_failed}")
    print(f"Success Rate: {patches_generated/len(test_cases)*100:.1f}%")
    print()


def test_database_patches():
    """Test patch generation for vulnerabilities in database"""
    print("="*70)
    print("GENERATING PATCHES FOR DATABASE VULNERABILITIES")
    print("="*70)
    print()
    
    try:
        with get_db() as db:
            # Get all vulnerabilities that are not fixed
            vulns = db.query(Vulnerability).filter(
                Vulnerability.state != 'fixed'
            ).order_by(Vulnerability.risk_score.desc()).limit(5).all()
            
            if not vulns:
                print("No vulnerabilities found in database.")
                print("Run phase 2 tests first to populate database.")
                return
            
            generator = PatchGenerator(repo_path="../vulnerable-app")
            
            print(f"Found {len(vulns)} vulnerabilities in database")
            print()
            
            for i, vuln in enumerate(vulns, 1):
                print(f"Vulnerability {i}/{len(vulns)}")
                print("-" * 70)
                print(f"ID: {vuln.id}")
                print(f"Type: {vuln.type}")
                print(f"File: {vuln.file_path}:{vuln.line_number}")
                print(f"Severity: {vuln.severity}")
                print(f"Risk Score: {vuln.risk_score}")
                print(f"State: {vuln.state.value}")
                print()
                
                context = PatchContext(
                    vulnerability_type=vuln.type,
                    file_path=vuln.file_path,
                    line_number=vuln.line_number,
                    vulnerable_code=vuln.message or "",
                    severity=vuln.severity,
                    confidence=vuln.confidence
                )
                
                patch = generator.generate_patch(context)
                
                if patch:
                    print("[PATCH AVAILABLE]")
                    print()
                    print("FIXED CODE:")
                    print(patch.fixed_code)
                    print()
                    print(f"Confidence: {patch.confidence}")
                    print(f"Manual Review: {patch.manual_review_needed}")
                    print()
                else:
                    print("[NO AUTOMATIC PATCH]")
                    print("This vulnerability type requires manual remediation.")
                    print()
                
                print()
    
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure database is initialized and has vulnerabilities.")


if __name__ == "__main__":
    # Test with predefined test cases
    test_patch_generation()
    
    print("\n" + "="*70 + "\n")
    
    # Test with database vulnerabilities
    test_database_patches()
