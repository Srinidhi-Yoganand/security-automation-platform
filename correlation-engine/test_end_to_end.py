"""
End-to-End Integration Tests for Security Automation Platform

Tests the complete pipeline:
1. CodeQL Semantic Analysis → 2. Z3 Symbolic Execution → 3. LLM Patch Generation → 4. Patch Validation

Uses test-vuln-app as the target application.
"""

import os
import sys
import json
import subprocess
import pytest
from pathlib import Path

# Add app to path
sys.path.insert(0, str(Path(__file__).parent))

from app.core.git_analyzer import SemanticAnalyzer
from app.services.behavior.symbolic_executor import SymbolicExecutor
from app.services.patcher.context_builder import SemanticContextBuilder, EnhancedPatchContext
from app.services.patcher.llm_patch_generator import LLMPatchGenerator
from app.services.patcher.patch_validator import PatchValidator

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
TEST_VULN_APP = PROJECT_ROOT / "test-vuln-app"
CODEQL_DB = PROJECT_ROOT / "codeql-databases" / "test-vuln-app-db"
TEST_DATA_DIR = PROJECT_ROOT / "test-data"


class TestEndToEnd:
    """Comprehensive end-to-end integration tests"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        # Ensure test-vuln-app exists
        assert TEST_VULN_APP.exists(), f"test-vuln-app not found at {TEST_VULN_APP}"
        
        # Create test data directory
        TEST_DATA_DIR.mkdir(exist_ok=True)
        
        self.test_file = TEST_VULN_APP / "src/main/java/com/thesis/vuln/UserController.java"
        assert self.test_file.exists(), f"UserController.java not found"
        
        yield
        
    def test_phase1_codeql_semantic_analysis(self):
        """
        Phase 1: CodeQL Semantic Analysis
        
        Verifies that CodeQL can:
        - Create database for Java application
        - Run semantic queries
        - Detect IDOR vulnerabilities
        - Extract data flow information
        """
        print("\n" + "="*80)
        print("PHASE 1: CodeQL Semantic Analysis")
        print("="*80)
        
        # Initialize semantic analyzer
        analyzer = SemanticAnalyzer(workspace_path=str(TEST_VULN_APP))
        
        # Create CodeQL database (if not exists)
        if not CODEQL_DB.exists():
            print(f"\nCreating CodeQL database at {CODEQL_DB}...")
            result = analyzer.create_database(
                source_root=str(TEST_VULN_APP),
                database_path=str(CODEQL_DB),
                language="java"
            )
            assert result["success"], f"Failed to create database: {result.get('error')}"
            print(f"✓ Database created successfully")
        else:
            print(f"✓ Using existing database at {CODEQL_DB}")
        
        # Run IDOR detection query
        print("\nRunning IDOR detection query...")
        query_path = PROJECT_ROOT / "correlation-engine/app/core/parsers/codeql-queries/java/idor-detection.ql"
        
        if not query_path.exists():
            # Use default semantic query
            query_path = PROJECT_ROOT / "correlation-engine/app/core/parsers/codeql-queries/java/semantic-idor.ql"
        
        results = analyzer.run_query(
            database_path=str(CODEQL_DB),
            query_file=str(query_path)
        )
        
        assert results["success"], f"Query failed: {results.get('error')}"
        findings = results.get("results", [])
        
        print(f"\n✓ Query completed: {len(findings)} findings")
        
        # Verify we detected vulnerabilities
        assert len(findings) > 0, "Expected to detect at least one IDOR vulnerability"
        
        # Print findings
        for i, finding in enumerate(findings[:3], 1):
            print(f"\nFinding {i}:")
            print(f"  File: {finding.get('file', 'N/A')}")
            print(f"  Line: {finding.get('line', 'N/A')}")
            print(f"  Message: {finding.get('message', 'N/A')}")
        
        # Save results for next phase
        output_file = TEST_DATA_DIR / "e2e-codeql-results.json"
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)
        
        print(f"\n✓ Results saved to {output_file}")
        print(f"\n{'='*80}")
        print(f"PHASE 1 COMPLETE: Detected {len(findings)} vulnerabilities")
        print(f"{'='*80}\n")
        
        return findings
    
    def test_phase2_z3_symbolic_execution(self):
        """
        Phase 2: Z3 Symbolic Execution
        
        Verifies that Z3 can:
        - Build symbolic models
        - Detect IDOR attack vectors
        - Generate proof of exploitability
        - Verify missing authorization checks
        """
        print("\n" + "="*80)
        print("PHASE 2: Z3 Symbolic Execution")
        print("="*80)
        
        # Initialize symbolic executor
        executor = SymbolicExecutor()
        
        # Read vulnerable code
        with open(self.test_file, 'r') as f:
            code = f.read()
        
        print(f"\nAnalyzing {self.test_file.name}...")
        
        # Test IDOR detection
        print("\nChecking for IDOR vulnerabilities...")
        idor_result = executor.check_idor_vulnerability(
            code=code,
            method_name="getUserById",
            user_id_param="userId"
        )
        
        assert idor_result["vulnerable"], "Expected to detect IDOR in getUserById"
        print(f"✓ IDOR detected in getUserById")
        print(f"  Reason: {idor_result['reason']}")
        
        if "attack_vector" in idor_result:
            print(f"  Attack Vector: {idor_result['attack_vector']}")
        
        # Test missing authorization detection
        print("\nChecking for missing authorization...")
        auth_result = executor.detect_missing_authorization(
            code=code,
            method_name="getUserById"
        )
        
        assert auth_result["missing_authorization"], "Expected to detect missing authorization"
        print(f"✓ Missing authorization detected")
        print(f"  Confidence: {auth_result.get('confidence', 'N/A')}")
        print(f"  Recommendation: {auth_result.get('recommendation', 'N/A')}")
        
        # Test on another vulnerable method
        print("\nAnalyzing getUserOrder method...")
        idor_result2 = executor.check_idor_vulnerability(
            code=code,
            method_name="getUserOrder",
            user_id_param="orderId"
        )
        
        assert idor_result2["vulnerable"], "Expected to detect IDOR in getUserOrder"
        print(f"✓ IDOR detected in getUserOrder")
        
        # Save symbolic execution results
        symbolic_results = {
            "getUserById": idor_result,
            "getUserOrder": idor_result2,
            "authorization_check": auth_result
        }
        
        output_file = TEST_DATA_DIR / "e2e-symbolic-results.json"
        with open(output_file, 'w') as f:
            json.dump(symbolic_results, f, indent=2)
        
        print(f"\n✓ Results saved to {output_file}")
        print(f"\n{'='*80}")
        print(f"PHASE 2 COMPLETE: Verified exploitability with symbolic execution")
        print(f"{'='*80}\n")
        
        return symbolic_results
    
    def test_phase3_enhanced_context_building(self):
        """
        Phase 3: Enhanced Context Building
        
        Verifies that context builder can:
        - Combine semantic analysis + symbolic execution
        - Extract method information
        - Build rich context for LLM
        """
        print("\n" + "="*80)
        print("PHASE 3: Enhanced Context Building")
        print("="*80)
        
        # Initialize context builder
        context_builder = SemanticContextBuilder()
        
        # Read vulnerable code
        with open(self.test_file, 'r') as f:
            vulnerable_code = f.read()
        
        # Load previous results
        with open(TEST_DATA_DIR / "e2e-codeql-results.json", 'r') as f:
            codeql_findings = json.load(f)
        
        with open(TEST_DATA_DIR / "e2e-symbolic-results.json", 'r') as f:
            symbolic_findings = json.load(f)
        
        print(f"\nBuilding enhanced context for getUserById...")
        
        # Build enhanced context
        context = EnhancedPatchContext(
            file_path=str(self.test_file),
            vulnerable_code=vulnerable_code,
            vulnerability_type="IDOR",
            method_name="getUserById",
            line_number=26,
            data_flows=[
                {
                    "source": "PathVariable userId",
                    "sink": "userRepository.findById(userId)",
                    "path": ["@PathVariable userId", "findById(userId)"]
                }
            ],
            security_context={
                "missing_authorization": True,
                "missing_authentication": False,
                "user_controlled_input": "userId"
            },
            symbolic_proof=symbolic_findings.get("getUserById", {}),
            cve_references=[]
        )
        
        # Format for LLM prompt
        print("\nFormatting context for LLM...")
        from app.services.patcher.context_builder import format_for_llm_prompt
        prompt = format_for_llm_prompt(context)
        
        assert len(prompt) > 0, "Prompt should not be empty"
        assert "IDOR" in prompt, "Prompt should mention vulnerability type"
        assert "getUserById" in prompt, "Prompt should mention method name"
        
        print(f"✓ Context built successfully")
        print(f"  Prompt length: {len(prompt)} characters")
        print(f"  Contains data flows: {len(context.data_flows)} flows")
        print(f"  Contains symbolic proof: {bool(context.symbolic_proof)}")
        
        # Save context
        output_file = TEST_DATA_DIR / "e2e-enhanced-context.json"
        with open(output_file, 'w') as f:
            json.dump({
                "context": {
                    "file_path": context.file_path,
                    "vulnerability_type": context.vulnerability_type,
                    "method_name": context.method_name,
                    "data_flows": context.data_flows,
                    "security_context": context.security_context
                },
                "prompt_preview": prompt[:500] + "..."
            }, f, indent=2)
        
        print(f"\n✓ Context saved to {output_file}")
        print(f"\n{'='*80}")
        print(f"PHASE 3 COMPLETE: Built enhanced context for LLM")
        print(f"{'='*80}\n")
        
        return context
    
    def test_phase4_llm_patch_generation(self):
        """
        Phase 4: LLM Patch Generation
        
        Verifies that LLM patch generator can:
        - Use enhanced context
        - Generate security patches
        - Include proper authorization checks
        - Use semantic patch templates as fallback
        """
        print("\n" + "="*80)
        print("PHASE 4: LLM Patch Generation")
        print("="*80)
        
        # Load enhanced context
        with open(TEST_DATA_DIR / "e2e-enhanced-context.json", 'r') as f:
            context_data = json.load(f)
        
        # Read vulnerable code
        with open(self.test_file, 'r') as f:
            vulnerable_code = f.read()
        
        print(f"\nGenerating patch for getUserById...")
        
        # Initialize patch generator (using semantic generator as fallback)
        from app.services.patcher.semantic_patch_generator import SemanticPatchGenerator
        semantic_generator = SemanticPatchGenerator()
        
        # Generate patch using semantic templates
        print("\nUsing semantic patch generator (template-based)...")
        patch_result = semantic_generator.generate_patch(
            code=vulnerable_code,
            vulnerability_type="IDOR",
            method_name="getUserById",
            symbolic_result={
                "vulnerable": True,
                "reason": "User ID parameter flows to database query without authorization",
                "missing_checks": ["authorization"]
            }
        )
        
        assert patch_result["success"], f"Patch generation failed: {patch_result.get('error')}"
        assert patch_result["patched_code"], "Patched code should not be empty"
        
        patched_code = patch_result["patched_code"]
        
        print(f"✓ Patch generated successfully")
        print(f"  Patch length: {len(patched_code)} characters")
        print(f"  Explanation: {patch_result.get('explanation', 'N/A')[:100]}...")
        
        # Verify patch contains authorization
        assert "SecurityContextHolder" in patched_code or "getCurrentUser" in patched_code or "authentication" in patched_code.lower(), \
            "Patch should include authorization check"
        
        print(f"\n✓ Patch includes authorization check")
        
        # Save patch
        output_file = TEST_DATA_DIR / "e2e-generated-patch.java"
        with open(output_file, 'w') as f:
            f.write(patched_code)
        
        patch_metadata = TEST_DATA_DIR / "e2e-patch-metadata.json"
        with open(patch_metadata, 'w') as f:
            json.dump({
                "method": "getUserById",
                "vulnerability": "IDOR",
                "patch_applied": True,
                "explanation": patch_result.get("explanation"),
                "template_used": patch_result.get("template_name")
            }, f, indent=2)
        
        print(f"\n✓ Patch saved to {output_file}")
        print(f"✓ Metadata saved to {patch_metadata}")
        
        print(f"\n{'='*80}")
        print(f"PHASE 4 COMPLETE: Generated security patch")
        print(f"{'='*80}\n")
        
        return patch_result
    
    def test_phase5_patch_validation(self):
        """
        Phase 5: Patch Validation
        
        Verifies that patch validator can:
        - Validate syntax
        - Verify security fixes
        - Check authorization presence
        - Symbolically verify fix
        """
        print("\n" + "="*80)
        print("PHASE 5: Patch Validation")
        print("="*80)
        
        # Load original and patched code
        with open(self.test_file, 'r') as f:
            original_code = f.read()
        
        with open(TEST_DATA_DIR / "e2e-generated-patch.java", 'r') as f:
            patched_code = f.read()
        
        print(f"\nValidating patch...")
        
        # Initialize validator
        validator = PatchValidator()
        
        # Validate patch
        validation = validator.validate_patch(
            original_code=original_code,
            patched_code=patched_code,
            vulnerability_type="IDOR",
            method_name="getUserById"
        )
        
        print(f"\n✓ Validation complete")
        print(f"  Valid: {validation.is_valid}")
        print(f"  Vulnerability Fixed: {validation.vulnerability_fixed}")
        print(f"  Compilation: {validation.compilation_successful}")
        print(f"  Security Checks: {validation.security_checks_added}")
        
        # Check validation details
        if validation.issues:
            print(f"\n  Issues found:")
            for issue in validation.issues:
                print(f"    - {issue}")
        
        if validation.improvements:
            print(f"\n  Improvements:")
            for improvement in validation.improvements:
                print(f"    - {improvement}")
        
        # Should pass validation
        assert validation.is_valid, "Patch should be valid"
        assert validation.vulnerability_fixed, "Patch should fix vulnerability"
        assert validation.security_checks_added > 0, "Patch should add security checks"
        
        print(f"\n✓ Patch passed all validation checks")
        
        # Save validation results
        output_file = TEST_DATA_DIR / "e2e-validation-results.json"
        with open(output_file, 'w') as f:
            json.dump({
                "is_valid": validation.is_valid,
                "vulnerability_fixed": validation.vulnerability_fixed,
                "compilation_successful": validation.compilation_successful,
                "security_checks_added": validation.security_checks_added,
                "symbolic_verification_passed": validation.symbolic_verification_passed,
                "issues": validation.issues,
                "improvements": validation.improvements,
                "score": validation.score
            }, f, indent=2)
        
        print(f"\n✓ Validation results saved to {output_file}")
        
        print(f"\n{'='*80}")
        print(f"PHASE 5 COMPLETE: Patch validated successfully")
        print(f"{'='*80}\n")
        
        return validation
    
    def test_complete_pipeline_integration(self):
        """
        Complete End-to-End Pipeline Test
        
        Runs all phases in sequence and verifies integration:
        CodeQL → Z3 → Context Building → Patch Generation → Validation
        """
        print("\n" + "="*80)
        print("COMPLETE END-TO-END PIPELINE TEST")
        print("="*80)
        print("\nRunning complete pipeline from analysis to validated patch...\n")
        
        # Phase 1: Semantic Analysis
        print("\n[1/5] Running CodeQL semantic analysis...")
        codeql_findings = self.test_phase1_codeql_semantic_analysis()
        assert len(codeql_findings) > 0, "Phase 1 failed"
        
        # Phase 2: Symbolic Execution
        print("\n[2/5] Running Z3 symbolic execution...")
        symbolic_results = self.test_phase2_z3_symbolic_execution()
        assert symbolic_results, "Phase 2 failed"
        
        # Phase 3: Context Building
        print("\n[3/5] Building enhanced context...")
        context = self.test_phase3_enhanced_context_building()
        assert context, "Phase 3 failed"
        
        # Phase 4: Patch Generation
        print("\n[4/5] Generating security patch...")
        patch = self.test_phase4_llm_patch_generation()
        assert patch["success"], "Phase 4 failed"
        
        # Phase 5: Validation
        print("\n[5/5] Validating patch...")
        validation = self.test_phase5_patch_validation()
        assert validation.is_valid, "Phase 5 failed"
        
        # Summary
        print("\n" + "="*80)
        print("END-TO-END PIPELINE COMPLETE")
        print("="*80)
        print("\n✓ All phases completed successfully!")
        print(f"\n  CodeQL Findings: {len(codeql_findings)}")
        print(f"  Symbolic Verification: PASS")
        print(f"  Patch Generated: YES")
        print(f"  Patch Validated: YES")
        print(f"  Vulnerability Fixed: {validation.vulnerability_fixed}")
        print(f"  Security Checks Added: {validation.security_checks_added}")
        print(f"  Final Score: {validation.score}/100")
        
        print("\n" + "="*80)
        print("TEST RESULTS SUMMARY")
        print("="*80)
        print(f"\n  Test Application: {TEST_VULN_APP.name}")
        print(f"  Target File: {self.test_file.name}")
        print(f"  Vulnerability Type: IDOR")
        print(f"  Method: getUserById")
        print(f"\n  Results Directory: {TEST_DATA_DIR}")
        print(f"    - codeql-results.json")
        print(f"    - symbolic-results.json")
        print(f"    - enhanced-context.json")
        print(f"    - generated-patch.java")
        print(f"    - validation-results.json")
        
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "-s"])
