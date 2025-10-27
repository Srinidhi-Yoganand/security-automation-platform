"""
Unit tests for missing authentication/authorization detection via symbolic execution
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.symbolic_executor import (
    SymbolicExecutor,
    VulnerabilityType,
    ExploitProof
)


class MockDataFlowPath:
    """Mock DataFlowPath for testing"""
    def __init__(self, vuln_type="missing_authentication"):
        self.vulnerability_type = vuln_type
        self.source_location = ("AdminController.java", 20, 20, 5, 15)
        self.sink_location = ("AdminController.java", 25, 25, 8, 30)
        self.intermediate_steps = []


class MockSecurityContext:
    """Mock SecurityContext for testing"""
    def __init__(self, has_annotations=False):
        self.security_annotations = []
        if has_annotations:
            self.security_annotations = ["@PreAuthorize"]
        self.framework = "spring"
        
    def has_authorization(self):
        return len(self.security_annotations) > 0
        
    def has_authentication(self):
        return len(self.security_annotations) > 0


class TestSymbolicMissingAuth(unittest.TestCase):
    """Test missing authentication detection with symbolic execution"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.executor = SymbolicExecutor()
    
    def test_missing_authentication_detected(self):
        """Test detection when no authentication exists"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        context = MockSecurityContext(has_annotations=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        self.assertEqual(proof.vulnerability_type, VulnerabilityType.MISSING_AUTHENTICATION)
        self.assertTrue(proof.exploitable)
        self.assertIn("authentication_required", proof.attack_vector)
        self.assertFalse(proof.attack_vector["authentication_required"])
    
    def test_authentication_present_no_vulnerability(self):
        """Test that authentication annotation prevents detection"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        context = MockSecurityContext(has_annotations=True)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        # Should not find vulnerability when authentication exists
        self.assertIsNone(proof)
    
    def test_missing_auth_proof_structure(self):
        """Test that missing auth proof has required structure"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        context = MockSecurityContext(has_annotations=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        
        # Check attack vector
        self.assertIn("endpoint", proof.attack_vector)
        self.assertIn("authentication_required", proof.attack_vector)
        
        # Check proof description
        self.assertIn("authentication", proof.proof_description.lower())
        
        # Check constraints
        self.assertGreater(len(proof.satisfying_constraints), 0)
        self.assertIn("isAuthenticated = false", proof.satisfying_constraints[0])
        
        # Check fix suggestion
        self.assertIn("PreAuthorize", proof.missing_check)
    
    def test_check_for_authentication_with_pattern(self):
        """Test authentication check detection with code patterns"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        flow.intermediate_steps = [
            {"code": "if (isAuthenticated()) { ... }"}
        ]
        context = MockSecurityContext(has_annotations=False)
        
        has_auth = self.executor._check_for_authentication(flow, context)
        
        self.assertTrue(has_auth)
    
    def test_check_for_authentication_without_pattern(self):
        """Test that missing authentication is detected"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        flow.intermediate_steps = []
        context = MockSecurityContext(has_annotations=False)
        
        has_auth = self.executor._check_for_authentication(flow, context)
        
        self.assertFalse(has_auth)


class TestMissingChecksAnalysis(unittest.TestCase):
    """Test missing checks identification"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.executor = SymbolicExecutor()
    
    def test_find_missing_authorization_for_idor(self):
        """Test identification of missing authorization checks"""
        flow = MockDataFlowPath(vuln_type="idor")
        context = MockSecurityContext(has_annotations=False)
        
        missing = self.executor.find_missing_checks(flow, context)
        
        self.assertIn("authorization", missing)
        self.assertGreater(len(missing["authorization"]), 0)
        self.assertEqual(missing["authorization"][0]["type"], "ownership_check")
    
    def test_find_missing_authentication(self):
        """Test identification of missing authentication"""
        flow = MockDataFlowPath(vuln_type="missing_authentication")
        context = MockSecurityContext(has_annotations=False)
        
        missing = self.executor.find_missing_checks(flow, context)
        
        self.assertIn("authentication", missing)
        self.assertGreater(len(missing["authentication"]), 0)
        self.assertIn("PreAuthorize", missing["authentication"][0]["suggested_code"])
    
    def test_suggest_authorization_code_spring(self):
        """Test authorization code suggestion for Spring"""
        context = MockSecurityContext(has_annotations=False)
        
        suggested = self.executor._suggest_authorization_code(context)
        
        self.assertIn("SecurityContextHolder", suggested)
        self.assertIn("AccessDeniedException", suggested)
        self.assertIn("currentuser", suggested.lower())


if __name__ == "__main__":
    unittest.main()
