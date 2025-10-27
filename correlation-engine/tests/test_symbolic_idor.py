"""
Unit tests for IDOR detection via symbolic execution
"""

import unittest
from unittest.mock import Mock, patch
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
    def __init__(self, vuln_type="idor", has_auth=False):
        self.vulnerability_type = vuln_type
        self.source_location = ("UserController.java", 42, 42, 10, 25)
        self.sink_location = ("UserController.java", 45, 45, 8, 30)
        self.intermediate_steps = []
        if has_auth:
            self.intermediate_steps = [
                {"code": "if (userId.equals(currentUser.getId())) { ... }"}
            ]


class MockSecurityContext:
    """Mock SecurityContext for testing"""
    def __init__(self, has_auth=False, has_authz=False):
        self._has_auth = has_auth
        self._has_authz = has_authz
        self.security_annotations = []
        self.framework = "spring"
        
    def has_authorization(self):
        return self._has_authz
        
    def has_authentication(self):
        return self._has_auth


class TestSymbolicIDOR(unittest.TestCase):
    """Test IDOR detection with symbolic execution"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.executor = SymbolicExecutor()
    
    def test_idor_no_authorization_check(self):
        """Test IDOR detection when no authorization check exists"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        self.assertEqual(proof.vulnerability_type, VulnerabilityType.IDOR)
        self.assertTrue(proof.exploitable)
        self.assertIn("attacker_value", proof.attack_vector)
        self.assertGreater(proof.confidence, 0.8)
    
    def test_idor_with_authorization_check(self):
        """Test that authorization check prevents IDOR detection"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=True)
        context = MockSecurityContext(has_auth=True, has_authz=True)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        # Should not find vulnerability when authorization check exists
        self.assertIsNone(proof)
    
    def test_idor_exploit_proof_structure(self):
        """Test that exploit proof has required structure"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        
        # Check attack vector structure
        self.assertIn("attacker_value", proof.attack_vector)
        self.assertIn("attacker_logged_in_as", proof.attack_vector)
        
        # Check proof has description
        self.assertIsNotNone(proof.proof_description)
        self.assertIn("IDOR", proof.proof_description)
        
        # Check constraints are recorded
        self.assertGreater(len(proof.satisfying_constraints), 0)
        
        # Check fix suggestion exists
        self.assertIsNotNone(proof.missing_check)
        self.assertIsNotNone(proof.fix_location)
    
    def test_idor_to_dict_serialization(self):
        """Test that exploit proof can be serialized to dict"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        
        # Convert to dict (for JSON serialization)
        proof_dict = proof.to_dict()
        
        self.assertIn("vulnerability_type", proof_dict)
        self.assertIn("exploitable", proof_dict)
        self.assertIn("attack_vector", proof_dict)
        self.assertIn("confidence", proof_dict)
        self.assertEqual(proof_dict["vulnerability_type"], "idor")
    
    def test_symbolic_values_created(self):
        """Test that symbolic values are properly created"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        self.executor.analyze_authorization_gap(flow, context)
        
        # Check symbolic values were created
        self.assertIn("userId", self.executor.symbolic_values)
        self.assertIn("currentUserId", self.executor.symbolic_values)
    
    def test_different_user_ids_in_exploit(self):
        """Test that exploit proof shows different user IDs"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        
        self.assertIsNotNone(proof)
        
        attacker_id = proof.attack_vector["attacker_value"]
        victim_id = proof.attack_vector["attacker_logged_in_as"]
        
        # Core IDOR property: attacker can access different user's data
        self.assertNotEqual(attacker_id, victim_id)
        self.assertGreater(attacker_id, 0)
        self.assertGreater(victim_id, 0)


class TestSymbolicExecutorHelpers(unittest.TestCase):
    """Test helper methods in SymbolicExecutor"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.executor = SymbolicExecutor()
    
    def test_check_for_authorization_with_pattern(self):
        """Test authorization check detection with code patterns"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        flow.intermediate_steps = [
            {"code": "if (hasPermission(userId)) { ... }"}
        ]
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        has_auth = self.executor._check_for_authorization(flow, context)
        
        self.assertTrue(has_auth)
    
    def test_check_for_authorization_without_pattern(self):
        """Test that missing authorization is detected"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        flow.intermediate_steps = []
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        has_auth = self.executor._check_for_authorization(flow, context)
        
        self.assertFalse(has_auth)
    
    def test_generate_exploit_test_for_idor(self):
        """Test exploit test generation for IDOR"""
        flow = MockDataFlowPath(vuln_type="idor", has_auth=False)
        context = MockSecurityContext(has_auth=False, has_authz=False)
        
        proof = self.executor.analyze_authorization_gap(flow, context)
        test_code = self.executor.generate_exploit_test(proof)
        
        # Check that generated test contains key elements
        self.assertIn("@Test", test_code)
        self.assertIn("testIDORVulnerability", test_code)
        self.assertIn("createUser", test_code)
        self.assertIn("loginAs", test_code)
        self.assertIn("assertEquals", test_code)


if __name__ == "__main__":
    unittest.main()
