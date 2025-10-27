"""
Integration test for semantic analyzer + symbolic executor
Tests the full pipeline: CodeQL finding -> Symbolic verification
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.symbolic_executor import SymbolicExecutor, VulnerabilityType
from app.core.semantic_analyzer_complete import (
    DataFlowPath,
    CodeLocation,
    SecurityContext
)


class TestSemanticSymbolicIntegration(unittest.TestCase):
    """Test integration between semantic analyzer and symbolic executor"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.executor = SymbolicExecutor()
    
    def test_verify_idor_finding_from_codeql(self):
        """Test verifying a CodeQL IDOR finding with symbolic execution"""
        # Simulate a DataFlowPath from semantic analyzer
        source_loc = CodeLocation(
            file_path="UserController.java",
            start_line=42,
            end_line=42,
            start_column=10,
            end_column=25
        )
        sink_loc = CodeLocation(
            file_path="UserController.java",
            start_line=45,
            end_line=45,
            start_column=8,
            end_column=30
        )
        
        dataflow = DataFlowPath(
            source="@PathVariable userId",
            sink="userRepository.findById(userId)",
            source_location=source_loc,
            sink_location=sink_loc,
            path=["userId parameter", "repository call"],
            vulnerability_type="idor",
            confidence=0.7,
            message="Potential IDOR: user input flows to database query",
            severity="high"
        )
        
        security_ctx = SecurityContext(
            file_path="UserController.java",
            line_number=42,
            authentication_present=True,
            authorization_present=False,
            security_annotations=["@GetMapping"],
            framework="spring"
        )
        
        # Verify the finding with symbolic execution
        proof = self.executor.verify_codeql_finding(dataflow, security_ctx)
        
        # Should confirm the IDOR vulnerability
        self.assertIsNotNone(proof)
        self.assertEqual(proof.vulnerability_type, VulnerabilityType.IDOR)
        self.assertTrue(proof.exploitable)
        self.assertGreater(proof.confidence, 0.8)
    
    def test_verify_finding_with_authorization_check(self):
        """Test that symbolic executor rejects false positives"""
        source_loc = CodeLocation(
            file_path="UserController.java",
            start_line=42,
            end_line=42,
            start_column=10,
            end_column=25
        )
        sink_loc = CodeLocation(
            file_path="UserController.java",
            start_line=45,
            end_line=45,
            start_column=8,
            end_column=30
        )
        
        dataflow = DataFlowPath(
            source="@PathVariable userId",
            sink="userRepository.findById(userId)",
            source_location=source_loc,
            sink_location=sink_loc,
            path=["userId parameter", "authorization check", "repository call"],
            vulnerability_type="idor",
            confidence=0.7,
            message="Potential IDOR",
            severity="medium"
        )
        
        # This time with authorization
        security_ctx = SecurityContext(
            file_path="UserController.java",
            line_number=42,
            authentication_present=True,
            authorization_present=True,  # Authorization check exists
            security_annotations=["@PreAuthorize", "@GetMapping"],
            framework="spring"
        )
        
        # Verify the finding
        proof = self.executor.verify_codeql_finding(dataflow, security_ctx)
        
        # Should NOT confirm vulnerability (false positive filtered)
        self.assertIsNone(proof)
    
    def test_verify_missing_auth_finding(self):
        """Test verifying missing authentication finding"""
        source_loc = CodeLocation(
            file_path="AdminController.java",
            start_line=20,
            end_line=20,
            start_column=5,
            end_column=15
        )
        sink_loc = CodeLocation(
            file_path="AdminController.java",
            start_line=25,
            end_line=25,
            start_column=8,
            end_column=30
        )
        
        dataflow = DataFlowPath(
            source="@RequestMapping /admin/delete",
            sink="userRepository.delete(userId)",
            source_location=source_loc,
            sink_location=sink_loc,
            path=[],
            vulnerability_type="missing_authentication",
            confidence=0.6,
            message="Sensitive operation without authentication",
            severity="high"
        )
        
        security_ctx = SecurityContext(
            file_path="AdminController.java",
            line_number=20,
            authentication_present=False,
            authorization_present=False,
            security_annotations=[],  # No security annotations
            framework="spring"
        )
        
        # Verify the finding
        proof = self.executor.verify_codeql_finding(dataflow, security_ctx)
        
        # Should confirm missing authentication
        self.assertIsNotNone(proof)
        self.assertEqual(proof.vulnerability_type, VulnerabilityType.MISSING_AUTHENTICATION)
        self.assertTrue(proof.exploitable)
    
    def test_dataflow_adaptation(self):
        """Test that dataflow adaptation works correctly"""
        source_loc = CodeLocation(
            file_path="TestController.java",
            start_line=10,
            end_line=10,
            start_column=1,
            end_column=10
        )
        sink_loc = CodeLocation(
            file_path="TestController.java",
            start_line=15,
            end_line=15,
            start_column=1,
            end_column=20
        )
        
        dataflow = DataFlowPath(
            source="input",
            sink="output",
            source_location=source_loc,
            sink_location=sink_loc,
            vulnerability_type="idor"
        )
        
        # Test adaptation
        adapted = self.executor._adapt_dataflow(dataflow)
        
        self.assertEqual(adapted.vulnerability_type, "idor")
        self.assertEqual(adapted.source_location[0], "TestController.java")
        self.assertEqual(adapted.source_location[1], 10)
        self.assertEqual(adapted.sink_location[0], "TestController.java")
        self.assertEqual(adapted.sink_location[1], 15)
    
    def test_security_context_adaptation(self):
        """Test that security context adaptation works correctly"""
        security_ctx = SecurityContext(
            file_path="TestController.java",
            line_number=10,
            authentication_present=True,
            authorization_present=False,
            security_annotations=["@PreAuthorize"],
            framework="spring"
        )
        
        # Test adaptation
        adapted = self.executor._adapt_security_context(security_ctx)
        
        self.assertEqual(adapted.framework, "spring")
        self.assertEqual(adapted.security_annotations, ["@PreAuthorize"])
        self.assertTrue(adapted.has_authentication())
        self.assertFalse(adapted.has_authorization())


if __name__ == "__main__":
    unittest.main()
