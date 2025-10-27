"""
Tests for enhanced context builder
"""

import unittest
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.context_builder import (
    EnhancedPatchContext,
    SemanticContextBuilder,
    create_context_from_analysis_results
)


class TestEnhancedPatchContext(unittest.TestCase):
    """Test EnhancedPatchContext dataclass"""
    
    def test_basic_creation(self):
        """Test creating basic context"""
        context = EnhancedPatchContext(
            vulnerability_type="idor",
            file_path="UserController.java",
            line_number=42,
            vulnerable_code="userRepository.findById(userId)",
            severity="high",
            confidence=0.95
        )
        
        self.assertEqual(context.vulnerability_type, "idor")
        self.assertEqual(context.line_number, 42)
        self.assertFalse(context.symbolically_verified)
    
    def test_from_semantic_finding(self):
        """Test creating context from semantic analysis finding"""
        finding = {
            'vulnerability_type': 'idor',
            'source': '@PathVariable userId',
            'sink': 'userRepository.findById(userId)',
            'source_location': {
                'file_path': 'UserController.java',
                'start_line': 40
            },
            'sink_location': {
                'file_path': 'UserController.java',
                'start_line': 42
            },
            'severity': 'high',
            'confidence': 0.85,
            'security_context': {
                'authentication_present': True,
                'authorization_present': False,
                'security_annotations': ['@GetMapping'],
                'framework': 'spring'
            },
            'symbolically_verified': True,
            'exploit_proof': {
                'vulnerability_type': 'idor',
                'attack_vector': {
                    'attacker_value': 42,
                    'attacker_logged_in_as': 1
                },
                'missing_check': 'Authorization check required'
            }
        }
        
        context = EnhancedPatchContext.from_semantic_finding(finding)
        
        self.assertEqual(context.vulnerability_type, 'idor')
        self.assertEqual(context.file_path, 'UserController.java')
        self.assertEqual(context.line_number, 42)
        self.assertTrue(context.authentication_present)
        self.assertFalse(context.authorization_present)
        self.assertTrue(context.symbolically_verified)
        self.assertIsNotNone(context.exploit_proof)
        self.assertEqual(context.framework, 'spring')
    
    def test_to_dict_serialization(self):
        """Test serialization to dict"""
        context = EnhancedPatchContext(
            vulnerability_type="idor",
            file_path="Test.java",
            line_number=10,
            vulnerable_code="test()",
            severity="medium",
            confidence=0.7,
            symbolically_verified=True
        )
        
        data = context.to_dict()
        
        self.assertIsInstance(data, dict)
        self.assertEqual(data['vulnerability_type'], 'idor')
        self.assertTrue(data['symbolically_verified'])


class TestSemanticContextBuilder(unittest.TestCase):
    """Test SemanticContextBuilder"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.builder = SemanticContextBuilder(repo_path=self.temp_dir)
        
        # Create test file
        test_file = Path(self.temp_dir) / "TestController.java"
        test_file.write_text("""package com.test;

public class TestController {
    public void getUser(Long userId) {
        User user = userRepository.findById(userId);
        return user;
    }
}
""")
    
    def test_read_surrounding_context(self):
        """Test reading code context around line"""
        context = self.builder._read_surrounding_context(
            "TestController.java",
            line_number=5,
            context_lines=3
        )
        
        self.assertIsNotNone(context)
        self.assertIn("TestController", context)
        self.assertIn("findById", context)
        self.assertIn(">>>", context)  # Marker for vulnerable line
    
    def test_build_context_from_finding(self):
        """Test building complete context from finding"""
        finding = {
            'vulnerability_type': 'idor',
            'source': 'userId',
            'sink': 'userRepository.findById(userId)',
            'sink_location': {
                'file_path': 'TestController.java',
                'start_line': 5
            },
            'severity': 'high',
            'confidence': 0.9,
            'security_context': {
                'framework': 'spring'
            },
            'symbolically_verified': True,
            'exploit_proof': {
                'missing_check': 'Auth check required'
            }
        }
        
        context = self.builder.build_context(finding)
        
        self.assertEqual(context.vulnerability_type, 'idor')
        self.assertIsNotNone(context.surrounding_context)
        self.assertIn("findById", context.surrounding_context)
    
    def test_format_for_llm_prompt(self):
        """Test formatting context as LLM prompt"""
        context = EnhancedPatchContext(
            vulnerability_type="idor",
            file_path="UserController.java",
            line_number=42,
            vulnerable_code="userRepository.findById(userId)",
            severity="high",
            confidence=0.95,
            framework="spring",
            authentication_present=True,
            authorization_present=False,
            symbolically_verified=True,
            exploit_proof={
                'attack_vector': {'attacker_value': 42},
                'missing_check': 'Authorization check required',
                'proof': 'User 1 can access user 42 data'
            },
            attack_vector={'attacker_value': 42},
            missing_check='Authorization check required'
        )
        
        prompt = self.builder.format_for_llm_prompt(context)
        
        # Check key sections are present
        self.assertIn("Vulnerability Analysis", prompt)
        self.assertIn("IDOR", prompt)
        self.assertIn("Security Context", prompt)
        self.assertIn("Symbolic Execution Proof", prompt)
        self.assertIn("Authorization check required", prompt)
        self.assertIn("spring", prompt)


class TestCreateContextFromResults(unittest.TestCase):
    """Test creating contexts from full analysis results"""
    
    def test_create_contexts_from_results(self):
        """Test extracting contexts from analysis results"""
        results = {
            'project_path': '/test/project',
            'vulnerabilities': [
                {
                    'vulnerability_type': 'idor',
                    'sink_location': {
                        'file_path': 'Test.java',
                        'start_line': 10
                    },
                    'severity': 'high',
                    'confidence': 0.9,
                    'symbolically_verified': True,
                    'exploit_proof': {}
                },
                {
                    'vulnerability_type': 'idor',
                    'sink_location': {
                        'file_path': 'Test2.java',
                        'start_line': 20
                    },
                    'severity': 'medium',
                    'confidence': 0.7,
                    'symbolically_verified': False  # Not verified, should be skipped
                }
            ]
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            contexts = create_context_from_analysis_results(results, repo_path=temp_dir)
            
            # Should only include symbolically verified findings
            self.assertEqual(len(contexts), 1)
            self.assertTrue(contexts[0].symbolically_verified)


if __name__ == "__main__":
    unittest.main()
