"""
Test semantic-aware patch generation with EnhancedPatchContext
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.context_builder import EnhancedPatchContext
from app.services.patcher.llm_patch_generator import LLMPatchGenerator


class TestSemanticPatchGeneration(unittest.TestCase):
    """Test LLM patch generator with semantic-aware context"""
    
    def setUp(self):
        """Set up test generator"""
        self.generator = LLMPatchGenerator(repo_path=".", llm_provider="template")
    
    def test_accepts_enhanced_context(self):
        """Test that generator accepts EnhancedPatchContext"""
        context = EnhancedPatchContext(
            vulnerability_type="idor",
            file_path="UserController.java",
            line_number=42,
            vulnerable_code="return userRepository.findById(userId);",
            severity="high",
            confidence=0.95,
            framework="spring",
            authentication_present=True,
            authorization_present=False,
            symbolically_verified=True,
            exploit_proof={
                'attack_vector': {'attacker_id': '999', 'victim_id': '1'},
                'missing_check': 'Authorization check required before accessing user data',
                'proof': 'User 999 can access user 1 data by manipulating userId parameter'
            },
            attack_vector={'attacker_id': '999', 'victim_id': '1'},
            missing_check='Authorization check required',
            surrounding_context="""
    @GetMapping("/user/{userId}")
    public User getUser(@PathVariable Long userId) {
        // VULNERABLE: No authorization check
        return userRepository.findById(userId);
    }
"""
        )
        
        # Should not raise an exception
        patch = self.generator.generate_patch(context, test_patch=False)
        self.assertIsNotNone(patch)
    
    def test_semantic_context_gathering(self):
        """Test that semantic context is properly gathered"""
        context = EnhancedPatchContext(
            vulnerability_type="idor",
            file_path="UserController.java",
            line_number=42,
            vulnerable_code="return userRepository.findById(userId);",
            severity="high",
            confidence=0.95,
            framework="spring",
            method_name="getUser",
            class_name="UserController",
            data_flow_path={
                'source': 'HTTP request parameter userId',
                'sink': 'Database query findById',
                'intermediate_steps': ['Parameter binding', 'Direct use in query']
            },
            symbolically_verified=True,
            exploit_proof={
                'attack_vector': {'attacker_id': '999'},
                'missing_check': 'Authorization check required',
                'proof': 'Attacker can access any user data'
            },
            attack_vector={'attacker_id': '999'},
            missing_check='Authorization check required'
        )
        
        full_context = self.generator._gather_context(context, use_semantic=True)
        
        # Verify semantic data is included
        self.assertEqual(full_context['vulnerability_type'], 'idor')
        self.assertTrue(full_context['symbolically_verified'])
        self.assertIsNotNone(full_context['data_flow_path'])
        self.assertIsNotNone(full_context['exploit_proof'])
        self.assertEqual(full_context['framework'], 'spring')
    
    def test_semantic_prompt_building(self):
        """Test that semantic-aware prompt is built correctly"""
        context_dict = {
            'vulnerability_type': 'idor',
            'file_path': 'UserController.java',
            'line_number': 42,
            'vulnerable_code': 'return userRepository.findById(userId);',
            'severity': 'high',
            'confidence': 0.95,
            'framework': 'spring',
            'data_flow_path': {
                'source': 'HTTP parameter',
                'sink': 'Database',
                'intermediate_steps': ['Parameter binding']
            },
            'security_context': {
                'authentication_present': True,
                'authorization_present': False
            },
            'symbolically_verified': True,
            'attack_vector': {'attacker_id': '999'},
            'missing_check': 'Authorization check required',
            'exploit_proof': {'proof': 'User can access any data'},
            'surrounding_code': '@GetMapping...'
        }
        
        prompt = self.generator._build_patch_prompt(context_dict, use_semantic=True)
        
        # Verify prompt includes semantic elements
        self.assertIn('Symbolic Verification', prompt)
        self.assertIn('Data Flow Analysis', prompt)
        self.assertIn('Authorization check required', prompt)
        self.assertIn('IDOR', prompt.upper())
        self.assertIn('Attack Vector', prompt)
        self.assertIn('CodeQL', prompt)
        self.assertIn('Z3 Solver', prompt)
    
    def test_idor_specific_instructions(self):
        """Test that IDOR gets specific fix instructions"""
        instructions = self.generator._get_vuln_type_instructions(
            'idor',
            'Authorization check required before accessing user data'
        )
        
        self.assertIn('IDOR', instructions)
        self.assertIn('authorization check', instructions.lower())
        self.assertIn('SecurityContext', instructions)
        self.assertIn('AccessDeniedException', instructions)
    
    def test_missing_auth_instructions(self):
        """Test that missing auth gets specific instructions"""
        instructions = self.generator._get_vuln_type_instructions(
            'missing_authorization',
            'Endpoint lacks authentication'
        )
        
        self.assertIn('Authentication', instructions)
        self.assertIn('@PreAuthorize', instructions)
        self.assertIn('hasRole', instructions)
    
    def test_legacy_context_still_works(self):
        """Test that old PatchContext still works (backwards compatibility)"""
        from app.services.patcher.llm_patch_generator import PatchContext
        
        legacy_context = PatchContext(
            vulnerability_type="sql_injection",
            file_path="UserService.java",
            line_number=10,
            vulnerable_code="String query = \"SELECT * FROM users WHERE id = \" + userId;",
            severity="high",
            confidence=0.9
        )
        
        # Should work without errors
        full_context = self.generator._gather_context(legacy_context, use_semantic=False)
        self.assertIsNotNone(full_context)


if __name__ == '__main__':
    unittest.main()
