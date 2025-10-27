"""
Tests for semantic patch generator
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.semantic_patch_generator import (
    SemanticPatchGenerator,
    create_idor_patch,
    create_missing_auth_patch
)


class TestSemanticPatchGenerator(unittest.TestCase):
    """Test semantic patch generator"""
    
    def setUp(self):
        """Set up test generator"""
        self.generator = SemanticPatchGenerator()
    
    def test_idor_findById_patch(self):
        """Test IDOR patch for findById pattern"""
        vulnerable_code = """
@GetMapping("/users/{userId}")
public User getUser(@PathVariable Long userId) {
    return userRepository.findById(userId).orElseThrow();
}
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='idor',
            missing_check='Authorization check required',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertIn('SecurityContextHolder', result['fixed_code'])
        self.assertIn('AccessDeniedException', result['fixed_code'])
        self.assertIn('currentUserId', result['fixed_code'])
        self.assertEqual(result['confidence'], 'high')
        self.assertIn('org.springframework.security', result['imports_needed'][0])
    
    def test_idor_getOne_patch(self):
        """Test IDOR patch for getOne pattern"""
        vulnerable_code = """
public Order getOrder(Long orderId) {
    return orderRepository.getOne(orderId);
}
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='idor',
            missing_check='Verify order ownership',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertIn('Authentication', result['fixed_code'])
        self.assertIn('canAccess', result['fixed_code'])
        self.assertIn('authorizationService', result['fixed_code'])
    
    def test_missing_auth_preauthorize_patch(self):
        """Test adding @PreAuthorize for missing authentication"""
        vulnerable_code = """
@GetMapping("/admin/users")
public List<User> getAllUsers() {
    return userRepository.findAll();
}
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='missing_authentication',
            missing_check='Authentication required',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertIn('@PreAuthorize', result['fixed_code'])
        self.assertIn('hasRole', result['fixed_code'])
        self.assertEqual(result['confidence'], 'high')
    
    def test_missing_auth_secured_patch(self):
        """Test adding @Secured annotation"""
        vulnerable_code = """
public void deleteUser(Long userId) {
    userRepository.deleteById(userId);
}
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='missing_authorization',
            missing_check='Role check required',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        # Should match one of the auth templates
        self.assertEqual(result['confidence'], 'high')
        self.assertTrue(
            '@Secured' in result['fixed_code'] or 
            '@PreAuthorize' in result['fixed_code'] or
            'Authentication' in result['fixed_code']
        )
    
    def test_sql_injection_patch(self):
        """Test SQL injection fix with PreparedStatement"""
        vulnerable_code = """
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='sql_injection',
            missing_check='Use parameterized query',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertIn('PreparedStatement', result['fixed_code'])
        self.assertIn('setString', result['fixed_code'])
        self.assertEqual(result['confidence'], 'high')
    
    def test_path_traversal_patch(self):
        """Test path traversal fix with validation"""
        vulnerable_code = """
String filename = request.getParameter("file");
File file = new File("/uploads/" + filename);
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='path_traversal',
            missing_check='Validate file path',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertIn('normalize', result['fixed_code'])
        self.assertIn('startsWith', result['fixed_code'])
        self.assertIn('SecurityException', result['fixed_code'])
    
    def test_unknown_vulnerability_generic_patch(self):
        """Test generic patch for unknown vulnerability types"""
        vulnerable_code = """
public void doSomething() {
    // Some vulnerable code
}
"""
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='unknown_vulnerability',
            missing_check='Some security check',
            framework='spring'
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result['confidence'], 'low')
        self.assertIn('TODO', result['fixed_code'])
        self.assertIn('SECURITY FIX REQUIRED', result['fixed_code'])
    
    def test_context_extraction(self):
        """Test extracting context from vulnerable code"""
        code = """
public User getUser(Long userId) {
    return userRepository.findById(userId).get();
}
"""
        
        context = self.generator._extract_code_context(
            code,
            r'(\w+)Repository\.findById\((\w+)\)'
        )
        
        self.assertEqual(context['repo'], 'user')
        self.assertEqual(context['entity'], 'user')
        self.assertEqual(context['param'], 'userId')
        self.assertEqual(context['return_type'], 'User')
        self.assertEqual(context['method_name'], 'getUser')
    
    def test_template_filling(self):
        """Test filling template with context"""
        template = "return {repo}Repository.findById({param});"
        context = {'repo': 'user', 'param': 'userId'}
        
        filled = self.generator._fill_template(
            template,
            context,
            "original code",
            "Authorization required"
        )
        
        self.assertIn('userRepository', filled)
        self.assertIn('userId', filled)
        self.assertIn('Authorization required', filled)
    
    def test_helper_create_idor_patch(self):
        """Test IDOR helper function"""
        vulnerable_code = "return userRepository.findById(userId);"
        
        fixed = create_idor_patch(
            vulnerable_code=vulnerable_code,
            entity_name='User',
            param_name='userId'
        )
        
        self.assertIsNotNone(fixed)
        self.assertIn('SecurityContextHolder', fixed)
    
    def test_helper_create_missing_auth_patch(self):
        """Test missing auth helper function"""
        vulnerable_code = "@GetMapping('/admin') public void admin() {}"
        
        fixed = create_missing_auth_patch(
            vulnerable_code=vulnerable_code,
            required_role='ADMIN'
        )
        
        self.assertIsNotNone(fixed)
        self.assertTrue('@PreAuthorize' in fixed or '@Secured' in fixed or 'Authentication' in fixed)
    
    def test_multiple_templates_for_same_vuln(self):
        """Test that multiple templates can match same vulnerability type"""
        idor_templates = self.generator._get_idor_templates()
        
        # Should have multiple IDOR templates
        self.assertGreater(len(idor_templates), 1)
        
        # Each should have required fields
        for template in idor_templates:
            self.assertIsNotNone(template.name)
            self.assertIsNotNone(template.pattern)
            self.assertIsNotNone(template.fix_template)
            self.assertIsNotNone(template.explanation)
    
    def test_imports_included_in_result(self):
        """Test that required imports are included in patch result"""
        vulnerable_code = "return userRepository.findById(userId);"
        
        result = self.generator.generate_semantic_patch(
            vulnerable_code=vulnerable_code,
            vulnerability_type='idor',
            missing_check='Authorization required',
            framework='spring'
        )
        
        self.assertIsNotNone(result['imports_needed'])
        self.assertGreater(len(result['imports_needed']), 0)
        self.assertTrue(any('springframework' in imp for imp in result['imports_needed']))


class TestPatchTemplates(unittest.TestCase):
    """Test patch template structure"""
    
    def setUp(self):
        """Set up generator"""
        self.generator = SemanticPatchGenerator()
    
    def test_idor_templates_structure(self):
        """Test IDOR templates are well-formed"""
        templates = self.generator._get_idor_templates()
        
        for template in templates:
            self.assertIsNotNone(template.name)
            self.assertIsNotNone(template.pattern)
            self.assertIsNotNone(template.fix_template)
            self.assertIsInstance(template.imports_needed, list)
            self.assertIsNotNone(template.explanation)
            
            # Should reference security concepts
            self.assertTrue(
                'authorization' in template.explanation.lower() or
                'security' in template.explanation.lower()
            )
    
    def test_sql_injection_templates_structure(self):
        """Test SQL injection templates are well-formed"""
        templates = self.generator._get_sql_injection_templates()
        
        for template in templates:
            # Should use either PreparedStatement or parameterized query
            self.assertTrue(
                'PreparedStatement' in template.fix_template or
                'setParameter' in template.fix_template
            )
            self.assertTrue(
                'injection' in template.explanation.lower() or
                'sql' in template.explanation.lower()
            )
    
    def test_path_traversal_templates_structure(self):
        """Test path traversal templates are well-formed"""
        templates = self.generator._get_path_traversal_templates()
        
        for template in templates:
            self.assertIn('normalize', template.fix_template)
            self.assertIn('path', template.explanation.lower())


if __name__ == '__main__':
    unittest.main()
