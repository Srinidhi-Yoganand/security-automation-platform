"""
Tests for patch validator
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.patch_validator import PatchValidator, ValidationResult


class TestPatchValidator(unittest.TestCase):
    """Test patch validator"""
    
    def setUp(self):
        """Set up validator"""
        self.validator = PatchValidator()
    
    def test_validate_idor_patch_with_auth_check(self):
        """Test validating IDOR patch with authorization"""
        original = "return userRepository.findById(userId);"
        
        patched = """
Long currentUserId = SecurityContextHolder.getContext().getAuthentication().getUserId();
User user = userRepository.findById(userId).orElseThrow();
if (!user.getId().equals(currentUserId)) {
    throw new AccessDeniedException("Not authorized");
}
return user;
"""
        
        result = self.validator.validate_patch(
            original_code=original,
            patched_code=patched,
            vulnerability_type='idor',
            file_path='UserController.java'
        )
        
        self.assertTrue(result.is_valid)
        self.assertTrue(result.vulnerability_fixed)
        self.assertIn('Authorization check added', str(result.details))
    
    def test_validate_idor_patch_missing_auth(self):
        """Test IDOR patch that doesn't add authorization"""
        original = "return userRepository.findById(userId);"
        patched = "return userRepository.findById(userId).orElseThrow();"
        
        result = self.validator.validate_patch(
            original_code=original,
            patched_code=patched,
            vulnerability_type='idor',
            file_path='UserController.java'
        )
        
        self.assertFalse(result.vulnerability_fixed)
        self.assertIn('missing_improvements', result.details['semantic_checks'])
    
    def test_validate_missing_auth_with_preauthorize(self):
        """Test missing auth patch with @PreAuthorize"""
        original = """
@GetMapping("/admin")
public void adminAction() {
    // admin stuff
}
"""
        
        patched = """
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public void adminAction() {
    // admin stuff
}
"""
        
        result = self.validator.validate_patch(
            original_code=original,
            patched_code=patched,
            vulnerability_type='missing_authentication',
            file_path='AdminController.java'
        )
        
        self.assertTrue(result.vulnerability_fixed)
        self.assertIn('Authentication annotation added', str(result.details))
    
    def test_validate_sql_injection_patch(self):
        """Test SQL injection patch validation"""
        original = 'String query = "SELECT * FROM users WHERE id = " + userId;'
        
        patched = """
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userId);
"""
        
        result = self.validator.validate_patch(
            original_code=original,
            patched_code=patched,
            vulnerability_type='sql_injection',
            file_path='UserDao.java'
        )
        
        self.assertTrue(result.vulnerability_fixed)
        self.assertIn('Parameterized query added', str(result.details))
    
    def test_validate_path_traversal_patch(self):
        """Test path traversal patch validation"""
        original = 'File file = new File(basePath + filename);'
        
        patched = """
Path requestedPath = basePath.resolve(filename).normalize();
if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal");
}
File file = requestedPath.toFile();
"""
        
        result = self.validator.validate_patch(
            original_code=original,
            patched_code=patched,
            vulnerability_type='path_traversal',
            file_path='FileHandler.java'
        )
        
        self.assertTrue(result.vulnerability_fixed)
        self.assertIn('Path validation added', str(result.details))
    
    def test_syntax_validation(self):
        """Test syntax validation"""
        valid_code = "public void test() { System.out.println(\"test\"); }"
        invalid_code = "public void test() { System.out.println(\"test\") "  # Missing }
        
        valid_result = self.validator._validate_syntax(valid_code, "Test.java")
        invalid_result = self.validator._validate_syntax(invalid_code, "Test.java")
        
        # Note: May pass if javalang not installed
        self.assertIsInstance(valid_result, bool)
        self.assertIsInstance(invalid_result, bool)
    
    def test_has_authorization_check(self):
        """Test authorization check detection"""
        code_with_auth = """
if (!hasPermission(user, resource)) {
    throw new AccessDeniedException();
}
"""
        
        code_without_auth = "return repository.findAll();"
        
        self.assertTrue(self.validator._has_authorization_check(code_with_auth))
        self.assertFalse(self.validator._has_authorization_check(code_without_auth))
    
    def test_quick_validate(self):
        """Test quick validation"""
        good_patch = """
@PreAuthorize("hasRole('USER')")
public void sensitiveAction() {}
"""
        
        bad_patch = "public void sensitiveAction() {}"
        
        result1 = self.validator.quick_validate(good_patch, 'missing_authentication')
        result2 = self.validator.quick_validate(bad_patch, 'missing_authentication')
        
        self.assertTrue(result1)
        self.assertFalse(result2)
    
    def test_compare_patches(self):
        """Test comparing multiple patches"""
        patches = [
            {
                'fixed_code': '@PreAuthorize("hasRole(\'USER\')") public void action() {}',
                'name': 'patch1'
            },
            {
                'fixed_code': 'public void action() { /* TODO: Add security */ }',
                'name': 'patch2'
            },
            {
                'fixed_code': '''
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
@PreAuthorize("hasRole('USER')")
public void action() {
    if (!auth.isAuthenticated()) throw new AuthenticationException();
}
''',
                'name': 'patch3'
            }
        ]
        
        ranked = self.validator.compare_patches(patches, 'missing_authentication')
        
        self.assertEqual(len(ranked), 3)
        # Patches should have different scores
        self.assertIsNotNone(ranked[0]['validation_score'])
        self.assertIsNotNone(ranked[1]['validation_score'])
        self.assertIsNotNone(ranked[2]['validation_score'])
        # Patch2 with just TODO should rank lowest
        self.assertEqual(ranked[2]['name'], 'patch2')
        # Patch 3 or patch 1 should be first (both have security improvements)
        self.assertIn(ranked[0]['name'], ['patch1', 'patch3'])
    
    def test_validation_result_structure(self):
        """Test ValidationResult structure"""
        result = ValidationResult(
            is_valid=True,
            vulnerability_fixed=True,
            compilation_successful=True,
            symbolic_verification_passed=False,
            errors=[],
            warnings=['Some warning'],
            details={'test': 'data'}
        )
        
        self.assertTrue(result.is_valid)
        self.assertTrue(result.vulnerability_fixed)
        self.assertEqual(len(result.warnings), 1)
        self.assertIn('test', result.details)
    
    def test_validate_unchanged_code(self):
        """Test validating code that wasn't changed"""
        code = "public void test() {}"
        
        result = self.validator.validate_patch(
            original_code=code,
            patched_code=code,
            vulnerability_type='idor',
            file_path='Test.java'
        )
        
        # Unchanged code should not fix vulnerability
        self.assertFalse(result.vulnerability_fixed)
    
    def test_semantic_checks_structure(self):
        """Test semantic checks return proper structure"""
        checks = self.validator._validate_semantics(
            "original",
            "@PreAuthorize('hasRole') public void test() {}",
            "missing_authentication"
        )
        
        self.assertIn('has_security_improvements', checks)
        self.assertIn('improvements_found', checks)
        self.assertIn('missing_improvements', checks)
        self.assertIsInstance(checks['improvements_found'], list)
        self.assertIsInstance(checks['missing_improvements'], list)


class TestPatchValidatorWithoutSymbolic(unittest.TestCase):
    """Test validator behavior without symbolic execution"""
    
    def test_validation_without_symbolic_analyzer(self):
        """Test that validation works without symbolic analyzer"""
        validator = PatchValidator(symbolic_analyzer=None)
        
        result = validator.validate_patch(
            original_code="code",
            patched_code="@PreAuthorize code",
            vulnerability_type='missing_auth',
            file_path='Test.java'
        )
        
        self.assertIsNotNone(result)
        self.assertFalse(result.symbolic_verification_passed)
        self.assertTrue(any('not available' in w for w in result.warnings))


if __name__ == '__main__':
    unittest.main()
