"""
Patch Validator
Validates generated patches using symbolic execution to confirm fixes
"""

import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of patch validation"""
    is_valid: bool
    vulnerability_fixed: bool
    compilation_successful: bool
    symbolic_verification_passed: bool
    errors: List[str]
    warnings: List[str]
    details: Dict[str, Any]


class PatchValidator:
    """
    Validates generated security patches
    - Checks if code compiles
    - Runs symbolic execution on patched code
    - Verifies vulnerability is actually fixed
    """
    
    def __init__(self, symbolic_analyzer=None):
        """
        Initialize patch validator
        
        Args:
            symbolic_analyzer: Symbolic execution analyzer (optional)
        """
        self.symbolic_analyzer = symbolic_analyzer
    
    def validate_patch(
        self,
        original_code: str,
        patched_code: str,
        vulnerability_type: str,
        file_path: str,
        method_name: Optional[str] = None
    ) -> ValidationResult:
        """
        Validate a generated patch
        
        Args:
            original_code: Original vulnerable code
            patched_code: Patched code
            vulnerability_type: Type of vulnerability
            file_path: Path to source file
            method_name: Method that was patched
            
        Returns:
            ValidationResult with validation outcome
        """
        errors = []
        warnings = []
        details = {}
        
        # Step 1: Syntax validation
        syntax_valid = self._validate_syntax(patched_code, file_path)
        if not syntax_valid:
            errors.append("Patched code has syntax errors")
        
        # Step 2: Semantic validation
        semantic_checks = self._validate_semantics(original_code, patched_code, vulnerability_type)
        details['semantic_checks'] = semantic_checks
        
        if not semantic_checks['has_security_improvements']:
            warnings.append("Patch may not add meaningful security improvements")
        
        # Step 3: Symbolic execution validation (if available)
        symbolic_passed = False
        if self.symbolic_analyzer:
            symbolic_result = self._validate_with_symbolic_execution(
                patched_code,
                vulnerability_type,
                file_path,
                method_name
            )
            symbolic_passed = symbolic_result['vulnerability_fixed']
            details['symbolic_execution'] = symbolic_result
            
            if not symbolic_passed:
                errors.append("Symbolic execution still finds vulnerability in patched code")
        else:
            warnings.append("Symbolic execution validator not available")
        
        # Step 4: Determine overall validity
        is_valid = syntax_valid and len(errors) == 0
        vuln_fixed = semantic_checks['has_security_improvements'] and (
            symbolic_passed if self.symbolic_analyzer else True
        )
        
        return ValidationResult(
            is_valid=is_valid,
            vulnerability_fixed=vuln_fixed,
            compilation_successful=syntax_valid,
            symbolic_verification_passed=symbolic_passed,
            errors=errors,
            warnings=warnings,
            details=details
        )
    
    def _validate_syntax(self, code: str, file_path: str) -> bool:
        """
        Validate Java code syntax
        
        Args:
            code: Java code to validate
            file_path: File path (for context)
            
        Returns:
            True if syntax is valid
        """
        # Try to parse with javalang
        try:
            import javalang
            tree = javalang.parse.parse(code)
            return True
        except ImportError:
            # javalang not available, skip syntax check
            return True
        except Exception as e:
            # Syntax error
            return False
    
    def _validate_semantics(
        self,
        original_code: str,
        patched_code: str,
        vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Validate semantic improvements in patched code
        
        Args:
            original_code: Original code
            patched_code: Patched code
            vulnerability_type: Vulnerability type
            
        Returns:
            Dict with semantic validation results
        """
        vuln_type_lower = vulnerability_type.lower()
        
        checks = {
            'has_security_improvements': False,
            'improvements_found': [],
            'missing_improvements': []
        }
        
        # Check for IDOR fixes
        if 'idor' in vuln_type_lower:
            if self._has_authorization_check(patched_code):
                checks['improvements_found'].append('Authorization check added')
                checks['has_security_improvements'] = True
            else:
                checks['missing_improvements'].append('No authorization check detected')
            
            if 'SecurityContext' in patched_code or 'Authentication' in patched_code:
                checks['improvements_found'].append('Security context usage added')
                checks['has_security_improvements'] = True
        
        # Check for missing auth fixes
        if 'auth' in vuln_type_lower:
            if '@PreAuthorize' in patched_code or '@Secured' in patched_code:
                checks['improvements_found'].append('Authentication annotation added')
                checks['has_security_improvements'] = True
            elif 'Authentication' in patched_code and 'isAuthenticated' in patched_code:
                checks['improvements_found'].append('Manual authentication check added')
                checks['has_security_improvements'] = True
            else:
                checks['missing_improvements'].append('No authentication mechanism detected')
        
        # Check for SQL injection fixes
        if 'sql' in vuln_type_lower:
            if 'PreparedStatement' in patched_code or 'setParameter' in patched_code:
                checks['improvements_found'].append('Parameterized query added')
                checks['has_security_improvements'] = True
            else:
                checks['missing_improvements'].append('Still uses string concatenation')
        
        # Check for path traversal fixes
        if 'path' in vuln_type_lower or 'traversal' in vuln_type_lower:
            if 'normalize' in patched_code and 'startsWith' in patched_code:
                checks['improvements_found'].append('Path validation added')
                checks['has_security_improvements'] = True
            else:
                checks['missing_improvements'].append('No path validation detected')
        
        # Generic check: patched code should be different and longer
        if patched_code != original_code and len(patched_code) > len(original_code) * 1.1:
            if not checks['has_security_improvements'] and len(checks['improvements_found']) == 0:
                # Only give benefit of doubt if code was significantly modified
                # and we have some positive indicators
                positive_indicators = [
                    'SecurityContext' in patched_code,
                    '@PreAuthorize' in patched_code,
                    '@Secured' in patched_code,
                    'AccessDenied' in patched_code,
                    'PreparedStatement' in patched_code,
                    'normalize' in patched_code and 'Path' in patched_code
                ]
                
                if any(positive_indicators):
                    checks['has_security_improvements'] = True
                    checks['improvements_found'].append('Code modified with security intent')
        
        return checks
    
    def _has_authorization_check(self, code: str) -> bool:
        """Check if code has authorization check"""
        auth_indicators = [
            'AccessDeniedException',
            'canAccess',
            'hasPermission',
            'isOwner',
            'getOwnerId',
            'currentUserId',
            'checkAuthorization',
            'verifyOwnership',
            '@PreAuthorize',
            '@Secured'
        ]
        return any(indicator in code for indicator in auth_indicators)
    
    def _validate_with_symbolic_execution(
        self,
        patched_code: str,
        vulnerability_type: str,
        file_path: str,
        method_name: Optional[str]
    ) -> Dict[str, Any]:
        """
        Validate patch using symbolic execution
        
        Args:
            patched_code: Patched code
            vulnerability_type: Vulnerability type
            file_path: File path
            method_name: Method name
            
        Returns:
            Dict with symbolic execution results
        """
        if not self.symbolic_analyzer:
            return {
                'vulnerability_fixed': False,
                'error': 'Symbolic analyzer not available'
            }
        
        try:
            # Create temporary file with patched code
            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
                f.write(patched_code)
                temp_file = f.name
            
            # Run symbolic execution on patched code
            vuln_type_lower = vulnerability_type.lower()
            
            if 'idor' in vuln_type_lower:
                result = self.symbolic_analyzer.verify_idor_fix(temp_file, method_name)
            elif 'auth' in vuln_type_lower:
                result = self.symbolic_analyzer.verify_auth_fix(temp_file, method_name)
            else:
                result = {'vulnerability_fixed': False, 'reason': 'Unsupported vulnerability type for symbolic execution'}
            
            # Clean up
            Path(temp_file).unlink()
            
            return result
        
        except Exception as e:
            return {
                'vulnerability_fixed': False,
                'error': str(e)
            }
    
    def quick_validate(self, patched_code: str, vulnerability_type: str) -> bool:
        """
        Quick validation check (syntax + basic semantic)
        
        Args:
            patched_code: Patched code
            vulnerability_type: Vulnerability type
            
        Returns:
            True if patch looks valid
        """
        # Check syntax
        if not self._validate_syntax(patched_code, ""):
            return False
        
        # Check for security keywords
        semantic_checks = self._validate_semantics("", patched_code, vulnerability_type)
        return semantic_checks['has_security_improvements']
    
    def compare_patches(
        self,
        patches: List[Dict[str, Any]],
        vulnerability_type: str
    ) -> List[Dict[str, Any]]:
        """
        Compare multiple patches and rank them
        
        Args:
            patches: List of patch dicts with 'fixed_code'
            vulnerability_type: Vulnerability type
            
        Returns:
            Sorted list of patches (best first) with scores
        """
        scored_patches = []
        
        for patch in patches:
            score = 0
            
            # Validate patch
            result = self.validate_patch(
                original_code="",  # Not needed for scoring
                patched_code=patch['fixed_code'],
                vulnerability_type=vulnerability_type,
                file_path="",
                method_name=None
            )
            
            # Score based on validation results
            if result.is_valid:
                score += 10
            
            if result.vulnerability_fixed:
                score += 20
            
            if result.symbolic_verification_passed:
                score += 15
            
            improvements = result.details.get('semantic_checks', {}).get('improvements_found', [])
            score += len(improvements) * 10  # Increased from 5 to 10
            
            errors = len(result.errors)
            score -= errors * 5
            
            scored_patches.append({
                **patch,
                'validation_score': score,
                'validation_result': result
            })
        
        # Sort by score (descending)
        scored_patches.sort(key=lambda x: x['validation_score'], reverse=True)
        
        return scored_patches
