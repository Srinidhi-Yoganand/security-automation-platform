"""
Semantic Patch Generator
Generates patches using symbolic execution root cause analysis
Produces template-based fixes for IDOR, missing auth, and other common vulnerabilities
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class PatchTemplate:
    """Template for generating a security patch"""
    name: str
    pattern: str  # Regex pattern to match vulnerable code
    fix_template: str  # Template for fixed code
    imports_needed: List[str]  # Additional imports required
    explanation: str  # Explanation of the fix


class SemanticPatchGenerator:
    """
    Generates semantic-aware patches based on symbolic execution findings
    Uses root cause analysis to produce targeted, effective fixes
    """
    
    def __init__(self):
        """Initialize patch generator with templates"""
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, List[PatchTemplate]]:
        """Initialize vulnerability-specific patch templates"""
        return {
            'idor': self._get_idor_templates(),
            'missing_authorization': self._get_missing_auth_templates(),
            'missing_authentication': self._get_missing_auth_templates(),
            'sql_injection': self._get_sql_injection_templates(),
            'path_traversal': self._get_path_traversal_templates(),
        }
    
    def generate_semantic_patch(
        self,
        vulnerable_code: str,
        vulnerability_type: str,
        missing_check: Optional[str] = None,
        attack_vector: Optional[Dict[str, Any]] = None,
        framework: str = "spring",
        method_name: Optional[str] = None,
        class_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate patch using semantic analysis and symbolic execution findings
        
        Args:
            vulnerable_code: The vulnerable code snippet
            vulnerability_type: Type of vulnerability (idor, missing_auth, etc.)
            missing_check: The specific check that's missing (from symbolic execution)
            attack_vector: Attack vector details from symbolic execution
            framework: Application framework (spring, jakarta, etc.)
            method_name: Method containing vulnerability
            class_name: Class containing vulnerability
            
        Returns:
            Dict with fixed_code, explanation, imports, confidence
        """
        vuln_type_lower = vulnerability_type.lower()
        
        # Try template-based generation first
        if vuln_type_lower in self.templates:
            result = self._apply_templates(
                vulnerable_code,
                self.templates[vuln_type_lower],
                missing_check,
                attack_vector,
                framework,
                method_name
            )
            if result:
                return result
        
        # Fallback to generic security improvement
        return self._generic_security_patch(
            vulnerable_code,
            vulnerability_type,
            missing_check
        )
    
    def _get_idor_templates(self) -> List[PatchTemplate]:
        """Get templates for IDOR vulnerabilities"""
        return [
            PatchTemplate(
                name="spring_idor_findById",
                pattern=r'(\w+)Repository\.findById\((\w+)\)',
                fix_template="""// Get current authenticated user
Long currentUserId = SecurityContextHolder.getContext()
    .getAuthentication().getPrincipal().getId();

// Verify authorization before accessing resource
{entity} entity = {repo}Repository.findById({param})
    .orElseThrow(() -> new ResourceNotFoundException("{entity} not found"));

if (!entity.getOwnerId().equals(currentUserId)) {{
    throw new AccessDeniedException("Not authorized to access this resource");
}}

return entity;""",
                imports_needed=[
                    "org.springframework.security.core.context.SecurityContextHolder",
                    "org.springframework.security.access.AccessDeniedException"
                ],
                explanation="Added authorization check to verify user owns the resource before access"
            ),
            PatchTemplate(
                name="spring_idor_getOne",
                pattern=r'(\w+)Repository\.getOne\((\w+)\)',
                fix_template="""// Get current authenticated user
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
Long currentUserId = ((UserPrincipal) auth.getPrincipal()).getId();

// Load and verify ownership
{entity} entity = {repo}Repository.findById({param})
    .orElseThrow(() -> new ResourceNotFoundException("{entity} not found"));

// Authorization check
if (!authorizationService.canAccess(currentUserId, entity)) {{
    throw new AccessDeniedException("Access denied");
}}

return entity;""",
                imports_needed=[
                    "org.springframework.security.core.context.SecurityContextHolder",
                    "org.springframework.security.core.Authentication",
                    "org.springframework.security.access.AccessDeniedException"
                ],
                explanation="Added explicit authorization verification using ownership check"
            ),
            PatchTemplate(
                name="spring_idor_method_param",
                pattern=r'@PathVariable.*?(\w+Id)',
                fix_template="""@PreAuthorize("@securityService.canAccessResource(authentication, #resourceId)")
@GetMapping("/{path}/{{resourceId}}")
public ResponseEntity<?> methodName(@PathVariable Long resourceId) {{
    // Authorization verified by @PreAuthorize
    return {repo}Repository.findById(resourceId)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.notFound().build());
}}""",
                imports_needed=[
                    "org.springframework.security.access.prepost.PreAuthorize"
                ],
                explanation="Added @PreAuthorize annotation to enforce authorization before method execution"
            )
        ]
    
    def _get_missing_auth_templates(self) -> List[PatchTemplate]:
        """Get templates for missing authentication/authorization"""
        return [
            PatchTemplate(
                name="spring_add_preauthorize",
                pattern=r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)',
                fix_template="""@PreAuthorize("hasRole('USER')")
{original_annotation}
public {return_type} {method_name}({params}) {{
    // Method now protected by authentication
    {method_body}
}}""",
                imports_needed=[
                    "org.springframework.security.access.prepost.PreAuthorize"
                ],
                explanation="Added @PreAuthorize to require authentication for endpoint access"
            ),
            PatchTemplate(
                name="spring_add_secured",
                pattern=r'public\s+\w+\s+(\w+)\s*\(',
                fix_template="""@Secured("ROLE_USER")
public {return_type} {method_name}({params}) {{
    // Verify user has required role
    {method_body}
}}""",
                imports_needed=[
                    "org.springframework.security.access.annotation.Secured"
                ],
                explanation="Added @Secured annotation to enforce role-based access control"
            ),
            PatchTemplate(
                name="manual_auth_check",
                pattern=r'public\s+.*?\{',
                fix_template="""public {return_type} {method_name}({params}) {{
    // Manual authentication check
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated()) {{
        throw new AuthenticationException("Authentication required");
    }}
    
    {method_body}
}}""",
                imports_needed=[
                    "org.springframework.security.core.Authentication",
                    "org.springframework.security.core.context.SecurityContextHolder",
                    "org.springframework.security.core.AuthenticationException"
                ],
                explanation="Added manual authentication verification at method entry"
            )
        ]
    
    def _get_sql_injection_templates(self) -> List[PatchTemplate]:
        """Get templates for SQL injection fixes"""
        return [
            PatchTemplate(
                name="jdbc_string_concat",
                pattern=r'String\s+query\s*=\s*".*?"\s*\+',
                fix_template="""// Use PreparedStatement instead of string concatenation
String query = "SELECT * FROM {table} WHERE {column} = ?";
try (PreparedStatement stmt = connection.prepareStatement(query)) {{
    stmt.setString(1, {param});
    ResultSet rs = stmt.executeQuery();
    // Process results
}}""",
                imports_needed=["java.sql.PreparedStatement"],
                explanation="Replaced string concatenation with PreparedStatement for safe SQL execution"
            ),
            PatchTemplate(
                name="jpa_native_query",
                pattern=r'createNativeQuery\(".*?"\s*\+',
                fix_template="""// Use parameterized query
Query query = entityManager.createNativeQuery(
    "SELECT * FROM {table} WHERE {column} = :param", {entity}.class);
query.setParameter("param", {param});
List<{entity}> results = query.getResultList();""",
                imports_needed=["javax.persistence.Query"],
                explanation="Converted to parameterized native query to prevent SQL injection"
            )
        ]
    
    def _get_path_traversal_templates(self) -> List[PatchTemplate]:
        """Get templates for path traversal fixes"""
        return [
            PatchTemplate(
                name="file_path_validation",
                pattern=r'new\s+File\([^)]+\)',
                fix_template="""// Validate and sanitize file path
Path basePath = Paths.get("/safe/base/directory").toAbsolutePath().normalize();
Path requestedPath = basePath.resolve({filename}).normalize();

// Ensure path is within allowed directory
if (!requestedPath.startsWith(basePath)) {{
    throw new SecurityException("Path traversal attempt detected");
}}

File file = requestedPath.toFile();""",
                imports_needed=[
                    "java.nio.file.Path",
                    "java.nio.file.Paths"
                ],
                explanation="Added path validation to prevent directory traversal attacks"
            )
        ]
    
    def _apply_templates(
        self,
        vulnerable_code: str,
        templates: List[PatchTemplate],
        missing_check: Optional[str],
        attack_vector: Optional[Dict[str, Any]],
        framework: str,
        method_name: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Apply patch templates to vulnerable code"""
        
        for template in templates:
            if re.search(template.pattern, vulnerable_code, re.IGNORECASE):
                # Extract context from vulnerable code
                context = self._extract_code_context(vulnerable_code, template.pattern)
                
                # Generate fixed code from template
                fixed_code = self._fill_template(
                    template.fix_template,
                    context,
                    vulnerable_code,
                    missing_check
                )
                
                return {
                    'fixed_code': fixed_code,
                    'explanation': template.explanation,
                    'imports_needed': template.imports_needed,
                    'confidence': 'high',
                    'template_used': template.name,
                    'breaking_changes': [],
                    'prerequisites': template.imports_needed
                }
        
        return None
    
    def _extract_code_context(self, code: str, pattern: str) -> Dict[str, str]:
        """Extract context variables from code using pattern"""
        context = {}
        
        match = re.search(pattern, code, re.IGNORECASE)
        if match:
            groups = match.groups()
            if len(groups) >= 1:
                context['repo'] = groups[0] if groups[0] else 'entity'
                context['entity'] = groups[0].replace('Repository', '') if groups[0] else 'Entity'
            if len(groups) >= 2:
                context['param'] = groups[1] if groups[1] else 'id'
        
        # Extract method info if present
        method_match = re.search(r'public\s+(\w+)\s+(\w+)\s*\(([^)]*)\)', code)
        if method_match:
            context['return_type'] = method_match.group(1)
            context['method_name'] = method_match.group(2)
            context['params'] = method_match.group(3)
        
        return context
    
    def _fill_template(
        self,
        template: str,
        context: Dict[str, str],
        original_code: str,
        missing_check: Optional[str]
    ) -> str:
        """Fill template with context variables"""
        filled = template
        
        # Replace context variables
        for key, value in context.items():
            filled = filled.replace(f'{{{key}}}', value)
        
        # Add missing check as comment if provided
        if missing_check:
            filled = f"// Fix: {missing_check}\n{filled}"
        
        return filled
    
    def _generic_security_patch(
        self,
        vulnerable_code: str,
        vulnerability_type: str,
        missing_check: Optional[str]
    ) -> Dict[str, Any]:
        """Generate generic security improvement when no template matches"""
        
        fixed_code = f"""// SECURITY FIX REQUIRED for {vulnerability_type}
// Root cause: {missing_check or 'Security validation missing'}

{vulnerable_code}

// TODO: Implement proper security controls:
// 1. Add input validation
// 2. Verify user authorization
// 3. Use framework security features
// 4. Follow principle of least privilege
"""
        
        return {
            'fixed_code': fixed_code,
            'explanation': f'Generic security annotation added. Manual review required for {vulnerability_type}.',
            'imports_needed': [],
            'confidence': 'low',
            'template_used': 'generic',
            'breaking_changes': ['Requires manual implementation'],
            'prerequisites': []
        }


def create_idor_patch(
    vulnerable_code: str,
    entity_name: str,
    param_name: str,
    framework: str = "spring"
) -> str:
    """
    Helper function to create IDOR patch
    
    Args:
        vulnerable_code: Code with IDOR vulnerability
        entity_name: Name of entity being accessed
        param_name: Parameter name used for access
        framework: Application framework
        
    Returns:
        Fixed code with authorization check
    """
    generator = SemanticPatchGenerator()
    result = generator.generate_semantic_patch(
        vulnerable_code=vulnerable_code,
        vulnerability_type='idor',
        missing_check='Authorization check required',
        framework=framework
    )
    return result['fixed_code'] if result else vulnerable_code


def create_missing_auth_patch(
    vulnerable_code: str,
    required_role: str = "USER",
    framework: str = "spring"
) -> str:
    """
    Helper function to create missing authentication patch
    
    Args:
        vulnerable_code: Code missing authentication
        required_role: Role required for access
        framework: Application framework
        
    Returns:
        Fixed code with authentication check
    """
    generator = SemanticPatchGenerator()
    result = generator.generate_semantic_patch(
        vulnerable_code=vulnerable_code,
        vulnerability_type='missing_authentication',
        missing_check=f'Authentication with role {required_role} required',
        framework=framework
    )
    return result['fixed_code'] if result else vulnerable_code
