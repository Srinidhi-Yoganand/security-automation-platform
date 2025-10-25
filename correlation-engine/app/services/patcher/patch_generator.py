"""
Automated Security Patch Generator

Generates code fixes for common Java vulnerabilities detected in Phase 1 and Phase 2.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
import re
from dataclasses import dataclass


@dataclass
class PatchContext:
    """Context information for generating a patch"""
    vulnerability_type: str
    file_path: str
    line_number: int
    vulnerable_code: str
    severity: str
    confidence: float
    
    # Additional context
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    surrounding_lines: Optional[List[str]] = None


@dataclass
class GeneratedPatch:
    """A generated security patch"""
    vulnerability_type: str
    file_path: str
    line_number: int
    
    # The fix
    original_code: str
    fixed_code: str
    explanation: str
    
    # Git diff format
    diff: str
    
    # Additional info
    confidence: str  # "high", "medium", "low"
    manual_review_needed: bool
    remediation_guide: str


class PatchGenerator:
    """Main patch generator class"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.patch_templates = self._load_patch_templates()
    
    def _load_patch_templates(self) -> Dict[str, Any]:
        """Load patch templates for different vulnerability types"""
        return {
            'sql-injection': SQLInjectionPatcher(),
            'idor': IDORPatcher(),
            'xss': XSSPatcher(),
            'path-traversal': PathTraversalPatcher(),
            'command-injection': CommandInjectionPatcher(),
        }
    
    def generate_patch(self, context: PatchContext) -> Optional[GeneratedPatch]:
        """
        Generate a patch for a vulnerability.
        
        Args:
            context: Vulnerability context with code location and details
            
        Returns:
            GeneratedPatch object or None if patch cannot be generated
        """
        # Normalize vulnerability type
        vuln_type = self._normalize_vuln_type(context.vulnerability_type)
        
        if vuln_type not in self.patch_templates:
            return None
        
        # Read the file to get context
        file_path = self.repo_path / context.file_path
        if not file_path.exists():
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_lines = f.readlines()
            
            # Get surrounding context (10 lines before and after)
            start_line = max(0, context.line_number - 11)  # -1 for 0-index, -10 for context
            end_line = min(len(file_lines), context.line_number + 10)
            context.surrounding_lines = file_lines[start_line:end_line]
            
            # Extract method and class context
            context.method_name = self._extract_method_name(file_lines, context.line_number)
            context.class_name = self._extract_class_name(file_path)
            
            # Generate patch using appropriate template
            patcher = self.patch_templates[vuln_type]
            patch = patcher.generate(context, file_lines)
            
            if patch:
                # Generate diff
                patch.diff = self._generate_diff(
                    context.file_path,
                    patch.original_code,
                    patch.fixed_code,
                    context.line_number
                )
            
            return patch
            
        except Exception as e:
            print(f"Error generating patch: {e}")
            return None
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type to match template keys"""
        vuln_type_lower = vuln_type.lower()
        
        if 'sql' in vuln_type_lower or 'injection' in vuln_type_lower:
            return 'sql-injection'
        elif 'idor' in vuln_type_lower or 'insecure direct object' in vuln_type_lower:
            return 'idor'
        elif 'xss' in vuln_type_lower or 'cross-site scripting' in vuln_type_lower:
            return 'xss'
        elif 'path' in vuln_type_lower and 'traversal' in vuln_type_lower:
            return 'path-traversal'
        elif 'command' in vuln_type_lower and 'injection' in vuln_type_lower:
            return 'command-injection'
        
        return vuln_type_lower
    
    def _extract_method_name(self, file_lines: List[str], line_number: int) -> Optional[str]:
        """Extract the method name containing the vulnerable code"""
        # Search backwards for method declaration
        for i in range(line_number - 1, max(0, line_number - 50), -1):
            line = file_lines[i].strip()
            # Look for method patterns: public/private/protected ... methodName(
            match = re.search(r'(public|private|protected|static|\s)+\s+\w+\s+(\w+)\s*\(', line)
            if match:
                return match.group(2)
        return None
    
    def _extract_class_name(self, file_path: Path) -> str:
        """Extract class name from file path"""
        return file_path.stem
    
    def _generate_diff(self, file_path: str, original: str, fixed: str, line_number: int) -> str:
        """Generate a git diff format patch"""
        diff_lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{line_number},{len(original.splitlines())} +{line_number},{len(fixed.splitlines())} @@"
        ]
        
        for line in original.splitlines():
            diff_lines.append(f"-{line}")
        
        for line in fixed.splitlines():
            diff_lines.append(f"+{line}")
        
        return "\n".join(diff_lines)


class BasePatcher:
    """Base class for vulnerability-specific patchers"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate a patch for this vulnerability type"""
        raise NotImplementedError


class SQLInjectionPatcher(BasePatcher):
    """Generates patches for SQL Injection vulnerabilities"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate SQL Injection fix"""
        original_line = file_lines[context.line_number - 1].strip()
        
        # Detect pattern: String concatenation in SQL
        if '+' in original_line and ('query' in original_line.lower() or 'sql' in original_line.lower()):
            return self._fix_string_concatenation(context, original_line, file_lines)
        
        # Detect pattern: jdbcTemplate.query with concatenation
        if 'jdbcTemplate.query' in original_line or 'jdbcTemplate.queryForObject' in original_line:
            return self._fix_jdbc_template(context, original_line, file_lines)
        
        # Detect pattern: createNativeQuery with concatenation
        if 'createNativeQuery' in original_line:
            return self._fix_native_query(context, original_line, file_lines)
        
        return None
    
    def _fix_string_concatenation(self, context: PatchContext, original_line: str, file_lines: List[str]) -> GeneratedPatch:
        """Fix basic string concatenation in SQL"""
        # Extract variable name and the concatenated part
        match = re.search(r'(\w+)\s*=\s*"([^"]+)"\s*\+\s*(\w+)', original_line)
        
        if match:
            var_name = match.group(1)
            sql_part = match.group(2)
            user_input = match.group(3)
            
            # Generate fixed code using PreparedStatement
            indent = len(original_line) - len(original_line.lstrip())
            indent_str = ' ' * indent
            
            fixed_code = f"""{indent_str}// FIX: Use PreparedStatement to prevent SQL injection
{indent_str}String {var_name} = "{sql_part}?";
{indent_str}PreparedStatement pstmt = connection.prepareStatement({var_name});
{indent_str}pstmt.setString(1, {user_input});"""
            
            explanation = (
                "Replaced string concatenation with PreparedStatement and parameterized query. "
                "This prevents SQL injection by properly escaping user input."
            )
            
            return GeneratedPatch(
                vulnerability_type="SQL Injection",
                file_path=context.file_path,
                line_number=context.line_number,
                original_code=original_line,
                fixed_code=fixed_code,
                explanation=explanation,
                diff="",  # Will be filled by parent
                confidence="high",
                manual_review_needed=True,
                remediation_guide="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            )
        
        return None
    
    def _fix_jdbc_template(self, context: PatchContext, original_line: str, file_lines: List[str]) -> GeneratedPatch:
        """Fix jdbcTemplate with string concatenation"""
        indent = len(original_line) - len(original_line.lstrip())
        indent_str = ' ' * indent
        
        # Extract the query and variable
        if 'queryForObject' in original_line:
            match = re.search(r'queryForObject\(([^,]+),', original_line)
            if match:
                query_part = match.group(1).strip()
                
                # Simple fix: add parameter placeholder
                fixed_line = original_line.replace(
                    query_part,
                    query_part.replace(' + ', ', ')
                ).replace('query', 'query.replace("+", "?")')
                
                fixed_code = f"""{indent_str}// FIX: Use parameterized query instead of string concatenation
{indent_str}String query = "SELECT * FROM users WHERE id=?";
{indent_str}return jdbcTemplate.queryForObject(query, new Object[]{{userId}}, new UserRowMapper());"""
                
                explanation = (
                    "Replaced string concatenation with parameterized query using Object array. "
                    "JdbcTemplate will properly escape the parameter."
                )
                
                return GeneratedPatch(
                    vulnerability_type="SQL Injection",
                    file_path=context.file_path,
                    line_number=context.line_number,
                    original_code=original_line,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    diff="",
                    confidence="high",
                    manual_review_needed=False,
                    remediation_guide="https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html"
                )
        
        return None
    
    def _fix_native_query(self, context: PatchContext, original_line: str, file_lines: List[str]) -> GeneratedPatch:
        """Fix JPA native query with concatenation"""
        indent = len(original_line) - len(original_line.lstrip())
        indent_str = ' ' * indent
        
        fixed_code = f"""{indent_str}// FIX: Use parameterized query with setParameter
{indent_str}String query = "SELECT * FROM users WHERE id = :userId";
{indent_str}Query nativeQuery = entityManager.createNativeQuery(query, User.class);
{indent_str}nativeQuery.setParameter("userId", userId);
{indent_str}return nativeQuery.getSingleResult();"""
        
        explanation = (
            "Replaced string concatenation with named parameter. "
            "JPA will properly escape the parameter using setParameter()."
        )
        
        return GeneratedPatch(
            vulnerability_type="SQL Injection",
            file_path=context.file_path,
            line_number=context.line_number,
            original_code=original_line,
            fixed_code=fixed_code,
            explanation=explanation,
            diff="",
            confidence="medium",
            manual_review_needed=True,
            remediation_guide="https://www.baeldung.com/jpa-query-parameters"
        )


class IDORPatcher(BasePatcher):
    """Generates patches for Insecure Direct Object Reference vulnerabilities"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate IDOR fix by adding authorization check"""
        original_line = file_lines[context.line_number - 1].strip()
        indent = len(file_lines[context.line_number - 1]) - len(original_line)
        indent_str = ' ' * indent
        
        # Look for method signature
        method_name = context.method_name or "handleRequest"
        
        # Generate authorization check
        fixed_code = f"""{indent_str}// FIX: Add authorization check before accessing resource
{indent_str}if (!authorizationService.canAccess(currentUser, resourceId)) {{
{indent_str}    throw new AccessDeniedException("User not authorized to access this resource");
{indent_str}}}
{indent_str}
{indent_str}{original_line}"""
        
        explanation = (
            "Added authorization check to verify that the current user has permission to access the requested resource. "
            "This prevents users from accessing resources they don't own by manipulating IDs."
        )
        
        return GeneratedPatch(
            vulnerability_type="IDOR",
            file_path=context.file_path,
            line_number=context.line_number,
            original_code=original_line,
            fixed_code=fixed_code,
            explanation=explanation,
            diff="",
            confidence="medium",
            manual_review_needed=True,
            remediation_guide="https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
        )


class XSSPatcher(BasePatcher):
    """Generates patches for Cross-Site Scripting vulnerabilities"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate XSS fix by adding output encoding"""
        original_line = file_lines[context.line_number - 1].strip()
        indent = len(file_lines[context.line_number - 1]) - len(original_line)
        indent_str = ' ' * indent
        
        # Check if it's a return statement with user input
        if 'return' in original_line:
            # Extract the returned variable/expression
            match = re.search(r'return\s+(.+);', original_line)
            if match:
                returned_value = match.group(1).strip()
                
                fixed_code = f"""{indent_str}// FIX: Encode output to prevent XSS
{indent_str}return HtmlUtils.htmlEscape({returned_value});"""
                
                explanation = (
                    "Added HTML encoding to user-controlled output. "
                    "This prevents XSS attacks by escaping special characters like <, >, &, etc."
                )
                
                return GeneratedPatch(
                    vulnerability_type="XSS",
                    file_path=context.file_path,
                    line_number=context.line_number,
                    original_code=original_line,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    diff="",
                    confidence="high",
                    manual_review_needed=False,
                    remediation_guide="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                )
        
        return None


class PathTraversalPatcher(BasePatcher):
    """Generates patches for Path Traversal vulnerabilities"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate Path Traversal fix"""
        original_line = file_lines[context.line_number - 1].strip()
        indent = len(file_lines[context.line_number - 1]) - len(original_line)
        indent_str = ' ' * indent
        
        # Look for file path construction
        if 'new File' in original_line or 'Paths.get' in original_line:
            # Extract the user input variable
            match = re.search(r'(new File|Paths\.get)\([^,)]*,?\s*([^)]+)\)', original_line)
            if match:
                user_input = match.group(2).strip()
                
                fixed_code = f"""{indent_str}// FIX: Validate and sanitize file path to prevent path traversal
{indent_str}String sanitizedPath = {user_input}.replaceAll("\\.\\.", "");
{indent_str}Path basePath = Paths.get("/safe/base/directory");
{indent_str}Path fullPath = basePath.resolve(sanitizedPath).normalize();
{indent_str}if (!fullPath.startsWith(basePath)) {{
{indent_str}    throw new SecurityException("Path traversal attempt detected");
{indent_str}}}
{indent_str}{original_line.replace(user_input, 'fullPath.toString()')}"""
                
                explanation = (
                    "Added path validation to prevent directory traversal attacks. "
                    "The code now: 1) Removes '..' sequences, 2) Resolves path relative to safe base, "
                    "3) Validates the resolved path stays within base directory."
                )
                
                return GeneratedPatch(
                    vulnerability_type="Path Traversal",
                    file_path=context.file_path,
                    line_number=context.line_number,
                    original_code=original_line,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    diff="",
                    confidence="medium",
                    manual_review_needed=True,
                    remediation_guide="https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html"
                )
        
        return None


class CommandInjectionPatcher(BasePatcher):
    """Generates patches for Command Injection vulnerabilities"""
    
    def generate(self, context: PatchContext, file_lines: List[str]) -> Optional[GeneratedPatch]:
        """Generate Command Injection fix"""
        original_line = file_lines[context.line_number - 1].strip()
        indent = len(file_lines[context.line_number - 1]) - len(original_line)
        indent_str = ' ' * indent
        
        if 'Runtime.getRuntime().exec' in original_line:
            fixed_code = f"""{indent_str}// FIX: Use ProcessBuilder with argument array to prevent command injection
{indent_str}// Validate input against whitelist
{indent_str}if (!isValidInput(userInput)) {{
{indent_str}    throw new IllegalArgumentException("Invalid input");
{indent_str}}}
{indent_str}ProcessBuilder pb = new ProcessBuilder("safe-command", userInput);
{indent_str}Process process = pb.start();"""
            
            explanation = (
                "Replaced Runtime.exec() with ProcessBuilder using argument array. "
                "This prevents command injection by treating user input as data, not as part of the command. "
                "Also added input validation."
            )
            
            return GeneratedPatch(
                vulnerability_type="Command Injection",
                file_path=context.file_path,
                line_number=context.line_number,
                original_code=original_line,
                fixed_code=fixed_code,
                explanation=explanation,
                diff="",
                confidence="medium",
                manual_review_needed=True,
                remediation_guide="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            )
        
        return None
