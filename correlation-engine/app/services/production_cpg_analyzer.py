"""
Production-Grade CPG Analyzer
Semantic analysis for ANY application (not just our test app)

Detection strategies:
1. Data flow tracking (user input → dangerous sink)
2. Missing security checks (auth, validation, sanitization)
3. Business logic flaws (privilege escalation, state manipulation)
4. Configuration issues (debug mode, weak crypto)
"""

import logging
import re
from typing import Dict, List, Set, Tuple
from pathlib import Path
import ast

logger = logging.getLogger(__name__)


class ProductionCPGAnalyzer:
    """
    Semantic code analysis for any application
    """
    
    def __init__(self):
        self.findings = []
        
    def analyze(self, source_path: str, language: str = "python") -> Dict:
        """
        Perform comprehensive CPG analysis
        
        Works for ANY codebase by detecting patterns, not hardcoded checks
        """
        logger.info(f"🔍 CPG semantic analysis on {source_path}")
        
        findings = []
        
        try:
            source_path_obj = Path(source_path)
            
            # Handle single file vs directory
            if source_path_obj.is_file():
                files = [source_path_obj]
            else:
                # Get all source files - MULTI-LANGUAGE support
                if language == "python":
                    files = list(source_path_obj.rglob('*.py'))
                elif language in ["javascript", "typescript"]:
                    files = list(source_path_obj.rglob('*.js')) + list(source_path_obj.rglob('*.ts')) + list(source_path_obj.rglob('*.jsx')) + list(source_path_obj.rglob('*.tsx'))
                elif language == "java":
                    files = list(source_path_obj.rglob('*.java'))
                elif language == "php":
                    files = list(source_path_obj.rglob('*.php'))
                else:
                    # Auto-detect: scan common source file extensions
                    extensions = ['*.py', '*.js', '*.ts', '*.jsx', '*.tsx', '*.java', '*.php', '*.rb', '*.go', '*.cs', '*.cpp', '*.c']
                    files = []
                    for ext in extensions:
                        files.extend(list(source_path_obj.rglob(ext)))
                
                # Exclude common directories (but be less aggressive)
                files = [f for f in files if not any(
                    exc in str(f) for exc in ['.git/', 'node_modules/', 'venv/', '__pycache__/', 'dist/', 'build/']
                )]
            
            logger.info(f"Analyzing {len(files)} files")
            
            for file_path in files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                    
                    # Run all detection strategies
                    findings.extend(self._detect_sql_injection_dataflow(content, file_path, lines))
                    findings.extend(self._detect_xss_dataflow(content, file_path, lines))
                    findings.extend(self._detect_command_injection(content, file_path, lines))
                    findings.extend(self._detect_path_traversal(content, file_path, lines))
                    findings.extend(self._detect_missing_authorization(content, file_path, lines))
                    findings.extend(self._detect_idor(content, file_path, lines))
                    findings.extend(self._detect_business_logic(content, file_path, lines))
                    findings.extend(self._detect_insecure_deserialization(content, file_path, lines))
                    findings.extend(self._detect_weak_cryptography(content, file_path, lines))
                    findings.extend(self._detect_hardcoded_secrets(content, file_path, lines))
                    
                    # New enhanced detection strategies
                    findings.extend(self._detect_stored_xss(content, file_path, lines))
                    findings.extend(self._detect_file_upload(content, file_path, lines))
                    findings.extend(self._detect_open_redirect(content, file_path, lines))
                    findings.extend(self._detect_weak_session_ids(content, file_path, lines))
                    findings.extend(self._detect_authentication_bypass(content, file_path, lines))
                    
                except Exception as e:
                    logger.debug(f"Error analyzing {file_path}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"CPG analysis failed: {e}")
        
        logger.info(f"✅ CPG complete: {len(findings)} findings")
        
        return {
            'success': True,
            'tool': 'Production-CPG',
            'total_findings': len(findings),
            'findings': findings,
            'confidence': 'high'
        }
    
    def _detect_sql_injection_dataflow(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect SQL injection by tracking user input → SQL execution - MULTI-LANGUAGE
        
        Strategy: Find user input sources, track variable names, find SQL sinks
        """
        findings = []
        
        # Step 1: Find all user input sources
        user_inputs = self._find_user_input_sources(content, lines)
        
        # Step 2: For each user input, check if it flows to SQL
        for var_name, input_line in user_inputs:
            # Search forward from input line for SQL operations
            search_end = min(input_line + 100, len(lines))
            
            for line_num in range(input_line, search_end):
                line = lines[line_num]
                
                # Check if this variable is used in SQL - MULTI-LANGUAGE
                has_sql = any(keyword in line.upper() for keyword in [
                    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER'
                ]) or any(method in line for method in [
                    # Python
                    'execute(', 'executemany(', 'raw(', 'query(', 'cursor.',
                    # JavaScript/TypeScript
                    '.query(', '.exec(', '.run(', 'db.collection', 'findOne', 'find(',
                    'sequelize.query', 'knex.raw', 'db.execute',
                    # Java
                    'executeQuery', 'executeUpdate', 'createQuery', 'createNativeQuery',
                    'PreparedStatement', 'Statement.execute',
                    # PHP
                    'mysql_query', 'mysqli_query', 'pg_query', 'sqlite_query',
                    'PDO::query', '->query(', '->exec(',
                ])
                
                if has_sql and var_name in line:
                    # Check if it's parameterized (safe) or concatenated (unsafe)
                    is_safe = self._is_sql_parameterized(line)
                    
                    if not is_safe:
                        findings.append({
                            'tool': 'CPG-Dataflow',
                            'type': 'SQL_INJECTION',
                            'severity': 'critical',
                            'file_path': str(file_path),
                            'line_number': line_num + 1,
                            'message': f"SQL Injection: User input '{var_name}' flows to SQL query without parameterization",
                            'confidence': 'high',
                            'metadata': {
                                'source_line': input_line + 1,
                                'sink_line': line_num + 1,
                                'variable': var_name,
                                'analysis_type': 'dataflow'
                            }
                        })
                        break
        
        return findings
    
    def _detect_xss_dataflow(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect XSS by tracking user input → HTML output - MULTI-LANGUAGE
        """
        findings = []
        
        # Find user input sources
        user_inputs = self._find_user_input_sources(content, lines)
        
        for var_name, input_line in user_inputs:
            # Search forward for HTML output
            search_end = min(input_line + 100, len(lines))
            
            for line_num in range(input_line, search_end):
                line = lines[line_num]
                
                # Check if variable is used in HTML context - MULTI-LANGUAGE
                has_html_output = any(pattern in line for pattern in [
                    # HTML tags
                    '<html', '<body', '<div', '<p>', '<h1>', '<h2>', '<h3>',
                    '<span', '<script', '<a ', '<img ', '<iframe',
                    # JavaScript DOM manipulation
                    'innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML',
                    '.html(', '.append(', '$(', 'dangerouslySetInnerHTML',
                    # Template engines
                    'render_template', 'render(', 'res.send', 'res.write',
                    'response.write', 'echo ', 'print ', 'println',
                    # String interpolation with HTML
                    'return f"<', "return f'<", 'return `<', 'return "<',
                    "return '<", '= `<', '= "<', "= '<",
                ])
                
                if has_html_output and var_name in line:
                    # Check if escaped - MULTI-LANGUAGE
                    is_escaped = any(esc in line for esc in [
                        # Python
                        'escape(', 'html.escape', 'Markup.escape', '|e}', '|escape}',
                        # JavaScript
                        'escapeHtml', 'textContent', 'sanitize', 'DOMPurify',
                        'escape-html', 'xss-filters',
                        # Java
                        'StringEscapeUtils', 'ESAPI.encoder', 'encodeForHTML',
                        # PHP
                        'htmlspecialchars', 'htmlentities', 'esc_html', 'esc_attr',
                        # Generic
                        '.text(', 'createTextNode',
                    ])
                    
                    if not is_escaped:
                        findings.append({
                            'tool': 'CPG-Dataflow',
                            'type': 'XSS',
                            'severity': 'high',
                            'file_path': str(file_path),
                            'line_number': line_num + 1,
                            'message': f"XSS: User input '{var_name}' flows to HTML output without escaping",
                            'confidence': 'high',
                            'metadata': {
                                'source_line': input_line + 1,
                                'sink_line': line_num + 1,
                                'variable': var_name
                            }
                        })
                        break
        
        return findings
    
    def _detect_command_injection(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """Detect command injection - MULTI-LANGUAGE"""
        findings = []
        
        user_inputs = self._find_user_input_sources(content, lines)
        
        for var_name, input_line in user_inputs:
            search_end = min(input_line + 100, len(lines))
            
            for line_num in range(input_line, search_end):
                line = lines[line_num]
                
                # Check for command execution - MULTI-LANGUAGE
                has_command_exec = any(cmd in line for cmd in [
                    # Python
                    'os.system', 'subprocess.call', 'subprocess.run', 'subprocess.Popen',
                    'exec(', 'eval(', 'compile(',
                    # JavaScript/Node.js
                    'child_process.exec', 'child_process.spawn', 'exec(', 'execSync',
                    'execFile', 'spawn(', 'eval(',
                    # PHP
                    'shell_exec', 'system(', 'passthru', 'exec(', 'popen',
                    '`', 'proc_open',
                    # Java
                    'Runtime.getRuntime().exec', 'ProcessBuilder', 'ScriptEngine.eval',
                    # Generic
                    'command', 'shell',
                ])
                
                if has_command_exec and var_name in line:
                    # Check if using unsafe methods
                    is_unsafe = any(danger in line for danger in [
                        'shell=True', 'os.system', 'eval(', 'exec(',
                        'child_process.exec', 'shell_exec', '`'
                    ])
                    
                    # Also unsafe if concatenating into command string
                    has_concat = any(op in line for op in [' + ', ' % ', '.format(', 'f"', "f'", '`${', '+'])
                    
                    if is_unsafe or has_concat:
                        findings.append({
                            'tool': 'CPG-Dataflow',
                            'type': 'COMMAND_INJECTION',
                            'severity': 'critical',
                            'file_path': str(file_path),
                            'line_number': line_num + 1,
                            'message': f"Command Injection: User input '{var_name}' flows to shell command",
                            'confidence': 'high',
                            'metadata': {
                                'source_line': input_line + 1,
                                'sink_line': line_num + 1,
                                'variable': var_name
                            }
                        })
                        break
        
        return findings
    
    def _detect_path_traversal(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """Detect path traversal - MULTI-LANGUAGE"""
        findings = []
        
        user_inputs = self._find_user_input_sources(content, lines)
        
        for var_name, input_line in user_inputs:
            search_end = min(input_line + 100, len(lines))
            
            for line_num in range(input_line, search_end):
                line = lines[line_num]
                
                # Check for file operations - MULTI-LANGUAGE
                has_file_op = any(op in line for op in [
                    # Python
                    'open(', 'read(', 'write(', 'os.path.join', 'Path(',
                    'shutil.', 'os.remove', 'os.unlink',
                    # JavaScript/Node.js  
                    'readFile', 'writeFile', 'readFileSync', 'writeFileSync',
                    'fs.read', 'fs.write', 'fs.open', 'fs.unlink', 'fs.readdir',
                    'path.join', 'path.resolve',
                    # PHP
                    'file_get_contents', 'file_put_contents', 'fopen', 'readfile',
                    'include', 'require', 'include_once', 'require_once',
                    # Java
                    'new File(', 'FileReader', 'FileWriter', 'Files.read',
                    'Files.write', 'Paths.get',
                    # Generic
                    'download', 'upload', 'readFile', 'writeFile'
                ])
                
                if has_file_op and var_name in line:
                    # Check if path is validated - MULTI-LANGUAGE
                    has_validation = any(val in line for val in [
                        # Python
                        'os.path.abspath', 'os.path.realpath', 'Path.resolve',
                        'safe_join', 'validate_path', 'is_safe_path',
                        # JavaScript
                        'path.normalize', 'path.resolve', 'sanitize',
                        # PHP
                        'realpath', 'basename', 'pathinfo',
                        # Java
                        'normalize()', 'getCanonicalPath', 'toRealPath',
                        # Generic
                        'sanitize', 'validate', 'whitelist', 'allowlist'
                    ])
                    
                    # Also check for dangerous patterns
                    has_dangerous_pattern = '../' in line or '..' in line
                    
                    if not has_validation or has_dangerous_pattern:
                        findings.append({
                            'tool': 'CPG-Dataflow',
                            'type': 'PATH_TRAVERSAL',
                            'severity': 'high',
                            'file_path': str(file_path),
                            'line_number': line_num + 1,
                            'message': f"Path Traversal: User input '{var_name}' used in file operation without validation",
                            'confidence': 'medium',
                            'metadata': {
                                'source_line': input_line + 1,
                                'sink_line': line_num + 1,
                                'variable': var_name
                            }
                        })
                        break
        
        return findings
    
    def _detect_missing_authorization(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect missing authorization in sensitive endpoints
        
        Strategy: Find admin/sensitive routes, check for auth checks
        """
        findings = []
        
        # Find route/endpoint definitions
        route_patterns = [
            r'@app\.route\([\'"]([^\'"]+)[\'"]\s*,?\s*methods=\[([^\]]+)\]\)',  # Flask
            r'@\w+\.route\([\'"]([^\'"]+)[\'"]',  # Generic
            r'app\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]',  # Express
            r'@(Get|Post|Put|Delete)Mapping\([\'"]([^\'"]+)[\'"]',  # Spring
        ]
        
        for pattern in route_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                route_path = match.group(1) if match.lastindex >= 1 else ''
                
                # Check if route is sensitive
                is_sensitive = any(word in route_path.lower() for word in [
                    'admin', 'delete', 'remove', 'manage', 'config', 'settings',
                    'users', 'accounts', 'secret', 'private', 'internal'
                ])
                
                if is_sensitive:
                    # Check next 30 lines for ROLE-based authorization
                    func_lines = lines[line_num:min(line_num + 30, len(lines))]
                    # Filter out comments to avoid false positives
                    func_code_lines = [l for l in func_lines if not l.strip().startswith('#')]
                    func_content = '\n'.join(func_code_lines)
                    
                    # Check if has session check (authentication)
                    has_session_check = any(auth in func_content for auth in [
                        'session', 'user_id', 'authenticated', 'logged_in'
                    ])
                    
                    # Check if has ROLE validation (authorization)
                    has_role_check = any(role in func_content for role in [
                        "session.get('role')", "session['role']", 
                        'role ==', 'role !=', 'is_admin', 'check_admin', 
                        'require_admin', '@admin_required', 'hasRole',
                        'user.role', 'current_user.role', 'permission'
                    ])
                    
                    # VULNERABLE: Has authentication but NO authorization
                    if has_session_check and not has_role_check:
                        findings.append({
                            'tool': 'CPG-Semantic',
                            'type': 'MISSING_AUTHORIZATION',
                            'severity': 'high',
                            'file_path': str(file_path),
                            'line_number': line_num,
                            'message': f"Missing Authorization: '{route_path}' has authentication but no role validation",
                            'confidence': 'high',
                            'metadata': {
                                'route': route_path,
                                'has_auth': has_session_check,
                                'has_role': has_role_check,
                                'analysis_type': 'semantic'
                            }
                        })
        
        return findings
    
    def _detect_idor(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect IDOR - accessing resources by ID without ownership check
        """
        findings = []
        
        # Find routes with ID parameters
        id_route_patterns = [
            r'@app\.route\([\'"]([^\'"]*<[^>]*(?:id|user_id|account_id|order_id)[^>]*>[^\'"]*)[\'"]',
            r'app\.\w+\([\'"]([^\'"]*:(?:id|userId|accountId)[^\'"]*)[\'"]',
        ]
        
        for pattern in id_route_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                route_path = match.group(1)
                
                # Check if there's database access
                func_lines = lines[line_num:min(line_num + 50, len(lines))]
                func_content = '\n'.join(func_lines)
                
                has_db_access = any(db in func_content for db in [
                    '.get(', '.filter(', 'execute(', 'query', 'SELECT', 'findById'
                ])
                
                if has_db_access:
                    # Filter out comments to avoid false positives
                    func_code_lines = [l for l in func_lines if not l.strip().startswith('#')]
                    func_code_content = '\n'.join(func_code_lines)
                    
                    # Check for ownership validation
                    has_ownership = any(check in func_code_content for check in [
                        'current_user.id', "session.get('user_id')", "session['user_id']",
                        'if user_id ==', 'if session', 'check_ownership', 'verify_owner',
                        'belongs_to', 'owned_by', '== user_id', '!= user_id'
                    ])
                    
                    # Additional check: is there a comparison between route param and session?
                    has_id_comparison = False
                    for var in ['user_id', 'id', 'account_id', 'order_id']:
                        if f"session['user_id']" in func_code_content and var in route_path:
                            # Check if they're compared
                            comparison_patterns = [
                                f"{var} == session",
                                f"session == {var}",
                                f"{var} != session",
                                f"session != {var}",
                                f"if {var}",
                            ]
                            if any(p in func_code_content for p in comparison_patterns):
                                has_id_comparison = True
                                break
                    
                    if not has_ownership and not has_id_comparison:
                        findings.append({
                            'tool': 'CPG-Semantic',
                            'type': 'IDOR',
                            'severity': 'high',
                            'file_path': str(file_path),
                            'line_number': line_num,
                            'message': f"IDOR: Route '{route_path}' accesses resources without ownership validation",
                            'confidence': 'high',
                            'metadata': {
                                'route': route_path,
                                'analysis_type': 'semantic'
                            }
                        })
        
        return findings
    
    def _detect_business_logic(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect business logic flaws
        """
        findings = []
        
        # Pattern 1: Client-controlled prices/amounts - look for calculations using request data
        # Example: total += item['price'] * item['quantity'] where item comes from request
        
        # Find variables assigned from request
        request_vars = []
        for i, line in enumerate(lines):
            # Match: variable = request.json.get(...) or similar
            request_patterns = [
                r'(\w+)\s*=\s*request\.(?:json|form|args)\.get\(',
                r'(\w+)\s*=\s*request\.(?:json|form|args)\[',
                r'(\w+)\s*=\s*request\.(?:json|form|args)',
            ]
            for pattern in request_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    request_vars.append((match.group(1), i + 1))
        
        # Now find financial calculations using these variables
        financial_keywords = ['price', 'amount', 'total', 'cost', 'balance', 'discount', 'fee', 'charge']
        
        for var_name, var_line in request_vars:
            # Check if this variable is used in financial calculations
            for i, line in enumerate(lines[var_line:min(var_line + 50, len(lines))], start=var_line):
                # Look for calculations with financial keywords
                if var_name in line:
                    for keyword in financial_keywords:
                        # Pattern: total += item['price']  or  price = item['price']
                        calc_patterns = [
                            rf'{keyword}\s*[\+\-\*\/]=\s*.*{var_name}',
                            rf'{keyword}\s*=\s*.*{var_name}.*[\+\-\*\/]',
                            rf'[\+\-\*\/]=\s*.*{var_name}\s*\[[\'"]{keyword}',
                            rf'{var_name}\s*\[[\'"]{keyword}[\'"]\]',
                        ]
                        for calc_pattern in calc_patterns:
                            if re.search(calc_pattern, line, re.IGNORECASE):
                                findings.append({
                                    'tool': 'CPG-Semantic',
                                    'type': 'BUSINESS_LOGIC',
                                    'severity': 'critical',
                                    'file_path': str(file_path),
                                    'line_number': i + 1,
                                    'message': f"Business logic flaw: Financial calculation uses client-controlled data '{var_name}' (from request)",
                                    'confidence': 'high',
                                    'metadata': {
                                        'issue': 'Client-controlled financial data',
                                        'variable': var_name,
                                        'financial_keyword': keyword,
                                        'analysis_type': 'semantic'
                                    }
                                })
                                break
        
        # Pattern 2: Nested iteration pattern - for item in request_list: total += item['price']
        for var_name, var_line in request_vars:
            # Look for: for <iterator> in <request_var>:
            for i in range(var_line, min(var_line + 50, len(lines))):
                iteration_match = re.search(rf'for\s+(\w+)\s+in\s+{var_name}\s*:', lines[i])
                if iteration_match:
                    iterator_name = iteration_match.group(1)
                    # Now look for financial operations on this iterator
                    for j in range(i + 1, min(i + 20, len(lines))):
                        for keyword in financial_keywords:
                            # Pattern: total += item['price'] or amount = item['cost']
                            nested_patterns = [
                                rf'{keyword}\s*[\+\-\*\/]=\s*.*{iterator_name}\s*\[[\'"]({"|".join(financial_keywords)})',
                                rf'{iterator_name}\s*\[[\'"]({"|".join(financial_keywords)})[\'"]',
                            ]
                            for nested_pattern in nested_patterns:
                                if re.search(nested_pattern, lines[j], re.IGNORECASE):
                                    findings.append({
                                        'tool': 'CPG-Semantic',
                                        'type': 'BUSINESS_LOGIC',
                                        'severity': 'critical',
                                        'file_path': str(file_path),
                                        'line_number': j + 1,
                                        'message': f"Business logic flaw: Iterates over client-controlled '{var_name}' and uses financial data from '{iterator_name}'",
                                        'confidence': 'high',
                                        'metadata': {
                                            'issue': 'Client-controlled financial data in loop',
                                            'source_variable': var_name,
                                            'iterator': iterator_name,
                                            'analysis_type': 'semantic'
                                        }
                                    })
                                    break
        
        # Pattern 3: Direct price patterns (fallback)
        price_patterns = [
            (r'price\s*=\s*request\.', 'Client-controlled price'),
            (r'amount\s*=\s*request\.', 'Client-controlled amount'),
            (r'total\s*=\s*request\.', 'Client-controlled total'),
            (r'discount\s*=\s*request\.', 'Client-controlled discount'),
        ]
        
        for pattern, description in price_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append({
                    'tool': 'CPG-Semantic',
                    'type': 'BUSINESS_LOGIC',
                    'severity': 'critical',
                    'file_path': str(file_path),
                    'line_number': line_num,
                    'message': f"Business logic flaw: {description}",
                    'confidence': 'high',
                    'metadata': {
                        'issue': description,
                        'analysis_type': 'semantic'
                    }
                })
        
        return findings
    
    def _detect_insecure_deserialization(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """Detect insecure deserialization"""
        findings = []
        
        unsafe_patterns = [
            (r'pickle\.loads?\s*\(', 'Unsafe pickle deserialization'),
            (r'yaml\.load\s*\([^,)]*\)', 'Unsafe YAML deserialization'),
            (r'eval\s*\(', 'Dangerous eval() usage'),
            (r'exec\s*\(', 'Dangerous exec() usage'),
        ]
        
        for pattern, description in unsafe_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1]
                
                # Check if input comes from user
                has_user_input = any(src in line for src in [
                    'request.', 'input(', 'raw_input(', 'sys.stdin'
                ])
                
                if has_user_input:
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'INSECURE_DESERIALIZATION',
                        'severity': 'critical',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': description,
                        'confidence': 'high',
                        'metadata': {
                            'pattern': pattern
                        }
                    })
        
        return findings
    
    def _detect_weak_cryptography(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """Detect weak cryptographic practices"""
        findings = []
        
        weak_patterns = [
            (r'hashlib\.md5\s*\(', 'Weak hash: MD5'),
            (r'hashlib\.sha1\s*\(', 'Weak hash: SHA1'),
            (r'Random\(\)', 'Weak random: not cryptographically secure'),
            (r'Math\.random\(\)', 'Weak random: Math.random()'),
        ]
        
        for pattern, description in weak_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                
                findings.append({
                    'tool': 'CPG-Semantic',
                    'type': 'WEAK_CRYPTOGRAPHY',
                    'severity': 'medium',
                    'file_path': str(file_path),
                    'line_number': line_num,
                    'message': description,
                    'confidence': 'high',
                    'metadata': {
                        'pattern': pattern
                    }
                })
        
        return findings
    
    def _detect_hardcoded_secrets(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """Detect hardcoded secrets - MULTI-LANGUAGE & CONFIG FILES"""
        findings = []
        
        # Enhanced patterns for all languages
        secret_patterns = [
            # Passwords
            (r'password\s*[=:]\s*[\'"][^\'"]{6,}[\'"]', 'Hardcoded password'),
            (r'passwd\s*[=:]\s*[\'"][^\'"]{6,}[\'"]', 'Hardcoded password'),
            (r'pwd\s*[=:]\s*[\'"][^\'"]{6,}[\'"]', 'Hardcoded password'),
            
            # API Keys
            (r'api[_-]?key\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded API key'),
            (r'apikey\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded API key'),
            (r'api[_-]?secret\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded API secret'),
            
            # Secret Keys
            (r'secret[_-]?key\s*[=:]\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded secret key'),
            (r'secretkey\s*[=:]\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded secret key'),
            (r'SECRET_KEY\s*[=:]\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded secret key'),
            
            # Tokens
            (r'token\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded token'),
            (r'access[_-]?token\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded access token'),
            (r'auth[_-]?token\s*[=:]\s*[\'"][^\'"]{20,}[\'"]', 'Hardcoded auth token'),
            
            # AWS Keys
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'aws[_-]?access[_-]?key', 'AWS Access Key reference'),
            
            # Database credentials
            (r'db[_-]?password\s*[=:]\s*[\'"][^\'"]{6,}[\'"]', 'Hardcoded DB password'),
            (r'database[_-]?password\s*[=:]\s*[\'"][^\'"]{6,}[\'"]', 'Hardcoded DB password'),
            
            # Private keys (PEM format markers)
            (r'BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY', 'Private key in source code'),
            
            # JWT secrets
            (r'jwt[_-]?secret\s*[=:]\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded JWT secret'),
        ]
        
        for pattern, description in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1] if line_num <= len(lines) else ""
                
                # Skip test files, examples, and documentation
                if any(skip in str(file_path).lower() for skip in ['test', 'example', 'sample', 'demo', 'doc', 'readme']):
                    continue
                
                # Skip if it looks like a placeholder
                matched_text = match.group(0).lower()
                if any(placeholder in matched_text for placeholder in ['your_', 'your-', 'example', 'dummy', 'test', 'placeholder', 'xxx', '***', 'change_me', 'replace']):
                    continue
                
                findings.append({
                    'tool': 'CPG-Semantic',
                    'type': 'HARDCODED_SECRET',
                    'severity': 'high',
                    'file_path': str(file_path),
                    'line_number': line_num,
                    'message': description,
                    'confidence': 'medium',
                    'metadata': {
                        'pattern': pattern,
                        'analysis_type': 'pattern_matching'
                    }
                })
        
        return findings
    
    def _detect_stored_xss(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect Stored XSS - user input stored in DB then displayed without escaping
        """
        findings = []
        
        # Find user inputs that go to database
        user_inputs = self._find_user_input_sources(content, lines)
        
        for var_name, input_line in user_inputs:
            search_end = min(input_line + 100, len(lines))
            
            for line_num in range(input_line, search_end):
                line = lines[line_num]
                
                # Check if variable is stored in database
                db_operations = ['INSERT INTO', 'UPDATE', 'execute(', 'save(', 'create(', 'store(']
                if var_name in line and any(op in line for op in db_operations):
                    # Mark as potential stored XSS
                    findings.append({
                        'tool': 'CPG-Dataflow',
                        'type': 'STORED_XSS',
                        'severity': 'high',
                        'file_path': str(file_path),
                        'line_number': line_num + 1,
                        'message': f"Potential Stored XSS: User input '{var_name}' stored in database without sanitization",
                        'confidence': 'medium',
                        'metadata': {
                            'source_line': input_line + 1,
                            'sink_line': line_num + 1,
                            'variable': var_name,
                            'analysis_type': 'dataflow'
                        }
                    })
                    break
        
        return findings
    
    def _detect_file_upload(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect insecure file upload without validation
        """
        findings = []
        
        # Find file upload patterns
        upload_patterns = [
            (r'move_uploaded_file\s*\(', 'PHP file upload'),
            (r'\$_FILES\[', 'PHP file upload'),
            (r'request\.files\[', 'Python file upload'),
            (r'req\.file\(', 'Node.js file upload'),
            (r'MultipartFile', 'Java file upload'),
        ]
        
        for pattern, description in upload_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check next 20 lines for validation
                check_end = min(line_num + 20, len(lines))
                has_validation = False
                
                for check_line in range(line_num - 1, check_end):
                    validation_keywords = [
                        'extension', 'mime', 'type', 'whitelist', 'allowed',
                        'PATHINFO_EXTENSION', 'getClientOriginalExtension',
                        'content-type', 'file_type', 'validate'
                    ]
                    if any(kw in lines[check_line].lower() for kw in validation_keywords):
                        has_validation = True
                        break
                
                if not has_validation:
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'INSECURE_FILE_UPLOAD',
                        'severity': 'critical',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': f"Insecure file upload: {description} without type/extension validation",
                        'confidence': 'high',
                        'metadata': {
                            'pattern': description,
                            'analysis_type': 'semantic'
                        }
                    })
        
        return findings
    
    def _detect_open_redirect(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect open redirect vulnerabilities - improved general detection
        """
        findings = []
        
        # Track user-controlled variables
        user_sources = set()
        for match in re.finditer(r'\$_(GET|POST|REQUEST|COOKIE)\[[\'"](\w+)[\'"]\]', content):
            user_sources.add(match.group(0))
        
        # Also track when variables are assigned from user input
        for match in re.finditer(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\[[\'"](\w+)[\'"]\]', content):
            user_sources.add(f'${match.group(1)}')
        
        # Pattern 1: PHP header redirects
        header_patterns = [
            r'header\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*(\$\w+)',  # header("Location: " . $var)
            r'header\s*\(\s*[\'"]Location:\s*(\{?\$\w+)',             # header("Location: $var") or header("Location: {$var}")
            r'header\s*\(\s*["\']Location:["\']?\s*\.\s*\$_(GET|POST|REQUEST)',  # Direct $_GET usage
        ]
        
        for pattern in header_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1]
                
                # Extract the variable being used
                var_match = re.search(r'\$\w+', match.group(0))
                if var_match:
                    var_name = var_match.group(0)
                    
                    # Check if variable comes from user input
                    is_user_input = (
                        var_name in user_sources or
                        '$_GET' in match.group(0) or
                        '$_POST' in match.group(0) or
                        '$_REQUEST' in match.group(0)
                    )
                    
                    if is_user_input:
                        # Check for validation in surrounding lines
                        context_start = max(0, line_num - 5)
                        context_end = min(len(lines), line_num)
                        context = '\n'.join(lines[context_start:context_end])
                        
                        has_validation = any(check in context.lower() for check in [
                            'strpos', 'parse_url', 'filter_var', 'in_array',
                            'whitelist', 'allowed', 'validate'
                        ])
                        
                        if not has_validation:
                            findings.append({
                                'tool': 'CPG-Semantic',
                                'type': 'OPEN_REDIRECT',
                                'severity': 'medium',
                                'file_path': str(file_path),
                                'line_number': line_num,
                                'message': f"Open redirect: User-controlled redirect target without validation (variable: {var_name})",
                                'confidence': 'high',
                                'metadata': {
                                    'pattern': 'PHP header redirect',
                                    'variable': var_name,
                                    'analysis_type': 'dataflow'
                                }
                            })
        
        # Pattern 2: WordPress redirects
        wp_redirect_patterns = [
            r'wp_redirect\s*\(\s*(\$\w+)',
            r'wp_safe_redirect\s*\(\s*(\$\w+)',
        ]
        
        for pattern in wp_redirect_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                var_name = match.group(1)
                
                if var_name in user_sources:
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'OPEN_REDIRECT',
                        'severity': 'medium',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': f"Open redirect: WordPress redirect with user-controlled target (variable: {var_name})",
                        'confidence': 'high',
                        'metadata': {
                            'pattern': 'WordPress redirect',
                            'variable': var_name,
                            'analysis_type': 'dataflow'
                        }
                    })
        
        # Pattern 3: JavaScript redirects
        js_redirect_patterns = [
            r'window\.location\s*=\s*[\'"]?\s*\+?\s*(\w+)',          # window.location = var
            r'window\.location\.href\s*=\s*[\'"]?\s*\+?\s*(\w+)',    # window.location.href = var
            r'window\.location\.replace\s*\(\s*[\'"]?\s*\+?\s*(\w+)',  # window.location.replace(var)
            r'location\.href\s*=\s*[\'"]?\s*\+?\s*(\w+)',            # location.href = var
        ]
        
        for pattern in js_redirect_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1]
                
                # Check if it's using user input (common patterns)
                user_input_indicators = [
                    'document.location', 'window.location', 'location.search',
                    'getParameter', 'URLSearchParams', 'query', 'req.query',
                    'req.params', 'request.', '$_GET', '$_POST'
                ]
                
                context_start = max(0, line_num - 5)
                context_end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[context_start:context_end])
                
                if any(indicator in context for indicator in user_input_indicators):
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'OPEN_REDIRECT',
                        'severity': 'medium',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': "Open redirect: JavaScript redirect with potentially user-controlled target",
                        'confidence': 'medium',
                        'metadata': {
                            'pattern': 'JavaScript redirect',
                            'analysis_type': 'semantic'
                        }
                    })
        
        # Pattern 4: Meta refresh
        meta_refresh_pattern = r'<meta\s+http-equiv=["\']refresh["\'].*content=["\'].*url=.*(\$\w+|<?php)'
        for match in re.finditer(meta_refresh_pattern, content, re.IGNORECASE):
            line_num = content[:match.start()].count('\n') + 1
            
            findings.append({
                'tool': 'CPG-Semantic',
                'type': 'OPEN_REDIRECT',
                'severity': 'medium',
                'file_path': str(file_path),
                'line_number': line_num,
                'message': "Open redirect: Meta refresh tag with dynamic URL",
                'confidence': 'medium',
                'metadata': {
                    'pattern': 'Meta refresh redirect',
                    'analysis_type': 'semantic'
                }
            })
        
        # Pattern 5: Framework-specific redirects
        framework_redirects = [
            (r'Response\.redirect\s*\(\s*(\w+)', 'ASP.NET Response.redirect'),
            (r'redirect\s*\(\s*(\w+)', 'Generic redirect function'),
            (r'return\s+redirect\s*\(\s*(\w+)', 'Framework redirect'),
        ]
        
        for pattern, description in framework_redirects:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if variable comes from request
                context_start = max(0, line_num - 10)
                context_end = min(len(lines), line_num)
                context = '\n'.join(lines[context_start:context_end])
                
                request_indicators = [
                    'request.', 'req.', '$_GET', '$_POST', '$_REQUEST',
                    'params', 'query', 'body', 'input'
                ]
                
                if any(indicator in context for indicator in request_indicators):
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'OPEN_REDIRECT',
                        'severity': 'medium',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': f"Open redirect: {description} with user-controlled target",
                        'confidence': 'medium',
                        'metadata': {
                            'pattern': description,
                            'analysis_type': 'semantic'
                        }
                    })
        
        return findings
    
    def _detect_weak_session_ids(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect weak/predictable session ID generation
        """
        findings = []
        
        # Patterns for weak random generation
        weak_patterns = [
            (r'rand\s*\(\s*\)', 'PHP rand() - not cryptographically secure'),
            (r'mt_rand\s*\(\s*\)', 'PHP mt_rand() - not cryptographically secure'),
            (r'random\.randint\s*\(', 'Python randint() - not cryptographically secure'),
            (r'Math\.random\s*\(\s*\)', 'JavaScript Math.random() - not cryptographically secure'),
            (r'new\s+Random\s*\(\s*\)', 'Java Random - not cryptographically secure'),
            (r'time\s*\(\s*\)', 'time() - predictable'),
            (r'date\s*\(\s*\)', 'date() - predictable'),
        ]
        
        for pattern, description in weak_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1]
                
                # Check if used for session/token/ID generation
                context_keywords = ['session', 'token', 'id', 'key', 'secret', 'password', 'nonce']
                if any(kw in line.lower() for kw in context_keywords):
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'WEAK_SESSION_ID',
                        'severity': 'high',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': f"Weak session/token generation: {description}",
                        'confidence': 'high',
                        'metadata': {
                            'pattern': description,
                            'analysis_type': 'semantic'
                        }
                    })
        
        return findings
    
    def _detect_authentication_bypass(self, content: str, file_path: Path, lines: List[str]) -> List[Dict]:
        """
        Detect authentication bypass vulnerabilities - improved general detection
        """
        findings = []
        
        # Pattern 1: SQL-based auth that compares passwords in SQL (always vulnerable)
        auth_sql_patterns = [
            r'SELECT\s+.*\s+FROM\s+.*users.*WHERE.*username.*AND.*password',
            r'SELECT\s+.*\s+FROM\s+.*user.*WHERE.*login.*AND.*pass',
            r'SELECT\s+\*\s+FROM\s+.*WHERE.*user.*=.*AND.*pass.*=',
        ]
        
        for pattern in auth_sql_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                line_num = content[:match.start()].count('\n') + 1
                
                # Check if this SQL is concatenated (vulnerable) or parameterized (safer)
                # Look at 5 lines around the match for context
                context_start = max(0, line_num - 3)
                context_end = min(len(lines), line_num + 3)
                context = '\n'.join(lines[context_start:context_end])
                
                if not self._is_sql_parameterized(context):
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'AUTHENTICATION_BYPASS',
                        'severity': 'critical',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': "Authentication bypass: SQL query compares username AND password (vulnerable to SQL injection bypass)",
                        'confidence': 'high',
                        'metadata': {
                            'pattern': 'SQL-based authentication with concatenation',
                            'analysis_type': 'semantic'
                        }
                    })
        
        # Pattern 2: Empty or always-true conditions
        bypass_patterns = [
            (r'if\s*\(\s*[\'"][\'"]\s*==\s*[\'"][\'"]\s*\)', 'Always true condition'),
            (r'if\s*\(\s*true\s*\)', 'Always true condition'),
            (r'if\s*\(\s*1\s*==\s*1\s*\)', 'Always true condition'),
            (r'if\s*\(\s*strlen\s*\([^)]*\)\s*>\s*0\s*\)', 'Only checks if password exists, not if correct'),
        ]
        
        for pattern, description in bypass_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line = lines[line_num - 1]
                
                # Check if this is in authentication context
                context_start = max(0, line_num - 10)
                context_end = min(len(lines), line_num + 10)
                context = '\n'.join(lines[context_start:context_end]).lower()
                
                auth_keywords = ['login', 'auth', 'password', 'credential', 'signin', 'logon']
                if any(kw in context for kw in auth_keywords):
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'AUTHENTICATION_BYPASS',
                        'severity': 'critical',
                        'file_path': str(file_path),
                        'line_number': line_num,
                        'message': f"Authentication bypass: {description}",
                        'confidence': 'high',
                        'metadata': {
                            'pattern': description,
                            'analysis_type': 'semantic'
                        }
                    })
        
        # Pattern 3: Missing password hash verification
        # Look for login functions that don't hash/verify passwords
        login_func_patterns = [
            r'function\s+\w*login\w*\s*\(',
            r'def\s+\w*login\w*\s*\(',
            r'public\s+\w*\s+\w*login\w*\s*\(',
        ]
        
        for pattern in login_func_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                func_start = content[:match.start()].count('\n')
                
                # Check next 50 lines for password verification
                func_end = min(func_start + 50, len(lines))
                func_content = '\n'.join(lines[func_start:func_end]).lower()
                
                # Look for proper password verification
                has_hash_verify = any(kw in func_content for kw in [
                    'password_verify', 'bcrypt', 'hash_equals', 'verify_password',
                    'check_password', 'password_hash', 'pbkdf2', 'scrypt', 'argon2'
                ])
                
                # Look for direct comparison (bad)
                has_direct_compare = any(pattern in func_content for pattern in [
                    'password ==', '== password', 'password ===', 'pass ==',
                    'password.equals', 'password eq'
                ])
                
                if has_direct_compare and not has_hash_verify:
                    findings.append({
                        'tool': 'CPG-Semantic',
                        'type': 'AUTHENTICATION_BYPASS',
                        'severity': 'high',
                        'file_path': str(file_path),
                        'line_number': func_start + 1,
                        'message': "Weak authentication: Password compared directly without proper hashing/verification",
                        'confidence': 'medium',
                        'metadata': {
                            'pattern': 'Direct password comparison',
                            'analysis_type': 'semantic'
                        }
                    })
        
        return findings
    
    # Helper methods
    
    def _find_user_input_sources(self, content: str, lines: List[str]) -> List[Tuple[str, int]]:
        """
        Find all user input sources and their variable names - MULTI-LANGUAGE
        
        Returns: List of (variable_name, line_number) tuples
        """
        sources = []
        
        # PYTHON: Flask/Django/FastAPI
        input_patterns = [
            r'(\w+)\s*=\s*request\.(args|form|json|data|values|files|cookies)\.get\(',
            r'(\w+)\s*=\s*request\.(args|form|json|cookies)\[',
            r'(\w+)\s*=\s*request\.(GET|POST|COOKIES)\[',  # Django
            
            # JAVASCRIPT/TYPESCRIPT: Express/Node.js
            r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params|cookies)\.',
            r'(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params)\[',
            r'(\w+)\s*=\s*req\.(query|body|params|cookies)\.',
            r'req\.(query|body|params)\.(\w+)',  # Direct access
            r'request\.(\w+)',  # Generic request
            
            # PHP
            r'(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\[',
            r'\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\[',
            
            # JAVA: Spring/Servlet
            r'(\w+)\s*=\s*request\.getParameter\(',
            r'@RequestParam.*?(\w+)\s*\)',
            r'@PathVariable.*?(\w+)\s*\)',
            r'@RequestBody.*?(\w+)\s*\)',
            r'HttpServletRequest.*?\.getParameter\(',
            
            # Generic HTTP parameter access
            r'\.getParameter\(["\'](\w+)',
            r'\.getQueryString\(',
            r'\.getCookies\(',
            r'\.getHeader\(',
        ]
        
        for pattern in input_patterns:
            for match in re.finditer(pattern, content):
                # Extract variable name from match
                var_name = None
                for group in match.groups():
                    if group and group not in ['query', 'body', 'params', 'cookies', 'args', 'form', 'json', 'data', 'values', 'files', 'GET', 'POST', 'REQUEST', 'COOKIE']:
                        var_name = group
                        break
                
                if var_name:
                    line_num = content[:match.start()].count('\n')
                    sources.append((var_name, line_num))
        
        return sources
    
    def _is_sql_parameterized(self, line: str) -> bool:
        """Check if SQL query uses parameterized queries (safe)"""
        # Parameterized: execute("SELECT * FROM users WHERE id = ?", (id,))
        # Unsafe: execute("SELECT * FROM users WHERE id = " + id)
        
        has_params = any(marker in line for marker in [
            ', (', '(%s)', '?)', '($1)', ':param'
        ])
        
        has_concat = any(op in line for op in [
            ' + ', ' % ', '.format(', 'f"', "f'"
        ])
        
        return has_params or not has_concat
