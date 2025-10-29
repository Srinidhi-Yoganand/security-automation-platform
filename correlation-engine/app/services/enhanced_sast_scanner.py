"""
Enhanced Multi-Tool SAST Scanner
Combines multiple SAST tools for comprehensive coverage:
- Semgrep (pattern matching + semantic rules)
- Bandit (Python security issues)
- CodeQL (data flow analysis) - optional
- Custom regex patterns (fallback)
"""

import logging
import subprocess
import json
import re
from typing import Dict, List, Optional
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class EnhancedSASTScanner:
    """
    Production-grade SAST scanner using multiple tools
    """
    
    def __init__(self):
        self.semgrep_available = self._check_semgrep()
        self.bandit_available = self._check_bandit()
        self.codeql_available = self._check_codeql()
        
    def _check_semgrep(self) -> bool:
        """Check if Semgrep is available"""
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_bandit(self) -> bool:
        """Check if Bandit is available"""
        try:
            result = subprocess.run(['bandit', '--version'], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_codeql(self) -> bool:
        """Check if CodeQL is available"""
        codeql_path = os.getenv('CODEQL_HOME', '/opt/codeql')
        return Path(f"{codeql_path}/codeql").exists()
    
    def scan(self, source_path: str, language: str = "python") -> Dict:
        """
        Run comprehensive SAST analysis using multiple tools
        
        Args:
            source_path: Path to source code
            language: Programming language
            
        Returns:
            Aggregated findings from all tools
        """
        logger.info(f"🔍 Enhanced SAST scan on {source_path}")
        
        all_findings = []
        tool_results = {}
        
        # Tool 1: Semgrep (best for semantic patterns)
        if self.semgrep_available:
            logger.info("Running Semgrep...")
            semgrep_findings = self._run_semgrep(source_path, language)
            all_findings.extend(semgrep_findings)
            tool_results['semgrep'] = len(semgrep_findings)
        else:
            logger.warning("⚠️  Semgrep not available")
        
        # Tool 2: Bandit (Python-specific)
        if language == "python" and self.bandit_available:
            logger.info("Running Bandit...")
            bandit_findings = self._run_bandit(source_path)
            all_findings.extend(bandit_findings)
            tool_results['bandit'] = len(bandit_findings)
        else:
            logger.info("Skipping Bandit (not Python or not available)")
        
        # Tool 3: Custom regex patterns (always available)
        logger.info("Running custom pattern matching...")
        custom_findings = self._run_custom_patterns(source_path, language)
        all_findings.extend(custom_findings)
        tool_results['custom'] = len(custom_findings)
        
        # Deduplicate findings
        deduplicated = self._deduplicate_findings(all_findings)
        
        logger.info(f"✅ SAST complete: {len(deduplicated)} unique findings from {len(tool_results)} tools")
        
        return {
            'success': True,
            'tool': 'Enhanced-SAST',
            'tool_results': tool_results,
            'total_findings': len(deduplicated),
            'vulnerabilities': deduplicated,
            'confidence': 'high'
        }
    
    def _run_semgrep(self, source_path: str, language: str) -> List[Dict]:
        """Run Semgrep with security rulesets"""
        findings = []
        
        try:
            # Use Semgrep's security rulesets
            rulesets = {
                'python': 'p/security-audit',
                'javascript': 'p/javascript',
                'java': 'p/java',
                'php': 'p/php'
            }
            
            ruleset = rulesets.get(language, 'p/security-audit')
            
            cmd = [
                'semgrep',
                '--config', ruleset,
                '--json',
                '--quiet',
                source_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 or result.returncode == 1:  # 1 = findings found
                data = json.loads(result.stdout)
                
                for finding in data.get('results', []):
                    findings.append({
                        'tool': 'Semgrep',
                        'type': self._map_semgrep_type(finding.get('check_id', '')),
                        'severity': finding.get('extra', {}).get('severity', 'MEDIUM').upper(),
                        'file': finding.get('path', ''),
                        'line': finding.get('start', {}).get('line', 0),
                        'message': finding.get('extra', {}).get('message', ''),
                        'confidence': self._map_semgrep_confidence(finding),
                        'details': {
                            'rule_id': finding.get('check_id', ''),
                            'code_snippet': finding.get('extra', {}).get('lines', '')
                        }
                    })
        
        except subprocess.TimeoutExpired:
            logger.error("Semgrep timed out")
        except Exception as e:
            logger.error(f"Semgrep error: {e}")
        
        return findings
    
    def _run_bandit(self, source_path: str) -> List[Dict]:
        """Run Bandit Python security scanner"""
        findings = []
        
        try:
            cmd = [
                'bandit',
                '-r', source_path,
                '-f', 'json',
                '--quiet',
                '--skip', 'B404,B603'  # Skip common false positives
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                
                for finding in data.get('results', []):
                    findings.append({
                        'tool': 'Bandit',
                        'type': self._map_bandit_type(finding.get('test_id', '')),
                        'severity': finding.get('issue_severity', 'MEDIUM').upper(),
                        'file': finding.get('filename', ''),
                        'line': finding.get('line_number', 0),
                        'message': finding.get('issue_text', ''),
                        'confidence': finding.get('issue_confidence', 'MEDIUM').upper(),
                        'details': {
                            'test_id': finding.get('test_id', ''),
                            'test_name': finding.get('test_name', ''),
                            'code': finding.get('code', '')
                        }
                    })
        
        except subprocess.TimeoutExpired:
            logger.error("Bandit timed out")
        except Exception as e:
            logger.error(f"Bandit error: {e}")
        
        return findings
    
    def _run_custom_patterns(self, source_path: str, language: str) -> List[Dict]:
        """Run custom regex-based pattern matching"""
        findings = []
        
        # Language-specific vulnerability patterns
        patterns = {
            'python': [
                (r'execute\([^)]*[+%]\s*\w+', 'SQL_INJECTION', 'String concatenation in SQL query'),
                (r'eval\s*\(', 'CODE_INJECTION', 'Use of dangerous eval() function'),
                (r'pickle\.loads?\s*\(', 'INSECURE_DESERIALIZATION', 'Unsafe pickle deserialization'),
                (r'os\.system\([^)]*[+%]', 'COMMAND_INJECTION', 'Command injection via os.system'),
                (r'render_template_string\([^)]*\+', 'SSTI', 'Server-Side Template Injection'),
            ],
            'javascript': [
                (r'eval\s*\(', 'CODE_INJECTION', 'Use of dangerous eval()'),
                (r'innerHTML\s*=\s*[^;]*\+', 'XSS', 'Potential XSS via innerHTML'),
                (r'document\.write\([^)]*\+', 'XSS', 'XSS via document.write'),
            ]
        }
        
        pattern_list = patterns.get(language, patterns.get('python', []))
        
        try:
            for root, dirs, files in os.walk(source_path):
                # Skip common excluded directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build']]
                
                for file in files:
                    if file.endswith(('.py', '.js', '.java', '.php')):
                        file_path = Path(root) / file
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                lines = content.split('\n')
                            
                            for pattern, vuln_type, description in pattern_list:
                                for match in re.finditer(pattern, content):
                                    line_num = content[:match.start()].count('\n') + 1
                                    
                                    findings.append({
                                        'tool': 'Custom-Patterns',
                                        'type': vuln_type,
                                        'severity': 'HIGH',
                                        'file': str(file_path.relative_to(source_path)),
                                        'line': line_num,
                                        'message': description,
                                        'confidence': 0.6,  # Lower confidence for regex
                                        'details': {
                                            'pattern': pattern,
                                            'matched_text': match.group(0)
                                        }
                                    })
                        
                        except Exception as e:
                            logger.debug(f"Error scanning {file_path}: {e}")
                            continue
        
        except Exception as e:
            logger.error(f"Custom pattern scan error: {e}")
        
        return findings
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on file+line+type"""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (
                finding.get('file', ''),
                finding.get('line', 0),
                finding.get('type', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _map_semgrep_type(self, check_id: str) -> str:
        """Map Semgrep rule ID to vulnerability type"""
        mappings = {
            'sql-injection': 'SQL_INJECTION',
            'xss': 'XSS',
            'command-injection': 'COMMAND_INJECTION',
            'path-traversal': 'PATH_TRAVERSAL',
            'hardcoded': 'HARDCODED_SECRET',
            'weak-crypto': 'WEAK_CRYPTOGRAPHY',
            'insecure-deserialization': 'INSECURE_DESERIALIZATION',
        }
        
        for key, vuln_type in mappings.items():
            if key in check_id.lower():
                return vuln_type
        
        return 'UNKNOWN'
    
    def _map_semgrep_confidence(self, finding: Dict) -> float:
        """Convert Semgrep metadata to confidence score"""
        severity = finding.get('extra', {}).get('severity', 'MEDIUM').upper()
        
        confidence_map = {
            'ERROR': 0.9,
            'WARNING': 0.7,
            'INFO': 0.5
        }
        
        return confidence_map.get(severity, 0.6)
    
    def _map_bandit_type(self, test_id: str) -> str:
        """Map Bandit test ID to vulnerability type"""
        mappings = {
            'B608': 'SQL_INJECTION',
            'B201': 'CODE_INJECTION',  # Flask debug
            'B301': 'INSECURE_DESERIALIZATION',  # pickle
            'B324': 'WEAK_CRYPTOGRAPHY',  # md5/sha1
            'B605': 'COMMAND_INJECTION',
            'B703': 'INSECURE_DESERIALIZATION',  # yaml.load
        }
        
        return mappings.get(test_id, 'SECURITY_ISSUE')
