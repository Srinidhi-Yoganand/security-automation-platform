"""
CVE Database Integration
Provides CVE references and remediation guidance for known vulnerability patterns
"""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class CVEReference:
    """CVE reference information"""
    cve_id: str
    description: str
    severity: str  # critical, high, medium, low
    cvss_score: Optional[float]
    remediation: str
    references: List[str]
    cwe_id: Optional[str] = None


class CVEDatabase:
    """
    Local CVE database for common vulnerability patterns
    Maps vulnerability types to relevant CVE examples and remediation guidance
    """
    
    def __init__(self):
        """Initialize CVE database with common patterns"""
        self.cve_data = self._initialize_cve_data()
    
    def _initialize_cve_data(self) -> Dict[str, List[CVEReference]]:
        """Initialize database with common vulnerability CVEs"""
        return {
            'idor': [
                CVEReference(
                    cve_id='CVE-2019-9978',
                    description='WordPress Social Warfare plugin IDOR allowing unauthorized access to user data',
                    severity='high',
                    cvss_score=8.1,
                    cwe_id='CWE-639',
                    remediation='Implement proper authorization checks before accessing resources. Verify user ownership or permissions.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/639.html',
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References'
                    ]
                ),
                CVEReference(
                    cve_id='CVE-2020-5844',
                    description='IBM Security Guardium IDOR vulnerability allowing access to arbitrary user records',
                    severity='high',
                    cvss_score=7.5,
                    cwe_id='CWE-639',
                    remediation='Use indirect reference maps or validate user permissions before accessing resources.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/639.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
                    ]
                )
            ],
            'missing_authorization': [
                CVEReference(
                    cve_id='CVE-2021-3156',
                    description='Sudo Baron Samedit - Missing authorization in privileged operations',
                    severity='critical',
                    cvss_score=7.8,
                    cwe_id='CWE-862',
                    remediation='Implement proper authorization checks using framework security features (@PreAuthorize, @Secured).',
                    references=[
                        'https://cwe.mitre.org/data/definitions/862.html',
                        'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control'
                    ]
                ),
                CVEReference(
                    cve_id='CVE-2020-5902',
                    description='F5 BIG-IP TMUI missing authorization allowing remote code execution',
                    severity='critical',
                    cvss_score=9.8,
                    cwe_id='CWE-306',
                    remediation='Add authentication and authorization checks to all sensitive endpoints.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/306.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
                    ]
                )
            ],
            'missing_authentication': [
                CVEReference(
                    cve_id='CVE-2021-44228',
                    description='Log4Shell - Missing authentication in JNDI lookups',
                    severity='critical',
                    cvss_score=10.0,
                    cwe_id='CWE-502',
                    remediation='Require authentication for all external resource access. Disable untrusted lookups.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/502.html',
                        'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication'
                    ]
                )
            ],
            'sql_injection': [
                CVEReference(
                    cve_id='CVE-2020-35489',
                    description='WordPress WP-Matomo SQL injection via unsanitized parameters',
                    severity='critical',
                    cvss_score=9.8,
                    cwe_id='CWE-89',
                    remediation='Use parameterized queries (PreparedStatement) for all database operations. Never concatenate user input into SQL.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/89.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                    ]
                ),
                CVEReference(
                    cve_id='CVE-2021-42013',
                    description='Apache HTTP Server path traversal and SQL injection',
                    severity='critical',
                    cvss_score=9.8,
                    cwe_id='CWE-89',
                    remediation='Always use parameterized queries. Validate and sanitize all inputs. Use ORM frameworks correctly.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/89.html',
                        'https://owasp.org/www-community/attacks/SQL_Injection'
                    ]
                )
            ],
            'path_traversal': [
                CVEReference(
                    cve_id='CVE-2021-41773',
                    description='Apache HTTP Server path traversal allowing arbitrary file read',
                    severity='high',
                    cvss_score=7.5,
                    cwe_id='CWE-22',
                    remediation='Validate file paths against whitelist. Use Path.normalize() and check for directory traversal patterns.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/22.html',
                        'https://owasp.org/www-community/attacks/Path_Traversal'
                    ]
                ),
                CVEReference(
                    cve_id='CVE-2022-24112',
                    description='Apache APISIX path traversal in request URI',
                    severity='high',
                    cvss_score=8.1,
                    cwe_id='CWE-22',
                    remediation='Sanitize file paths, validate against base directory, use secure file APIs.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/22.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
                    ]
                )
            ],
            'xss': [
                CVEReference(
                    cve_id='CVE-2021-43798',
                    description='Grafana XSS vulnerability allowing arbitrary JavaScript execution',
                    severity='high',
                    cvss_score=7.3,
                    cwe_id='CWE-79',
                    remediation='Encode all user input in HTML context. Use Content-Security-Policy headers. Sanitize untrusted data.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/79.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                    ]
                )
            ],
            'csrf': [
                CVEReference(
                    cve_id='CVE-2020-36179',
                    description='Jackson-databind CSRF via gadget chains',
                    severity='high',
                    cvss_score=8.1,
                    cwe_id='CWE-352',
                    remediation='Use CSRF tokens for all state-changing operations. Enable Spring Security CSRF protection.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/352.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
                    ]
                )
            ],
            'deserialization': [
                CVEReference(
                    cve_id='CVE-2020-9484',
                    description='Apache Tomcat insecure deserialization leading to RCE',
                    severity='high',
                    cvss_score=7.0,
                    cwe_id='CWE-502',
                    remediation='Avoid deserializing untrusted data. Use allow-lists for classes. Consider JSON instead of serialization.',
                    references=[
                        'https://cwe.mitre.org/data/definitions/502.html',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
                    ]
                )
            ]
        }
    
    def lookup_cve(self, vulnerability_type: str) -> List[CVEReference]:
        """
        Look up CVE references for vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability (idor, sql_injection, etc.)
            
        Returns:
            List of relevant CVE references
        """
        vuln_type_lower = vulnerability_type.lower().replace(' ', '_')
        
        # Try exact match first
        if vuln_type_lower in self.cve_data:
            return self.cve_data[vuln_type_lower]
        
        # Try partial matches
        for key in self.cve_data.keys():
            if key in vuln_type_lower or vuln_type_lower in key:
                return self.cve_data[key]
        
        return []
    
    def get_remediation_guide(self, vulnerability_type: str) -> str:
        """
        Get remediation guidance for vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            Remediation guidance string
        """
        cve_refs = self.lookup_cve(vulnerability_type)
        
        if not cve_refs:
            return "Follow OWASP guidelines for this vulnerability type."
        
        # Combine remediation guidance from all CVEs
        guidance = []
        for cve in cve_refs:
            guidance.append(f"• {cve.remediation}")
        
        return "\n".join(guidance)
    
    def get_references(self, vulnerability_type: str) -> List[str]:
        """
        Get external references for vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            List of reference URLs
        """
        cve_refs = self.lookup_cve(vulnerability_type)
        
        all_refs = []
        for cve in cve_refs:
            all_refs.extend(cve.references)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_refs = []
        for ref in all_refs:
            if ref not in seen:
                seen.add(ref)
                unique_refs.append(ref)
        
        return unique_refs
    
    def enrich_patch_with_cve(
        self,
        patch_data: Dict[str, Any],
        vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Enrich patch data with CVE references and remediation
        
        Args:
            patch_data: Original patch data
            vulnerability_type: Type of vulnerability
            
        Returns:
            Enriched patch data with CVE info
        """
        cve_refs = self.lookup_cve(vulnerability_type)
        
        if cve_refs:
            patch_data['cve_references'] = [
                {
                    'id': cve.cve_id,
                    'severity': cve.severity,
                    'cvss': cve.cvss_score,
                    'cwe': cve.cwe_id
                }
                for cve in cve_refs
            ]
            
            # Add detailed remediation
            remediation_details = []
            for cve in cve_refs:
                remediation_details.append(f"{cve.cve_id}: {cve.remediation}")
            
            patch_data['detailed_remediation'] = "\n\n".join(remediation_details)
            
            # Add references
            patch_data['security_references'] = self.get_references(vulnerability_type)
        
        return patch_data
    
    def get_severity_score(self, vulnerability_type: str) -> Optional[float]:
        """
        Get average CVSS score for vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            Average CVSS score or None
        """
        cve_refs = self.lookup_cve(vulnerability_type)
        
        if not cve_refs:
            return None
        
        scores = [cve.cvss_score for cve in cve_refs if cve.cvss_score is not None]
        
        if not scores:
            return None
        
        return sum(scores) / len(scores)


# Singleton instance
_cve_db_instance = None


def get_cve_database() -> CVEDatabase:
    """Get singleton CVE database instance"""
    global _cve_db_instance
    if _cve_db_instance is None:
        _cve_db_instance = CVEDatabase()
    return _cve_db_instance
