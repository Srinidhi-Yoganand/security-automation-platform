"""
OWASP ZAP JSON Parser

Parses ZAP scan output in JSON format and converts to normalized Finding objects.
"""

import json
from typing import List
from app.core.correlator import Finding, Severity


class ZapParser:
    """Parser for OWASP ZAP JSON output"""
    
    @staticmethod
    def parse(file_path: str) -> List[Finding]:
        """
        Parse ZAP JSON file and return list of normalized findings.
        
        Args:
            file_path: Path to ZAP JSON file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                zap_data = json.load(f)
            
            # ZAP JSON can have different structures, handle both formats
            if 'site' in zap_data:
                # Full report format
                for site in zap_data['site']:
                    for alert in site.get('alerts', []):
                        findings.extend(ZapParser._parse_alert(alert))
            elif 'alerts' in zap_data:
                # Simple format
                for alert in zap_data['alerts']:
                    findings.extend(ZapParser._parse_alert(alert))
        
        except Exception as e:
            print(f"Error parsing ZAP JSON: {e}")
        
        return findings
    
    @staticmethod
    def _parse_alert(alert: dict) -> List[Finding]:
        """Parse individual ZAP alert"""
        findings = []
        
        alert_name = alert.get('name', 'Unknown')
        risk = alert.get('risk', 'Medium')
        confidence = alert.get('confidence', 'Medium')
        cwe_id = str(alert.get('cweid', ''))
        description = alert.get('desc', '')
        
        # Map ZAP risk to Severity
        risk_map = {
            'Informational': Severity.INFO,
            'Low': Severity.LOW,
            'Medium': Severity.MEDIUM,
            'High': Severity.HIGH
        }
        severity = risk_map.get(risk, Severity.MEDIUM)
        
        # Map ZAP confidence to score
        confidence_map = {
            'Low': 0.3,
            'Medium': 0.6,
            'High': 0.9
        }
        confidence_score = confidence_map.get(confidence, 0.5)
        
        # Process instances
        for instance in alert.get('instances', []):
            uri = instance.get('uri', '')
            method = instance.get('method', 'GET')
            param = instance.get('param', '')
            
            # Try to extract file path from URI if it's pointing to code
            # For now, we use the URI as the file path (will be enhanced in Phase 2)
            file_path = uri
            
            finding = Finding(
                id=f"zap-{hash(alert_name + uri + param)}",
                source="zap",
                type=alert_name,
                severity=severity,
                file_path=file_path,
                line_number=0,  # DAST doesn't have line numbers initially
                message=f"{description} ({method} {uri}{' - param: ' + param if param else ''})",
                cwe_id=cwe_id,
                confidence=confidence_score,
                raw_data=instance
            )
            findings.append(finding)
        
        return findings
