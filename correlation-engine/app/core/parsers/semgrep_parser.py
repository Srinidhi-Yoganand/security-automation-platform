"""
Semgrep SARIF Parser

Parses Semgrep output in SARIF format and converts to normalized Finding objects.
"""

import json
from pathlib import Path
from typing import List
from app.core.correlator import Finding, Severity


class SemgrepParser:
    """Parser for Semgrep SARIF output"""
    
    @staticmethod
    def parse(file_path: str) -> List[Finding]:
        """
        Parse Semgrep SARIF file and return list of normalized findings.
        
        Args:
            file_path: Path to SARIF file
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                sarif_data = json.load(f)
            
            # Extract runs from SARIF
            for run in sarif_data.get('runs', []):
                tool_name = run.get('tool', {}).get('driver', {}).get('name', 'semgrep')
                
                # Process results
                for result in run.get('results', []):
                    finding = SemgrepParser._parse_result(result, tool_name)
                    if finding:
                        findings.append(finding)
        
        except Exception as e:
            print(f"Error parsing Semgrep SARIF: {e}")
        
        return findings
    
    @staticmethod
    def _parse_result(result: dict, tool_name: str) -> Finding:
        """Parse individual SARIF result"""
        rule_id = result.get('ruleId', 'unknown')
        message = result.get('message', {}).get('text', '')
        level = result.get('level', 'warning')
        
        # Get location information
        locations = result.get('locations', [])
        file_path = ""
        line_number = 0
        
        if locations:
            physical_location = locations[0].get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            file_path = artifact_location.get('uri', '')
            
            region = physical_location.get('region', {})
            line_number = region.get('startLine', 0)
        
        # Map SARIF level to Severity
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'note': Severity.LOW
        }
        severity = severity_map.get(level, Severity.MEDIUM)
        
        return Finding(
            id=f"semgrep-{rule_id}-{hash(file_path + str(line_number))}",
            source="semgrep",
            type=rule_id,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            message=message,
            confidence=0.7,
            raw_data=result
        )
