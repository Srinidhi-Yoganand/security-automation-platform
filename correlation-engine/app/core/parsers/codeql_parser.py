"""
CodeQL Parser

Parses CodeQL query results (CSV format) and extracts:
1. Data flow paths from sources to sinks
2. Security annotations (@PreAuthorize, etc.)
3. Code structure information
"""

import csv
from pathlib import Path
from typing import List, Dict, Any
from app.core.correlator import Finding, Severity


class CodeQLParser:
    """Parser for CodeQL analysis results"""
    
    @staticmethod
    def parse(directory_path: str) -> List[Finding]:
        """
        Parse CodeQL results directory and return list of normalized findings.
        
        CodeQL can output:
        - SARIF files (for standard queries)
        - CSV files (for custom queries)
        - Database (for detailed analysis)
        
        Args:
            directory_path: Path to CodeQL results directory
            
        Returns:
            List of Finding objects
        """
        findings = []
        results_dir = Path(directory_path)
        
        if not results_dir.exists():
            print(f"CodeQL results directory not found: {directory_path}")
            return findings
        
        # Parse CSV files (data flow results)
        for csv_file in results_dir.glob('*.csv'):
            findings.extend(CodeQLParser._parse_csv(str(csv_file)))
        
        # Parse SARIF files (standard queries)
        for sarif_file in results_dir.glob('*.sarif'):
            findings.extend(CodeQLParser._parse_sarif(str(sarif_file)))
        
        return findings
    
    @staticmethod
    def _parse_csv(file_path: str) -> List[Finding]:
        """Parse CodeQL CSV output (typically from custom queries)"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # CSV format may vary based on query
                    # Common columns: name, description, file, line, column
                    finding = CodeQLParser._create_finding_from_csv(row)
                    if finding:
                        findings.append(finding)
        
        except Exception as e:
            print(f"Error parsing CodeQL CSV {file_path}: {e}")
        
        return findings
    
    @staticmethod
    def _parse_sarif(file_path: str) -> List[Finding]:
        """Parse CodeQL SARIF output"""
        import json
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                sarif_data = json.load(f)
            
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    finding = CodeQLParser._create_finding_from_sarif(result)
                    if finding:
                        findings.append(finding)
        
        except Exception as e:
            print(f"Error parsing CodeQL SARIF {file_path}: {e}")
        
        return findings
    
    @staticmethod
    def _create_finding_from_csv(row: Dict[str, str]) -> Finding:
        """Create Finding from CSV row"""
        # Extract common fields
        name = row.get('name', row.get('query', 'unknown'))
        description = row.get('description', row.get('message', ''))
        file_path = row.get('file', row.get('path', ''))
        line_number = int(row.get('line', row.get('startLine', '0')))
        
        # CodeQL findings are generally high confidence
        return Finding(
            id=f"codeql-{hash(name + file_path + str(line_number))}",
            source="codeql",
            type=name,
            severity=Severity.HIGH,  # Default, will be refined
            file_path=file_path,
            line_number=line_number,
            message=description,
            confidence=0.9,
            raw_data=row
        )
    
    @staticmethod
    def _create_finding_from_sarif(result: dict) -> Finding:
        """Create Finding from SARIF result"""
        rule_id = result.get('ruleId', 'unknown')
        message = result.get('message', {}).get('text', '')
        level = result.get('level', 'warning')
        
        # Get location
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
            id=f"codeql-{rule_id}-{hash(file_path + str(line_number))}",
            source="codeql",
            type=rule_id,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            message=message,
            confidence=0.9,  # CodeQL is high confidence
            raw_data=result
        )
