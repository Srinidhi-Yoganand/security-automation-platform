"""
Security Correlation Engine - Core Logic

This module contains the main correlation algorithm that:
1. Normalizes findings from different scanners
2. Matches findings by location (file, line, function)
3. Uses CodeQL data flow to confirm vulnerabilities
4. Calculates confidence scores
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Normalized security finding"""
    id: str
    source: str  # semgrep, zap, codeql
    type: str
    severity: Severity
    file_path: str = ""
    line_number: int = 0
    function_name: str = ""
    message: str = ""
    cwe_id: str = ""
    confidence: float = 0.5
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelatedFinding:
    """A finding confirmed by multiple sources"""
    id: str
    findings: List[Finding]
    severity: Severity
    confidence: float
    file_path: str
    line_number: int
    vulnerability_type: str
    data_flow_confirmed: bool = False
    recommendation: str = ""


class SecurityCorrelator:
    """
    Main correlation engine that processes findings from multiple
    security scanners and identifies confirmed vulnerabilities.
    """
    
    def __init__(self):
        self.findings: Dict[str, List[Finding]] = {
            "semgrep": [],
            "codeql": [],
            "zap": []
        }
        self.correlated: List[CorrelatedFinding] = []
    
    def add_findings(self, source: str, findings: List[Finding]):
        """Add findings from a specific scanner"""
        if source in self.findings:
            self.findings[source].extend(findings)
    
    def correlate(self) -> Dict[str, Any]:
        """
        Perform correlation analysis.
        
        Algorithm:
        1. Group findings by file/location
        2. Match DAST findings with SAST findings
        3. Confirm with CodeQL data flow
        4. Calculate confidence scores
        5. Generate correlation report
        """
        # Phase 1: Basic location-based correlation
        location_groups = self._group_by_location()
        
        # Phase 2: Match across scanners
        for location, findings_at_location in location_groups.items():
            if len(findings_at_location) >= 2:
                # Multiple scanners found something at this location
                correlated = self._create_correlated_finding(findings_at_location)
                self.correlated.append(correlated)
        
        # Phase 3: Check CodeQL data flow
        self._enhance_with_dataflow()
        
        # Phase 4: Generate report
        return self._generate_report()
    
    def _group_by_location(self) -> Dict[str, List[Finding]]:
        """Group findings by file and line number"""
        groups = {}
        
        for source, findings in self.findings.items():
            for finding in findings:
                # Create location key
                key = f"{finding.file_path}:{finding.line_number}"
                if key not in groups:
                    groups[key] = []
                groups[key].append(finding)
        
        return groups
    
    def _create_correlated_finding(self, findings: List[Finding]) -> CorrelatedFinding:
        """Create a correlated finding from multiple sources"""
        # Determine highest severity
        severity = max(findings, key=lambda f: self._severity_score(f.severity)).severity
        
        # Calculate confidence based on number of sources
        confidence = min(0.9, 0.4 + (len(findings) * 0.25))
        
        # Get common attributes
        file_path = findings[0].file_path
        line_number = findings[0].line_number
        
        # Determine vulnerability type
        vuln_types = [f.type for f in findings]
        vulnerability_type = max(set(vuln_types), key=vuln_types.count)
        
        return CorrelatedFinding(
            id=f"corr-{hash((file_path, line_number))}",
            findings=findings,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            vulnerability_type=vulnerability_type
        )
    
    def _enhance_with_dataflow(self):
        """Use CodeQL data flow results to increase confidence"""
        # TODO: Phase 1 - implement data flow confirmation
        # For each correlated finding, check if CodeQL shows a data flow
        # from a source (e.g., @RequestParam) to a sink (e.g., SQL execute)
        pass
    
    def _severity_score(self, severity: Severity) -> int:
        """Convert severity to numeric score for comparison"""
        scores = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }
        return scores.get(severity, 0)
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate correlation report"""
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for finding in self.correlated:
            severity_key = finding.severity.value
            if severity_key in severity_counts:
                severity_counts[severity_key] += 1
        
        # Calculate totals
        total_findings = sum(len(f) for f in self.findings.values())
        correlated_count = len(self.correlated)
        
        return {
            "total_findings": total_findings,
            "correlated_count": correlated_count,
            "confirmed_vulnerabilities": correlated_count,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "findings": [
                {
                    "id": f.id,
                    "type": f.vulnerability_type,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "file": f.file_path,
                    "line": f.line_number,
                    "sources": [source.source for source in f.findings],
                    "data_flow_confirmed": f.data_flow_confirmed
                }
                for f in self.correlated
            ]
        }
