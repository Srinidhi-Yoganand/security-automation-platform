"""
Vulnerability Lifecycle Tracker for Phase 2
Tracks vulnerability state changes over time
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models import (
    Vulnerability,
    VulnerabilityState,
    VulnerabilityStateHistory,
    Scan
)
from app.core.git_analyzer import GitHistoryAnalyzer
from app.core.correlator import Finding


class VulnerabilityLifecycleTracker:
    """
    Tracks vulnerabilities across scans to identify:
    - New vulnerabilities
    - Fixed vulnerabilities
    - Regressed vulnerabilities (fixed then reappeared)
    - Persistent vulnerabilities
    """
    
    def __init__(self, db: Session, git_analyzer: Optional[GitHistoryAnalyzer] = None):
        """
        Initialize tracker.
        
        Args:
            db: Database session
            git_analyzer: Optional Git analyzer for historical context
        """
        self.db = db
        self.git_analyzer = git_analyzer
    
    def process_scan_results(
        self,
        scan_id: int,
        findings: List[Finding],
        commit_hash: str
    ) -> Dict[str, List[Vulnerability]]:
        """
        Process scan results and update vulnerability lifecycle.
        
        Args:
            scan_id: ID of the current scan
            findings: List of findings from correlation engine
            commit_hash: Git commit hash for this scan
            
        Returns:
            Dictionary with categorized vulnerabilities (new, existing, fixed)
        """
        result = {
            'new': [],
            'existing': [],
            'fixed': [],
            'regressed': []
        }
        
        # Get current scan
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Generate fingerprints for current findings
        current_fingerprints = set()
        for finding in findings:
            fingerprint = GitHistoryAnalyzer.generate_vulnerability_fingerprint(
                finding.file_path,
                finding.line_number,
                finding.type
            )
            current_fingerprints.add(fingerprint)
            
            # Check if vulnerability already exists
            existing_vuln = self.db.query(Vulnerability).filter(
                Vulnerability.fingerprint == fingerprint
            ).first()
            
            if existing_vuln:
                # Update existing vulnerability
                updated_vuln = self._update_existing_vulnerability(
                    existing_vuln,
                    finding,
                    scan_id,
                    commit_hash
                )
                result['existing'].append(updated_vuln)
            else:
                # Create new vulnerability
                new_vuln = self._create_new_vulnerability(
                    finding,
                    fingerprint,
                    scan_id,
                    commit_hash
                )
                result['new'].append(new_vuln)
        
        # Find fixed vulnerabilities (in previous scans but not current)
        fixed_vulns = self._find_fixed_vulnerabilities(
            current_fingerprints,
            scan_id,
            commit_hash
        )
        result['fixed'] = fixed_vulns
        
        # Check for regressions
        regressed = self._check_for_regressions(result['new'])
        result['regressed'] = regressed
        
        return result
    
    def _create_new_vulnerability(
        self,
        finding: Finding,
        fingerprint: str,
        scan_id: int,
        commit_hash: str
    ) -> Vulnerability:
        """Create a new vulnerability record"""
        
        # Try to find when it was introduced
        introduced_commit = commit_hash
        if self.git_analyzer:
            blame_info = self.git_analyzer.get_blame_info(
                finding.file_path,
                finding.line_number
            )
            if blame_info:
                introduced_commit = blame_info['commit_hash']
        
        vuln = Vulnerability(
            fingerprint=fingerprint,
            type=finding.type,
            severity=finding.severity.value,
            confidence=finding.confidence,
            file_path=finding.file_path,
            line_number=finding.line_number,
            message=finding.message,
            state=VulnerabilityState.NEW,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            scan_id=scan_id,
            introduced_commit=introduced_commit,
            raw_data=finding.raw_data
        )
        
        self.db.add(vuln)
        
        # Record state history
        history = VulnerabilityStateHistory(
            vulnerability=vuln,
            from_state=None,
            to_state=VulnerabilityState.NEW,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            reason="First detection",
            commit_hash=commit_hash
        )
        self.db.add(history)
        
        self.db.commit()
        return vuln
    
    def _update_existing_vulnerability(
        self,
        vuln: Vulnerability,
        finding: Finding,
        scan_id: int,
        commit_hash: str
    ) -> Vulnerability:
        """Update an existing vulnerability"""
        
        # Update last seen
        vuln.last_seen = datetime.utcnow()
        vuln.scan_id = scan_id
        
        # Update confidence if higher
        if finding.confidence > vuln.confidence:
            vuln.confidence = finding.confidence
        
        # Check if state should change
        new_state = VulnerabilityState.EXISTING
        
        if vuln.state == VulnerabilityState.NEW:
            # Still new on second detection
            new_state = VulnerabilityState.EXISTING
        elif vuln.state == VulnerabilityState.FIXED:
            # Was fixed but appeared again - regression!
            new_state = VulnerabilityState.REGRESSED
        
        # Record state change if different
        if vuln.state != new_state:
            self._record_state_change(
                vuln,
                vuln.state,
                new_state,
                scan_id,
                commit_hash,
                "Detected in scan"
            )
            vuln.state = new_state
        
        # Calculate age
        if vuln.first_seen:
            vuln.age_days = (datetime.utcnow() - vuln.first_seen).days
        
        self.db.commit()
        return vuln
    
    def _find_fixed_vulnerabilities(
        self,
        current_fingerprints: set,
        scan_id: int,
        commit_hash: str
    ) -> List[Vulnerability]:
        """Find vulnerabilities that were fixed (not in current scan)"""
        
        # Get all vulnerabilities that are not fixed
        active_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.state.in_([
                VulnerabilityState.NEW,
                VulnerabilityState.EXISTING,
                VulnerabilityState.REGRESSED
            ])
        ).all()
        
        fixed = []
        for vuln in active_vulns:
            if vuln.fingerprint not in current_fingerprints:
                # Not in current scan - mark as fixed
                self._record_state_change(
                    vuln,
                    vuln.state,
                    VulnerabilityState.FIXED,
                    scan_id,
                    commit_hash,
                    "No longer detected in scan"
                )
                
                vuln.state = VulnerabilityState.FIXED
                vuln.fixed_at = datetime.utcnow()
                vuln.fixed_commit = commit_hash
                
                fixed.append(vuln)
        
        if fixed:
            self.db.commit()
        
        return fixed
    
    def _check_for_regressions(self, new_vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Check if any 'new' vulnerabilities are actually regressions"""
        regressions = []
        
        for vuln in new_vulns:
            # Look for previously fixed vulnerability with same fingerprint
            old_vuln = self.db.query(Vulnerability).filter(
                Vulnerability.fingerprint == vuln.fingerprint,
                Vulnerability.state == VulnerabilityState.FIXED,
                Vulnerability.id != vuln.id
            ).first()
            
            if old_vuln:
                # This is a regression!
                vuln.state = VulnerabilityState.REGRESSED
                regressions.append(vuln)
        
        if regressions:
            self.db.commit()
        
        return regressions
    
    def _record_state_change(
        self,
        vuln: Vulnerability,
        from_state: VulnerabilityState,
        to_state: VulnerabilityState,
        scan_id: int,
        commit_hash: str,
        reason: str
    ):
        """Record a state transition in history"""
        history = VulnerabilityStateHistory(
            vulnerability=vuln,
            from_state=from_state,
            to_state=to_state,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            reason=reason,
            commit_hash=commit_hash
        )
        self.db.add(history)
    
    def calculate_mean_time_to_fix(self) -> float:
        """Calculate average time to fix vulnerabilities (in days)"""
        fixed_vulns = self.db.query(Vulnerability).filter(
            Vulnerability.state == VulnerabilityState.FIXED,
            Vulnerability.first_seen.isnot(None),
            Vulnerability.fixed_at.isnot(None)
        ).all()
        
        if not fixed_vulns:
            return 0.0
        
        total_days = 0
        for vuln in fixed_vulns:
            delta = vuln.fixed_at - vuln.first_seen
            total_days += delta.days
        
        return total_days / len(fixed_vulns)
    
    def get_vulnerability_history(self, fingerprint: str) -> Dict[str, any]:
        """Get complete history of a vulnerability"""
        vuln = self.db.query(Vulnerability).filter(
            Vulnerability.fingerprint == fingerprint
        ).first()
        
        if not vuln:
            return None
        
        history = self.db.query(VulnerabilityStateHistory).filter(
            VulnerabilityStateHistory.vulnerability_id == vuln.id
        ).order_by(VulnerabilityStateHistory.timestamp).all()
        
        return {
            'vulnerability': {
                'type': vuln.type,
                'severity': vuln.severity,
                'file_path': vuln.file_path,
                'line_number': vuln.line_number,
                'state': vuln.state.value,
                'first_seen': vuln.first_seen.isoformat() if vuln.first_seen else None,
                'last_seen': vuln.last_seen.isoformat() if vuln.last_seen else None,
                'age_days': vuln.age_days,
            },
            'history': [
                {
                    'from': h.from_state.value if h.from_state else None,
                    'to': h.to_state.value,
                    'timestamp': h.timestamp.isoformat(),
                    'reason': h.reason,
                    'commit': h.commit_hash[:8] if h.commit_hash else None
                }
                for h in history
            ]
        }
