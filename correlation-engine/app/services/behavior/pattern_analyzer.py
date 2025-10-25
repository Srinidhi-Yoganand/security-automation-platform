"""
Security Pattern Analyzer for Phase 2
Identifies recurring vulnerability patterns and anti-patterns in code
"""

from typing import List, Dict, Set, Optional
from collections import defaultdict
import re
from pathlib import Path

from app.models import Vulnerability, SecurityPattern
from sqlalchemy.orm import Session


class PatternAnalyzer:
    """
    Analyzes vulnerabilities to identify:
    - Recurring patterns (same vulnerability type in similar contexts)
    - Anti-patterns (problematic code structures)
    - Hotspots (files/directories with many vulnerabilities)
    - Vulnerability clusters (related issues)
    """
    
    # Common vulnerability patterns to detect
    PATTERNS = {
        'sql-injection-controller': {
            'name': 'SQL Injection in Controllers',
            'description': 'SQL injection vulnerabilities found in controller/endpoint classes',
            'category': 'vulnerability-pattern',
            'detection': lambda v: 'sql' in v.type.lower() and 'controller' in v.file_path.lower(),
            'severity': 'high',
            'remediation': 'Use parameterized queries or ORM. Never concatenate user input into SQL.'
        },
        'idor-authorization': {
            'name': 'IDOR in Authorization Layer',
            'description': 'Insecure Direct Object Reference in authorization/security classes',
            'category': 'vulnerability-pattern',
            'detection': lambda v: 'idor' in v.type.lower() and ('authorization' in v.file_path.lower() or 'security' in v.file_path.lower()),
            'severity': 'high',
            'remediation': 'Always validate that the authenticated user owns the requested resource.'
        },
        'missing-input-validation': {
            'name': 'Missing Input Validation',
            'description': 'Multiple vulnerabilities caused by insufficient input validation',
            'category': 'anti-pattern',
            'detection': lambda v: v.message and any(keyword in v.message.lower() for keyword in ['validation', 'sanitiz', 'input', 'user-provided']),
            'severity': 'medium',
            'remediation': 'Implement comprehensive input validation at API boundaries.'
        },
        'authentication-bypass': {
            'name': 'Authentication/Authorization Bypass',
            'description': 'Weak or missing authentication checks',
            'category': 'vulnerability-pattern',
            'detection': lambda v: any(keyword in v.type.lower() for keyword in ['auth', 'access control', 'bypass']),
            'severity': 'critical',
            'remediation': 'Implement proper authentication and authorization checks at all protected endpoints.'
        },
        'injection-vulnerabilities': {
            'name': 'Injection Vulnerability Pattern',
            'description': 'Multiple types of injection vulnerabilities (SQL, command, etc.)',
            'category': 'vulnerability-pattern',
            'detection': lambda v: 'injection' in v.type.lower(),
            'severity': 'high',
            'remediation': 'Use safe APIs that avoid interpreters or provide parameterized interfaces.'
        },
        'controller-layer-vulnerabilities': {
            'name': 'Controller Layer Security Issues',
            'description': 'Multiple vulnerabilities concentrated in controller/API layer',
            'category': 'anti-pattern',
            'detection': lambda v: 'controller' in v.file_path.lower(),
            'severity': 'medium',
            'remediation': 'Review API security patterns. Consider middleware for common security checks.'
        },
        'data-access-issues': {
            'name': 'Data Access Security Issues',
            'description': 'Vulnerabilities in data access layer (repositories, DAOs)',
            'category': 'anti-pattern',
            'detection': lambda v: any(keyword in v.file_path.lower() for keyword in ['repository', 'dao', 'service']),
            'severity': 'medium',
            'remediation': 'Ensure data access layer enforces authorization and uses safe query methods.'
        }
    }
    
    def __init__(self, db: Session):
        """
        Initialize pattern analyzer.
        
        Args:
            db: Database session
        """
        self.db = db
    
    def analyze_patterns(self, vulnerabilities: Optional[List[Vulnerability]] = None) -> Dict[str, any]:
        """
        Analyze vulnerabilities for patterns.
        
        Args:
            vulnerabilities: List of vulnerabilities to analyze (None = all active)
            
        Returns:
            Dictionary with pattern analysis results
        """
        if vulnerabilities is None:
            # Analyze all active (non-fixed) vulnerabilities
            vulnerabilities = self.db.query(Vulnerability).filter(
                Vulnerability.state != 'fixed'
            ).all()
        
        if not vulnerabilities:
            return {
                'patterns_found': [],
                'hotspots': [],
                'clusters': [],
                'recommendations': []
            }
        
        # Detect patterns
        patterns_found = self._detect_patterns(vulnerabilities)
        
        # Find hotspots (files with many vulnerabilities)
        hotspots = self._find_hotspots(vulnerabilities)
        
        # Find clusters (related vulnerabilities)
        clusters = self._find_clusters(vulnerabilities)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(patterns_found, hotspots)
        
        # Update pattern statistics in database
        self._update_pattern_records(patterns_found)
        
        return {
            'patterns_found': patterns_found,
            'hotspots': hotspots,
            'clusters': clusters,
            'recommendations': recommendations
        }
    
    def _detect_patterns(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, any]]:
        """Detect known vulnerability patterns"""
        pattern_matches = defaultdict(list)
        
        # Check each vulnerability against each pattern
        for vuln in vulnerabilities:
            for pattern_id, pattern_def in self.PATTERNS.items():
                if pattern_def['detection'](vuln):
                    pattern_matches[pattern_id].append(vuln)
        
        # Build results
        results = []
        for pattern_id, vulns in pattern_matches.items():
            if len(vulns) >= 1:  # Pattern needs at least 1 match
                pattern_def = self.PATTERNS[pattern_id]
                
                # Get affected files
                affected_files = list(set(v.file_path for v in vulns))
                
                results.append({
                    'id': pattern_id,
                    'name': pattern_def['name'],
                    'description': pattern_def['description'],
                    'category': pattern_def['category'],
                    'severity': pattern_def['severity'],
                    'occurrences': len(vulns),
                    'affected_files': affected_files,
                    'vulnerabilities': [
                        {
                            'type': v.type,
                            'file': v.file_path,
                            'line': v.line_number,
                            'fingerprint': v.fingerprint
                        }
                        for v in vulns
                    ],
                    'remediation': pattern_def['remediation']
                })
        
        # Sort by occurrences (most common first)
        results.sort(key=lambda x: x['occurrences'], reverse=True)
        
        return results
    
    def _find_hotspots(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, any]]:
        """Find files/directories with many vulnerabilities"""
        file_counts = defaultdict(list)
        dir_counts = defaultdict(list)
        
        # Count vulnerabilities by file and directory
        for vuln in vulnerabilities:
            file_counts[vuln.file_path].append(vuln)
            
            # Extract directory
            directory = str(Path(vuln.file_path).parent)
            dir_counts[directory].append(vuln)
        
        # Build file hotspots (files with 2+ vulnerabilities)
        file_hotspots = [
            {
                'type': 'file',
                'path': file_path,
                'vulnerability_count': len(vulns),
                'severities': self._count_severities(vulns),
                'types': list(set(v.type for v in vulns))
            }
            for file_path, vulns in file_counts.items()
            if len(vulns) >= 2
        ]
        
        # Build directory hotspots (directories with 3+ vulnerabilities)
        dir_hotspots = [
            {
                'type': 'directory',
                'path': dir_path,
                'vulnerability_count': len(vulns),
                'severities': self._count_severities(vulns),
                'affected_files': len(set(v.file_path for v in vulns))
            }
            for dir_path, vulns in dir_counts.items()
            if len(vulns) >= 3
        ]
        
        # Combine and sort
        hotspots = file_hotspots + dir_hotspots
        hotspots.sort(key=lambda x: x['vulnerability_count'], reverse=True)
        
        return hotspots
    
    def _find_clusters(self, vulnerabilities: List[Vulnerability]) -> List[Dict[str, any]]:
        """Find clusters of related vulnerabilities"""
        clusters = []
        
        # Cluster 1: Same vulnerability type
        type_groups = defaultdict(list)
        for vuln in vulnerabilities:
            type_groups[vuln.type].append(vuln)
        
        for vuln_type, vulns in type_groups.items():
            if len(vulns) >= 2:
                clusters.append({
                    'type': 'same-vulnerability-type',
                    'name': f'{vuln_type} (multiple occurrences)',
                    'count': len(vulns),
                    'vulnerabilities': [v.fingerprint for v in vulns],
                    'affected_files': list(set(v.file_path for v in vulns))
                })
        
        # Cluster 2: Same file
        file_groups = defaultdict(list)
        for vuln in vulnerabilities:
            file_groups[vuln.file_path].append(vuln)
        
        for file_path, vulns in file_groups.items():
            if len(vulns) >= 2:
                clusters.append({
                    'type': 'same-file',
                    'name': f'Multiple issues in {Path(file_path).name}',
                    'count': len(vulns),
                    'file': file_path,
                    'types': [v.type for v in vulns]
                })
        
        return clusters
    
    def _generate_recommendations(
        self,
        patterns: List[Dict[str, any]],
        hotspots: List[Dict[str, any]]
    ) -> List[Dict[str, any]]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Recommendations from patterns
        for pattern in patterns:
            if pattern['occurrences'] >= 3:
                recommendations.append({
                    'priority': 'high' if pattern['severity'] in ['critical', 'high'] else 'medium',
                    'title': f"Address {pattern['name']} pattern",
                    'description': f"Found {pattern['occurrences']} instances of {pattern['name'].lower()}",
                    'action': pattern['remediation'],
                    'affected_files': pattern['affected_files'][:5]  # Show max 5
                })
        
        # Recommendations from hotspots
        for hotspot in hotspots[:3]:  # Top 3 hotspots
            if hotspot['type'] == 'file':
                recommendations.append({
                    'priority': 'high',
                    'title': f"Review security in {Path(hotspot['path']).name}",
                    'description': f"This file has {hotspot['vulnerability_count']} vulnerabilities",
                    'action': f"Conduct thorough security review of {hotspot['path']}. Consider refactoring to improve security.",
                    'affected_files': [hotspot['path']]
                })
            else:
                recommendations.append({
                    'priority': 'medium',
                    'title': f"Security review needed for {hotspot['path']} directory",
                    'description': f"This directory has {hotspot['vulnerability_count']} vulnerabilities across {hotspot['affected_files']} files",
                    'action': f"Review security architecture of components in {hotspot['path']}",
                    'affected_files': []
                })
        
        # Sort by priority
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def _count_severities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = defaultdict(int)
        for vuln in vulnerabilities:
            counts[vuln.severity] += 1
        return dict(counts)
    
    def _update_pattern_records(self, patterns: List[Dict[str, any]]):
        """Update or create SecurityPattern records in database"""
        from datetime import datetime
        
        for pattern in patterns:
            # Check if pattern exists
            existing = self.db.query(SecurityPattern).filter(
                SecurityPattern.name == pattern['name']
            ).first()
            
            if existing:
                # Update existing
                existing.occurrence_count = pattern['occurrences']
                existing.files_affected = pattern['affected_files']
                existing.last_detected = datetime.utcnow()
            else:
                # Create new
                new_pattern = SecurityPattern(
                    name=pattern['name'],
                    category=pattern['category'],
                    description=pattern['description'],
                    pattern_type='code-structure',
                    detection_rule=pattern['id'],
                    occurrence_count=pattern['occurrences'],
                    files_affected=pattern['affected_files'],
                    severity=pattern['severity'],
                    remediation=pattern['remediation'],
                    first_detected=datetime.utcnow(),
                    last_detected=datetime.utcnow()
                )
                self.db.add(new_pattern)
        
        self.db.commit()
    
    def get_pattern_trends(self) -> List[Dict[str, any]]:
        """Get historical pattern trends"""
        patterns = self.db.query(SecurityPattern).order_by(
            SecurityPattern.occurrence_count.desc()
        ).all()
        
        return [
            {
                'name': p.name,
                'category': p.category,
                'occurrences': p.occurrence_count,
                'severity': p.severity,
                'first_seen': p.first_detected.isoformat() if p.first_detected else None,
                'last_seen': p.last_detected.isoformat() if p.last_detected else None,
                'affected_files_count': len(p.files_affected) if p.files_affected else 0
            }
            for p in patterns
        ]
