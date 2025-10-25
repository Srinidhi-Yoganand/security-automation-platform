"""
Risk Scoring Algorithm for Phase 2
Calculates comprehensive risk scores for vulnerabilities
"""

from typing import Dict
from datetime import datetime

from app.models import Vulnerability, VulnerabilityState


class RiskScorer:
    """
    Calculates risk scores based on multiple factors:
    - Severity (from scanners)
    - Exploitability (confirmed vs potential)
    - Age (how long it's existed)
    - Frequency (similar patterns)
    - Blast radius (impact estimate)
    - Fix difficulty (complexity)
    """
    
    # Weight for each factor (must sum to 1.0)
    WEIGHTS = {
        'severity': 0.30,
        'exploitability': 0.25,
        'age': 0.15,
        'frequency': 0.15,
        'blast_radius': 0.10,
        'fix_difficulty': 0.05
    }
    
    @staticmethod
    def calculate_risk_score(vuln: Vulnerability, context: Dict = None) -> float:
        """
        Calculate comprehensive risk score (0.0 - 10.0).
        
        Args:
            vuln: Vulnerability to score
            context: Optional context dict with additional data:
                - pattern_frequency: How often this pattern occurs
                - affected_endpoints: Number of affected endpoints
                - code_complexity: Cyclomatic complexity score
                
        Returns:
            Risk score between 0.0 and 10.0
        """
        context = context or {}
        
        # Calculate individual component scores (0-10 scale)
        severity_score = RiskScorer._score_severity(vuln.severity)
        exploitability_score = RiskScorer._score_exploitability(
            vuln.confidence,
            vuln.state
        )
        age_score = RiskScorer._score_age(vuln.age_days)
        frequency_score = RiskScorer._score_frequency(
            vuln.pattern_frequency,
            context.get('pattern_frequency', 0)
        )
        blast_radius_score = RiskScorer._score_blast_radius(
            vuln.type,
            context.get('affected_endpoints', 1)
        )
        fix_difficulty_score = RiskScorer._score_fix_difficulty(
            vuln.type,
            context.get('code_complexity', 1)
        )
        
        # Calculate weighted sum
        risk_score = (
            severity_score * RiskScorer.WEIGHTS['severity'] +
            exploitability_score * RiskScorer.WEIGHTS['exploitability'] +
            age_score * RiskScorer.WEIGHTS['age'] +
            frequency_score * RiskScorer.WEIGHTS['frequency'] +
            blast_radius_score * RiskScorer.WEIGHTS['blast_radius'] +
            fix_difficulty_score * RiskScorer.WEIGHTS['fix_difficulty']
        )
        
        return round(risk_score, 2)
    
    @staticmethod
    def _score_severity(severity: str) -> float:
        """
        Score based on severity level.
        Returns: 0-10
        """
        severity_map = {
            'critical': 10.0,
            'high': 8.0,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        return severity_map.get(severity.lower(), 5.0)
    
    @staticmethod
    def _score_exploitability(confidence: float, state: VulnerabilityState) -> float:
        """
        Score based on confidence and state.
        High confidence or confirmed vulnerabilities score higher.
        Returns: 0-10
        """
        # Base score from confidence (0.0-1.0 → 0-10)
        base_score = confidence * 10.0
        
        # Boost for certain states
        if state == VulnerabilityState.REGRESSED:
            # Regressions are serious - already fixed once
            base_score = min(10.0, base_score * 1.5)
        elif state == VulnerabilityState.EXISTING:
            # Persistent vulnerabilities are concerning
            base_score = min(10.0, base_score * 1.2)
        
        return base_score
    
    @staticmethod
    def _score_age(age_days: int) -> float:
        """
        Score based on how long vulnerability has existed.
        Older vulnerabilities score higher.
        Returns: 0-10
        """
        if age_days < 1:
            return 2.0  # Brand new
        elif age_days < 7:
            return 4.0  # Less than a week
        elif age_days < 30:
            return 6.0  # Less than a month
        elif age_days < 90:
            return 8.0  # Less than 3 months
        else:
            return 10.0  # 3+ months old
    
    @staticmethod
    def _score_frequency(vuln_frequency: int, total_pattern_frequency: int) -> float:
        """
        Score based on pattern frequency.
        More common patterns indicate systematic issues.
        Returns: 0-10
        """
        if total_pattern_frequency == 0:
            return 5.0  # Unknown
        
        # If this vulnerability's pattern appears frequently
        if vuln_frequency >= 5:
            return 9.0  # Very common pattern
        elif vuln_frequency >= 3:
            return 7.0  # Common pattern
        elif vuln_frequency >= 2:
            return 5.0  # Somewhat common
        else:
            return 3.0  # Rare pattern
    
    @staticmethod
    def _score_blast_radius(vuln_type: str, affected_endpoints: int) -> float:
        """
        Score based on potential impact.
        SQL injection and authentication issues have high blast radius.
        Returns: 0-10
        """
        # High-impact vulnerability types
        high_impact_types = [
            'sql injection',
            'command injection',
            'authentication bypass',
            'authorization bypass',
            'remote code execution',
            'path traversal'
        ]
        
        # Base score from type
        base_score = 7.0 if any(t in vuln_type.lower() for t in high_impact_types) else 4.0
        
        # Adjust for number of affected endpoints
        if affected_endpoints > 10:
            base_score = min(10.0, base_score * 1.5)
        elif affected_endpoints > 5:
            base_score = min(10.0, base_score * 1.3)
        elif affected_endpoints > 2:
            base_score = min(10.0, base_score * 1.1)
        
        return base_score
    
    @staticmethod
    def _score_fix_difficulty(vuln_type: str, code_complexity: int) -> float:
        """
        Score based on estimated difficulty to fix.
        Higher difficulty means vulnerability may persist longer.
        Returns: 0-10
        """
        # Vulnerability types that are typically harder to fix
        complex_fixes = [
            'idor',
            'access control',
            'authorization',
            'cryptographic',
            'deserialization'
        ]
        
        base_score = 6.0 if any(t in vuln_type.lower() for t in complex_fixes) else 4.0
        
        # Adjust for code complexity (cyclomatic complexity)
        if code_complexity > 20:
            base_score = min(10.0, base_score * 1.5)
        elif code_complexity > 10:
            base_score = min(10.0, base_score * 1.3)
        elif code_complexity > 5:
            base_score = min(10.0, base_score * 1.1)
        
        return base_score
    
    @staticmethod
    def get_risk_category(risk_score: float) -> str:
        """
        Categorize risk score into human-readable category.
        
        Args:
            risk_score: Risk score (0-10)
            
        Returns:
            Category string: Critical, High, Medium, Low
        """
        if risk_score >= 8.5:
            return "Critical"
        elif risk_score >= 7.0:
            return "High"
        elif risk_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    @staticmethod
    def explain_risk_score(vuln: Vulnerability, context: Dict = None) -> Dict[str, any]:
        """
        Provide detailed explanation of risk score calculation.
        
        Args:
            vuln: Vulnerability to explain
            context: Optional context dict
            
        Returns:
            Dictionary with component scores and explanations
        """
        context = context or {}
        
        components = {
            'severity': {
                'score': RiskScorer._score_severity(vuln.severity),
                'weight': RiskScorer.WEIGHTS['severity'],
                'explanation': f"Severity: {vuln.severity}"
            },
            'exploitability': {
                'score': RiskScorer._score_exploitability(vuln.confidence, vuln.state),
                'weight': RiskScorer.WEIGHTS['exploitability'],
                'explanation': f"Confidence: {vuln.confidence:.2f}, State: {vuln.state.value}"
            },
            'age': {
                'score': RiskScorer._score_age(vuln.age_days),
                'weight': RiskScorer.WEIGHTS['age'],
                'explanation': f"Age: {vuln.age_days} days"
            },
            'frequency': {
                'score': RiskScorer._score_frequency(
                    vuln.pattern_frequency,
                    context.get('pattern_frequency', 0)
                ),
                'weight': RiskScorer.WEIGHTS['frequency'],
                'explanation': f"Pattern occurs {vuln.pattern_frequency} times"
            },
            'blast_radius': {
                'score': RiskScorer._score_blast_radius(
                    vuln.type,
                    context.get('affected_endpoints', 1)
                ),
                'weight': RiskScorer.WEIGHTS['blast_radius'],
                'explanation': f"Type: {vuln.type}, Affected endpoints: {context.get('affected_endpoints', 1)}"
            },
            'fix_difficulty': {
                'score': RiskScorer._score_fix_difficulty(
                    vuln.type,
                    context.get('code_complexity', 1)
                ),
                'weight': RiskScorer.WEIGHTS['fix_difficulty'],
                'explanation': f"Complexity: {context.get('code_complexity', 1)}"
            }
        }
        
        # Calculate total
        total_score = sum(
            comp['score'] * comp['weight']
            for comp in components.values()
        )
        
        return {
            'total_score': round(total_score, 2),
            'category': RiskScorer.get_risk_category(total_score),
            'components': components
        }
