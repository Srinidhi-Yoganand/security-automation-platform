"""
Database models for Phase 2: Security Behavior Analysis
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey, Enum, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class VulnerabilityState(enum.Enum):
    """Vulnerability lifecycle states"""
    NEW = "new"
    EXISTING = "existing"
    FIXED = "fixed"
    REGRESSED = "regressed"
    IGNORED = "ignored"


class Scan(Base):
    """Represents a security scan at a point in time"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    commit_hash = Column(String(40), nullable=False)
    branch = Column(String(255), default="main")
    author = Column(String(255))
    commit_message = Column(Text)
    
    # Scanner metadata
    semgrep_version = Column(String(50))
    codeql_version = Column(String(50))
    zap_version = Column(String(50))
    
    # Scan results summary
    total_findings = Column(Integer, default=0)
    correlated_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    code_changes = relationship("CodeChange", back_populates="scan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, commit={self.commit_hash[:8]}, timestamp={self.timestamp})>"


class Vulnerability(Base):
    """Tracks individual vulnerabilities over time"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    
    # Unique identifier for tracking across scans
    fingerprint = Column(String(64), nullable=False, index=True)
    
    # Basic info
    type = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, default=0.0)
    
    # Location
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=False)
    
    # Description
    message = Column(Text)
    cwe_id = Column(String(20))
    owasp_category = Column(String(50))
    
    # Lifecycle
    state = Column(Enum(VulnerabilityState), default=VulnerabilityState.NEW)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    fixed_at = Column(DateTime, nullable=True)
    
    # Risk scoring
    risk_score = Column(Float, default=0.0)
    exploitability_score = Column(Float, default=0.0)
    age_days = Column(Integer, default=0)
    pattern_frequency = Column(Integer, default=0)
    
    # Foreign keys
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    introduced_commit = Column(String(40), nullable=True)
    fixed_commit = Column(String(40), nullable=True)
    
    # Raw data from scanners
    raw_data = Column(JSON)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    state_history = relationship("VulnerabilityStateHistory", back_populates="vulnerability")
    
    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type={self.type}, state={self.state.value})>"


class VulnerabilityStateHistory(Base):
    """Tracks state transitions for vulnerabilities"""
    __tablename__ = "vulnerability_state_history"
    
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    
    from_state = Column(Enum(VulnerabilityState))
    to_state = Column(Enum(VulnerabilityState), nullable=False)
    
    timestamp = Column(DateTime, default=datetime.utcnow)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    
    # Context
    reason = Column(Text)  # Why the state changed
    commit_hash = Column(String(40))
    
    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="state_history")
    
    def __repr__(self):
        return f"<StateHistory(vuln_id={self.vulnerability_id}, {self.from_state} → {self.to_state})>"


class CodeChange(Base):
    """Tracks code changes between scans"""
    __tablename__ = "code_changes"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    file_path = Column(String(512), nullable=False)
    change_type = Column(String(20))  # added, modified, deleted, renamed
    
    lines_added = Column(Integer, default=0)
    lines_deleted = Column(Integer, default=0)
    complexity_delta = Column(Integer, default=0)  # Change in cyclomatic complexity
    
    commit_hash = Column(String(40), nullable=False)
    author = Column(String(255))
    timestamp = Column(DateTime)
    
    # Relationships
    scan = relationship("Scan", back_populates="code_changes")
    
    def __repr__(self):
        return f"<CodeChange(file={self.file_path}, type={self.change_type})>"


class SecurityPattern(Base):
    """Identified security patterns and anti-patterns"""
    __tablename__ = "security_patterns"
    
    id = Column(Integer, primary_key=True)
    
    name = Column(String(255), nullable=False)
    category = Column(String(100))  # vulnerability-pattern, anti-pattern, best-practice
    description = Column(Text)
    
    # Pattern detection
    pattern_type = Column(String(50))  # code-structure, naming, data-flow
    detection_rule = Column(Text)  # Rule or regex for detection
    
    # Statistics
    occurrence_count = Column(Integer, default=0)
    files_affected = Column(JSON)  # List of files where pattern appears
    
    # Risk
    severity = Column(String(20))
    remediation = Column(Text)
    
    first_detected = Column(DateTime, default=datetime.utcnow)
    last_detected = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<SecurityPattern(name={self.name}, occurrences={self.occurrence_count})>"


class SecurityMetric(Base):
    """Historical security metrics for trend analysis"""
    __tablename__ = "security_metrics"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Vulnerability counts by severity
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    # Lifecycle metrics
    new_vulnerabilities = Column(Integer, default=0)
    fixed_vulnerabilities = Column(Integer, default=0)
    regressed_vulnerabilities = Column(Integer, default=0)
    
    # Time metrics
    mean_time_to_fix_days = Column(Float, default=0.0)
    oldest_vulnerability_days = Column(Integer, default=0)
    
    # Code metrics
    total_files_scanned = Column(Integer, default=0)
    vulnerable_files_count = Column(Integer, default=0)
    code_churn_lines = Column(Integer, default=0)  # Lines changed since last scan
    
    # Risk metrics
    average_risk_score = Column(Float, default=0.0)
    max_risk_score = Column(Float, default=0.0)
    
    # Pattern metrics
    pattern_count = Column(Integer, default=0)
    
    def __repr__(self):
        return f"<SecurityMetric(scan_id={self.scan_id}, total={self.critical_count + self.high_count + self.medium_count + self.low_count})>"
