"""
Main application entry point for the Security Correlation Engine.
Provides both FastAPI web service and CLI interface.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Application metadata
__version__ = "0.1.0"
__title__ = "Security Correlation Engine"

# Create FastAPI app
app = FastAPI(
    title=__title__,
    version=__version__,
    description="Intelligent security findings correlation and analysis platform",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Models
class CorrelationRequest(BaseModel):
    """Request model for correlation endpoint"""
    semgrep_sarif: Optional[str] = None
    codeql_data: Optional[str] = None
    zap_json: Optional[str] = None


class CorrelationResponse(BaseModel):
    """Response model for correlation results"""
    correlation_id: str
    total_findings: int
    correlated_findings: int
    confirmed_vulnerabilities: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings: list


# API Routes
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": __title__,
        "version": __version__,
        "status": "operational",
        "endpoints": {
            "correlate": "/api/v1/correlate",
            "findings": "/api/v1/findings/{correlation_id}",
            "health": "/health"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": __version__}


@app.post("/api/v1/correlate", response_model=CorrelationResponse)
async def correlate_findings(request: CorrelationRequest):
    """
    Correlate security findings from multiple scanners.
    
    Phase 1 implementation:
    - Parse SARIF, JSON, and CodeQL results
    - Perform basic correlation by file/line matching
    - Use CodeQL data flow to confirm vulnerabilities
    """
    # TODO: Implement correlation logic
    # For now, return a mock response
    return CorrelationResponse(
        correlation_id="mock-correlation-001",
        total_findings=0,
        correlated_findings=0,
        confirmed_vulnerabilities=0,
        findings=[]
    )


# Phase 2 API Endpoints
@app.get("/api/v1/vulnerabilities")
async def list_vulnerabilities(
    state: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50
):
    """
    List vulnerabilities with optional filtering.
    
    Query parameters:
    - state: Filter by state (new, existing, fixed, regressed, ignored)
    - severity: Filter by severity (critical, high, medium, low)
    - limit: Maximum number of results (default: 50)
    """
    from app.database import get_db
    from app.models import Vulnerability
    
    with get_db() as db:
        query = db.query(Vulnerability)
        
        if state:
            query = query.filter(Vulnerability.state == state)
        if severity:
            query = query.filter(Vulnerability.severity == severity)
        
        vulns = query.limit(limit).all()
        
        return {
            "count": len(vulns),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type,
                    "severity": v.severity,
                    "state": v.state.value,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "confidence": v.confidence,
                    "risk_score": v.risk_score,
                    "age_days": v.age_days,
                    "first_seen": v.first_seen.isoformat() if v.first_seen else None,
                    "last_seen": v.last_seen.isoformat() if v.last_seen else None
                }
                for v in vulns
            ]
        }


@app.get("/api/v1/vulnerabilities/{vuln_id}/history")
async def get_vulnerability_history(vuln_id: int):
    """Get complete history of a vulnerability including all state transitions"""
    from app.database import get_db
    from app.models import Vulnerability
    from app.services.behavior.lifecycle_tracker import VulnerabilityLifecycleTracker
    
    with get_db() as db:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        tracker = VulnerabilityLifecycleTracker(db, None)
        history = tracker.get_vulnerability_history(vuln.fingerprint)
        
        return history


@app.get("/api/v1/metrics/overview")
async def get_metrics_overview():
    """Get overall security metrics"""
    from app.database import get_db
    from app.models import Vulnerability, Scan
    from app.services.behavior.lifecycle_tracker import VulnerabilityLifecycleTracker
    
    with get_db() as db:
        total_scans = db.query(Scan).count()
        total_vulns = db.query(Vulnerability).count()
        
        # Count by state
        from collections import defaultdict
        state_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        vulns = db.query(Vulnerability).all()
        for v in vulns:
            state_counts[v.state.value] += 1
            severity_counts[v.severity] += 1
        
        # Calculate MTTF
        tracker = VulnerabilityLifecycleTracker(db, None)
        mttf = tracker.calculate_mean_time_to_fix()
        
        # Average risk score
        avg_risk = sum(v.risk_score for v in vulns) / len(vulns) if vulns else 0
        
        return {
            "total_scans": total_scans,
            "total_vulnerabilities": total_vulns,
            "by_state": dict(state_counts),
            "by_severity": dict(severity_counts),
            "mean_time_to_fix_days": round(mttf, 2),
            "average_risk_score": round(avg_risk, 2)
        }


@app.get("/api/v1/patterns")
async def get_security_patterns():
    """Get identified security patterns and anti-patterns"""
    from app.database import get_db
    from app.services.behavior.pattern_analyzer import PatternAnalyzer
    
    with get_db() as db:
        analyzer = PatternAnalyzer(db)
        
        # Get pattern trends
        trends = analyzer.get_pattern_trends()
        
        return {
            "patterns": trends
        }


@app.post("/api/v1/patterns/analyze")
async def analyze_patterns():
    """Run pattern analysis on current vulnerabilities"""
    from app.database import get_db
    from app.services.behavior.pattern_analyzer import PatternAnalyzer
    
    with get_db() as db:
        analyzer = PatternAnalyzer(db)
        results = analyzer.analyze_patterns()
        
        return results


@app.get("/api/v1/risk-scores")
async def get_risk_ranked_vulnerabilities(limit: int = 20):
    """Get vulnerabilities ranked by risk score"""
    from app.database import get_db
    from app.models import Vulnerability
    from app.services.behavior.risk_scorer import RiskScorer
    
    with get_db() as db:
        vulns = db.query(Vulnerability).filter(
            Vulnerability.state != 'fixed'
        ).order_by(Vulnerability.risk_score.desc()).limit(limit).all()
        
        scorer = RiskScorer()
        
        return {
            "count": len(vulns),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type,
                    "severity": v.severity,
                    "risk_score": v.risk_score,
                    "risk_category": scorer.get_risk_category(v.risk_score),
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "age_days": v.age_days,
                    "state": v.state.value
                }
                for v in vulns
            ]
        }


@app.get("/api/v1/findings/{correlation_id}")
async def get_findings(correlation_id: str):
    """Retrieve correlation results by ID"""
    # TODO: Implement database lookup
    raise HTTPException(status_code=404, detail="Correlation not found")


# CLI Interface
def cli_correlate(args):
    """CLI command to correlate scan results"""
    from app.core.correlator import SecurityCorrelator
    from app.core.parsers.semgrep_parser import SemgrepParser
    from app.core.parsers.zap_parser import ZapParser
    from app.core.parsers.codeql_parser import CodeQLParser
    
    print(f"🔍 Starting correlation analysis...")
    
    # Initialize correlator
    correlator = SecurityCorrelator()
    
    # Parse Semgrep results
    if args.semgrep:
        print(f"📄 Parsing Semgrep SARIF: {args.semgrep}")
        semgrep_findings = SemgrepParser.parse(args.semgrep)
        correlator.add_findings("semgrep", semgrep_findings)
    
    # Parse CodeQL results
    if args.codeql:
        print(f"📄 Parsing CodeQL data: {args.codeql}")
        codeql_findings = CodeQLParser.parse(args.codeql)
        correlator.add_findings("codeql", codeql_findings)
    
    # Parse ZAP results
    if args.zap:
        print(f"📄 Parsing ZAP JSON: {args.zap}")
        zap_findings = ZapParser.parse(args.zap)
        correlator.add_findings("zap", zap_findings)
    
    # Perform correlation
    print("🔗 Correlating findings...")
    results = correlator.correlate()
    
    # Save results
    output_path = Path(args.output)
    output_path.write_text(json.dumps(results, indent=2))
    print(f"✅ Correlation report saved to: {args.output}")
    print(f"📊 Total findings: {results.get('total_findings', 0)}")
    print(f"🎯 Correlated: {results.get('correlated_count', 0)}")
    print(f"⚠️  Critical: {results.get('critical', 0)}")
    print(f"🔴 High: {results.get('high', 0)}")


def cli_dashboard(args):
    """CLI command to generate security dashboard"""
    from app.services.dashboard_generator import DashboardGenerator
    
    print(f"📊 Generating security dashboard...")
    
    # Load correlation report
    report_path = Path(args.input)
    if not report_path.exists():
        print(f"❌ Error: Report file not found: {args.input}")
        sys.exit(1)
    
    report_data = json.loads(report_path.read_text())
    
    # Generate dashboard
    generator = DashboardGenerator()
    dashboard_html = generator.generate(report_data)
    
    # Save dashboard
    output_path = Path(args.output)
    output_path.write_text(dashboard_html, encoding='utf-8')
    print(f"✅ Dashboard generated: {args.output}")


def cli_database(args):
    """Handle database operations"""
    from app.database import init_db, drop_db, engine
    from app.models import Base
    
    if args.action == "init":
        print("🔧 Initializing database...")
        init_db()
        
    elif args.action == "reset":
        print("⚠️  Resetting database (this will delete all data)...")
        response = input("Are you sure? (yes/no): ")
        if response.lower() == "yes":
            drop_db()
            init_db()
            print("✅ Database reset complete")
        else:
            print("❌ Operation cancelled")
            
    elif args.action == "status":
        print("📊 Database status:")
        print(f"   Engine: {engine.url}")
        print(f"   Tables: {', '.join(Base.metadata.tables.keys())}")
        
        # Check if tables exist
        from sqlalchemy import inspect
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        if existing_tables:
            print(f"   Initialized: ✅ ({len(existing_tables)} tables found)")
        else:
            print(f"   Initialized: ❌ (run 'db init' to create tables)")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Security Correlation Engine - CLI Interface"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Correlate command
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="Correlate security scan results"
    )
    correlate_parser.add_argument(
        "--semgrep",
        help="Path to Semgrep SARIF file"
    )
    correlate_parser.add_argument(
        "--codeql",
        help="Path to CodeQL results directory"
    )
    correlate_parser.add_argument(
        "--zap",
        help="Path to ZAP JSON file"
    )
    correlate_parser.add_argument(
        "--output",
        default="correlation-report.json",
        help="Output file path"
    )
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="Generate security dashboard"
    )
    dashboard_parser.add_argument(
        "--input",
        required=True,
        help="Path to correlation report JSON"
    )
    dashboard_parser.add_argument(
        "--output",
        default="security-dashboard.html",
        help="Output HTML file path"
    )
    
    # Database command (Phase 2)
    db_parser = subparsers.add_parser(
        "db",
        help="Database operations"
    )
    db_parser.add_argument(
        "action",
        choices=["init", "reset", "status"],
        help="Database action to perform"
    )
    
    args = parser.parse_args()
    
    if args.command == "correlate":
        cli_correlate(args)
    elif args.command == "dashboard":
        cli_dashboard(args)
    elif args.command == "db":
        cli_database(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    # Check if running as CLI or web server
    if len(sys.argv) > 1 and sys.argv[1] != "uvicorn":
        main()
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
