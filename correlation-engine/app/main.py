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
    
    args = parser.parse_args()
    
    if args.command == "correlate":
        cli_correlate(args)
    elif args.command == "dashboard":
        cli_dashboard(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    # Check if running as CLI or web server
    if len(sys.argv) > 1 and sys.argv[1] != "uvicorn":
        main()
    else:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000)
