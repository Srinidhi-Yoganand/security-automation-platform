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

# Import semantic analysis router
from app.api.semantic_routes import router as semantic_router

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

# Register routers
app.include_router(semantic_router)


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


@app.get("/api/llm/status")
async def llm_status():
    """Check LLM provider status"""
    try:
        from app.services.patcher.llm_patch_generator import LLMPatchGenerator
        
        generator = LLMPatchGenerator()
        
        status = {
            "provider": generator.llm_provider,
            "status": "operational" if generator.llm_provider != "template" else "fallback",
            "available_providers": []
        }
        
        # Check each provider
        try:
            import google.generativeai as genai
            import os
            if os.getenv("GEMINI_API_KEY"):
                status["available_providers"].append("gemini")
        except:
            pass
        
        try:
            import ollama
            try:
                client = ollama.Client()
                models = client.list()
                if models and models.get('models'):
                    status["available_providers"].append("ollama")
                    status["ollama_models"] = [m.get('name', m.get('model', '')) for m in models['models']]
            except:
                pass
        except:
            pass
        
        try:
            import openai
            import os
            if os.getenv("OPENAI_API_KEY"):
                status["available_providers"].append("openai")
        except:
            pass
        
        if not status["available_providers"]:
            status["available_providers"].append("template")
        
        return status
    except Exception as e:
        return {"status": "error", "error": str(e)}


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


@app.post("/api/v1/vulnerabilities/{vuln_id}/generate-patch")
async def generate_patch_for_vulnerability(
    vuln_id: int, 
    repo_path: str = "../vulnerable-app",
    test_patch: bool = True
):
    """
    Generate an LLM-powered security patch for a specific vulnerability
    
    Args:
        vuln_id: Vulnerability ID from database
        repo_path: Path to repository (default: ../vulnerable-app)
        test_patch: Whether to test patch in separate branch (default: True)
    """
    from app.database import get_db
    from app.models import Vulnerability
    from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
    
    with get_db() as db:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Create patch context with full vulnerability info
        context = PatchContext(
            vulnerability_type=vuln.type,
            file_path=vuln.file_path,
            line_number=vuln.line_number,
            vulnerable_code=vuln.message or "",
            severity=vuln.severity,
            confidence=vuln.confidence,
            description=vuln.description,
            cwe_id=vuln.cwe_id,
            tool_name=vuln.tool
        )
        
        # Generate patch using LLM
        generator = LLMPatchGenerator(repo_path)
        patch = generator.generate_patch(context, test_patch=test_patch)
        
        if not patch:
            return {
                "success": False,
                "message": f"Unable to generate patch for {vuln.type}",
                "vulnerability": {
                    "id": vuln.id,
                    "type": vuln.type,
                    "file": vuln.file_path,
                    "line": vuln.line_number
                }
            }
        
        # Update vulnerability with patch info
        vuln.patch_available = True
        db.commit()
        
        # Send notifications
        try:
            from app.services.notifications import NotificationService
            notifier = NotificationService()
            notification_results = notifier.notify_patch_generated({
                "vulnerability_type": patch.vulnerability_type,
                "severity": vuln.severity,
                "file_path": patch.file_path,
                "line_number": patch.line_number,
                "confidence": patch.confidence,
                "explanation": patch.explanation,
                "llm_provider": generator.llm_provider,
                "original_code": patch.original_code,
                "fixed_code": patch.fixed_code
            })
        except Exception as e:
            print(f"Notification failed: {e}")
            notification_results = {"error": str(e)}
        
        return {
            "success": True,
            "notifications_sent": notification_results,
            "vulnerability": {
                "id": vuln.id,
                "type": patch.vulnerability_type,
                "file": patch.file_path,
                "line": patch.line_number,
                "severity": vuln.severity,
                "risk_score": vuln.risk_score
            },
            "patch": {
                "original_code": patch.original_code,
                "fixed_code": patch.fixed_code,
                "explanation": patch.explanation,
                "confidence": patch.confidence,
                "status": patch.status.value,
                "test_branch": patch.test_branch,
                "test_results": patch.test_results,
                "breaking_changes": patch.breaking_changes or [],
                "prerequisites": patch.prerequisites or [],
                "manual_review_needed": patch.manual_review_needed,
                "remediation_guide": patch.remediation_guide,
                "diff": patch.diff
            }
        }


@app.post("/api/v1/scans/{scan_id}/generate-patches")
async def generate_patches_for_scan(
    scan_id: int, 
    repo_path: str = "../vulnerable-app", 
    limit: int = 20,
    test_patches: bool = True
):
    """
    Generate LLM-powered patches for all fixable vulnerabilities in a scan
    
    Args:
        scan_id: Scan ID from database
        repo_path: Path to repository (default: ../vulnerable-app)
        limit: Maximum number of patches to generate (default: 20)
        test_patches: Whether to test patches in separate branches (default: True)
    """
    from app.database import get_db
    from app.models import Vulnerability, Scan
    from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
    
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get all non-fixed vulnerabilities from this scan
        vulns = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_id,
            Vulnerability.state != 'fixed'
        ).order_by(Vulnerability.risk_score.desc()).limit(limit).all()
        
        generator = LLMPatchGenerator(repo_path)
        patches = []
        skipped = []
        
        for vuln in vulns:
            print(f"\n{'='*60}")
            print(f"Processing vulnerability {vuln.id}: {vuln.type}")
            print(f"{'='*60}")
            
            context = PatchContext(
                vulnerability_type=vuln.type,
                file_path=vuln.file_path,
                line_number=vuln.line_number,
                vulnerable_code=vuln.message or "",
                severity=vuln.severity,
                confidence=vuln.confidence,
                description=vuln.description,
                cwe_id=vuln.cwe_id,
                tool_name=vuln.tool
            )
            
            patch = generator.generate_patch(context, test_patch=test_patches)
            
            if patch:
                # Update vulnerability
                vuln.patch_available = True
                
                patches.append({
                    "vulnerability_id": vuln.id,
                    "type": patch.vulnerability_type,
                    "file": patch.file_path,
                    "line": patch.line_number,
                    "risk_score": vuln.risk_score,
                    "original_code": patch.original_code,
                    "fixed_code": patch.fixed_code,
                    "explanation": patch.explanation,
                    "confidence": patch.confidence,
                    "status": patch.status.value,
                    "test_branch": patch.test_branch,
                    "test_results": patch.test_results,
                    "breaking_changes": patch.breaking_changes or [],
                    "prerequisites": patch.prerequisites or [],
                    "manual_review_needed": patch.manual_review_needed,
                    "diff": patch.diff
                })
            else:
                skipped.append({
                    "vulnerability_id": vuln.id,
                    "type": vuln.type,
                    "reason": "Patch generation failed or not applicable"
                })
        
        # Commit database changes
        db.commit()
        
        return {
            "scan_id": scan_id,
            "commit_hash": scan.commit_hash,
            "patches_generated": len(patches),
            "vulnerabilities_skipped": len(skipped),
            "patches": patches,
            "skipped": skipped,
            "note": "Test patches in their respective branches before approving and applying"
        }


@app.post("/api/v1/patches/{vuln_id}/test")
async def test_patch_in_branch(vuln_id: int, repo_path: str = "../vulnerable-app"):
    """
    Test an existing patch in an isolated branch
    Re-tests a previously generated patch
    """
    from app.database import get_db
    from app.models import Vulnerability
    from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
    
    with get_db() as db:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        if not vuln.patch_available:
            raise HTTPException(status_code=400, detail="No patch available for this vulnerability")
        
        # Regenerate patch with testing enabled
        context = PatchContext(
            vulnerability_type=vuln.type,
            file_path=vuln.file_path,
            line_number=vuln.line_number,
            vulnerable_code=vuln.message or "",
            severity=vuln.severity,
            confidence=vuln.confidence,
            description=vuln.description,
            cwe_id=vuln.cwe_id,
            tool_name=vuln.tool
        )
        
        generator = LLMPatchGenerator(repo_path)
        patch = generator.generate_patch(context, test_patch=True)
        
        if not patch:
            return {"success": False, "message": "Failed to regenerate patch"}
        
        return {
            "success": True,
            "vulnerability_id": vuln_id,
            "test_branch": patch.test_branch,
            "test_results": patch.test_results,
            "status": patch.status.value
        }


@app.post("/api/v1/patches/apply")
async def apply_patch(
    test_branch: str,
    target_branch: str = "main",
    repo_path: str = "../vulnerable-app"
):
    """
    Apply an approved patch from test branch to target branch
    
    Args:
        test_branch: Name of the test branch with the patch
        target_branch: Target branch to merge into (default: main)
        repo_path: Path to repository
    """
    from app.services.patcher.llm_patch_generator import LLMPatchGenerator
    from git import Repo
    
    try:
        repo = Repo(repo_path)
        generator = LLMPatchGenerator(repo_path)
        
        # Check if test branch exists
        if test_branch not in [b.name for b in repo.heads]:
            raise HTTPException(status_code=404, detail=f"Test branch '{test_branch}' not found")
        
        # Checkout target branch
        repo.heads[target_branch].checkout()
        
        # Merge test branch
        repo.git.merge(test_branch, no_ff=True)
        
        return {
            "success": True,
            "message": f"Patch from '{test_branch}' applied to '{target_branch}'",
            "target_branch": target_branch,
            "merged_branch": test_branch
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply patch: {str(e)}")



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
    
    # Generate dashboard with optional Phase 2 behavior analysis
    include_behavior = args.behavior if hasattr(args, 'behavior') else False
    generator = DashboardGenerator(include_behavior_analysis=include_behavior)
    dashboard_html = generator.generate(report_data)
    
    # Save dashboard
    output_path = Path(args.output)
    output_path.write_text(dashboard_html, encoding='utf-8')
    
    if include_behavior:
        print(f"✅ Enhanced dashboard with behavior analysis generated: {args.output}")
    else:
        print(f"✅ Dashboard generated: {args.output}")


def cli_integrate(args):
    """Integrate Phase 1 correlation with Phase 2 behavior tracking"""
    from app.core.correlator import SecurityCorrelator
    from app.services.behavior.lifecycle_tracker import VulnerabilityLifecycleTracker
    from app.core.git_analyzer import GitHistoryAnalyzer
    from app.database import get_db, init_db
    from app.models import Scan
    from datetime import datetime
    
    print("🔗 Running Phase 1 + Phase 2 Integration...")
    
    # Initialize database
    init_db()
    
    # Phase 1: Correlation
    print("\n📊 Phase 1: Correlating findings...")
    correlator = SecurityCorrelator()
    
    # Load scanner outputs
    if args.semgrep:
        semgrep_path = Path(args.semgrep)
        if semgrep_path.exists():
            correlator.add_semgrep_results(semgrep_path.read_text())
            print(f"  ✅ Loaded Semgrep results: {args.semgrep}")
    
    if args.codeql:
        codeql_path = Path(args.codeql)
        if codeql_path.exists():
            correlator.add_codeql_results(codeql_path.read_text())
            print(f"  ✅ Loaded CodeQL results: {args.codeql}")
    
    if args.zap:
        zap_path = Path(args.zap)
        if zap_path.exists():
            correlator.add_zap_results(zap_path.read_text())
            print(f"  ✅ Loaded ZAP results: {args.zap}")
    
    # Run correlation
    correlation_results = correlator.correlate()
    print(f"  ✅ Found {correlation_results['correlated_count']} correlated findings")
    
    # Phase 2: Behavior Analysis
    print("\n🔍 Phase 2: Tracking vulnerability lifecycle...")
    
    # Get git information
    git_analyzer = GitHistoryAnalyzer(args.repo if hasattr(args, 'repo') else '.')
    commit_info = git_analyzer.get_current_commit()
    
    with get_db() as db:
        # Create scan record
        scan = Scan(
            timestamp=datetime.now(),
            commit_hash=commit_info['hash'],
            branch=commit_info.get('branch', 'main'),
            author=commit_info['author'],
            commit_message=commit_info.get('message', 'Automated scan'),
            total_findings=correlation_results['total_findings'],
            correlated_count=correlation_results['correlated_count'],
            critical_count=correlation_results.get('critical', 0),
            high_count=correlation_results.get('high', 0),
            medium_count=correlation_results.get('medium', 0),
            low_count=correlation_results.get('low', 0)
        )
        db.add(scan)
        db.flush()
        
        print(f"  ✅ Created scan #{scan.id} for commit {commit_info['hash'][:8]}")
        
        # Track vulnerabilities
        tracker = VulnerabilityLifecycleTracker(db, git_analyzer)
        lifecycle_results = tracker.process_scan_results(
            scan.id,
            correlation_results['findings'],
            commit_info['hash']
        )
        
        db.commit()
        
        print(f"\n📈 Lifecycle Analysis:")
        print(f"  🆕 New vulnerabilities: {len(lifecycle_results['new'])}")
        print(f"  ♻️  Existing vulnerabilities: {len(lifecycle_results['existing'])}")
        print(f"  ✅ Fixed vulnerabilities: {len(lifecycle_results['fixed'])}")
        print(f"  ⚠️  Regressed vulnerabilities: {len(lifecycle_results['regressed'])}")
        
        # Calculate risk scores
        from app.services.behavior.risk_scorer import RiskScorer
        scorer = RiskScorer()
        
        high_risk = []
        for vuln_list in [lifecycle_results['new'], lifecycle_results['existing'], lifecycle_results['regressed']]:
            for vuln in vuln_list:
                if vuln.risk_score >= 7.0:
                    high_risk.append(vuln)
        
        if high_risk:
            print(f"\n⚠️  HIGH RISK VULNERABILITIES: {len(high_risk)}")
            for vuln in sorted(high_risk, key=lambda v: v.risk_score, reverse=True)[:5]:
                risk_cat = scorer.get_risk_category(vuln.risk_score)
                print(f"  - {vuln.type} (Risk: {vuln.risk_score:.1f} - {risk_cat})")
                print(f"    {vuln.file_path}:{vuln.line_number}")
        
        # Run pattern analysis
        print(f"\n🎯 Analyzing security patterns...")
        from app.services.behavior.pattern_analyzer import PatternAnalyzer
        analyzer = PatternAnalyzer(db)
        patterns = analyzer.analyze_patterns()
        
        print(f"  ✅ Detected {len(patterns['patterns_found'])} patterns")
        print(f"  🔥 Found {len(patterns['hotspots'])} security hotspots")
        print(f"  🔗 Identified {len(patterns['clusters'])} vulnerability clusters")
        
        # Save combined results
        if args.output:
            combined_results = {
                'phase1_correlation': correlation_results,
                'phase2_lifecycle': {
                    'scan_id': scan.id,
                    'commit': commit_info,
                    'new': len(lifecycle_results['new']),
                    'existing': len(lifecycle_results['existing']),
                    'fixed': len(lifecycle_results['fixed']),
                    'regressed': len(lifecycle_results['regressed'])
                },
                'phase2_patterns': {
                    'patterns': len(patterns['patterns_found']),
                    'hotspots': len(patterns['hotspots']),
                    'clusters': len(patterns['clusters'])
                },
                'high_risk_count': len(high_risk)
            }
            
            output_path = Path(args.output)
            output_path.write_text(json.dumps(combined_results, indent=2))
            print(f"\n💾 Results saved to: {args.output}")
        
        # Generate enhanced dashboard if requested
        if args.dashboard:
            print(f"\n📊 Generating enhanced dashboard...")
            from app.services.dashboard_generator import DashboardGenerator
            
            generator = DashboardGenerator(include_behavior_analysis=True)
            dashboard_html = generator.generate(correlation_results)
            
            dashboard_path = Path(args.dashboard)
            dashboard_path.write_text(dashboard_html, encoding='utf-8')
            print(f"  ✅ Enhanced dashboard: {args.dashboard}")
    
    print("\n✅ Phase 1 + Phase 2 Integration Complete!")


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
    dashboard_parser.add_argument(
        "--behavior",
        action="store_true",
        help="Include Phase 2 behavior analysis (requires database)"
    )
    
    # Integrate command (Phase 1 + Phase 2)
    integrate_parser = subparsers.add_parser(
        "integrate",
        help="Run Phase 1 correlation + Phase 2 behavior tracking"
    )
    integrate_parser.add_argument(
        "--semgrep",
        help="Path to Semgrep SARIF file"
    )
    integrate_parser.add_argument(
        "--codeql",
        help="Path to CodeQL results directory"
    )
    integrate_parser.add_argument(
        "--zap",
        help="Path to ZAP JSON file"
    )
    integrate_parser.add_argument(
        "--repo",
        default=".",
        help="Path to git repository (default: current directory)"
    )
    integrate_parser.add_argument(
        "--output",
        help="Output JSON file for combined results"
    )
    integrate_parser.add_argument(
        "--dashboard",
        help="Generate enhanced dashboard HTML file"
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
    elif args.command == "integrate":
        cli_integrate(args)
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
