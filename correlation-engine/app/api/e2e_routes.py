"""
End-to-End API Routes

Unified endpoints that orchestrate complete security analysis pipeline:
CodeQL Semantic Analysis → Z3 Symbolic Execution → LLM Patch Generation → Validation
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
from pathlib import Path
import json

router = APIRouter(prefix="/api/v1/e2e", tags=["end-to-end"])


class AnalyzeAndFixRequest(BaseModel):
    """Request model for complete analysis and fix"""
    source_path: str
    language: str = "java"
    create_database: bool = True
    generate_patches: bool = True
    validate_patches: bool = True
    test_patches: bool = False
    llm_provider: Optional[str] = None  # gemini, openai, ollama, or template


class VulnerabilityResult(BaseModel):
    """Vulnerability detection result"""
    type: str
    file_path: str
    line_number: int
    method_name: Optional[str]
    severity: str
    confidence: float
    data_flows: List[Dict]
    symbolic_proof: Dict
    cve_references: List[str]


class PatchResult(BaseModel):
    """Patch generation result"""
    original_code: str
    patched_code: str
    explanation: str
    template_used: Optional[str]
    validation: Dict


class AnalyzeAndFixResponse(BaseModel):
    """Complete analysis and fix response"""
    success: bool
    source_path: str
    vulnerabilities_found: int
    vulnerabilities_fixed: int
    results: List[Dict]
    summary: Dict


@router.post("/analyze-and-fix", response_model=AnalyzeAndFixResponse)
async def analyze_and_fix(request: AnalyzeAndFixRequest):
    """
    Complete end-to-end security analysis and automated patching
    
    Pipeline stages:
    1. CodeQL semantic analysis - Detect vulnerabilities with data flow
    2. Z3 symbolic execution - Verify exploitability
    3. Enhanced context building - Combine semantic + symbolic data
    4. LLM patch generation - Generate security fixes
    5. Patch validation - Verify fixes work correctly
    
    Returns comprehensive results with validated patches.
    """
    from app.core.git_analyzer import SemanticAnalyzer
    from app.services.behavior.symbolic_executor import SymbolicExecutor
    from app.services.patcher.context_builder import SemanticContextBuilder, EnhancedPatchContext
    from app.services.patcher.semantic_patch_generator import SemanticPatchGenerator
    from app.services.patcher.patch_validator import PatchValidator
    from app.services.patcher.cve_database import get_cve_database
    
    source_path = Path(request.source_path)
    if not source_path.exists():
        raise HTTPException(status_code=404, detail=f"Source path not found: {request.source_path}")
    
    results = []
    
    # ============================================
    # STAGE 1: CodeQL Semantic Analysis
    # ============================================
    print("\n" + "="*80)
    print("STAGE 1: CodeQL Semantic Analysis")
    print("="*80)
    
    analyzer = SemanticAnalyzer(workspace_path=str(source_path))
    
    # Create or use existing database
    db_path = source_path.parent / "codeql-databases" / f"{source_path.name}-db"
    
    if request.create_database and not db_path.exists():
        print(f"Creating CodeQL database at {db_path}...")
        db_result = analyzer.create_database(
            source_root=str(source_path),
            database_path=str(db_path),
            language=request.language
        )
        if not db_result["success"]:
            raise HTTPException(status_code=500, detail=f"Database creation failed: {db_result.get('error')}")
    
    # Run semantic queries
    print("Running semantic analysis queries...")
    
    # Try multiple query files
    query_files = [
        "correlation-engine/app/core/parsers/codeql-queries/java/idor-detection.ql",
        "correlation-engine/app/core/parsers/codeql-queries/java/semantic-idor.ql"
    ]
    
    codeql_findings = []
    for query_file in query_files:
        query_path = Path(query_file)
        if query_path.exists():
            query_result = analyzer.run_query(
                database_path=str(db_path),
                query_file=str(query_path)
            )
            if query_result["success"]:
                codeql_findings.extend(query_result.get("results", []))
                break
    
    print(f"✓ Found {len(codeql_findings)} vulnerabilities")
    
    # ============================================
    # STAGE 2-5: Process Each Vulnerability
    # ============================================
    
    symbolic_executor = SymbolicExecutor()
    context_builder = SemanticContextBuilder()
    patch_generator = SemanticPatchGenerator()
    patch_validator = PatchValidator()
    cve_db = get_cve_database()
    
    vulnerabilities_fixed = 0
    
    for idx, finding in enumerate(codeql_findings, 1):
        print(f"\n{'='*80}")
        print(f"Processing Vulnerability {idx}/{len(codeql_findings)}")
        print(f"{'='*80}")
        
        vuln_type = finding.get("vulnerability_type", "IDOR")
        file_path = finding.get("file", "")
        line_number = finding.get("line", 0)
        method_name = finding.get("method", "")
        
        print(f"Type: {vuln_type}")
        print(f"File: {file_path}")
        print(f"Line: {line_number}")
        print(f"Method: {method_name}")
        
        # Read source code
        try:
            code_file = source_path / file_path if not Path(file_path).is_absolute() else Path(file_path)
            if not code_file.exists():
                print(f"⚠️  File not found, skipping...")
                continue
                
            with open(code_file, 'r') as f:
                source_code = f.read()
        except Exception as e:
            print(f"⚠️  Error reading file: {e}")
            continue
        
        # ============================================
        # STAGE 2: Z3 Symbolic Execution
        # ============================================
        print("\nSTAGE 2: Running symbolic execution...")
        
        symbolic_result = symbolic_executor.check_idor_vulnerability(
            code=source_code,
            method_name=method_name,
            user_id_param=finding.get("parameter", "userId")
        )
        
        if not symbolic_result.get("vulnerable"):
            print("✓ Symbolic execution: Not exploitable, skipping...")
            continue
        
        print(f"✓ Symbolic execution confirmed: {symbolic_result.get('reason')}")
        
        # ============================================
        # STAGE 3: Enhanced Context Building
        # ============================================
        print("\nSTAGE 3: Building enhanced context...")
        
        # Extract data flows from CodeQL finding
        data_flows = finding.get("data_flows", [])
        if not data_flows and "source" in finding and "sink" in finding:
            data_flows = [{
                "source": finding["source"],
                "sink": finding["sink"],
                "path": [finding["source"], finding["sink"]]
            }]
        
        # Get CVE references
        cve_refs = cve_db.get_references_for_vulnerability(vuln_type)
        cve_list = [cve.cve_id for cve in cve_refs] if cve_refs else []
        
        context = EnhancedPatchContext(
            file_path=str(code_file),
            vulnerable_code=source_code,
            vulnerability_type=vuln_type,
            method_name=method_name,
            line_number=line_number,
            data_flows=data_flows,
            security_context={
                "missing_authorization": symbolic_result.get("missing_authorization", True),
                "missing_authentication": False,
                "user_controlled_input": finding.get("parameter", "userId")
            },
            symbolic_proof=symbolic_result,
            cve_references=cve_list
        )
        
        print(f"✓ Context built with {len(data_flows)} data flows")
        
        # ============================================
        # STAGE 4: Patch Generation
        # ============================================
        if not request.generate_patches:
            print("\nSkipping patch generation (disabled)")
            results.append({
                "vulnerability": {
                    "type": vuln_type,
                    "file": str(code_file),
                    "line": line_number,
                    "method": method_name,
                    "severity": finding.get("severity", "high"),
                    "data_flows": data_flows,
                    "symbolic_proof": symbolic_result,
                    "cve_references": cve_list
                },
                "patch": None
            })
            continue
        
        print("\nSTAGE 4: Generating patch...")
        
        patch_result = patch_generator.generate_patch(
            code=source_code,
            vulnerability_type=vuln_type,
            method_name=method_name,
            symbolic_result=symbolic_result
        )
        
        if not patch_result.get("success"):
            print(f"⚠️  Patch generation failed: {patch_result.get('error')}")
            results.append({
                "vulnerability": {
                    "type": vuln_type,
                    "file": str(code_file),
                    "line": line_number,
                    "method": method_name
                },
                "patch": {"error": patch_result.get("error")}
            })
            continue
        
        patched_code = patch_result["patched_code"]
        print(f"✓ Patch generated using template: {patch_result.get('template_name')}")
        
        # ============================================
        # STAGE 5: Patch Validation
        # ============================================
        validation_result = None
        
        if request.validate_patches:
            print("\nSTAGE 5: Validating patch...")
            
            validation_result = patch_validator.validate_patch(
                original_code=source_code,
                patched_code=patched_code,
                vulnerability_type=vuln_type,
                method_name=method_name
            )
            
            print(f"✓ Validation complete")
            print(f"  Valid: {validation_result.is_valid}")
            print(f"  Vulnerability Fixed: {validation_result.vulnerability_fixed}")
            print(f"  Security Checks Added: {validation_result.security_checks_added}")
            print(f"  Score: {validation_result.score}/100")
            
            if validation_result.is_valid and validation_result.vulnerability_fixed:
                vulnerabilities_fixed += 1
        else:
            print("\nSkipping validation (disabled)")
            vulnerabilities_fixed += 1  # Assume success if validation disabled
        
        # Add to results
        results.append({
            "vulnerability": {
                "type": vuln_type,
                "file": str(code_file),
                "line": line_number,
                "method": method_name,
                "severity": finding.get("severity", "high"),
                "confidence": finding.get("confidence", 0.8),
                "data_flows": data_flows,
                "symbolic_proof": symbolic_result,
                "cve_references": cve_list
            },
            "patch": {
                "original_code": source_code[:500] + "..." if len(source_code) > 500 else source_code,
                "patched_code": patched_code[:500] + "..." if len(patched_code) > 500 else patched_code,
                "explanation": patch_result.get("explanation"),
                "template_used": patch_result.get("template_name"),
                "validation": {
                    "is_valid": validation_result.is_valid if validation_result else None,
                    "vulnerability_fixed": validation_result.vulnerability_fixed if validation_result else None,
                    "security_checks_added": validation_result.security_checks_added if validation_result else None,
                    "score": validation_result.score if validation_result else None,
                    "issues": validation_result.issues if validation_result else [],
                    "improvements": validation_result.improvements if validation_result else []
                } if validation_result else None
            }
        })
    
    # ============================================
    # FINAL SUMMARY
    # ============================================
    print("\n" + "="*80)
    print("END-TO-END ANALYSIS COMPLETE")
    print("="*80)
    print(f"\n✓ Vulnerabilities found: {len(codeql_findings)}")
    print(f"✓ Vulnerabilities processed: {len(results)}")
    print(f"✓ Vulnerabilities fixed: {vulnerabilities_fixed}")
    print("="*80 + "\n")
    
    return AnalyzeAndFixResponse(
        success=True,
        source_path=str(source_path),
        vulnerabilities_found=len(codeql_findings),
        vulnerabilities_fixed=vulnerabilities_fixed,
        results=results,
        summary={
            "total_analyzed": len(codeql_findings),
            "patches_generated": len([r for r in results if r["patch"]]),
            "patches_validated": len([r for r in results if r["patch"] and r["patch"].get("validation")]),
            "successful_fixes": vulnerabilities_fixed,
            "skipped": len(codeql_findings) - len(results)
        }
    )


@router.post("/analyze-and-fix-with-pr")
async def analyze_and_fix_with_pr(request: AnalyzeAndFixRequest, create_pr: bool = True, github_token: Optional[str] = None):
    """
    Complete end-to-end analysis with automatic PR creation
    
    Same as /analyze-and-fix but also:
    - Creates git branch with patches
    - Pushes branch to GitHub
    - Creates pull request automatically
    
    Requires GITHUB_TOKEN environment variable or github_token parameter
    """
    # Run standard analysis
    analysis_result = await analyze_and_fix(request)
    
    if not analysis_result.success or analysis_result.vulnerabilities_fixed == 0:
        return analysis_result
    
    if not create_pr:
        return analysis_result
    
    # Create PR with patches
    print("\n" + "="*80)
    print("CREATING PULL REQUEST")
    print("="*80)
    
    try:
        from app.services.github_integration import create_pr_for_patches
        import os
        from datetime import datetime
        
        # Use provided token or env variable
        token = github_token or os.getenv("GITHUB_TOKEN")
        
        if not token:
            print("⚠️  GITHUB_TOKEN not provided, skipping PR creation")
            analysis_result.summary["pr_created"] = False
            analysis_result.summary["pr_url"] = None
            return analysis_result
        
        # Create branch name
        branch_name = f"security-patches-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Create PR
        pr_data = create_pr_for_patches(
            repo_path=request.source_path,
            branch_name=branch_name,
            vulnerabilities_fixed=analysis_result.vulnerabilities_fixed,
            patches_details=analysis_result.results,
            github_token=token
        )
        
        if pr_data:
            print(f"✅ Pull request created: {pr_data['html_url']}")
            analysis_result.summary["pr_created"] = True
            analysis_result.summary["pr_url"] = pr_data["html_url"]
            analysis_result.summary["pr_number"] = pr_data["number"]
        else:
            print("⚠️  Failed to create pull request")
            analysis_result.summary["pr_created"] = False
            analysis_result.summary["pr_url"] = None
        
    except Exception as e:
        print(f"❌ Error creating PR: {e}")
        analysis_result.summary["pr_created"] = False
        analysis_result.summary["pr_error"] = str(e)
    
    print("="*80 + "\n")
    
    return analysis_result


@router.get("/dashboard")
async def get_dashboard(include_behavior: bool = True):
    """
    Get interactive HTML dashboard with analysis results
    
    Args:
        include_behavior: Include behavior analysis data (default: true)
        
    Returns:
        HTML dashboard
    """
    from fastapi.responses import HTMLResponse
    from app.services.dashboard_generator import DashboardGenerator
    from pathlib import Path
    
    # Load latest analysis results if available
    results_file = Path("test-data/e2e-api-results.json")
    
    if results_file.exists():
        import json
        with open(results_file, 'r') as f:
            data = json.load(f)
    else:
        # Generate empty dashboard
        data = {
            "vulnerabilities_found": 0,
            "vulnerabilities_fixed": 0,
            "results": []
        }
    
    # Generate dashboard
    generator = DashboardGenerator(include_behavior_analysis=include_behavior)
    html = generator.generate(data)
    
    return HTMLResponse(content=html)


@router.get("/status")
async def get_pipeline_status():
    """Get status of end-to-end pipeline components"""
    status = {
        "pipeline": "ready",
        "stages": {}
    }
    
    # Check CodeQL
    try:
        import subprocess
        result = subprocess.run(["codeql", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            status["stages"]["codeql"] = {
                "available": True,
                "version": result.stdout.strip().split("\n")[0]
            }
        else:
            status["stages"]["codeql"] = {"available": False}
    except:
        status["stages"]["codeql"] = {"available": False}
    
    # Check Z3
    try:
        from z3 import Solver
        status["stages"]["z3_symbolic"] = {"available": True}
    except:
        status["stages"]["z3_symbolic"] = {"available": False}
    
    # Check LLM providers
    llm_providers = []
    
    try:
        import google.generativeai
        import os
        if os.getenv("GEMINI_API_KEY"):
            llm_providers.append("gemini")
    except:
        pass
    
    try:
        import ollama
        client = ollama.Client()
        models = client.list()
        if models:
            llm_providers.append("ollama")
    except:
        pass
    
    try:
        import openai
        import os
        if os.getenv("OPENAI_API_KEY"):
            llm_providers.append("openai")
    except:
        pass
    
    # Template-based always available
    llm_providers.append("template")
    
    status["stages"]["llm_patching"] = {
        "available": True,
        "providers": llm_providers
    }
    
    # Validation always available
    status["stages"]["patch_validation"] = {"available": True}
    
    # Check GitHub integration
    import os
    status["github_integration"] = {
        "available": bool(os.getenv("GITHUB_TOKEN")),
        "pr_creation_enabled": bool(os.getenv("GITHUB_TOKEN"))
    }
    
    return status
