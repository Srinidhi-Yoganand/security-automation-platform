"""
Automated Remediation Pipeline API Routes
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import logging
import os
import subprocess
import time
from datetime import datetime

from ..services.dast_scanner import DASTScanner
from ..services.enhanced_sast_scanner import EnhancedSASTScanner
from ..services.production_cpg_analyzer import ProductionCPGAnalyzer
from ..services.cpg_analyzer import CPGAnalyzer  # Legacy fallback
from ..services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
from ..services.patcher.patch_applier import PatchApplier
from ..core.semantic_analyzer_complete import SemanticAnalyzer
from pathlib import Path

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


class AutoRemediationRequest(BaseModel):
    """Request for automated remediation pipeline"""
    target_url: str = Field(..., description="URL of the target application")
    target_source: str = Field(..., description="Path to source code")
    enable_sast: bool = Field(default=True, description="Enable SAST scanning")
    enable_dast: bool = Field(default=True, description="Enable DAST scanning")
    enable_cpg: bool = Field(default=True, description="Enable CPG analysis")
    llm_provider: str = Field(default="ollama", description="LLM provider (ollama/openai)")
    auto_apply_patches: bool = Field(default=True, description="Automatically apply patches")
    restart_after_patch: bool = Field(default=False, description="Restart app after patching")
    confidence_threshold: float = Field(default=0.7, description="Min confidence to auto-apply patch")


class AutoRemediationResponse(BaseModel):
    """Response from automated remediation pipeline"""
    status: str
    pipeline_id: str
    initial_scan: Dict[str, Any]
    patches_generated: int
    patches_applied: int
    patches_failed: int
    final_scan: Optional[Dict[str, Any]] = None
    vulnerabilities_fixed: int = 0
    execution_time: float
    details: Dict[str, Any]


@router.post("/auto-remediate", response_model=AutoRemediationResponse)
async def auto_remediate(request: AutoRemediationRequest):
    """
    Automated vulnerability remediation pipeline:
    1. Scan for vulnerabilities (SAST + DAST + CPG)
    2. Correlate findings
    3. Generate patches using LLM
    4. Auto-apply high-confidence patches
    5. Re-scan to verify fixes
    6. Report results
    """
    start_time = time.time()
    pipeline_id = f"remediation-{int(time.time())}"
    
    logger.info(f"Starting automated remediation pipeline {pipeline_id}")
    
    try:
        # Stage 1: Initial Scan
        logger.info("Stage 1: Running initial vulnerability scan")
        initial_scan_result = await _run_combined_scan(request)
        
        initial_vulns = len(initial_scan_result.get('correlated_findings', []))
        logger.info(f"Initial scan found {initial_vulns} vulnerabilities")
        
        if initial_vulns == 0:
            return AutoRemediationResponse(
                status="completed",
                pipeline_id=pipeline_id,
                initial_scan=initial_scan_result,
                patches_generated=0,
                patches_applied=0,
                patches_failed=0,
                final_scan=None,
                vulnerabilities_fixed=0,
                execution_time=time.time() - start_time,
                details={"message": "No vulnerabilities found"}
            )
        
        # Stage 2: Generate Patches
        logger.info("Stage 2: Generating patches for vulnerabilities")
        patch_results = await _generate_patches(
            initial_scan_result.get('correlated_findings', []),
            request.target_source,
            request.llm_provider,
            request.confidence_threshold
        )
        
        patches_generated = len(patch_results['patches'])
        logger.info(f"Generated {patches_generated} patches")
        
        # Stage 3: Apply Patches
        applied_results = {"applied": 0, "failed": 0, "skipped": 0, "details": []}
        
        if request.auto_apply_patches and patches_generated > 0:
            logger.info("Stage 3: Applying patches")
            applied_results = await _apply_patches(
                patch_results['patches'],
                request.target_source
            )
            
            logger.info(f"Applied {applied_results['applied']} patches successfully")
        
        # Stage 4: Restart Application (if requested)
        if request.restart_after_patch and applied_results['applied'] > 0:
            logger.info("Stage 4: Restarting application")
            restart_success = await _restart_application()
            if not restart_success:
                logger.warning("Failed to restart application")
        
        # Stage 5: Re-scan to Verify Fixes
        final_scan_result = None
        vulnerabilities_fixed = 0
        
        if applied_results['applied'] > 0:
            logger.info("Stage 5: Re-scanning to verify fixes")
            time.sleep(5)  # Wait for app to stabilize
            
            final_scan_result = await _run_combined_scan(request)
            final_vulns = len(final_scan_result.get('correlated_findings', []))
            vulnerabilities_fixed = max(0, initial_vulns - final_vulns)
            
            logger.info(f"Final scan found {final_vulns} vulnerabilities ({vulnerabilities_fixed} fixed)")
        
        # Stage 6: Prepare Response
        execution_time = time.time() - start_time
        
        return AutoRemediationResponse(
            status="completed",
            pipeline_id=pipeline_id,
            initial_scan=initial_scan_result,
            patches_generated=patches_generated,
            patches_applied=applied_results['applied'],
            patches_failed=applied_results['failed'],
            final_scan=final_scan_result,
            vulnerabilities_fixed=vulnerabilities_fixed,
            execution_time=execution_time,
            details={
                "patch_generation": patch_results,
                "patch_application": applied_results,
                "initial_vulnerabilities": initial_vulns,
                "final_vulnerabilities": final_scan_result.get('correlated_findings', []) if final_scan_result else None
            }
        )
        
    except Exception as e:
        logger.error(f"Error in automated remediation pipeline: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


async def _run_combined_scan(request: AutoRemediationRequest) -> Dict[str, Any]:
    """Run combined vulnerability scan with production-grade tools"""
    results = {
        'sast_findings': [],
        'dast_findings': [],
        'cpg_findings': [],
        'correlated_findings': []
    }
    
    try:
        source_path = Path(request.target_source)
        language = request.target_language if hasattr(request, 'target_language') else 'python'
        
        # SAST using Enhanced Multi-Tool Scanner
        if request.enable_sast:
            try:
                logger.info("Running Enhanced SAST (Semgrep + Bandit + Custom)")
                sast_scanner = EnhancedSASTScanner()
                sast_result = sast_scanner.scan(str(source_path), language)
                
                results['sast_findings'] = sast_result.get('vulnerabilities', [])
                logger.info(f"Enhanced SAST found {len(results['sast_findings'])} findings")
                
            except Exception as e:
                logger.error(f"Enhanced SAST error: {e}")
                results['sast_findings'] = []
        
        # CPG using Production CPG Analyzer
        if request.enable_cpg:
            try:
                logger.info("Running Production CPG Analyzer")
                cpg_analyzer = ProductionCPGAnalyzer()
                cpg_result = cpg_analyzer.analyze(str(source_path), language)
                
                results['cpg_findings'] = cpg_result.get('findings', [])
                logger.info(f"Production CPG found {len(results['cpg_findings'])} findings")
                
            except Exception as e:
                logger.error(f"Production CPG error: {e}, falling back to legacy CPG")
                # Fallback to legacy CPG
                legacy_cpg = CPGAnalyzer()
                cpg_result = legacy_cpg.analyze(str(source_path), language)
                results['cpg_findings'] = cpg_result.get('findings', [])
        
        # DAST
        if request.enable_dast:
            dast_scanner = DASTScanner()
            dast_result = dast_scanner.scan(request.target_url)
            results['dast_findings'] = dast_result.get('alerts', [])
            logger.info(f"DAST found {len(results['dast_findings'])} findings")
        
        # Correlate findings from all sources
        all_findings = []
        
        # Process CPG findings
        for finding in results['cpg_findings']:
            all_findings.append({
                'file': finding.get('file_path', finding.get('file')),
                'line': finding.get('line_number', finding.get('line')),
                'type': finding.get('type'),
                'severity': finding.get('severity', 'MEDIUM').upper(),
                'confidence': _normalize_confidence(finding.get('confidence', 'medium')),
                'source': 'CPG',
                'description': finding.get('message', finding.get('description', ''))
            })
        
        # Process SAST findings
        for finding in results['sast_findings']:
            all_findings.append({
                'file': finding.get('file'),
                'line': finding.get('line'),
                'type': finding.get('type'),
                'severity': finding.get('severity', 'MEDIUM').upper(),
                'confidence': _normalize_confidence(finding.get('confidence', 0.7)),
                'source': finding.get('tool', 'SAST'),
                'description': finding.get('message', '')
            })
        
        # Deduplicate by file+line+type
        seen = set()
        unique_findings = []
        for finding in all_findings:
            key = (finding['file'], finding['line'], finding['type'])
            if key not in seen and finding['file'] and finding['line']:
                seen.add(key)
                unique_findings.append(finding)
        
        results['correlated_findings'] = unique_findings
        logger.info(f"Correlated to {len(unique_findings)} unique high-confidence findings")
        
        return results
        
    except Exception as e:
        logger.error(f"Error in combined scan: {str(e)}")
        raise


def _normalize_confidence(confidence) -> float:
    """Normalize confidence to 0-1 float"""
    if isinstance(confidence, float):
        return confidence
    elif isinstance(confidence, str):
        confidence_map = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5,
            'critical': 0.95
        }
        return confidence_map.get(confidence.lower(), 0.7)
    else:
        return 0.7


async def _generate_patches(findings: List[Dict], source_path: str, 
                           llm_provider: str, confidence_threshold: float) -> Dict[str, Any]:
    """Generate patches for vulnerabilities"""
    # Import the context class
    from ..services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
    
    # Initialize patch generator with the specified provider
    patch_generator = LLMPatchGenerator(llm_provider=llm_provider)
    
    patches = []
    failed = []
    
    for finding in findings:
        try:
            # Only generate patches for findings above confidence threshold
            confidence = finding.get('confidence', 0.5)
            
            if confidence < confidence_threshold:
                logger.info(f"Skipping low-confidence finding: {finding.get('type')} (confidence: {confidence})")
                continue
            
            # Extract file and location info
            file_path = finding.get('file')
            line_number = finding.get('line')
            vuln_type = finding.get('type')
            
            if not file_path or not line_number:
                logger.warning(f"Missing file/line info for finding: {finding}")
                continue
            
            # Construct full file path if it's relative
            if file_path.startswith('/target-app'):
                full_path = file_path  # Already absolute in container
            elif not os.path.isabs(file_path):
                full_path = os.path.join(source_path, file_path)
            else:
                full_path = file_path
            
            if not os.path.exists(full_path):
                logger.warning(f"File not found: {full_path}")
                continue
            
            # Read vulnerable code
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if 0 < line_number <= len(lines):
                        vulnerable_code = lines[line_number - 1]
                    else:
                        vulnerable_code = ""
            except Exception as e:
                logger.error(f"Error reading file {full_path}: {e}")
                vulnerable_code = ""
            
            # Create patch context
            context = PatchContext(
                vulnerability_type=vuln_type,
                file_path=full_path,
                line_number=line_number,
                vulnerable_code=vulnerable_code,
                severity=finding.get('severity', 'MEDIUM'),
                confidence=confidence,
                description=finding.get('description', ''),
                cwe_id=None,
                tool_name=finding.get('source', 'UNKNOWN')
            )
            
            # Generate patch
            logger.info(f"Generating patch for {vuln_type} at {file_path}:{line_number}")
            
            patch_result = patch_generator.generate_patch(context, test_patch=False)
            
            if patch_result and hasattr(patch_result, 'fixed_code'):
                patches.append({
                    'finding': finding,
                    'patch_content': patch_result.diff if hasattr(patch_result, 'diff') else patch_result.fixed_code,
                    'file_path': full_path,
                    'line_number': line_number,
                    'vuln_type': vuln_type,
                    'confidence': confidence,
                    'explanation': patch_result.explanation if hasattr(patch_result, 'explanation') else ''
                })
            else:
                failed.append({
                    'finding': finding,
                    'error': 'Patch generation returned None or invalid result'
                })
                
        except Exception as e:
            logger.error(f"Error generating patch for finding: {str(e)}")
            failed.append({
                'finding': finding,
                'error': str(e)
            })
    
    return {
        'patches': patches,
        'failed': failed,
        'total': len(findings),
        'generated': len(patches)
    }


async def _apply_patches(patches: List[Dict], source_path: str) -> Dict[str, Any]:
    """Apply generated patches to source files"""
    patch_applier = PatchApplier()
    
    applied = []
    failed = []
    
    for patch_info in patches:
        try:
            file_path = patch_info['file_path']
            patch_content = patch_info['patch_content']
            
            logger.info(f"Applying patch to {file_path}")
            
            # Try to apply the patch
            success, message = patch_applier.apply_patch(file_path, patch_content)
            
            if success:
                applied.append({
                    'file': file_path,
                    'vuln_type': patch_info['vuln_type'],
                    'line': patch_info['line_number'],
                    'message': message
                })
                logger.info(f"Successfully applied patch to {file_path}")
            else:
                failed.append({
                    'file': file_path,
                    'vuln_type': patch_info['vuln_type'],
                    'line': patch_info['line_number'],
                    'error': message
                })
                logger.error(f"Failed to apply patch to {file_path}: {message}")
                
        except Exception as e:
            logger.error(f"Error applying patch: {str(e)}")
            failed.append({
                'file': patch_info.get('file_path', 'unknown'),
                'error': str(e)
            })
    
    return {
        'applied': len(applied),
        'failed': len(failed),
        'skipped': 0,
        'details': {
            'applied_patches': applied,
            'failed_patches': failed
        }
    }


async def _restart_application() -> bool:
    """Restart the target application (if running in Docker)"""
    try:
        # Try to restart the custom-app container
        result = subprocess.run(
            ['docker-compose', 'restart', 'custom-app'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info("Successfully restarted application")
            return True
        else:
            logger.error(f"Failed to restart application: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Error restarting application: {str(e)}")
        return False


@router.get("/pipeline-status/{pipeline_id}")
async def get_pipeline_status(pipeline_id: str):
    """Get status of a remediation pipeline"""
    # Placeholder for future async pipeline tracking
    return {
        "pipeline_id": pipeline_id,
        "status": "not_implemented",
        "message": "Async pipeline tracking coming soon"
    }
