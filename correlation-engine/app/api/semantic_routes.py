"""
API endpoints for Semantic Analysis
Integrates SemanticAnalyzer with FastAPI
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from pathlib import Path
import logging

from app.core.semantic_analyzer_complete import (
    SemanticAnalyzer,
    analyze_java_project
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/semantic", tags=["Semantic Analysis"])

# Global analyzer instance (initialized per project)
_analyzers: Dict[str, SemanticAnalyzer] = {}


class SemanticAnalysisRequest(BaseModel):
    """Request model for semantic analysis"""
    project_path: str
    force_refresh: bool = False
    run_queries: bool = True


class SemanticAnalysisResponse(BaseModel):
    """Response model for semantic analysis results"""
    status: str
    project_path: str
    database_path: Optional[str] = None
    results_file: Optional[str] = None
    total_findings: int = 0
    vulnerabilities: List[Dict[str, Any]] = []
    statistics: Dict[str, Any] = {}
    error: Optional[str] = None


class DatabaseCreateRequest(BaseModel):
    """Request model for database creation"""
    project_path: str
    db_name: Optional[str] = None
    force: bool = False


class DatabaseCreateResponse(BaseModel):
    """Response model for database creation"""
    success: bool
    database_path: str = ""
    message: str = ""


class QueryRunRequest(BaseModel):
    """Request model for running queries"""
    database_path: str
    query_path: Optional[str] = None


class QueryRunResponse(BaseModel):
    """Response model for query execution"""
    success: bool
    results_file: str = ""
    findings_count: int = 0
    message: str = ""


def get_analyzer(project_path: str) -> SemanticAnalyzer:
    """Get or create analyzer instance for a project"""
    if project_path not in _analyzers:
        _analyzers[project_path] = SemanticAnalyzer(project_path)
    return _analyzers[project_path]


@router.post("/analyze", response_model=SemanticAnalysisResponse)
async def analyze_project(request: SemanticAnalysisRequest):
    """
    Perform complete semantic analysis of a Java project
    
    This endpoint:
    1. Creates CodeQL database
    2. Runs security queries
    3. Parses SARIF results
    4. Extracts security context
    5. Returns detailed findings
    """
    try:
        project_path = Path(request.project_path)
        if not project_path.exists():
            raise HTTPException(status_code=404, detail=f"Project path not found: {request.project_path}")
        
        logger.info(f"Starting semantic analysis for {request.project_path}")
        
        analyzer = get_analyzer(request.project_path)
        results = analyzer.analyze_project(
            request.project_path,
            force_refresh=request.force_refresh
        )
        
        response = SemanticAnalysisResponse(
            status=results.get('status', 'unknown'),
            project_path=results.get('project_path', request.project_path),
            database_path=results.get('database_path'),
            results_file=results.get('results_file'),
            total_findings=results.get('statistics', {}).get('total_findings', 0),
            vulnerabilities=results.get('vulnerabilities', []),
            statistics=results.get('statistics', {}),
            error=results.get('error')
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in semantic analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/database/create", response_model=DatabaseCreateResponse)
async def create_database(request: DatabaseCreateRequest):
    """
    Create CodeQL database from Java project
    
    This is a standalone endpoint for database creation without running queries.
    Useful for CI/CD pipelines or batch processing.
    """
    try:
        project_path = Path(request.project_path)
        if not project_path.exists():
            raise HTTPException(status_code=404, detail=f"Project path not found: {request.project_path}")
        
        analyzer = get_analyzer(request.project_path)
        success, db_path = analyzer.create_codeql_database(
            request.project_path,
            db_name=request.db_name,
            force=request.force
        )
        
        return DatabaseCreateResponse(
            success=success,
            database_path=db_path,
            message="Database created successfully" if success else "Failed to create database"
        )
        
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/queries/run", response_model=QueryRunResponse)
async def run_queries(request: QueryRunRequest):
    """
    Run CodeQL queries on an existing database
    
    This endpoint allows running queries on a pre-existing database.
    Useful for re-running analysis with different queries.
    """
    try:
        db_path = Path(request.database_path)
        if not db_path.exists():
            raise HTTPException(status_code=404, detail=f"Database not found: {request.database_path}")
        
        # Get analyzer from database path (extract project root)
        project_root = db_path.parent.parent
        analyzer = get_analyzer(str(project_root))
        
        success, results_file = analyzer.run_codeql_queries(
            request.database_path,
            query_path=request.query_path
        )
        
        findings_count = 0
        if success and results_file:
            # Parse results to get count
            paths = analyzer.parse_sarif_results(results_file)
            findings_count = len(paths)
        
        return QueryRunResponse(
            success=success,
            results_file=results_file,
            findings_count=findings_count,
            message=f"Found {findings_count} potential vulnerabilities" if success else "Query execution failed"
        )
        
    except Exception as e:
        logger.error(f"Error running queries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{results_file:path}")
async def get_results(results_file: str):
    """
    Retrieve parsed results from a SARIF file
    
    Returns the parsed and enhanced vulnerability findings.
    """
    try:
        results_path = Path(results_file)
        if not results_path.exists():
            raise HTTPException(status_code=404, detail=f"Results file not found: {results_file}")
        
        # Get analyzer
        project_root = results_path.parent.parent
        analyzer = get_analyzer(str(project_root))
        
        # Parse SARIF
        data_flows = analyzer.parse_sarif_results(results_file)
        
        # Convert to dict
        vulnerabilities = []
        for flow in data_flows:
            vuln = flow.to_dict()
            # Add security context
            context = analyzer.extract_security_context(
                flow.sink_location.file_path,
                flow.sink_location.start_line
            )
            vuln['security_context'] = context.to_dict()
            vulnerabilities.append(vuln)
        
        return {
            'results_file': results_file,
            'total_findings': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
        
    except Exception as e:
        logger.error(f"Error retrieving results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_statistics():
    """
    Get statistics about semantic analysis operations
    
    Returns information about active analyzers, cached results, etc.
    """
    return {
        'active_analyzers': len(_analyzers),
        'projects': list(_analyzers.keys())
    }
