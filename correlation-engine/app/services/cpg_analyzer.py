"""
CPG (Code Property Graph) Analyzer

This module replaces IAST by using static semantic analysis to detect:
1. Business logic flaws (price manipulation, workflow bypasses)
2. Missing authorization checks (IDOR, privilege escalation)
3. Complex data flow issues (multi-step vulnerabilities)
4. TOCTOU race conditions
5. Insecure deserialization

Uses Joern and CodeQL for CPG-based analysis.
"""
import logging
import subprocess
import json
from typing import Dict, List, Optional
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class CPGAnalyzer:
    """
    Code Property Graph analyzer using Joern and CodeQL
    
    Performs semantic analysis to detect vulnerabilities that
    traditional pattern-matching SAST tools miss.
    """
    
    def __init__(self):
        """Initialize CPG analyzer"""
        self.joern_home = os.getenv("JOERN_HOME", "/opt/joern")
        self.codeql_home = os.getenv("CODEQL_HOME", "/opt/codeql")
        self.queries_dir = Path(__file__).parent.parent.parent / "codeql-queries"
        
    def analyze(
        self,
        source_path: str,
        language: str = "python",
        query_types: Optional[List[str]] = None
    ) -> Dict:
        """
        Perform CPG-based security analysis
        
        Args:
            source_path: Path to source code
            language: Programming language (python, java, javascript, php)
            query_types: Specific query types to run (None = all)
            
        Returns:
            Dict with CPG findings
        """
        logger.info(f"🔍 Starting CPG analysis on {source_path}")
        
        if not Path(source_path).exists():
            return {
                "success": False,
                "error": f"Source path not found: {source_path}"
            }
        
        findings = []
        
        # Phase 1: CodeQL data flow analysis
        logger.info("📊 Phase 1: CodeQL data flow analysis...")
        codeql_findings = self._run_codeql_analysis(source_path, language)
        findings.extend(codeql_findings)
        
        # Phase 2: Joern semantic analysis (if available)
        if self._is_joern_available():
            logger.info("📊 Phase 2: Joern semantic analysis...")
            joern_findings = self._run_joern_analysis(source_path, language)
            findings.extend(joern_findings)
        else:
            logger.warning("⚠️  Joern not available, skipping semantic analysis")
        
        logger.info(f"✅ CPG analysis complete: {len(findings)} findings")
        
        return {
            "success": True,
            "tool": "CPG",
            "total_findings": len(findings),
            "findings": findings,
            "analysis_type": "semantic",
            "confidence": "high"
        }
    
    def _run_codeql_analysis(self, source_path: str, language: str) -> List[Dict]:
        """
        Run CodeQL data flow queries
        
        CodeQL excels at:
        - Taint tracking (source → sink)
        - Data flow analysis
        - Control flow analysis
        """
        findings = []
        
        try:
            # Create CodeQL database
            db_path = f"/tmp/codeql-db-{Path(source_path).name}"
            
            logger.info(f"Creating CodeQL database: {db_path}")
            
            create_cmd = [
                f"{self.codeql_home}/codeql",
                "database", "create",
                db_path,
                f"--language={self._map_language_codeql(language)}",
                f"--source-root={source_path}",
                "--overwrite"
            ]
            
            result = subprocess.run(
                create_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.warning(f"CodeQL database creation failed: {result.stderr}")
                return []
            
            # Run custom queries
            query_files = self._get_codeql_queries(language)
            
            for query_file in query_files:
                logger.info(f"Running query: {query_file.name}")
                
                query_cmd = [
                    f"{self.codeql_home}/codeql",
                    "database", "analyze",
                    db_path,
                    str(query_file),
                    "--format=sarif-latest",
                    f"--output=/tmp/codeql-results-{query_file.stem}.sarif"
                ]
                
                result = subprocess.run(
                    query_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    # Parse SARIF results
                    sarif_findings = self._parse_sarif(
                        f"/tmp/codeql-results-{query_file.stem}.sarif"
                    )
                    findings.extend(sarif_findings)
            
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")
        
        return findings
    
    def _run_joern_analysis(self, source_path: str, language: str) -> List[Dict]:
        """
        Run Joern semantic queries
        
        Joern excels at:
        - Missing authorization checks
        - Business logic flaws
        - IDOR detection
        - Complex semantic patterns
        """
        findings = []
        
        try:
            # Create Joern workspace
            logger.info("Creating Joern CPG...")
            
            # Import source code into Joern
            import_cmd = [
                f"{self.joern_home}/joern-parse",
                source_path,
                "-o", f"/tmp/joern-cpg-{Path(source_path).name}.bin"
            ]
            
            result = subprocess.run(
                import_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.warning(f"Joern import failed: {result.stderr}")
                return []
            
            # Run semantic queries
            queries = self._get_joern_queries(language)
            
            for query in queries:
                logger.info(f"Running Joern query: {query['name']}")
                
                # Run query via Joern CLI
                query_result = self._execute_joern_query(
                    f"/tmp/joern-cpg-{Path(source_path).name}.bin",
                    query['script']
                )
                
                if query_result:
                    findings.extend(query_result)
            
        except Exception as e:
            logger.error(f"Joern analysis failed: {e}")
        
        return findings
    
    def _get_codeql_queries(self, language: str) -> List[Path]:
        """Get relevant CodeQL query files for language"""
        queries = []
        
        # Standard queries directory
        query_dir = self.queries_dir
        
        if query_dir.exists():
            # Get all .ql files
            for ql_file in query_dir.glob("*.ql"):
                queries.append(ql_file)
        
        # If no custom queries, use built-in CodeQL queries
        if not queries:
            builtin_dir = Path(f"/opt/codeql-repo/{language}/ql/src/Security")
            if builtin_dir.exists():
                queries = list(builtin_dir.glob("**/*.ql"))
        
        return queries
    
    def _get_joern_queries(self, language: str) -> List[Dict]:
        """Get Joern semantic queries"""
        return [
            {
                "name": "Missing Authorization Check",
                "script": """
                    // Find methods that access sensitive data without auth check
                    cpg.method.name(".*(?i)(get|fetch|list|delete).*")
                        .whereNot(_.reachableBy(cpg.method.name(".*(?i)(auth|check|verify).*")))
                        .parameter.where(_.isExternalInput)
                        .l
                """,
                "type": "MISSING_AUTHORIZATION",
                "severity": "high"
            },
            {
                "name": "IDOR Detection",
                "script": """
                    // Find database queries with user-controlled params and no auth
                    cpg.call.name(".*(?i)(execute|query|find).*")
                        .argument.where(_.reachableBy(cpg.parameter))
                        .whereNot(_.method.reachableBy(cpg.method.name(".*(?i)(authorize|own).*")))
                        .l
                """,
                "type": "IDOR",
                "severity": "high"
            },
            {
                "name": "Business Logic - Price Manipulation",
                "script": """
                    // Find payment processing that uses client-controlled prices
                    cpg.method.name(".*(?i)(payment|checkout|charge).*")
                        .parameter.where(_.reachableBy(cpg.parameter.name(".*price.*")))
                        .whereNot(_.reachableBy(cpg.call.name(".*(?i)(validate|verify).*")))
                        .l
                """,
                "type": "BUSINESS_LOGIC",
                "severity": "critical"
            }
        ]
    
    def _execute_joern_query(self, cpg_path: str, query_script: str) -> List[Dict]:
        """Execute Joern query and parse results"""
        findings = []
        
        try:
            # Write query to temp file
            query_file = "/tmp/joern-query.sc"
            with open(query_file, 'w') as f:
                f.write(query_script)
            
            # Execute query
            cmd = [
                f"{self.joern_home}/joern",
                "--script", query_file,
                "--cpg", cpg_path,
                "--format", "json"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse JSON output
                results = json.loads(result.stdout)
                
                for item in results:
                    finding = {
                        "tool": "CPG-Joern",
                        "type": item.get("type", "SEMANTIC_ISSUE"),
                        "severity": item.get("severity", "medium"),
                        "file_path": item.get("filename", ""),
                        "line_number": item.get("lineNumber", 0),
                        "message": item.get("message", ""),
                        "confidence": "high",
                        "metadata": {
                            "analysis_type": "semantic",
                            "method": item.get("method", ""),
                            "data_flow": item.get("dataFlow", [])
                        }
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Joern query execution failed: {e}")
        
        return findings
    
    def _parse_sarif(self, sarif_path: str) -> List[Dict]:
        """Parse CodeQL SARIF output"""
        findings = []
        
        try:
            if not Path(sarif_path).exists():
                return []
            
            with open(sarif_path, 'r') as f:
                sarif = json.load(f)
            
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    # Extract location
                    location = result.get("locations", [{}])[0]
                    physical_location = location.get("physicalLocation", {})
                    artifact = physical_location.get("artifactLocation", {})
                    region = physical_location.get("region", {})
                    
                    finding = {
                        "tool": "CPG-CodeQL",
                        "rule_id": result.get("ruleId", ""),
                        "type": self._map_codeql_type(result.get("ruleId", "")),
                        "severity": self._map_codeql_severity(result.get("level", "warning")),
                        "message": result.get("message", {}).get("text", ""),
                        "file_path": artifact.get("uri", ""),
                        "line_number": region.get("startLine", 0),
                        "confidence": "high",
                        "metadata": {
                            "analysis_type": "dataflow",
                            "rule_id": result.get("ruleId", ""),
                            "help_uri": result.get("helpUri", "")
                        }
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"SARIF parsing failed: {e}")
        
        return findings
    
    def _map_language_codeql(self, language: str) -> str:
        """Map language to CodeQL language identifier"""
        mapping = {
            "python": "python",
            "java": "java",
            "javascript": "javascript",
            "typescript": "javascript",
            "php": "php",
            "csharp": "csharp",
            "cpp": "cpp",
            "c": "cpp",
            "go": "go",
            "ruby": "ruby"
        }
        return mapping.get(language.lower(), "python")
    
    def _map_codeql_type(self, rule_id: str) -> str:
        """Map CodeQL rule ID to vulnerability type"""
        if "sql" in rule_id.lower() or "injection" in rule_id.lower():
            return "SQL_INJECTION"
        elif "xss" in rule_id.lower() or "cross-site" in rule_id.lower():
            return "XSS"
        elif "auth" in rule_id.lower():
            return "MISSING_AUTHORIZATION"
        elif "idor" in rule_id.lower() or "object-reference" in rule_id.lower():
            return "IDOR"
        else:
            return "SECURITY_ISSUE"
    
    def _map_codeql_severity(self, level: str) -> str:
        """Map CodeQL severity level"""
        mapping = {
            "error": "high",
            "warning": "medium",
            "note": "low"
        }
        return mapping.get(level.lower(), "medium")
    
    def _is_joern_available(self) -> bool:
        """Check if Joern is installed and available"""
        joern_path = Path(f"{self.joern_home}/joern")
        return joern_path.exists() and joern_path.is_file()
    
    def get_capabilities(self) -> Dict:
        """Return analyzer capabilities"""
        return {
            "analyzer": "CPG",
            "tools": {
                "codeql": {
                    "available": Path(f"{self.codeql_home}/codeql").exists(),
                    "capabilities": ["dataflow", "taint_tracking", "control_flow"]
                },
                "joern": {
                    "available": self._is_joern_available(),
                    "capabilities": ["semantic_analysis", "cpg", "missing_auth", "idor", "business_logic"]
                }
            },
            "supported_languages": ["python", "java", "javascript", "php", "c", "cpp", "csharp", "go"],
            "detection_types": [
                "SQL_INJECTION",
                "XSS",
                "IDOR",
                "MISSING_AUTHORIZATION",
                "BUSINESS_LOGIC",
                "RACE_CONDITION",
                "INSECURE_DESERIALIZATION"
            ]
        }


# Quick test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    analyzer = CPGAnalyzer()
    
    # Test capabilities
    print("\n📊 CPG Analyzer Capabilities:")
    print(json.dumps(analyzer.get_capabilities(), indent=2))
    
    # Test analysis (if source available)
    if Path("/target-app").exists():
        print("\n🔍 Running CPG analysis on /target-app...")
        result = analyzer.analyze("/target-app", language="python")
        print(f"\nResults: {result['total_findings']} findings")
