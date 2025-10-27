"""
Semantic Analyzer - Code Property Graph Builder
Part of the Enhanced Thesis Implementation (Option 1 + 2)

This module builds Code Property Graphs (CPG) for semantic program analysis.
It combines AST, CFG, and DFG into a unified representation for vulnerability detection.
"""

from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import subprocess
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class DataFlowPath:
    """Represents a data flow path from source to sink"""
    source: str
    source_type: str  # "http_parameter", "file_input", "user_input"
    source_location: Tuple[str, int]  # (file, line)
    
    sink: str
    sink_type: str  # "database_query", "file_operation", "command_execution"
    sink_location: Tuple[str, int]
    
    intermediate_steps: List[Dict]
    sanitizers: List[str]
    validators: List[str]
    
    vulnerability_type: Optional[str] = None
    confidence: float = 0.0
    
    def has_sanitization(self) -> bool:
        """Check if there's any sanitization in the path"""
        return len(self.sanitizers) > 0 or len(self.validators) > 0
    
    def is_potentially_vulnerable(self) -> bool:
        """Determine if this path represents a potential vulnerability"""
        # High-risk sinks without sanitization
        high_risk_sinks = ["database_query", "command_execution", "deserialization"]
        return self.sink_type in high_risk_sinks and not self.has_sanitization()


@dataclass
class SecurityContext:
    """Security context around a code location"""
    file_path: str
    line_number: int
    
    # Available security mechanisms
    authentication_methods: List[str]
    authorization_checks: List[str]
    security_annotations: List[str]
    
    # Framework information
    framework: str  # "spring", "jakarta", "plain_java"
    framework_version: Optional[str] = None
    
    # Available security APIs
    available_apis: List[str] = None
    
    def has_authorization(self) -> bool:
        """Check if authorization mechanisms are available"""
        return len(self.authorization_checks) > 0 or len(self.security_annotations) > 0
    
    def suggest_security_api(self, vulnerability_type: str) -> str:
        """Suggest appropriate security API based on vulnerability type"""
        if vulnerability_type == "idor" and self.framework == "spring":
            return "SecurityContextHolder.getContext().getAuthentication()"
        elif vulnerability_type == "sql_injection":
            return "PreparedStatement or JPA with parameterized queries"
        return "Framework-specific authorization mechanism"


@dataclass
class CPGNode:
    """Node in the Code Property Graph"""
    node_id: str
    node_type: str  # "statement", "expression", "method_call", "parameter"
    code: str
    file_path: str
    line_number: int
    
    # Connections
    control_flow_successors: List[str] = None
    data_flow_successors: List[str] = None
    dominates: List[str] = None


class SemanticAnalyzer:
    """
    Builds Code Property Graphs and performs semantic analysis
    for vulnerability detection.
    
    This is the foundation for Option 1 (semantic analysis) integrated
    with Option 2 (symbolic execution).
    """
    
    def __init__(self, codebase_path: str, codeql_path: str = "./tools/codeql/codeql"):
        """
        Initialize semantic analyzer
        
        Args:
            codebase_path: Path to the codebase to analyze
            codeql_path: Path to CodeQL CLI executable
        """
        self.codebase_path = Path(codebase_path)
        self.codeql_path = Path(codeql_path)
        self.cpg: Optional[Dict] = None
        self.database_path: Optional[Path] = None
        
        # Security-sensitive operations (sinks)
        self.security_sinks = {
            "database_query": [
                "executeQuery", "execute", "executeUpdate",
                "findById", "findAll", "save", "delete",
                "createQuery", "createNativeQuery"
            ],
            "file_operation": [
                "readFile", "writeFile", "deleteFile",
                "FileInputStream", "FileOutputStream"
            ],
            "command_execution": [
                "Runtime.exec", "ProcessBuilder",
                "Runtime.getRuntime().exec"
            ],
            "deserialization": [
                "readObject", "ObjectInputStream",
                "XMLDecoder.readObject"
            ],
            "authentication": [
                "login", "authenticate", "setAuthentication"
            ]
        }
        
        # User input sources
        self.input_sources = {
            "http_parameter": [
                "getParameter", "getHeader", "getPathVariable",
                "@PathVariable", "@RequestParam", "@RequestBody"
            ],
            "file_input": [
                "readLine", "read", "FileInputStream"
            ]
        }
    
    def create_codeql_database(self, project_path: Optional[str] = None) -> Path:
        """
        Create a CodeQL database for the codebase
        
        Args:
            project_path: Optional override for codebase path
            
        Returns:
            Path to created database
        """
        if project_path is None:
            project_path = self.codebase_path
        
        db_name = f"{Path(project_path).name}-codeql-db"
        db_path = Path("./codeql-databases") / db_name
        
        logger.info(f"Creating CodeQL database at {db_path}")
        
        # Create database directory
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Run CodeQL database creation
        cmd = [
            str(self.codeql_path),
            "database", "create",
            str(db_path),
            "--language=java",
            f"--source-root={project_path}",
            "--command=mvn clean compile",
            "--overwrite"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("CodeQL database created successfully")
            self.database_path = db_path
            return db_path
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create CodeQL database: {e.stderr}")
            raise
    
    def find_taint_flows(self, db_path: Optional[Path] = None) -> List[DataFlowPath]:
        """
        Find all taint flows from sources to sinks using CodeQL
        
        Args:
            db_path: Path to CodeQL database (uses self.database_path if not provided)
            
        Returns:
            List of DataFlowPath objects representing potential vulnerabilities
        """
        if db_path is None:
            db_path = self.database_path
        
        if db_path is None:
            raise ValueError("No CodeQL database available. Run create_codeql_database() first.")
        
        logger.info("Finding taint flows using CodeQL...")
        
        # Run IDOR detection query
        query_path = Path("./codeql-queries/idor-detection.ql")
        results_file = Path("./codeql-results/taint-flows.json")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Execute query
        cmd = [
            str(self.codeql_path),
            "query", "run",
            str(query_path),
            f"--database={db_path}",
            f"--output={results_file}.bqrs"
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        # Convert to JSON
        cmd = [
            str(self.codeql_path),
            "bqrs", "decode",
            f"{results_file}.bqrs",
            "--format=json",
            f"--output={results_file}"
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        # Parse results
        with open(results_file) as f:
            results = json.load(f)
        
        return self._parse_taint_flow_results(results)
    
    def _parse_taint_flow_results(self, codeql_results: Dict) -> List[DataFlowPath]:
        """Parse CodeQL results into DataFlowPath objects"""
        flows = []
        
        # CodeQL returns paths with source and sink information
        for result in codeql_results.get("results", []):
            try:
                flow = DataFlowPath(
                    source=result["source"]["code"],
                    source_type=self._classify_source(result["source"]["code"]),
                    source_location=(
                        result["source"]["file"],
                        result["source"]["line"]
                    ),
                    sink=result["sink"]["code"],
                    sink_type=self._classify_sink(result["sink"]["code"]),
                    sink_location=(
                        result["sink"]["file"],
                        result["sink"]["line"]
                    ),
                    intermediate_steps=result.get("path", []),
                    sanitizers=[],  # Will be populated by analyzing path
                    validators=[],
                    confidence=0.8  # High confidence from CodeQL
                )
                
                # Determine vulnerability type
                if flow.is_potentially_vulnerable():
                    flow.vulnerability_type = self._infer_vulnerability_type(flow)
                
                flows.append(flow)
                
            except KeyError as e:
                logger.warning(f"Skipping malformed result: {e}")
                continue
        
        logger.info(f"Found {len(flows)} taint flows")
        return flows
    
    def _classify_source(self, code: str) -> str:
        """Classify the type of input source"""
        for source_type, patterns in self.input_sources.items():
            if any(pattern in code for pattern in patterns):
                return source_type
        return "unknown"
    
    def _classify_sink(self, code: str) -> str:
        """Classify the type of security sink"""
        for sink_type, patterns in self.security_sinks.items():
            if any(pattern in code for pattern in patterns):
                return sink_type
        return "unknown"
    
    def _infer_vulnerability_type(self, flow: DataFlowPath) -> str:
        """Infer vulnerability type from flow characteristics"""
        if flow.sink_type == "database_query":
            if not flow.has_sanitization():
                return "sql_injection"
        elif flow.sink_type == "command_execution":
            return "command_injection"
        elif flow.sink_type == "deserialization":
            return "insecure_deserialization"
        
        # Check for IDOR pattern
        if "findById" in flow.sink or "getById" in flow.sink:
            return "idor"
        
        return "unknown"
    
    def extract_security_context(self, file_path: str, line_number: int) -> SecurityContext:
        """
        Extract security context around a specific code location
        
        Args:
            file_path: Path to the file
            line_number: Line number to analyze
            
        Returns:
            SecurityContext object with available security mechanisms
        """
        logger.info(f"Extracting security context for {file_path}:{line_number}")
        
        # Analyze the file to find security mechanisms
        # This would use CodeQL or AST parsing to find:
        # - Security annotations (@PreAuthorize, @Secured, etc.)
        # - Available authentication/authorization methods
        # - Framework being used
        
        # For now, return a basic context
        # TODO: Implement full AST/CodeQL analysis
        
        return SecurityContext(
            file_path=file_path,
            line_number=line_number,
            authentication_methods=["SecurityContextHolder.getContext()"],
            authorization_checks=["hasPermission", "hasRole"],
            security_annotations=["@PreAuthorize", "@Secured"],
            framework="spring",
            framework_version="3.2",
            available_apis=[
                "SecurityContextHolder.getContext().getAuthentication()",
                "@PreAuthorize(\"hasRole('ADMIN')\")",
                "userService.hasPermission(userId, currentUser)"
            ]
        )
    
    def identify_authorization_points(self, flows: List[DataFlowPath]) -> List[Dict]:
        """
        Identify where authorization checks should exist but might not
        
        Args:
            flows: List of data flow paths
            
        Returns:
            List of potential authorization gaps
        """
        authorization_gaps = []
        
        for flow in flows:
            # Check if this is a resource access pattern
            if flow.vulnerability_type == "idor":
                # Extract resource identifier
                gap = {
                    "location": flow.sink_location,
                    "type": "missing_authorization",
                    "description": "Resource access without authorization check",
                    "flow": flow,
                    "suggested_check": f"Verify current user can access resource",
                    "confidence": 0.9 if not flow.has_sanitization() else 0.6
                }
                authorization_gaps.append(gap)
        
        return authorization_gaps
    
    def build_cpg(self) -> Dict:
        """
        Build a simplified Code Property Graph
        
        Returns:
            Dictionary representing the CPG
        """
        # This would integrate with CodeQL to get full CPG
        # For now, we use the taint flow information as a foundation
        
        if self.database_path is None:
            raise ValueError("No CodeQL database. Run create_codeql_database() first.")
        
        flows = self.find_taint_flows()
        
        cpg = {
            "nodes": [],
            "edges": [],
            "taint_flows": flows,
            "security_contexts": {}
        }
        
        # Build nodes from flows
        for flow in flows:
            # Add source node
            cpg["nodes"].append({
                "id": f"{flow.source_location[0]}:{flow.source_location[1]}",
                "type": "source",
                "code": flow.source,
                "location": flow.source_location
            })
            
            # Add sink node
            cpg["nodes"].append({
                "id": f"{flow.sink_location[0]}:{flow.sink_location[1]}",
                "type": "sink",
                "code": flow.sink,
                "location": flow.sink_location
            })
            
            # Add edge
            cpg["edges"].append({
                "from": f"{flow.source_location[0]}:{flow.source_location[1]}",
                "to": f"{flow.sink_location[0]}:{flow.sink_location[1]}",
                "type": "data_flow"
            })
        
        self.cpg = cpg
        return cpg


# Example usage
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python semantic_analyzer.py <path-to-java-project>")
        sys.exit(1)
    
    project_path = sys.argv[1]
    
    # Initialize analyzer
    analyzer = SemanticAnalyzer(project_path)
    
    # Create CodeQL database
    print("Creating CodeQL database...")
    db_path = analyzer.create_codeql_database()
    
    # Find taint flows
    print("\nFinding taint flows...")
    flows = analyzer.find_taint_flows(db_path)
    
    print(f"\nFound {len(flows)} taint flows:")
    for i, flow in enumerate(flows, 1):
        print(f"\n{i}. {flow.vulnerability_type or 'Unknown'}")
        print(f"   Source: {flow.source} at {flow.source_location}")
        print(f"   Sink: {flow.sink} at {flow.sink_location}")
        print(f"   Has sanitization: {flow.has_sanitization()}")
        print(f"   Confidence: {flow.confidence}")
    
    # Identify authorization gaps
    print("\nIdentifying authorization gaps...")
    gaps = analyzer.identify_authorization_points(flows)
    
    print(f"\nFound {len(gaps)} potential authorization gaps:")
    for i, gap in enumerate(gaps, 1):
        print(f"\n{i}. {gap['description']}")
        print(f"   Location: {gap['location']}")
        print(f"   Suggested check: {gap['suggested_check']}")
        print(f"   Confidence: {gap['confidence']}")
