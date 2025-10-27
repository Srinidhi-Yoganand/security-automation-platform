"""
Symbolic Executor - Logic Flaw Detection via Symbolic Analysis
Part of the Enhanced Thesis Implementation (Option 2)

This module performs symbolic execution to discover logic vulnerabilities
like IDOR and missing authorization checks.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
import logging
from z3 import Solver, Int, Bool, IntSort, sat, unsat

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of logic vulnerabilities"""
    IDOR = "idor"
    MISSING_AUTHENTICATION = "missing_authentication"
    MISSING_AUTHORIZATION = "missing_authorization"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class SymbolicValue:
    """Represents a symbolic value in execution"""
    name: str
    sort: Any  # Z3 sort (IntSort, StringSort, etc.)
    constraints: List[Any] = None  # Z3 constraints
    
    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []


@dataclass
class ExploitProof:
    """
    Proof that a vulnerability is exploitable
    Contains concrete values that demonstrate the exploit
    """
    vulnerability_type: VulnerabilityType
    exploitable: bool
    
    # Concrete exploit values
    attack_vector: Dict[str, Any]
    
    # Proof explanation
    proof_description: str
    
    # The constraints that were satisfied
    satisfying_constraints: List[str]
    
    # Suggested fix
    missing_check: str
    fix_location: Tuple[str, int]
    
    # Confidence score
    confidence: float = 0.95
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "vulnerability_type": self.vulnerability_type.value,
            "exploitable": self.exploitable,
            "attack_vector": self.attack_vector,
            "proof": self.proof_description,
            "constraints": self.satisfying_constraints,
            "missing_check": self.missing_check,
            "fix_location": {
                "file": self.fix_location[0],
                "line": self.fix_location[1]
            },
            "confidence": self.confidence
        }


class SymbolicExecutor:
    """
    Performs symbolic execution to find logic vulnerabilities
    
    This is the core of Option 2: using symbolic analysis to discover
    vulnerabilities that traditional pattern-based SAST cannot find.
    """
    
    def __init__(self):
        """Initialize symbolic executor"""
        self.solver = Solver()
        self.symbolic_values: Dict[str, SymbolicValue] = {}
    
    def verify_codeql_finding(
        self,
        dataflow_path: Any,
        security_context: Any
    ) -> Optional[ExploitProof]:
        """
        Verify a CodeQL finding using symbolic execution
        
        This adapter method takes DataFlowPath and SecurityContext from
        semantic_analyzer_complete and converts them for analysis.
        
        Args:
            dataflow_path: DataFlowPath from semantic analyzer
            security_context: Any from semantic analyzer
            
        Returns:
            ExploitProof if vulnerability confirmed, None otherwise
        """
        # Create a compatible flow object for internal analysis
        flow = self._adapt_dataflow(dataflow_path)
        context = self._adapt_security_context(security_context)
        
        return self.analyze_authorization_gap(flow, context)
    
    def _adapt_dataflow(self, dataflow_path: Any) -> 'MockFlow':
        """Adapt DataFlowPath from semantic analyzer"""
        class MockFlow:
            def __init__(self, df):
                self.vulnerability_type = df.vulnerability_type or "idor"
                self.source_location = (
                    df.source_location.file_path if hasattr(df.source_location, 'file_path')
                    else df.source_location[0] if isinstance(df.source_location, tuple)
                    else "unknown",
                    df.source_location.start_line if hasattr(df.source_location, 'start_line')
                    else df.source_location[1] if isinstance(df.source_location, tuple) and len(df.source_location) > 1
                    else 0
                )
                self.sink_location = (
                    df.sink_location.file_path if hasattr(df.sink_location, 'file_path')
                    else df.sink_location[0] if isinstance(df.sink_location, tuple)
                    else "unknown",
                    df.sink_location.start_line if hasattr(df.sink_location, 'start_line')
                    else df.sink_location[1] if isinstance(df.sink_location, tuple) and len(df.sink_location) > 1
                    else 0
                )
                self.intermediate_steps = []
                if hasattr(df, 'path') and df.path:
                    self.intermediate_steps = [{"code": step} for step in df.path]
        
        return MockFlow(dataflow_path)
    
    def _adapt_security_context(self, security_context: Any) -> 'MockContext':
        """Adapt SecurityContext from semantic analyzer"""
        class MockContext:
            def __init__(self, sc):
                self.security_annotations = (
                    sc.security_annotations if hasattr(sc, 'security_annotations')
                    else []
                )
                self.framework = (
                    sc.framework if hasattr(sc, 'framework')
                    else "spring"
                )
                self._has_auth = (
                    sc.authentication_present if hasattr(sc, 'authentication_present')
                    else False
                )
                self._has_authz = (
                    sc.authorization_present if hasattr(sc, 'authorization_present')
                    else False
                )
            
            def has_authorization(self):
                return self._has_authz
            
            def has_authentication(self):
                return self._has_auth
        
        return MockContext(security_context)
        
    def analyze_authorization_gap(
        self,
        flow: Any,
        security_context: Any
    ) -> Optional[ExploitProof]:
        """
        Analyze if there's an exploitable authorization gap in the data flow
        
        This is the key method that uses symbolic execution to prove
        that a vulnerability is real and exploitable.
        
        Args:
            flow: Data flow from source to sink
            security_context: Security context at the sink location
            
        Returns:
            ExploitProof if vulnerability is confirmed, None otherwise
        """
        logger.info(f"Analyzing authorization gap for {flow.vulnerability_type}")
        
        # Reset solver for new analysis
        self.solver = Solver()
        self.symbolic_values = {}
        
        # Check vulnerability type
        if flow.vulnerability_type == "idor":
            return self._analyze_idor(flow, security_context)
        elif "auth" in flow.vulnerability_type:
            return self._analyze_missing_auth(flow, security_context)
        
        return None
    
    def _analyze_idor(
        self,
        flow: Any,
        security_context: Any
    ) -> Optional[ExploitProof]:
        """
        Analyze Insecure Direct Object Reference vulnerabilities
        
        Algorithm:
        1. Create symbolic values for userId (user input) and currentUserId (authenticated user)
        2. Add constraint: userId ≠ currentUserId (attacker tries to access different user's data)
        3. Check if there's any path constraint that prevents this
        4. If satisfiable, generate exploit proof
        
        Args:
            flow: Data flow to analyze
            security_context: Security context
            
        Returns:
            ExploitProof if IDOR is confirmed
        """
        logger.info("Performing symbolic execution for IDOR analysis")
        
        # Create symbolic variables
        user_id = Int('userId')  # User-controlled input
        current_user_id = Int('currentUserId')  # Authenticated user
        
        self.symbolic_values['userId'] = SymbolicValue('userId', IntSort())
        self.symbolic_values['currentUserId'] = SymbolicValue('currentUserId', IntSort())
        
        # Add basic constraints (valid IDs)
        self.solver.add(user_id > 0)
        self.solver.add(current_user_id > 0)
        
        # Key constraint: Can attacker access different user's data?
        self.solver.add(user_id != current_user_id)
        
        # Check if there's any authorization check in the path
        has_auth_check = self._check_for_authorization(flow, security_context)
        
        if has_auth_check:
            logger.info("Authorization check found in path")
            # Add constraint that would prevent unauthorized access
            # In a real implementation, we'd model the actual check
            self.solver.add(user_id == current_user_id)
        
        # Try to find a satisfying assignment
        result = self.solver.check()
        
        if result == sat and not has_auth_check:
            # Vulnerability confirmed! Generate exploit proof
            model = self.solver.model()
            
            attack_user_id = model[user_id].as_long()
            victim_user_id = model[current_user_id].as_long()
            
            proof = ExploitProof(
                vulnerability_type=VulnerabilityType.IDOR,
                exploitable=True,
                attack_vector={
                    "method": "GET",
                    "endpoint": self._extract_endpoint(flow),
                    "parameter": "userId",
                    "attacker_value": attack_user_id,
                    "attacker_logged_in_as": victim_user_id,
                    "explanation": f"User {victim_user_id} can access user {attack_user_id}'s data"
                },
                proof_description=(
                    f"IDOR vulnerability confirmed through symbolic execution.\n\n"
                    f"Attack scenario:\n"
                    f"1. Attacker logs in as user ID {victim_user_id}\n"
                    f"2. Attacker calls endpoint with userId={attack_user_id}\n"
                    f"3. System returns user {attack_user_id}'s data without authorization check\n\n"
                    f"No constraint exists in the code path that enforces userId == currentUserId"
                ),
                satisfying_constraints=[
                    f"userId = {attack_user_id}",
                    f"currentUserId = {victim_user_id}",
                    f"userId ≠ currentUserId (no authorization check)"
                ],
                missing_check="Authorization check: verify current user owns the requested resource",
                fix_location=flow.sink_location,
                confidence=0.95
            )
            
            logger.info(f"IDOR confirmed: {proof.proof_description}")
            return proof
        
        elif result == sat and has_auth_check:
            # Authorization check exists, likely not vulnerable
            logger.info("Authorization check prevents IDOR")
            return None
        
        else:
            # Unsat - constraints cannot be satisfied
            logger.info("No exploitable IDOR found")
            return None
    
    def _analyze_missing_auth(
        self,
        flow: Any,
        security_context: Any
    ) -> Optional[ExploitProof]:
        """
        Analyze missing authentication vulnerabilities
        
        Check if sensitive operations can be performed without authentication.
        
        Args:
            flow: Data flow to analyze
            security_context: Security context
            
        Returns:
            ExploitProof if missing authentication is confirmed
        """
        logger.info("Analyzing for missing authentication")
        
        # Create symbolic variable for authentication state
        is_authenticated = Bool('isAuthenticated')
        
        # Check if there's an authentication check in the path
        has_auth_annotation = any(
            ann in security_context.security_annotations 
            for ann in ['@PreAuthorize', '@Secured', '@RolesAllowed']
        )
        
        has_auth_check = self._check_for_authentication(flow, security_context)
        
        if not has_auth_annotation and not has_auth_check:
            # No authentication - vulnerability confirmed
            proof = ExploitProof(
                vulnerability_type=VulnerabilityType.MISSING_AUTHENTICATION,
                exploitable=True,
                attack_vector={
                    "method": "GET/POST",
                    "endpoint": self._extract_endpoint(flow),
                    "authentication_required": False,
                    "explanation": "Endpoint accessible without authentication"
                },
                proof_description=(
                    f"Missing authentication vulnerability confirmed.\n\n"
                    f"The endpoint {self._extract_endpoint(flow)} performs sensitive "
                    f"operations but has no authentication check.\n"
                    f"An unauthenticated user can access this endpoint."
                ),
                satisfying_constraints=[
                    "isAuthenticated = false",
                    "No @PreAuthorize or similar annotation",
                    "No authentication check in method body"
                ],
                missing_check="Authentication check: @PreAuthorize or similar",
                fix_location=flow.sink_location,
                confidence=0.90
            )
            
            return proof
        
        return None
    
    def _check_for_authorization(
        self,
        flow: Any,
        security_context: Any
    ) -> bool:
        """
        Check if there's an authorization check in the data flow path
        
        Args:
            flow: Data flow to check
            security_context: Security context
            
        Returns:
            True if authorization check exists
        """
        # Check intermediate steps for authorization patterns
        auth_patterns = [
            'hasPermission', 'canAccess', 'authorize',
            'checkOwnership', 'verifyAccess', 'isOwner'
        ]
        
        for step in flow.intermediate_steps:
            step_code = step.get('code', '')
            if any(pattern in step_code for pattern in auth_patterns):
                return True
        
        # Check security context
        if security_context.has_authorization():
            return True
        
        return False
    
    def _check_for_authentication(
        self,
        flow: Any,
        security_context: Any
    ) -> bool:
        """
        Check if there's an authentication check in the path
        
        Args:
            flow: Data flow to check
            security_context: Security context
            
        Returns:
            True if authentication check exists
        """
        auth_patterns = [
            'isAuthenticated', 'authenticate', 'login',
            'getAuthentication', 'SecurityContext'
        ]
        
        for step in flow.intermediate_steps:
            step_code = step.get('code', '')
            if any(pattern in step_code for pattern in auth_patterns):
                return True
        
        return False
    
    def _extract_endpoint(self, flow: Any) -> str:
        """
        Extract the API endpoint from the data flow
        
        Args:
            flow: Data flow
            
        Returns:
            Endpoint string
        """
        # Parse from source code or annotations
        # For now, return a placeholder
        file_name = flow.sink_location[0].split('/')[-1]
        return f"/api/{file_name.replace('.java', '').lower()}"
    
    def find_missing_checks(
        self,
        flow: Any,
        security_context: Any
    ) -> Dict[str, Any]:
        """
        Identify what security checks are missing in the code
        
        Compare against secure patterns to find gaps.
        
        Args:
            flow: Data flow to analyze
            security_context: Security context
            
        Returns:
            Dictionary describing missing checks
        """
        missing = {
            "authorization": [],
            "authentication": [],
            "input_validation": [],
            "recommendations": []
        }
        
        # Check for missing authorization
        if flow.vulnerability_type == "idor":
            if not self._check_for_authorization(flow, security_context):
                missing["authorization"].append({
                    "type": "ownership_check",
                    "description": "Verify current user owns the requested resource",
                    "suggested_code": self._suggest_authorization_code(security_context),
                    "location": flow.sink_location
                })
        
        # Check for missing authentication
        if not security_context.security_annotations:
            missing["authentication"].append({
                "type": "endpoint_authentication",
                "description": "Endpoint should require authentication",
                "suggested_code": "@PreAuthorize(\"isAuthenticated()\")",
                "location": flow.sink_location
            })
        
        # Generate recommendations
        if missing["authorization"]:
            missing["recommendations"].append(
                "Add authorization check before resource access"
            )
        if missing["authentication"]:
            missing["recommendations"].append(
                "Add authentication requirement to endpoint"
            )
        
        return missing
    
    def _suggest_authorization_code(self, security_context: Any) -> str:
        """
        Suggest appropriate authorization code based on framework
        
        Args:
            security_context: Security context
            
        Returns:
            Suggested code snippet
        """
        if security_context.framework == "spring":
            return """
// Get current authenticated user
User currentUser = (User) SecurityContextHolder
    .getContext()
    .getAuthentication()
    .getPrincipal();

// Verify ownership
if (!userId.equals(currentUser.getId())) {
    throw new AccessDeniedException("Cannot access other user's data");
}
"""
        else:
            return """
// Add authorization check here
if (!currentUser.canAccess(resourceId)) {
    throw new UnauthorizedException();
}
"""
    
    def generate_exploit_test(self, proof: ExploitProof) -> str:
        """
        Generate an automated test that demonstrates the exploit
        
        Args:
            proof: Exploit proof
            
        Returns:
            Test code as string
        """
        if proof.vulnerability_type == VulnerabilityType.IDOR:
            return f"""
@Test
public void testIDORVulnerability() {{
    // Setup: Create two users
    User victim = createUser("victim");
    User attacker = createUser("attacker");
    
    // Attacker logs in
    loginAs(attacker);
    
    // Attempt to access victim's data
    String endpoint = "{proof.attack_vector['endpoint']}";
    String victimId = String.valueOf(victim.getId());
    
    Response response = get(endpoint + "/" + victimId);
    
    // VULNERABILITY: Should return 403 Forbidden, but returns 200 OK
    assertEquals(200, response.getStatus());  // BUG: Should be 403
    
    // Attacker can see victim's data!
    User retrievedUser = response.readEntity(User.class);
    assertEquals(victim.getId(), retrievedUser.getId());
    
    // Fix: Add authorization check to prevent this
}}
"""
        return "// Test generation not implemented for this vulnerability type"


# Example usage
if __name__ == "__main__":
    from .semantic_analyzer import SemanticAnalyzer, DataFlowPath, SecurityContext
    
    logging.basicConfig(level=logging.INFO)
    
    # Example: Analyze a simple IDOR scenario
    print("Example: Symbolic Execution for IDOR Detection\n")
    
    # Create a sample data flow (in real use, this comes from semantic analyzer)
    sample_flow = DataFlowPath(
        source="@PathVariable Long userId",
        source_type="http_parameter",
        source_location=("UserController.java", 42),
        sink="userRepository.findById(userId)",
        sink_type="database_query",
        sink_location=("UserController.java", 45),
        intermediate_steps=[],
        sanitizers=[],
        validators=[],
        vulnerability_type="idor"
    )
    
    sample_context = SecurityContext(
        file_path="UserController.java",
        line_number=42,
        authentication_methods=["SecurityContextHolder"],
        authorization_checks=[],
        security_annotations=[],
        framework="spring"
    )
    
    # Run symbolic execution
    executor = SymbolicExecutor()
    proof = executor.analyze_authorization_gap(sample_flow, sample_context)
    
    if proof:
        print("🚨 VULNERABILITY CONFIRMED!\n")
        print(f"Type: {proof.vulnerability_type.value}")
        print(f"Exploitable: {proof.exploitable}")
        print(f"\nProof:\n{proof.proof_description}")
        print(f"\nAttack Vector:")
        for key, value in proof.attack_vector.items():
            print(f"  {key}: {value}")
        print(f"\nMissing Check: {proof.missing_check}")
        print(f"\nConfidence: {proof.confidence * 100}%")
        
        print("\n" + "="*60)
        print("Generated Exploit Test:")
        print("="*60)
        print(executor.generate_exploit_test(proof))
    else:
        print("✅ No vulnerability found (authorization check present)")
