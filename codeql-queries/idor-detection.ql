/**
 * @name Insecure Direct Object Reference (IDOR) Detection - Enhanced
 * @description Detects IDOR vulnerabilities where user-controlled input flows
 *              to resource access methods without proper authorization checks.
 *              Supports multiple frameworks and patterns.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id java/idor-vulnerability-enhanced
 * @tags security
 *       external/cwe/cwe-639
 *       external/cwe/cwe-862
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/**
 * User-controlled sources that could be manipulated for IDOR attacks
 */
class IdorSource extends DataFlow::Node {
  IdorSource() {
    // Path variables from REST endpoints
    exists(Parameter p |
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam")
      ) and
      this.asParameter() = p
    )
    or
    // Query parameters
    exists(Parameter p |
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "QueryParam")
      ) and
      this.asParameter() = p
    )
    or
    // Request headers (less common but possible)
    exists(Parameter p |
      p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") and
      this.asParameter() = p
    )
  }
}

/**
 * Database access sinks where IDOR vulnerabilities manifest
 */
class IdorSink extends DataFlow::Node {
  IdorSink() {
    // JPA Repository findById methods
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("findById%") and
      this.asExpr() = ma.getAnArgument()
    )
    or
    // JPA EntityManager find/getReference methods
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      (
        ma.getMethod().getName() = "find" or
        ma.getMethod().getName() = "getReference"
      ) and
      this.asExpr() = ma.getArgument(1) // The ID argument
    )
    or
    // JDBC PreparedStatement with ID in WHERE clause
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "PreparedStatement") and
      ma.getMethod().getName().matches("set%") and
      this.asExpr() = ma.getArgument(1)
    )
    or
    // Spring Data methods
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("findBy%Id") or
        ma.getMethod().getName().matches("get%ById") or
        ma.getMethod().getName().matches("delete%ById")
      ) and
      this.asExpr() = ma.getAnArgument()
    )
  }
}

/**
 * Authorization check methods that indicate proper access control
 */
predicate isAuthorizationCheck(Expr e) {
  exists(MethodAccess ma |
    ma = e and
    (
      // Spring Security checks
      ma.getMethod().getName().matches("%authorize%") or
      ma.getMethod().getName().matches("%hasRole%") or
      ma.getMethod().getName().matches("%hasAuthority%") or
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.security.core.context", "SecurityContextHolder") or
      // Custom authorization checks
      ma.getMethod().getName().matches("%checkAccess%") or
      ma.getMethod().getName().matches("%verifyOwnership%") or
      ma.getMethod().getName().matches("%canAccess%") or
      ma.getMethod().getName().matches("%isOwner%") or
      // Exception throwing for access denied
      ma.getMethod().getName() = "throw" and
      ma.getAnArgument().getType().getName().matches("%AccessDenied%")
    )
  )
  or
  // If statement checking user ownership
  exists(IfStmt ifstmt, EqualityTest eq |
    ifstmt.getCondition() = eq and
    (
      eq.getAnOperand().(MethodAccess).getMethod().getName().matches("%getAuthenticatedUser%") or
      eq.getAnOperand().(MethodAccess).getMethod().getName().matches("%getCurrentUser%")
    ) and
    e = ifstmt
  )
}

/**
 * Check if there's an authorization barrier between source and sink
 */
predicate hasAuthorizationBarrier(DataFlow::PathNode source, DataFlow::PathNode sink) {
  exists(Expr authCheck |
    isAuthorizationCheck(authCheck) and
    authCheck.getEnclosingCallable() = sink.getNode().asExpr().getEnclosingCallable() and
    authCheck.getLocation().getStartLine() < sink.getNode().asExpr().getLocation().getStartLine() and
    authCheck.getLocation().getStartLine() > source.getNode().asParameter().getLocation().getStartLine()
  )
}

/**
 * Main taint tracking configuration for IDOR detection
 */
class IdorConfig extends TaintTracking::Configuration {
  IdorConfig() { this = "IdorConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof IdorSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof IdorSink
  }

  // Allow taint through common transformations
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Taint through Long.valueOf(), Integer.parseInt(), etc.
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("parse%") or
      ma.getMethod().getName() = "valueOf" or
      ma.getMethod().getName() = "toString"
    |
      node1.asExpr() = ma.getAnArgument() and
      node2.asExpr() = ma
    )
  }
}

from IdorConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where
  cfg.hasFlowPath(source, sink) and
  not hasAuthorizationBarrier(source, sink)
select sink.getNode(), source, sink,
  "Potential IDOR vulnerability: User-controlled $@ flows to resource access without authorization check.",
  source.getNode(), "input"
