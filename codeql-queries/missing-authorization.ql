/**
 * @name Missing Authorization Check in API Endpoints
 * @description Detects REST API endpoints that access sensitive resources
 *              without proper authorization checks
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id java/missing-authorization
 * @tags security
 *       external/cwe/cwe-862
 *       external/cwe/cwe-285
 */

import java

/**
 * REST API endpoint methods
 */
class RestEndpointMethod extends Method {
  RestEndpointMethod() {
    // Spring REST annotations
    (
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "GetMapping") or
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PostMapping") or
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PutMapping") or
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "DeleteMapping") or
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PatchMapping") or
      this.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")
    )
    or
    // JAX-RS annotations
    (
      this.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "GET") or
      this.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "POST") or
      this.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PUT") or
      this.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "DELETE") or
      this.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PATCH")
    )
  }

  /**
   * Check if endpoint has user-controlled ID parameter
   */
  predicate hasUserIdParameter() {
    exists(Parameter p |
      p = this.getAParameter() and
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "QueryParam")
      ) and
      (
        p.getName().toLowerCase().matches("%id%") or
        p.getName().toLowerCase().matches("%user%") or
        p.getType().getName().matches("%Id") or
        p.getType().getName() = "Long" or
        p.getType().getName() = "Integer"
      )
    )
  }

  /**
   * Check if endpoint accesses database/repository
   */
  predicate accessesDatabase() {
    exists(MethodAccess ma |
      ma.getEnclosingCallable() = this and
      (
        ma.getMethod().getName().matches("find%") or
        ma.getMethod().getName().matches("get%") or
        ma.getMethod().getName().matches("save%") or
        ma.getMethod().getName().matches("delete%") or
        ma.getMethod().getName().matches("update%") or
        ma.getMethod().getDeclaringType().getName().matches("%Repository") or
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager")
      )
    )
  }
}

/**
 * Check if method has authorization annotation
 */
predicate hasAuthorizationAnnotation(Method m) {
  exists(Annotation ann |
    ann = m.getAnAnnotation() or ann = m.getDeclaringType().getAnAnnotation()
  |
    ann.getType().hasQualifiedName("org.springframework.security.access.prepost", "PreAuthorize") or
    ann.getType().hasQualifiedName("org.springframework.security.access.annotation", "Secured") or
    ann.getType().hasQualifiedName("javax.annotation.security", "RolesAllowed") or
    ann.getType().hasQualifiedName("javax.annotation.security", "PermitAll") or
    ann.getType().hasQualifiedName("javax.annotation.security", "DenyAll")
  )
}

/**
 * Check if method performs runtime authorization check
 */
predicate hasRuntimeAuthorizationCheck(Method m) {
  exists(MethodAccess ma |
    ma.getEnclosingCallable() = m and
    (
      // Spring Security checks
      ma.getMethod().getName().matches("%authorize%") or
      ma.getMethod().getName().matches("%hasRole%") or
      ma.getMethod().getName().matches("%hasAuthority%") or
      ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.security.core.context", "SecurityContextHolder") or
      // Custom authorization
      ma.getMethod().getName().matches("%checkAccess%") or
      ma.getMethod().getName().matches("%verifyOwnership%") or
      ma.getMethod().getName().matches("%canAccess%") or
      ma.getMethod().getName().matches("%isOwner%") or
      ma.getMethod().getName().matches("%hasPermission%")
    )
  )
  or
  // Check for ownership comparison
  exists(IfStmt ifstmt, EqualityTest eq |
    ifstmt.getEnclosingCallable() = m and
    ifstmt.getCondition() = eq and
    (
      eq.getAnOperand().(MethodAccess).getMethod().getName().matches("%getAuthenticatedUser%") or
      eq.getAnOperand().(MethodAccess).getMethod().getName().matches("%getCurrentUser%") or
      eq.getAnOperand().(MethodAccess).getMethod().getName().matches("%getUserId%")
    )
  )
  or
  // Check for throwing AccessDeniedException
  exists(ThrowStmt throw |
    throw.getEnclosingCallable() = m and
    throw.getExpr().getType().getName().matches("%AccessDenied%")
  )
}

/**
 * Check if endpoint returns sensitive data
 */
predicate returnsSensitiveData(Method m) {
  exists(ReturnStmt ret |
    ret.getEnclosingCallable() = m and
    (
      ret.getResult().getType().getName().matches("%User%") or
      ret.getResult().getType().getName().matches("%Account%") or
      ret.getResult().getType().getName().matches("%Profile%") or
      ret.getResult().getType().getName().matches("%Order%") or
      ret.getResult().getType().getName().matches("%Payment%") or
      ret.getResult().getType().getName().matches("%Transaction%")
    )
  )
}

from RestEndpointMethod endpoint
where
  endpoint.hasUserIdParameter() and
  endpoint.accessesDatabase() and
  returnsSensitiveData(endpoint) and
  not hasAuthorizationAnnotation(endpoint) and
  not hasRuntimeAuthorizationCheck(endpoint) and
  not endpoint.isPrivate() // Private methods might be called from authorized context
select endpoint,
  "REST endpoint '" + endpoint.getName() + "' accesses sensitive resources without authorization checks. " +
  "This could allow unauthorized users to access data by manipulating ID parameters."
