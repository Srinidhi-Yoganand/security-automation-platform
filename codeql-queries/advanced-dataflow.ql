/**
 * @name Advanced Data Flow Security Analysis
 * @description Tracks user input through the application to identify security-sensitive
 *              data flows including sanitization gaps and complex attack paths
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/advanced-data-flow-security
 * @tags security
 *       external/cwe/cwe-20
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/**
 * User-controlled input sources
 */
class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    // HTTP request parameters
    exists(Parameter p |
      (
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
        p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "PathParam") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "QueryParam") or
        p.getAnAnnotation().getType().hasQualifiedName("javax.ws.rs", "FormParam")
      ) and
      this.asParameter() = p
    )
    or
    // Servlet request methods
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
      (
        ma.getMethod().getName().matches("getParameter%") or
        ma.getMethod().getName().matches("getHeader%") or
        ma.getMethod().getName() = "getCookies" or
        ma.getMethod().getName() = "getInputStream"
      ) and
      this.asExpr() = ma
    )
  }
}

/**
 * Security-sensitive sinks that could lead to vulnerabilities
 */
class SecuritySensitiveSink extends DataFlow::Node {
  string sinkType;

  SecuritySensitiveSink() {
    // Database access (SQL Injection, IDOR)
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("find%") or
        ma.getMethod().getName().matches("get%") or
        ma.getMethod().getName() = "createQuery" or
        ma.getMethod().getName() = "createNativeQuery" or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement")
      ) and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "database-access"
    )
    or
    // File operations (Path Traversal)
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Paths") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files")
      ) and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "file-access"
    )
    or
    // Command execution (Command Injection)
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
        ma.getMethod().getName() = "exec"
      ) or
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
      ) and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "command-execution"
    )
    or
    // Reflection (Code Injection)
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
        ma.getMethod().getName() = "forName"
      ) or
      (
        ma.getMethod().getName() = "newInstance"
      ) and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "reflection"
    )
    or
    // LDAP queries (LDAP Injection)
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.naming.directory", "DirContext") and
      ma.getMethod().getName() = "search" and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "ldap-query"
    )
    or
    // XPath queries (XPath Injection)
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPath") and
      ma.getMethod().getName().matches("compile%") and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "xpath-query"
    )
    or
    // Response output (XSS)
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter")
      ) and
      (
        ma.getMethod().getName() = "write" or
        ma.getMethod().getName().matches("print%")
      ) and
      this.asExpr() = ma.getAnArgument() and
      sinkType = "response-output"
    )
  }

  string getSinkType() { result = sinkType }
}

/**
 * Sanitization methods that validate/escape user input
 */
class Sanitizer extends DataFlow::Node {
  Sanitizer() {
    exists(MethodAccess ma |
      (
        // Input validation
        ma.getMethod().getName().matches("%validate%") or
        ma.getMethod().getName().matches("%sanitize%") or
        ma.getMethod().getName().matches("%clean%") or
        ma.getMethod().getName().matches("%escape%") or
        // Encoding methods
        ma.getMethod().getName().matches("%encode%") or
        ma.getMethod().getName().matches("%htmlEncode%") or
        ma.getMethod().getName().matches("%urlEncode%") or
        // Apache Commons validators
        ma.getMethod().getDeclaringType().getPackage().getName().matches("%validation%") or
        ma.getMethod().getDeclaringType().getName().matches("%Validator%") or
        // OWASP ESAPI
        ma.getMethod().getDeclaringType().getPackage().getName().matches("%esapi%")
      ) and
      this.asExpr() = ma
    )
  }
}

/**
 * Main taint tracking configuration
 */
class AdvancedSecurityFlowConfig extends TaintTracking::Configuration {
  AdvancedSecurityFlowConfig() { this = "AdvancedSecurityFlowConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof UserInputSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SecuritySensitiveSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof Sanitizer
  }

  // Track through common transformations
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // String operations
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
      (
        ma.getMethod().getName() = "concat" or
        ma.getMethod().getName() = "replace" or
        ma.getMethod().getName() = "replaceAll" or
        ma.getMethod().getName() = "substring" or
        ma.getMethod().getName() = "toLowerCase" or
        ma.getMethod().getName() = "toUpperCase" or
        ma.getMethod().getName() = "trim"
      )
    |
      node1.asExpr() = ma.getQualifier() and
      node2.asExpr() = ma
    )
    or
    // StringBuilder/StringBuffer operations
    exists(MethodAccess ma |
      (
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") or
        ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "StringBuffer")
      ) and
      ma.getMethod().getName() = "append"
    |
      node1.asExpr() = ma.getAnArgument() and
      node2.asExpr() = ma
    )
    or
    // Type conversions
    exists(MethodAccess ma |
      (
        ma.getMethod().getName().matches("parse%") or
        ma.getMethod().getName() = "valueOf" or
        ma.getMethod().getName() = "toString"
      )
    |
      node1.asExpr() = ma.getAnArgument() and
      node2.asExpr() = ma
    )
  }
}

from AdvancedSecurityFlowConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink, SecuritySensitiveSink sensitiveSink
where
  cfg.hasFlowPath(source, sink) and
  sink.getNode() = sensitiveSink
select sink.getNode(), source, sink,
  "Unsanitized user input from $@ flows to " + sensitiveSink.getSinkType() + " operation. " +
  "This could lead to security vulnerabilities if not properly validated.",
  source.getNode(), "user-controlled source"
