#!/bin/bash

# CodeQL Setup Script for Security Automation Platform
# This script downloads and configures CodeQL for semantic analysis

set -e

echo "=================================="
echo "CodeQL Setup for Thesis Project"
echo "=================================="
echo ""

# Configuration
CODEQL_VERSION="2.15.3"
INSTALL_DIR="$(pwd)/tools/codeql"
JAVA_QUERIES_DIR="$(pwd)/codeql-queries"

echo "📦 Step 1: Downloading CodeQL CLI..."
mkdir -p tools
cd tools

# Download CodeQL CLI
if [ ! -d "codeql" ]; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        wget "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip"
        unzip codeql-linux64.zip
        rm codeql-linux64.zip
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        wget "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-osx64.zip"
        unzip codeql-osx64.zip
        rm codeql-osx64.zip
    else
        echo "⚠️  For Windows, download manually from:"
        echo "https://github.com/github/codeql-cli-binaries/releases"
        exit 1
    fi
    echo "✅ CodeQL CLI downloaded"
else
    echo "✅ CodeQL CLI already installed"
fi

cd ..

echo ""
echo "📚 Step 2: Cloning CodeQL Standard Libraries..."
if [ ! -d "tools/codeql-repo" ]; then
    git clone https://github.com/github/codeql.git tools/codeql-repo
    echo "✅ CodeQL libraries cloned"
else
    echo "✅ CodeQL libraries already present"
fi

echo ""
echo "🔍 Step 3: Creating custom queries directory..."
mkdir -p "$JAVA_QUERIES_DIR"

# Create sample IDOR detection query
cat > "$JAVA_QUERIES_DIR/idor-detection.ql" << 'EOL'
/**
 * @name Insecure Direct Object Reference (IDOR) Detection
 * @description Detects potential IDOR vulnerabilities where user-controlled
 *              input is used to access resources without authorization checks
 * @kind path-problem
 * @problem.severity warning
 * @id java/idor-vulnerability
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.PathSanitizer

/**
 * A configuration for tracking taint from HTTP parameters to database access
 */
class IdorTaintConfig extends TaintTracking::Configuration {
  IdorTaintConfig() { this = "IdorTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP request parameters
    source.asExpr().(MethodAccess).getMethod().hasName("getParameter")
    or
    // Path variables in Spring
    exists(Annotation ann |
      ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") and
      source.asParameter() = ann.getAnnotatedElement()
    )
    or
    // Request parameters in Spring
    exists(Annotation ann |
      ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") and
      source.asParameter() = ann.getAnnotatedElement()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Database access methods
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("findById%") or
      ma.getMethod().getName().matches("get%ById") or
      ma.getMethod().getName().matches("delete%ById") or
      ma.getMethod().getName().matches("update%")
    |
      sink.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Authorization checks
    exists(MethodAccess auth |
      auth.getMethod().getName().matches("%authorize%") or
      auth.getMethod().getName().matches("%hasPermission%") or
      auth.getMethod().getName().matches("%canAccess%")
    |
      node.asExpr() = auth.getAnArgument()
    )
  }
}

from IdorTaintConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential IDOR: User-controlled value $@ flows to resource access without authorization check.",
  source.getNode(), "user input"
EOL

echo "✅ Created IDOR detection query"

# Create authentication bypass query
cat > "$JAVA_QUERIES_DIR/auth-bypass-detection.ql" << 'EOL'
/**
 * @name Missing Authentication Check
 * @description Detects endpoints that may be missing authentication checks
 * @kind problem
 * @problem.severity warning
 * @id java/missing-authentication
 */

import java

/**
 * A Spring REST endpoint method
 */
class RestEndpoint extends Method {
  RestEndpoint() {
    this.getAnAnnotation().getType().getName().matches("%Mapping")
  }
  
  predicate hasAuthAnnotation() {
    this.getAnAnnotation().getType().getName().matches("%Secured%") or
    this.getAnAnnotation().getType().getName().matches("%PreAuthorize%") or
    this.getAnAnnotation().getType().getName().matches("%RolesAllowed%")
  }
  
  predicate hasAuthCheck() {
    exists(MethodAccess ma |
      ma.getEnclosingCallable() = this and
      (
        ma.getMethod().getName().matches("%authenticate%") or
        ma.getMethod().getName().matches("%isAuthenticated%") or
        ma.getMethod().getName().matches("%checkPermission%")
      )
    )
  }
}

from RestEndpoint endpoint
where not endpoint.hasAuthAnnotation() and not endpoint.hasAuthCheck()
select endpoint, "Endpoint may be missing authentication: " + endpoint.getName()
EOL

echo "✅ Created authentication bypass query"

# Create qlpack file
cat > "$JAVA_QUERIES_DIR/qlpack.yml" << 'EOL'
name: security-automation/java-queries
version: 1.0.0
libraryPathDependencies:
  - codeql/java-all
EOL

echo ""
echo "🎯 Step 4: Creating CodeQL database creation script..."
cat > create-codeql-db.sh << 'EOL'
#!/bin/bash

# Create CodeQL database for a Java project

if [ -z "$1" ]; then
    echo "Usage: ./create-codeql-db.sh <path-to-java-project>"
    exit 1
fi

PROJECT_PATH="$1"
DB_NAME="$(basename $PROJECT_PATH)-codeql-db"
DB_PATH="./codeql-databases/$DB_NAME"

echo "Creating CodeQL database for: $PROJECT_PATH"
echo "Database will be saved to: $DB_PATH"

mkdir -p codeql-databases

# Create database
./tools/codeql/codeql database create "$DB_PATH" \
    --language=java \
    --source-root="$PROJECT_PATH" \
    --command="mvn clean compile" \
    --overwrite

echo "✅ Database created: $DB_PATH"
echo ""
echo "Run queries with:"
echo "./run-codeql-queries.sh $DB_PATH"
EOL

chmod +x create-codeql-db.sh
echo "✅ Created database creation script"

echo ""
echo "🔎 Step 5: Creating query execution script..."
cat > run-codeql-queries.sh << 'EOL'
#!/bin/bash

# Run CodeQL queries on a database

if [ -z "$1" ]; then
    echo "Usage: ./run-codeql-queries.sh <path-to-codeql-database>"
    exit 1
fi

DB_PATH="$1"
RESULTS_DIR="./codeql-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Running CodeQL queries on: $DB_PATH"

mkdir -p "$RESULTS_DIR"

# Run IDOR detection
echo "🔍 Running IDOR detection..."
./tools/codeql/codeql query run \
    codeql-queries/idor-detection.ql \
    --database="$DB_PATH" \
    --output="$RESULTS_DIR/idor-results-$TIMESTAMP.bqrs"

# Convert to SARIF
./tools/codeql/codeql bqrs decode \
    "$RESULTS_DIR/idor-results-$TIMESTAMP.bqrs" \
    --format=json \
    --output="$RESULTS_DIR/idor-results-$TIMESTAMP.json"

echo "✅ IDOR results saved to: $RESULTS_DIR/idor-results-$TIMESTAMP.json"

# Run authentication check
echo "🔍 Running authentication check..."
./tools/codeql/codeql query run \
    codeql-queries/auth-bypass-detection.ql \
    --database="$DB_PATH" \
    --output="$RESULTS_DIR/auth-results-$TIMESTAMP.bqrs"

./tools/codeql/codeql bqrs decode \
    "$RESULTS_DIR/auth-results-$TIMESTAMP.bqrs" \
    --format=json \
    --output="$RESULTS_DIR/auth-results-$TIMESTAMP.json"

echo "✅ Auth results saved to: $RESULTS_DIR/auth-results-$TIMESTAMP.json"

echo ""
echo "📊 All results saved to: $RESULTS_DIR/"
EOL

chmod +x run-codeql-queries.sh
echo "✅ Created query execution script"

echo ""
echo "================================================"
echo "✅ CodeQL Setup Complete!"
echo "================================================"
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Create a CodeQL database for your Java project:"
echo "   ./create-codeql-db.sh /path/to/your/java/project"
echo ""
echo "2. Run the custom queries:"
echo "   ./run-codeql-queries.sh ./codeql-databases/your-project-codeql-db"
echo ""
echo "3. View results in ./codeql-results/"
echo ""
echo "📚 CodeQL Resources:"
echo "   - Query documentation: https://codeql.github.com/docs/"
echo "   - Java library: https://codeql.github.com/codeql-standard-libraries/java/"
echo ""
echo "🎯 For thesis: These queries detect IDOR and missing auth - the foundation"
echo "   of your logic flaw detection system!"
echo ""
