#!/bin/bash
# Simple CodeQL Setup Script for Git Bash on Windows

echo "=================================="
echo "CodeQL Setup"
echo "=================================="

# Step 1: Download CodeQL CLI
echo ""
echo "Step 1: Downloading CodeQL CLI..."
mkdir -p tools

if [ ! -d "tools/codeql" ]; then
    echo "Downloading CodeQL for Windows..."
    curl -L "https://github.com/github/codeql-cli-binaries/releases/download/v2.15.3/codeql-win64.zip" -o tools/codeql-win64.zip
    
    echo "Extracting..."
    unzip -q tools/codeql-win64.zip -d tools/
    rm tools/codeql-win64.zip
    echo "✅ CodeQL CLI downloaded"
else
    echo "✅ CodeQL CLI already installed"
fi

# Step 2: Clone CodeQL Standard Libraries (Java only to avoid long path issues)
echo ""
echo "Step 2: Setting up CodeQL Java library..."
if [ ! -d "tools/codeql-repo" ]; then
    echo "Cloning minimal CodeQL repo..."
    git clone --depth 1 --filter=blob:none --sparse https://github.com/github/codeql.git tools/codeql-repo
    cd tools/codeql-repo
    git sparse-checkout set java
    cd ../..
    echo "✅ CodeQL Java library set up"
else
    echo "✅ CodeQL library already exists"
fi

# Step 3: Create custom queries directory
echo ""
echo "Step 3: Creating custom queries..."
mkdir -p codeql-queries

# Create IDOR detection query
cat > codeql-queries/idor-detection.ql << 'EOF'
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

class IdorConfig extends TaintTracking::Configuration {
  IdorConfig() { this = "IdorConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName().matches("findById%") and
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

from IdorConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential IDOR: User-controlled value flows to resource access."
EOF

# Create qlpack.yml
cat > codeql-queries/qlpack.yml << 'EOF'
name: security-automation/java-queries
version: 1.0.0
libraryPathDependencies:
  - codeql/java-all
EOF

echo "✅ Created custom queries"

# Step 4: Create helper scripts
echo ""
echo "Step 4: Creating helper scripts..."

# Database creation script
cat > create-codeql-db.sh << 'EOF'
#!/bin/bash
# Create CodeQL database for a Java project

if [ -z "$1" ]; then
    echo "Usage: ./create-codeql-db.sh <java-project-path>"
    exit 1
fi

PROJECT_PATH=$1
DB_NAME=$(basename $PROJECT_PATH)-codeql-db

echo "Creating CodeQL database for: $PROJECT_PATH"
echo "Database name: $DB_NAME"

mkdir -p codeql-databases

./tools/codeql/codeql database create \
    codeql-databases/$DB_NAME \
    --language=java \
    --source-root=$PROJECT_PATH \
    --command="mvn clean compile -DskipTests" \
    --overwrite

echo "✅ Database created: codeql-databases/$DB_NAME"
EOF
chmod +x create-codeql-db.sh

# Query execution script
cat > run-codeql-queries.sh << 'EOF'
#!/bin/bash
# Run custom CodeQL queries on a database

if [ -z "$1" ]; then
    echo "Usage: ./run-codeql-queries.sh <database-path>"
    exit 1
fi

DB_PATH=$1
OUTPUT_DIR="codeql-results"

echo "Running CodeQL queries on: $DB_PATH"
mkdir -p $OUTPUT_DIR

./tools/codeql/codeql database analyze $DB_PATH \
    codeql-queries/idor-detection.ql \
    --format=sarif-latest \
    --output=$OUTPUT_DIR/idor-results.sarif

./tools/codeql/codeql database analyze $DB_PATH \
    codeql-queries/idor-detection.ql \
    --format=csv \
    --output=$OUTPUT_DIR/idor-results.csv

echo "✅ Results saved to: $OUTPUT_DIR/"
EOF
chmod +x run-codeql-queries.sh

echo "✅ Helper scripts created"

echo ""
echo "================================================"
echo "✅ CodeQL Setup Complete!"
echo "================================================"
echo ""
echo "📚 Next Steps:"
echo "1. Test CodeQL: ./tools/codeql/codeql version"
echo "2. Create database: ./create-codeql-db.sh ./sample-vuln-app"
echo "3. Run queries: ./run-codeql-queries.sh ./codeql-databases/sample-vuln-app-codeql-db"
echo ""
echo "🎯 For thesis: These queries detect IDOR - the foundation of your research!"
