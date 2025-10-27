# PowerShell Script for CodeQL Setup on Windows
# This script downloads and configures CodeQL for semantic analysis

Write-Host "=================================="
Write-Host "CodeQL Setup for Windows"
Write-Host "=================================="
Write-Host ""

# Configuration
$CODEQL_VERSION = "2.15.3"
$INSTALL_DIR = "$(Get-Location)\tools\codeql"
$JAVA_QUERIES_DIR = "$(Get-Location)\codeql-queries"

Write-Host "📦 Step 1: Downloading CodeQL CLI..."
New-Item -ItemType Directory -Force -Path "tools" | Out-Null

if (!(Test-Path "tools\codeql")) {
    Write-Host "Downloading CodeQL for Windows..."
    $downloadUrl = "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-win64.zip"
    $zipPath = "tools\codeql-win64.zip"
    
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath "tools" -Force
    Remove-Item $zipPath
    Write-Host "✅ CodeQL CLI downloaded"
} else {
    Write-Host "✅ CodeQL CLI already installed"
}

Write-Host ""
Write-Host "📚 Step 2: Cloning CodeQL Standard Libraries..."
if (!(Test-Path "tools\codeql-repo")) {
    git clone https://github.com/github/codeql.git tools\codeql-repo
    Write-Host "✅ CodeQL libraries cloned"
} else {
    Write-Host "✅ CodeQL libraries already present"
}

Write-Host ""
Write-Host "🔍 Step 3: Creating custom queries directory..."
New-Item -ItemType Directory -Force -Path $JAVA_QUERIES_DIR | Out-Null

# Create IDOR detection query
$idorQuery = @'
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
'@

$idorQuery | Out-File -FilePath "$JAVA_QUERIES_DIR\idor-detection.ql" -Encoding UTF8
Write-Host "✅ Created IDOR detection query"

# Create qlpack.yml
$qlpack = @'
name: security-automation/java-queries
version: 1.0.0
libraryPathDependencies:
  - codeql/java-all
'@

$qlpack | Out-File -FilePath "$JAVA_QUERIES_DIR\qlpack.yml" -Encoding UTF8

Write-Host ""
Write-Host "================================================"
Write-Host "✅ CodeQL Setup Complete!"
Write-Host "================================================"
Write-Host ""
Write-Host "📝 Next Steps:"
Write-Host ""
Write-Host "1. Create a CodeQL database (see create-codeql-db.ps1)"
Write-Host "2. Run custom queries (see run-codeql-queries.ps1)"
Write-Host ""
Write-Host "🎯 For thesis: These queries detect IDOR - the foundation of your research!"
Write-Host ""
