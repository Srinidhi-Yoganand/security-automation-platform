#!/bin/bash
# Repository Cleanup Script
# Organizes files into appropriate branches for professional main branch

set -e

echo "=========================================="
echo "🧹 REPOSITORY CLEANUP SCRIPT"
echo "=========================================="
echo ""

# Save current branch
CURRENT_BRANCH=$(git branch --show-current)
echo "📍 Current branch: $CURRENT_BRANCH"
echo ""

# === STEP 1: Commit current changes to main ===
echo "📝 Step 1: Committing new files to main (temporary)..."
git add .
git commit -m "temp: staging files for branch organization" || echo "Nothing to commit"
echo ""

# === STEP 2: Move test files to testing branch ===
echo "🧪 Step 2: Moving test files to testing branch..."
git checkout testing

# Cherry-pick test files from main
TEST_FILES=(
    "test_local_platform.py"
    "test_complete_pipeline.py"
    "run_performance_test.py"
    "run_e2e_workflow_test.py"
    "test_multilang.py"
    "test_complete_workflow.py"
    "test_comprehensive_vulnerabilities.py"
    "test_idor_focused.py"
    "test_idor_improved.py"
    "validate_patches.py"
    "demo_real_app.py"
    "run-real-test.py"
    "test-e2e.sh"
    "build-and-test-docker.sh"
    "diagnose-docker.sh"
)

# Copy test files from main
git checkout main -- "${TEST_FILES[@]}" 2>/dev/null || true
git checkout main -- multi-app-test-results/ 2>/dev/null || true
git checkout main -- test-app/ 2>/dev/null || true
git checkout main -- e2e-artifacts/ 2>/dev/null || true

git add .
git commit -m "test: move test scripts and results from main" || echo "Already up to date"
echo "✅ Test files moved to testing branch"
echo ""

# === STEP 3: Move documentation to documentation branch ===
echo "📚 Step 3: Moving detailed documentation to documentation branch..."
git checkout documentation

DOC_FILES=(
    "COMPREHENSIVE-TEST-REPORT.md"
    "HYBRID-ANALYSIS-REPORT.md"
    "TESTING-SUMMARY.md"
    "E2E-WORKFLOW-COMPLETE.md"
    "WORKFLOW-PROOF.md"
    "IDOR-TEST-SUCCESS.md"
    "PRESENTATION-GUIDE.md"
    "COMPLETE-DEMO-GUIDE.md"
    "PRESENTATION-SLIDES.md"
)

# Copy doc files from main
git checkout main -- "${DOC_FILES[@]}" 2>/dev/null || true

git add .
git commit -m "docs: move detailed documentation from main" || echo "Already up to date"
echo "✅ Documentation moved to documentation branch"
echo ""

# === STEP 4: Clean up main branch ===
echo "🧹 Step 4: Cleaning up main branch..."
git checkout main

# Remove test files from main
echo "Removing test files..."
rm -f test_local_platform.py
rm -f test_complete_pipeline.py
rm -f run_performance_test.py
rm -f run_e2e_workflow_test.py
rm -f test_multilang.py
rm -f test_complete_workflow.py
rm -f test_comprehensive_vulnerabilities.py
rm -f test_idor_focused.py
rm -f test_idor_improved.py
rm -f validate_patches.py
rm -f demo_real_app.py
rm -f run-real-test.py
rm -f test-e2e.sh
rm -f build-and-test-docker.sh
rm -f diagnose-docker.sh
rm -rf multi-app-test-results/
rm -rf test-app/
rm -rf e2e-artifacts/

# Remove detailed docs from main
echo "Removing detailed documentation..."
rm -f COMPREHENSIVE-TEST-REPORT.md
rm -f HYBRID-ANALYSIS-REPORT.md
rm -f TESTING-SUMMARY.md
rm -f E2E-WORKFLOW-COMPLETE.md
rm -f WORKFLOW-PROOF.md
rm -f IDOR-TEST-SUCCESS.md
rm -f PRESENTATION-GUIDE.md
rm -f COMPLETE-DEMO-GUIDE.md
rm -f PRESENTATION-SLIDES.md

# Remove temporary/log files
echo "Removing temporary files..."
rm -f docker-build.log
rm -f workflow-execution.log
rm -f idor-execution-log.txt
rm -f idor-report.json
rm -f COMPLETE-SUCCESS-SUMMARY.txt
rm -f IDOR-COMPLETE-SUMMARY.txt
rm -f CLEANUP-PLAN.md

# Remove duplicate docker-compose files (keep only main ones)
rm -f docker-compose.test.yml

echo "✅ Main branch cleaned"
echo ""

# === STEP 5: Commit cleanup ===
echo "💾 Step 5: Committing cleanup..."
git add -A
git commit -m "cleanup: organize repository structure

- Moved test files to testing branch
- Moved detailed docs to documentation branch  
- Removed temporary and log files
- Cleaned up main branch for professional appearance

Main branch now contains only:
- Core application code (correlation-engine/)
- Essential configuration (docker-compose.yml, Dockerfile)
- Primary documentation (README.md, QUICK-START.md, DOCKER-SETUP-GUIDE.md)
- Build scripts (build-with-progress.sh, start-presentation.sh)
- Security queries (codeql-queries/)
- Example workspace (test-workspace/)
" || echo "Nothing to commit"
echo ""

# === STEP 6: Show summary ===
echo "=========================================="
echo "✅ CLEANUP COMPLETE!"
echo "=========================================="
echo ""
echo "📊 Branch Summary:"
echo ""
echo "main branch (current):"
git ls-files | wc -l | xargs echo "  Files:"
echo "  Focus: Core application + essential docs"
echo ""
echo "testing branch:"
git checkout testing --quiet
git ls-files | wc -l | xargs echo "  Files:"
echo "  Focus: All test scripts and results"
echo ""
echo "documentation branch:"
git checkout documentation --quiet
git ls-files | wc -l | xargs echo "  Files:"
echo "  Focus: Detailed documentation and guides"
echo ""
git checkout main --quiet

echo "📁 Main branch now contains:"
ls -1 | head -20
echo ""

echo "=========================================="
echo "🚀 Next Steps:"
echo "=========================================="
echo ""
echo "1. Review changes:"
echo "   git log --oneline -5"
echo ""
echo "2. Push all branches:"
echo "   git push origin main"
echo "   git push origin testing"
echo "   git push origin documentation"
echo ""
echo "3. Update README if needed"
echo ""
echo "✅ Repository is now professionally organized!"
