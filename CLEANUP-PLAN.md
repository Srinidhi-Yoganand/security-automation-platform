# Repository Cleanup Plan

## Current State
Main branch is cluttered with test files, logs, temporary scripts, and multiple documentation files.

## Goal
Professional main branch with:
- Clear README
- Essential configuration files
- Core application code
- Single comprehensive documentation

## Cleanup Strategy

### 🗑️ DELETE (Temporary/Generated Files)
```
docker-build.log
workflow-execution.log
idor-execution-log.txt
idor-report.json
COMPLETE-SUCCESS-SUMMARY.txt
IDOR-COMPLETE-SUMMARY.txt
```

### 📦 MOVE TO `testing` BRANCH
```
test-local-platform.py
test_complete_pipeline.py
run_performance_test.py
run_e2e_workflow_test.py
test_multilang.py
test_complete_workflow.py
test_comprehensive_vulnerabilities.py
test_idor_focused.py
test_idor_improved.py
validate_patches.py
demo_real_app.py
run-real-test.py
test-e2e.sh
build-and-test-docker.sh
diagnose-docker.sh
multi-app-test-results/
test-app/
e2e-artifacts/
```

### 📚 MOVE TO `documentation` BRANCH
```
COMPREHENSIVE-TEST-REPORT.md
HYBRID-ANALYSIS-REPORT.md
TESTING-SUMMARY.md
E2E-WORKFLOW-COMPLETE.md
WORKFLOW-PROOF.md
IDOR-TEST-SUCCESS.md
PRESENTATION-GUIDE.md
COMPLETE-DEMO-GUIDE.md
PRESENTATION-SLIDES.md
```

### ✅ KEEP IN MAIN (Professional Files)
```
README.md                    # Main documentation
LICENSE                      # Legal
action.yml                   # GitHub Action
Dockerfile                   # Container build
docker-compose.yml           # Production compose
docker-compose.local.yml     # Local dev compose
DOCKER-SETUP-GUIDE.md       # Setup instructions
QUICK-START.md              # Quick start guide (consolidated)
.dockerignore
.gitignore
.env
correlation-engine/          # Core application
codeql-queries/             # Security queries
test-workspace/             # Example workspace
build-with-progress.sh      # Build script
start-presentation.sh       # Demo script (keep for presentations)
```

### 📝 CREATE NEW FILES
```
CONTRIBUTING.md             # How to contribute
ARCHITECTURE.md            # System architecture
API.md                     # API documentation (consolidated)
CHANGELOG.md               # Version history
```

## Execution Order

1. Switch to testing branch → Move test files
2. Switch to documentation branch → Move docs
3. Switch back to main → Delete temp files
4. Create new consolidated documentation
5. Update README with professional structure
6. Commit and push all branches

## Result
Professional main branch:
- ~15 files in root (down from 45+)
- Clear purpose for each file
- All tests isolated in testing branch
- All detailed docs in documentation branch
- Easy to navigate for new users
