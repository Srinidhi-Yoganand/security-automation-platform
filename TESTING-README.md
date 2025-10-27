# Testing Branch

This branch contains all testing scripts and downloaded vulnerable applications for platform validation.

## What's in This Branch

### Testing Scripts
- `setup-multi-app-tests.sh` - Downloads all test applications
- `test-all-apps.py` - Runs systematic tests on all apps
- `collect-metrics.py` - Collects and analyzes metrics

### Test Applications (Downloaded)
- `test-workspace/WebGoat/` - OWASP WebGoat (Java, ~50K LOC)
- `test-workspace/java-sec-code/` - Java vulnerable code samples (~10K LOC)
- `test-workspace/benchmark/` - OWASP BenchmarkJava (~15K LOC)
- `test-workspace/NodeGoat/` - OWASP NodeGoat (JavaScript, ~3K LOC)
- `test-workspace/DVWA/` - Damn Vulnerable Web App (PHP, ~5K LOC)
- `test-workspace/vulnerable_python.py` - Simple Python vulnerable app
- `test-workspace/vulnerable_javascript.js` - Simple JavaScript vulnerable app

### Test Results
- `multi-app-test-results/` - Generated after running tests
  - `MULTI-APP-TEST-REPORT.md` - Comprehensive test report
  - `test-results.json` - Raw data for analysis
  - `TEST-PLAN.md` - Testing strategy

### Documentation
- `LETS-TEST-EVERYTHING.md` - Quick start guide
- `REALISTIC-TESTING-GUIDE.md` - Honest assessment of what works
- `TESTING-PLAN.md` - Detailed testing methodology
- `TESTING-QUICKSTART.md` - Fast testing guide

## Quick Start

### 1. Download Test Applications (10 minutes)
```bash
./setup-multi-app-tests.sh
```

### 2. Run All Tests (15 minutes)
```bash
python test-all-apps.py
```

### 3. View Reports
```bash
cat multi-app-test-results/MULTI-APP-TEST-REPORT.md
```

## What Gets Tested

### Java (Primary - Should Work ✅)
- Custom vulnerable app (validated: 1.0% FP rate)
- WebGoat
- java-sec-code
- BenchmarkJava

### Other Languages (Experimental 🧪)
- Python (simple vulnerable app)
- JavaScript (simple vulnerable app + NodeGoat)
- PHP (DVWA)

## Results Location

After testing, find your results in:
- `multi-app-test-results/MULTI-APP-TEST-REPORT.md` - Main thesis-ready report
- `multi-app-test-results/test-results.json` - Data for charts/tables

## Branch Organization

```
testing/          ← You are here (testing branch)
├── test-workspace/          ← Downloaded vulnerable apps
├── multi-app-test-results/  ← Generated test reports
├── setup-*.sh               ← Setup scripts
├── test-*.py                ← Testing scripts
└── TESTING-*.md             ← Testing guides

main/             ← Clean production code
├── README.md                ← Professional project README
├── correlation-engine/      ← Platform code
└── docs/                    ← Documentation
```

## After Testing

### If tests are successful:
```bash
# Switch back to main
git checkout main

# Cherry-pick specific results if needed
# (Keep main clean, just add final metrics)
```

### For thesis:
Use the generated report (`MULTI-APP-TEST-REPORT.md`) directly in Chapter 6 (Results).

## Notes

- This branch is for **testing only** - not for production
- Main branch stays clean with just the platform code
- Test results documented here for thesis validation
- Can be shared with thesis advisor for review

## Status

- [x] Testing framework created
- [ ] Applications downloaded (run setup-multi-app-tests.sh)
- [ ] Tests executed (run test-all-apps.py)
- [ ] Results analyzed
- [ ] Thesis metrics collected
