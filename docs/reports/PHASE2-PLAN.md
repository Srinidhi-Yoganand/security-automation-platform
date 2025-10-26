# Phase 2: Security Behavior Analysis

## Overview
Phase 2 extends the correlation engine with historical behavior tracking and pattern analysis to provide deeper security insights.

## Goals
1. Track vulnerability lifecycle across commits
2. Analyze code change patterns that introduce vulnerabilities
3. Calculate risk scores based on historical behavior
4. Identify recurring vulnerability patterns
5. Provide actionable insights for developers

## Components

### 2.1 Database Schema (SQLAlchemy)
- **Vulnerabilities Table**: Track each vulnerability over time
- **Scans Table**: Record scan metadata (timestamp, commit, branch)
- **Code Changes Table**: Track files modified between scans
- **Patterns Table**: Store identified security patterns
- **Metrics Table**: Historical security metrics

### 2.2 Git History Analyzer
- Parse git log to identify when vulnerabilities were introduced
- Track file modification history
- Correlate vulnerabilities with specific commits and authors
- Analyze commit messages for security keywords

### 2.3 Vulnerability Lifecycle Tracker
- **States**: new, existing, fixed, regressed, ignored
- Track state transitions over time
- Calculate mean time to fix (MTTF)
- Identify vulnerabilities that persist across releases

### 2.4 Pattern Analysis Engine
- Detect common vulnerability patterns (e.g., SQL injection in DAO layer)
- Identify anti-patterns (e.g., missing input validation)
- Code complexity metrics (cyclomatic complexity, nesting depth)
- Dependency analysis (vulnerable libraries)

### 2.5 Risk Scoring Algorithm
**Factors:**
- Severity (from scanners)
- Exploitability (confirmed vs potential)
- Age (how long vulnerability has existed)
- Frequency (similar patterns in codebase)
- Blast radius (affected endpoints/users)
- Fix difficulty (code complexity, dependencies)

**Formula:**
```
Risk Score = (Severity × 0.3) + (Exploitability × 0.25) + (Age × 0.15) + 
             (Frequency × 0.15) + (Blast Radius × 0.10) + (Fix Difficulty × 0.05)
```

### 2.6 Behavior Analysis API
**New Endpoints:**
- `POST /api/v1/scans` - Register new scan
- `GET /api/v1/vulnerabilities/{id}/history` - Vulnerability timeline
- `GET /api/v1/metrics/trends` - Security metrics over time
- `GET /api/v1/patterns` - Identified security patterns
- `GET /api/v1/risk-scores` - Risk-ranked vulnerabilities

### 2.7 Enhanced Dashboard
**New Visualizations:**
- Vulnerability trend chart (over time)
- Time-to-fix histogram
- Risk heatmap by component
- Pattern frequency chart
- Developer security scorecard

## Implementation Plan

### Step 1: Database Setup
1. Create SQLAlchemy models
2. Set up Alembic migrations
3. Initialize database schema
4. Seed with Phase 1 data

### Step 2: Git Integration
1. Build GitPython wrapper
2. Implement commit parser
3. Create file history tracker
4. Test with vulnerable-app repo

### Step 3: Lifecycle Tracking
1. Define state machine
2. Implement state transition logic
3. Create persistence layer
4. Build query interface

### Step 4: Pattern Analysis
1. Define pattern templates
2. Implement AST-based code analysis
3. Build pattern matching engine
4. Calculate pattern frequencies

### Step 5: Risk Scoring
1. Implement scoring algorithm
2. Normalize score components
3. Create risk ranking service
4. Add confidence intervals

### Step 6: API Enhancement
1. Add new endpoints to FastAPI
2. Implement service layer
3. Create request/response models
4. Add API documentation

### Step 7: Dashboard v2
1. Design new chart types
2. Implement trend analysis
3. Add filtering and drill-down
4. Create export functionality

### Step 8: Testing
1. Unit tests for all components
2. Integration tests with git history
3. Performance testing with large datasets
4. Validation with real vulnerability data

## Success Criteria
- ✅ Track at least 10 vulnerability state transitions
- ✅ Identify 3+ common vulnerability patterns
- ✅ Calculate risk scores for all vulnerabilities
- ✅ Generate trend charts showing historical data
- ✅ MTTF calculation within 10% accuracy
- ✅ API response time < 500ms for queries
- ✅ Dashboard loads with 6+ months of data

## Timeline
- Database Setup: 30 mins
- Git Integration: 45 mins
- Lifecycle Tracking: 30 mins
- Pattern Analysis: 60 mins
- Risk Scoring: 30 mins
- API Enhancement: 30 mins
- Dashboard v2: 45 mins
- Testing: 45 mins

**Total Estimated Time**: ~4.5 hours

## Dependencies
- GitPython (git operations)
- SQLAlchemy (ORM)
- Alembic (migrations)
- Pandas (data analysis)
- Numpy (calculations)
- Plotly (advanced charts)

## Risks & Mitigations
1. **Risk**: Git history analysis may be slow for large repos
   - **Mitigation**: Cache results, implement pagination
   
2. **Risk**: Pattern matching may have high false positive rate
   - **Mitigation**: Use multiple signals, require confidence threshold
   
3. **Risk**: Database may grow large over time
   - **Mitigation**: Implement data retention policy, archive old scans

## Next Steps
Begin with Step 1: Database Setup
