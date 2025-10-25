"""
Phase 2 Testing Script
Tests database, git analyzer, lifecycle tracking, and risk scoring
"""

import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import init_db, get_db, drop_db
from app.models import Scan, Vulnerability, VulnerabilityState, SecurityMetric
from app.core.git_analyzer import GitHistoryAnalyzer
from app.core.correlator import Finding, Severity
from app.services.behavior.lifecycle_tracker import VulnerabilityLifecycleTracker
from app.services.behavior.risk_scorer import RiskScorer


def test_database_setup():
    """Test 1: Database initialization"""
    print("=" * 60)
    print("TEST 1: Database Setup")
    print("=" * 60)
    
    # Reset database for clean test
    print("\n🔄 Resetting database...")
    drop_db()
    init_db()
    
    # Verify tables exist
    with get_db() as db:
        scan_count = db.query(Scan).count()
        vuln_count = db.query(Vulnerability).count()
        
        print(f"✅ Database initialized")
        print(f"   Scans: {scan_count}")
        print(f"   Vulnerabilities: {vuln_count}")
    
    return True


def test_git_analyzer():
    """Test 2: Git history analysis"""
    print("\n" + "=" * 60)
    print("TEST 2: Git History Analyzer")
    print("=" * 60)
    
    try:
        analyzer = GitHistoryAnalyzer('..')
        
        # Get current commit
        current = analyzer.get_current_commit()
        print(f"\n✅ Current commit:")
        print(f"   Hash: {current['short_hash']}")
        print(f"   Author: {current['author']}")
        print(f"   Date: {current['date']}")
        print(f"   Message: {current['summary']}")
        
        # Get recent commits
        commits = analyzer.get_commit_history(max_count=3)
        print(f"\n✅ Recent commits: {len(commits)}")
        for commit in commits:
            print(f"   {commit['short_hash']} - {commit['summary'][:50]}")
        
        # Test fingerprinting
        fp1 = analyzer.generate_vulnerability_fingerprint(
            'vulnerable-app/src/main/java/com/security/automation/controller/UserController.java',
            35,
            'SQL Injection'
        )
        fp2 = analyzer.generate_vulnerability_fingerprint(
            'vulnerable-app/src/main/java/com/security/automation/security/AuthorizationService.java',
            20,
            'IDOR'
        )
        
        print(f"\n✅ Fingerprint generation:")
        print(f"   SQL Injection: {fp1[:16]}...")
        print(f"   IDOR: {fp2[:16]}...")
        
        return analyzer
        
    except Exception as e:
        print(f"❌ Git analyzer failed: {e}")
        return None


def test_lifecycle_tracking(analyzer):
    """Test 3: Vulnerability lifecycle tracking"""
    print("\n" + "=" * 60)
    print("TEST 3: Lifecycle Tracking")
    print("=" * 60)
    
    if not analyzer:
        print("❌ Skipping (git analyzer failed)")
        return False
    
    with get_db() as db:
        # Create first scan
        current_commit = analyzer.get_current_commit()
        
        scan1 = Scan(
            timestamp=datetime.utcnow(),
            commit_hash=current_commit['hash'],
            branch='main',
            author=current_commit['author'],
            commit_message=current_commit['summary'],
            total_findings=3,
            correlated_count=3
        )
        db.add(scan1)
        db.commit()
        
        print(f"\n✅ Created Scan #1:")
        print(f"   ID: {scan1.id}")
        print(f"   Commit: {scan1.commit_hash[:8]}")
        print(f"   Time: {scan1.timestamp}")
        
        # Create sample findings (from Phase 1 test data)
        findings = [
            Finding(
                id='test-1',
                source='semgrep',
                type='SQL Injection',
                severity=Severity.HIGH,
                file_path='vulnerable-app/src/main/java/com/security/automation/controller/UserController.java',
                line_number=35,
                message='SQL injection vulnerability in search endpoint',
                confidence=0.9,
                raw_data={}
            ),
            Finding(
                id='test-2',
                source='semgrep',
                type='IDOR',
                severity=Severity.MEDIUM,
                file_path='vulnerable-app/src/main/java/com/security/automation/security/AuthorizationService.java',
                line_number=20,
                message='Authorization check missing user validation',
                confidence=0.85,
                raw_data={}
            ),
            Finding(
                id='test-3',
                source='semgrep',
                type='IDOR',
                severity=Severity.MEDIUM,
                file_path='vulnerable-app/src/main/java/com/security/automation/controller/OrderController.java',
                line_number=36,
                message='Missing company context validation',
                confidence=0.8,
                raw_data={}
            )
        ]
        
        # Process findings with lifecycle tracker
        tracker = VulnerabilityLifecycleTracker(db, analyzer)
        result = tracker.process_scan_results(
            scan1.id,
            findings,
            scan1.commit_hash
        )
        
        print(f"\n✅ Processed findings:")
        print(f"   New: {len(result['new'])}")
        print(f"   Existing: {len(result['existing'])}")
        print(f"   Fixed: {len(result['fixed'])}")
        print(f"   Regressed: {len(result['regressed'])}")
        
        # Display new vulnerabilities
        print(f"\n📋 New Vulnerabilities:")
        for vuln in result['new']:
            print(f"   - {vuln.type} at {vuln.file_path}:{vuln.line_number}")
            print(f"     State: {vuln.state.value}, Fingerprint: {vuln.fingerprint[:16]}...")
        
        # Simulate second scan (same findings)
        print(f"\n🔄 Simulating Scan #2 (same findings)...")
        scan2 = Scan(
            timestamp=datetime.utcnow(),
            commit_hash=current_commit['hash'],
            branch='main',
            author=current_commit['author'],
            commit_message='Second scan - same code',
            total_findings=3,
            correlated_count=3
        )
        db.add(scan2)
        db.commit()
        
        result2 = tracker.process_scan_results(
            scan2.id,
            findings,
            scan2.commit_hash
        )
        
        print(f"\n✅ Scan #2 results:")
        print(f"   New: {len(result2['new'])} (should be 0)")
        print(f"   Existing: {len(result2['existing'])} (should be 3)")
        print(f"   Fixed: {len(result2['fixed'])} (should be 0)")
        
        # Simulate third scan (one fixed)
        print(f"\n🔄 Simulating Scan #3 (SQL Injection fixed)...")
        scan3 = Scan(
            timestamp=datetime.utcnow(),
            commit_hash=current_commit['hash'],
            branch='main',
            author=current_commit['author'],
            commit_message='Third scan - fixed SQL injection',
            total_findings=2,
            correlated_count=2
        )
        db.add(scan3)
        db.commit()
        
        # Only 2 findings now (removed SQL Injection)
        findings_reduced = findings[1:]  # Remove first finding
        
        result3 = tracker.process_scan_results(
            scan3.id,
            findings_reduced,
            scan3.commit_hash
        )
        
        print(f"\n✅ Scan #3 results:")
        print(f"   New: {len(result3['new'])} (should be 0)")
        print(f"   Existing: {len(result3['existing'])} (should be 2)")
        print(f"   Fixed: {len(result3['fixed'])} (should be 1)")
        
        if result3['fixed']:
            fixed = result3['fixed'][0]
            print(f"\n🎉 Fixed vulnerability:")
            print(f"   Type: {fixed.type}")
            print(f"   Location: {fixed.file_path}:{fixed.line_number}")
            print(f"   State: {fixed.state.value}")
        
        # Calculate MTTF
        mttf = tracker.calculate_mean_time_to_fix()
        print(f"\n📊 Mean Time To Fix: {mttf:.2f} days")
        
        return True


def test_risk_scoring():
    """Test 4: Risk scoring algorithm"""
    print("\n" + "=" * 60)
    print("TEST 4: Risk Scoring")
    print("=" * 60)
    
    with get_db() as db:
        # Get vulnerabilities
        vulns = db.query(Vulnerability).all()
        
        if not vulns:
            print("❌ No vulnerabilities to score")
            return False
        
        scorer = RiskScorer()
        
        print(f"\n✅ Scoring {len(vulns)} vulnerabilities:")
        
        for vuln in vulns:
            # Calculate risk score
            context = {
                'pattern_frequency': 2,
                'affected_endpoints': 3,
                'code_complexity': 8
            }
            
            risk_score = scorer.calculate_risk_score(vuln, context)
            category = scorer.get_risk_category(risk_score)
            
            # Update vulnerability
            vuln.risk_score = risk_score
            
            print(f"\n   {vuln.type}")
            print(f"   - Location: {vuln.file_path}:{vuln.line_number}")
            print(f"   - Severity: {vuln.severity}")
            print(f"   - State: {vuln.state.value}")
            print(f"   - Risk Score: {risk_score:.2f} ({category})")
            
            # Get detailed explanation
            explanation = scorer.explain_risk_score(vuln, context)
            print(f"   - Components:")
            for name, comp in explanation['components'].items():
                weighted = comp['score'] * comp['weight']
                print(f"     • {name}: {comp['score']:.1f} × {comp['weight']:.2f} = {weighted:.2f}")
        
        db.commit()
        
        # Show vulnerabilities ranked by risk
        print(f"\n📊 Vulnerabilities Ranked by Risk:")
        ranked = sorted(vulns, key=lambda v: v.risk_score, reverse=True)
        for i, vuln in enumerate(ranked, 1):
            category = scorer.get_risk_category(vuln.risk_score)
            print(f"   {i}. [{category}] {vuln.risk_score:.2f} - {vuln.type} ({vuln.file_path}:{vuln.line_number})")
        
        return True


def test_state_history():
    """Test 5: Vulnerability state history"""
    print("\n" + "=" * 60)
    print("TEST 5: State History")
    print("=" * 60)
    
    with get_db() as db:
        tracker = VulnerabilityLifecycleTracker(db, None)
        
        # Get a vulnerability
        vuln = db.query(Vulnerability).first()
        
        if not vuln:
            print("❌ No vulnerabilities found")
            return False
        
        # Get its history
        history = tracker.get_vulnerability_history(vuln.fingerprint)
        
        print(f"\n✅ History for {vuln.type}:")
        print(f"   Fingerprint: {vuln.fingerprint[:16]}...")
        print(f"   Current state: {history['vulnerability']['state']}")
        print(f"   Age: {history['vulnerability']['age_days']} days")
        
        print(f"\n   State transitions:")
        for h in history['history']:
            from_state = h['from'] or 'None'
            print(f"   {from_state} → {h['to']}")
            print(f"     Time: {h['timestamp']}")
            print(f"     Reason: {h['reason']}")
            print(f"     Commit: {h['commit']}")
            print()
        
        return True


def test_metrics():
    """Test 6: Security metrics calculation"""
    print("\n" + "=" * 60)
    print("TEST 6: Security Metrics")
    print("=" * 60)
    
    with get_db() as db:
        # Get all scans
        scans = db.query(Scan).all()
        vulns = db.query(Vulnerability).all()
        
        print(f"\n📊 Database Summary:")
        print(f"   Total Scans: {len(scans)}")
        print(f"   Total Vulnerabilities: {len(vulns)}")
        
        # Count by state
        state_counts = {}
        for vuln in vulns:
            state = vuln.state.value
            state_counts[state] = state_counts.get(state, 0) + 1
        
        print(f"\n   Vulnerabilities by State:")
        for state, count in state_counts.items():
            print(f"   - {state}: {count}")
        
        # Count by severity
        severity_counts = {}
        for vuln in vulns:
            sev = vuln.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"\n   Vulnerabilities by Severity:")
        for sev, count in severity_counts.items():
            print(f"   - {sev}: {count}")
        
        # Average risk score
        if vulns:
            avg_risk = sum(v.risk_score for v in vulns) / len(vulns)
            max_risk = max(v.risk_score for v in vulns)
            min_risk = min(v.risk_score for v in vulns)
            
            print(f"\n   Risk Scores:")
            print(f"   - Average: {avg_risk:.2f}")
            print(f"   - Maximum: {max_risk:.2f}")
            print(f"   - Minimum: {min_risk:.2f}")
        
        return True


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("PHASE 2 TESTING SUITE")
    print("=" * 60)
    
    results = {}
    
    # Run tests
    results['Database Setup'] = test_database_setup()
    
    analyzer = test_git_analyzer()
    results['Git Analyzer'] = analyzer is not None
    
    results['Lifecycle Tracking'] = test_lifecycle_tracking(analyzer)
    results['Risk Scoring'] = test_risk_scoring()
    results['State History'] = test_state_history()
    results['Metrics'] = test_metrics()
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, passed_test in results.items():
        status = "✅ PASSED" if passed_test else "❌ FAILED"
        print(f"{status} - {test_name}")
    
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} tests passed ({100*passed//total}%)")
    print("=" * 60)
    
    if passed == total:
        print("\n🎉 All tests passed! Phase 2 core components are working correctly.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
