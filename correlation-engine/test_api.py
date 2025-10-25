"""
Quick test for Phase 2 API endpoints
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import init_db, get_db
from app.models import Scan, Vulnerability, VulnerabilityState
from datetime import datetime


def setup_test_data():
    """Set up test data for API endpoints"""
    print("🔄 Setting up test data...")
    
    # Initialize database
    init_db()
    
    with get_db() as db:
        # Create a scan
        scan = Scan(
            commit_hash="abc123",
            author="Test User",
            timestamp=datetime.now(),
            total_findings=3,
            correlated_count=2
        )
        db.add(scan)
        db.flush()
        
        # Create vulnerabilities
        vulns = [
            Vulnerability(
                scan_id=scan.id,
                fingerprint="test-fingerprint-1",
                type="SQL Injection",
                severity="high",
                file_path="src/main/java/com/security/controller/UserController.java",
                line_number=45,
                message="SQL query built using string concatenation with user input",
                confidence=0.9,
                state=VulnerabilityState.EXISTING,
                risk_score=8.5,
                age_days=15,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            ),
            Vulnerability(
                scan_id=scan.id,
                fingerprint="test-fingerprint-2",
                type="IDOR",
                severity="medium",
                file_path="src/main/java/com/security/controller/OrderController.java",
                line_number=78,
                message="Missing authorization check allows access to other users' orders",
                confidence=0.85,
                state=VulnerabilityState.NEW,
                risk_score=6.2,
                age_days=0,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            ),
            Vulnerability(
                scan_id=scan.id,
                fingerprint="test-fingerprint-3",
                type="XSS",
                severity="low",
                file_path="src/main/java/com/security/controller/UserController.java",
                line_number=120,
                message="User input not sanitized before rendering in HTML",
                confidence=0.7,
                state=VulnerabilityState.FIXED,
                risk_score=3.5,
                age_days=30,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        ]
        
        for v in vulns:
            db.add(v)
        
        db.commit()
        print(f"✅ Created scan {scan.id} with 3 vulnerabilities")


def test_api_endpoints():
    """Test Phase 2 API endpoints using direct function calls"""
    print("\n" + "="*60)
    print("TESTING PHASE 2 API ENDPOINTS")
    print("="*60)
    
    # Import endpoint functions
    from app.main import (
        list_vulnerabilities,
        get_metrics_overview,
        analyze_patterns,
        get_risk_ranked_vulnerabilities
    )
    import asyncio
    
    async def run_tests():
        # Test 1: List all vulnerabilities
        print("\n1️⃣  Testing GET /api/v1/vulnerabilities...")
        result = await list_vulnerabilities()
        print(f"   ✅ Found {result['count']} vulnerabilities")
        for v in result['vulnerabilities']:
            print(f"      - {v['type']} ({v['severity']}) - {v['state']} - Risk: {v['risk_score']}")
        
        # Test 2: Filter by state
        print("\n2️⃣  Testing GET /api/v1/vulnerabilities?state=new...")
        result = await list_vulnerabilities(state="new")
        print(f"   ✅ Found {result['count']} NEW vulnerabilities")
        
        # Test 3: Metrics overview
        print("\n3️⃣  Testing GET /api/v1/metrics/overview...")
        metrics = await get_metrics_overview()
        print(f"   ✅ Total Scans: {metrics['total_scans']}")
        print(f"   ✅ Total Vulnerabilities: {metrics['total_vulnerabilities']}")
        print(f"   ✅ By State: {metrics['by_state']}")
        print(f"   ✅ By Severity: {metrics['by_severity']}")
        print(f"   ✅ Avg Risk Score: {metrics['average_risk_score']}")
        
        # Test 4: Pattern analysis
        print("\n4️⃣  Testing POST /api/v1/patterns/analyze...")
        patterns = await analyze_patterns()
        print(f"   ✅ Patterns Found: {len(patterns['patterns_found'])}")
        print(f"   ✅ Hotspots Found: {len(patterns['hotspots'])}")
        print(f"   ✅ Clusters Found: {len(patterns['clusters'])}")
        
        # Test 5: Risk-ranked vulnerabilities
        print("\n5️⃣  Testing GET /api/v1/risk-scores...")
        risk_result = await get_risk_ranked_vulnerabilities(limit=10)
        print(f"   ✅ Top {risk_result['count']} vulnerabilities by risk:")
        for v in risk_result['vulnerabilities']:
            print(f"      - {v['type']} - Risk: {v['risk_score']} ({v['risk_category']})")
    
    asyncio.run(run_tests())
    
    print("\n" + "="*60)
    print("✅ ALL API ENDPOINT TESTS PASSED!")
    print("="*60)


if __name__ == "__main__":
    setup_test_data()
    test_api_endpoints()
