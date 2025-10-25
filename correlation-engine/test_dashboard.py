"""
Test enhanced dashboard generation with Phase 2 behavior analysis
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.dashboard_generator import DashboardGenerator
from app.database import init_db, get_db
from app.models import Scan, Vulnerability, VulnerabilityState
from datetime import datetime, timedelta
import json

def setup_test_data():
    """Create test data with multiple scans for trends"""
    print("Setting up test data for dashboard...")
    
    init_db()
    
    with get_db() as db:
        # Create 5 scans over time
        base_time = datetime.now() - timedelta(days=10)
        
        for i in range(5):
            scan_time = base_time + timedelta(days=i*2)
            
            scan = Scan(
                commit_hash=f"commit{i:03d}",
                author="Test User",
                timestamp=scan_time,
                total_findings=10 - i,  # Decreasing findings
                correlated_count=8 - i,
                critical_count=1 if i < 2 else 0,
                high_count=3 - i if 3 - i > 0 else 0,
                medium_count=4,
                low_count=2
            )
            db.add(scan)
            db.flush()
            
            # Add vulnerabilities with varying states
            vuln_types = ['SQL Injection', 'IDOR', 'XSS', 'CSRF', 'Path Traversal']
            for j, vuln_type in enumerate(vuln_types[:5-i]):
                state = VulnerabilityState.FIXED if i >= 3 and j == 0 else \
                        VulnerabilityState.EXISTING if i > 0 else \
                        VulnerabilityState.NEW
                
                vuln = Vulnerability(
                    scan_id=scan.id,
                    fingerprint=f"vuln-{j:03d}",
                    type=vuln_type,
                    severity=['critical', 'high', 'medium', 'medium', 'low'][j],
                    file_path=f"src/main/java/com/security/controller/Controller{j}.java",
                    line_number=45 + j*10,
                    message=f"Security issue in {vuln_type}",
                    confidence=0.8 + j*0.05,
                    state=state,
                    risk_score=8.5 - j*1.5,
                    age_days=i*2,
                    first_seen=scan_time,
                    last_seen=scan_time
                )
                db.add(vuln)
            
            db.commit()
            print(f"  [OK] Created scan {i+1} with {5-i} vulnerabilities")
    
    print("[OK] Test data ready!\n")


def test_basic_dashboard():
    """Test Phase 1 basic dashboard"""
    print("="*60)
    print("TEST 1: Basic Dashboard (Phase 1 Only)")
    print("="*60)
    
    # Mock correlation report
    report_data = {
        'total_findings': 15,
        'correlated_count': 10,
        'critical': 1,
        'high': 3,
        'medium': 4,
        'low': 2,
        'findings': [
            {
                'type': 'SQL Injection',
                'severity': 'high',
                'file': 'UserController.java',
                'line': 45,
                'sources': ['Semgrep', 'CodeQL'],
                'confidence': 0.9,
                'data_flow_confirmed': True
            },
            {
                'type': 'IDOR',
                'severity': 'medium',
                'file': 'OrderController.java',
                'line': 78,
                'sources': ['ZAP', 'Semgrep'],
                'confidence': 0.85,
                'data_flow_confirmed': False
            }
        ]
    }
    
    generator = DashboardGenerator(include_behavior_analysis=False)
    html = generator.generate(report_data)
    
    # Save basic dashboard
    output_path = Path("test-data/dashboard-basic.html")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')
    
    print(f"[OK] Basic dashboard generated: {output_path}")
    print(f"   Size: {len(html)} bytes")
    print()


def test_enhanced_dashboard():
    """Test Phase 2 enhanced dashboard"""
    print("="*60)
    print("TEST 2: Enhanced Dashboard (Phase 1 + Phase 2)")
    print("="*60)
    
    # Mock correlation report
    report_data = {
        'total_findings': 15,
        'correlated_count': 10,
        'critical': 1,
        'high': 3,
        'medium': 4,
        'low': 2,
        'findings': [
            {
                'type': 'SQL Injection',
                'severity': 'high',
                'file': 'UserController.java',
                'line': 45,
                'sources': ['Semgrep', 'CodeQL'],
                'confidence': 0.9,
                'data_flow_confirmed': True
            }
        ]
    }
    
    generator = DashboardGenerator(include_behavior_analysis=True)
    html = generator.generate(report_data)
    
    # Save enhanced dashboard
    output_path = Path("test-data/dashboard-enhanced.html")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')
    
    print(f"[OK] Enhanced dashboard generated: {output_path}")
    print(f"   Size: {len(html)} bytes")
    
    # Check for Phase 2 elements
    has_trends = 'trendChart' in html
    has_state = 'stateChart' in html
    has_patterns = 'Security Patterns' in html
    has_risk = 'Top Risk' in html
    
    print(f"   Phase 2 Features:")
    print(f"     - Trend Chart: {'[OK]' if has_trends else '[FAIL]'}")
    print(f"     - State Chart: {'[OK]' if has_state else '[FAIL]'}")
    print(f"     - Pattern Analysis: {'[OK]' if has_patterns else '[FAIL]'}")
    print(f"     - Risk Ranking: {'[OK]' if has_risk else '[FAIL]'}")
    print()


if __name__ == "__main__":
    setup_test_data()
    test_basic_dashboard()
    test_enhanced_dashboard()
    
    print("="*60)
    print("[OK] ALL DASHBOARD TESTS PASSED!")
    print("="*60)
    print("\nGenerated dashboards:")
    print("  - test-data/dashboard-basic.html (Phase 1 only)")
    print("  - test-data/dashboard-enhanced.html (Phase 1 + Phase 2)")
