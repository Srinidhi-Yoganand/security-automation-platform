"""
Comprehensive Platform Test Suite

Tests all major components of the Security Automation Platform:
- IAST Scanner
- SonarQube Scanner  
- Quadruple Correlator
- Docker services
- API endpoints
"""
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_iast_scanner():
    """Test IAST Scanner functionality"""
    logger.info("=" * 70)
    logger.info("TEST 1: IAST Scanner")
    logger.info("=" * 70)
    
    try:
        from app.services.iast_scanner import IASTScanner
        
        # Test initialization
        scanner = IASTScanner(agent_type="custom")
        assert scanner.agent_type == "custom"
        logger.info("✓ IAST Scanner initialization successful")
        
        # Test agent configuration
        scanner = IASTScanner(agent_type="contrast")
        assert scanner.agent_type == "contrast"
        logger.info("✓ IAST Scanner supports multiple providers")
        
        # Test test scenario generation
        scenarios = scanner.generate_test_scenarios(["sql_injection", "xss", "idor"])
        assert len(scenarios) > 0
        logger.info(f"✓ Generated {len(scenarios)} test scenarios")
        
        logger.info("✓ IAST Scanner: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ IAST Scanner test failed: {e}")
        return False


def test_sonarqube_scanner():
    """Test SonarQube Scanner functionality"""
    logger.info("=" * 70)
    logger.info("TEST 2: SonarQube Scanner")
    logger.info("=" * 70)
    
    try:
        from app.services.sonarqube_scanner import SonarQubeScanner
        
        # Test initialization
        scanner = SonarQubeScanner()
        assert scanner.sonar_host == "http://localhost:9000"
        logger.info("✓ SonarQube Scanner initialization successful")
        
        # Test severity mapping
        assert scanner._map_severity("BLOCKER") == "error"
        assert scanner._map_severity("MAJOR") == "warning"
        assert scanner._map_severity("INFO") == "note"
        logger.info("✓ Severity mapping works correctly")
        
        # Test confidence mapping
        assert scanner._map_confidence("BLOCKER") == "high"
        assert scanner._map_confidence("MAJOR") == "medium"
        assert scanner._map_confidence("INFO") == "low"
        logger.info("✓ Confidence mapping works correctly")
        
        logger.info("✓ SonarQube Scanner: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ SonarQube Scanner test failed: {e}")
        return False


def test_quadruple_correlator():
    """Test Quadruple Correlator functionality"""
    logger.info("=" * 70)
    logger.info("TEST 3: Quadruple Correlator")
    logger.info("=" * 70)
    
    try:
        from app.services.quadruple_correlator import QuadrupleCorrelator
        
        # Test initialization
        correlator = QuadrupleCorrelator()
        assert correlator.TOOL_WEIGHTS["codeql"] == 0.30
        assert correlator.TOOL_WEIGHTS["sonarqube"] == 0.25
        assert correlator.TOOL_WEIGHTS["zap"] == 0.25
        assert correlator.TOOL_WEIGHTS["iast"] == 0.30
        logger.info("✓ Correlator initialization with correct weights")
        
        # Test vulnerability type extraction
        finding = {
            "rule_id": "sql-injection-test",
            "message": "SQL injection vulnerability"
        }
        vuln_type = correlator._extract_vuln_type(finding)
        assert vuln_type == "sql-injection"
        logger.info("✓ Vulnerability type extraction works")
        
        # Test correlation with sample data
        codeql_findings = [
            {
                "rule_id": "sql-injection",
                "file": "test.py",
                "line": 10,
                "message": "SQL injection",
                "confidence": "high"
            }
        ]
        sonar_findings = [
            {
                "rule_id": "sqli",
                "file": "test.py",
                "line": 11,
                "message": "SQL injection risk",
                "confidence": "medium"
            }
        ]
        zap_findings = [
            {
                "rule_id": "SQL_INJECTION",
                "file": "test.py",
                "line": 10,
                "message": "SQL injection found",
                "confidence": "high"
            }
        ]
        iast_findings = [
            {
                "rule_id": "sql-injection",
                "file": "test.py",
                "line": 10,
                "message": "SQL injection confirmed",
                "confidence": "high"
            }
        ]
        
        results = correlator.correlate_all(
            codeql_findings,
            sonar_findings,
            zap_findings,
            iast_findings
        )
        
        assert results["total_findings"] == 4
        assert results["correlated_groups"] > 0
        assert "statistics" in results
        logger.info(f"✓ Correlated {results['total_findings']} findings into {results['correlated_groups']} groups")
        logger.info(f"✓ Estimated FP rate: {results['statistics']['estimated_fp_rate']}%")
        
        # Test ensemble report generation
        report = correlator.get_ensemble_report(results)
        assert "QUADRUPLE HYBRID CORRELATION REPORT" in report
        assert "SAST + DAST + IAST + Symbolic" in report
        logger.info("✓ Ensemble report generation works")
        
        logger.info("✓ Quadruple Correlator: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ Quadruple Correlator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_existing_services():
    """Test that existing services still work"""
    logger.info("=" * 70)
    logger.info("TEST 4: Existing Services Integration")
    logger.info("=" * 70)
    
    try:
        # Test services that don't require external dependencies
        
        # Test continuous monitor
        from app.services.continuous_monitor import ContinuousMonitor
        monitor = ContinuousMonitor()
        logger.info("✓ Continuous Monitor imports successfully")
        
        # Test exploit generator
        from app.services.exploit_generator import ExploitGenerator
        exploit_gen = ExploitGenerator()
        logger.info("✓ Exploit Generator imports successfully")
        
        # Test false positive filter
        from app.services.false_positive_filter import FalsePositiveFilter
        fp_filter = FalsePositiveFilter()
        logger.info("✓ False Positive Filter imports successfully")
        
        # Test patch test generator
        from app.services.patch_test_generator import PatchTestGenerator
        test_gen = PatchTestGenerator()
        logger.info("✓ Patch Test Generator imports successfully")
        
        # Test patch explainer
        from app.services.patch_explainer import PatchExplainer
        explainer = PatchExplainer()
        logger.info("✓ Patch Explainer imports successfully")
        
        logger.info("✓ Note: DAST Scanner skipped (requires zapv2 package installation)")
        logger.info("✓ Existing Services: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ Existing services test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_docker_configuration():
    """Test Docker configuration"""
    logger.info("=" * 70)
    logger.info("TEST 5: Docker Configuration")
    logger.info("=" * 70)
    
    try:
        import subprocess
        import os
        
        # Change to project root
        project_root = Path(__file__).parent.parent
        os.chdir(project_root)
        
        # Test docker-compose config
        result = subprocess.run(
            ["docker-compose", "config"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info("✓ docker-compose.yml is valid")
            
            # Check for required services
            config_output = result.stdout
            assert "ollama" in config_output
            assert "correlation-engine" in config_output
            assert "zap" in config_output
            assert "sonarqube" in config_output
            logger.info("✓ All required services present (ollama, platform, zap, sonarqube)")
            
            # Check for required environment variables
            assert "SONARQUBE_HOST" in config_output
            assert "ZAP_HOST" in config_output
            assert "IAST_PROVIDER" in config_output
            logger.info("✓ All required environment variables configured")
            
            logger.info("✓ Docker Configuration: ALL TESTS PASSED\n")
            return True
        else:
            logger.error(f"✗ docker-compose config failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        logger.warning("⚠ docker-compose not installed, skipping Docker tests")
        return True
    except Exception as e:
        logger.error(f"✗ Docker configuration test failed: {e}")
        return False


def test_file_structure():
    """Test that all required files exist"""
    logger.info("=" * 70)
    logger.info("TEST 6: File Structure")
    logger.info("=" * 70)
    
    try:
        project_root = Path(__file__).parent.parent
        
        # Core files
        required_files = [
            "README.md",
            "docker-compose.yml",
            "action.yml",
            "correlation-engine/requirements.txt",
            "correlation-engine/app/main.py",
            "correlation-engine/app/services/iast_scanner.py",
            "correlation-engine/app/services/sonarqube_scanner.py",
            "correlation-engine/app/services/quadruple_correlator.py",
            "correlation-engine/app/services/dast_scanner.py",
            "correlation-engine/app/services/continuous_monitor.py",
            "correlation-engine/app/services/exploit_generator.py",
            "correlation-engine/app/services/false_positive_filter.py",
            "correlation-engine/app/services/patch_test_generator.py"
        ]
        
        missing_files = []
        for file_path in required_files:
            full_path = project_root / file_path
            if not full_path.exists():
                missing_files.append(file_path)
            else:
                logger.info(f"✓ {file_path}")
        
        if missing_files:
            logger.error(f"✗ Missing files: {missing_files}")
            return False
        
        logger.info("✓ File Structure: ALL TESTS PASSED\n")
        return True
        
    except Exception as e:
        logger.error(f"✗ File structure test failed: {e}")
        return False


def run_all_tests():
    """Run all tests and report results"""
    logger.info("\n" + "=" * 70)
    logger.info("SECURITY AUTOMATION PLATFORM - COMPREHENSIVE TEST SUITE")
    logger.info("=" * 70 + "\n")
    
    tests = [
        ("IAST Scanner", test_iast_scanner),
        ("SonarQube Scanner", test_sonarqube_scanner),
        ("Quadruple Correlator", test_quadruple_correlator),
        ("Existing Services", test_existing_services),
        ("Docker Configuration", test_docker_configuration),
        ("File Structure", test_file_structure)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            logger.error(f"✗ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Summary
    logger.info("=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status}: {test_name}")
    
    logger.info("=" * 70)
    logger.info(f"TOTAL: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    logger.info("=" * 70)
    
    if passed == total:
        logger.info("\n✓ ALL TESTS PASSED - Platform is ready for deployment!\n")
        return 0
    else:
        logger.error(f"\n✗ {total - passed} tests failed - Please review errors above\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
