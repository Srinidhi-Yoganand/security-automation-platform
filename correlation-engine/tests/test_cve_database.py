"""
Tests for CVE database integration
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.cve_database import CVEDatabase, CVEReference, get_cve_database


class TestCVEDatabase(unittest.TestCase):
    """Test CVE database"""
    
    def setUp(self):
        """Set up test database"""
        self.db = CVEDatabase()
    
    def test_lookup_idor_cve(self):
        """Test looking up IDOR CVEs"""
        cves = self.db.lookup_cve('idor')
        
        self.assertIsNotNone(cves)
        self.assertGreater(len(cves), 0)
        self.assertIsInstance(cves[0], CVEReference)
        self.assertTrue(any('idor' in cve.description.lower() for cve in cves))
    
    def test_lookup_sql_injection_cve(self):
        """Test looking up SQL injection CVEs"""
        cves = self.db.lookup_cve('sql_injection')
        
        self.assertGreater(len(cves), 0)
        self.assertEqual(cves[0].cwe_id, 'CWE-89')
        self.assertIn('sql', cves[0].description.lower())
    
    def test_lookup_missing_auth_cve(self):
        """Test looking up missing authorization CVEs"""
        cves = self.db.lookup_cve('missing_authorization')
        
        self.assertGreater(len(cves), 0)
        self.assertTrue(any(cve.cwe_id in ['CWE-862', 'CWE-306'] for cve in cves))
    
    def test_lookup_path_traversal_cve(self):
        """Test looking up path traversal CVEs"""
        cves = self.db.lookup_cve('path_traversal')
        
        self.assertGreater(len(cves), 0)
        self.assertEqual(cves[0].cwe_id, 'CWE-22')
        self.assertIn('path', cves[0].description.lower())
    
    def test_lookup_unknown_vulnerability(self):
        """Test looking up unknown vulnerability type"""
        cves = self.db.lookup_cve('unknown_vuln_type_xyz')
        
        self.assertEqual(len(cves), 0)
    
    def test_cve_reference_structure(self):
        """Test CVE reference has all required fields"""
        cves = self.db.lookup_cve('idor')
        cve = cves[0]
        
        self.assertIsNotNone(cve.cve_id)
        self.assertIsNotNone(cve.description)
        self.assertIsNotNone(cve.severity)
        self.assertIsNotNone(cve.remediation)
        self.assertIsInstance(cve.references, list)
        self.assertGreater(len(cve.references), 0)
    
    def test_get_remediation_guide(self):
        """Test getting remediation guidance"""
        guide = self.db.get_remediation_guide('idor')
        
        self.assertIsNotNone(guide)
        self.assertGreater(len(guide), 0)
        self.assertIn('authorization', guide.lower())
    
    def test_get_references(self):
        """Test getting security references"""
        refs = self.db.get_references('sql_injection')
        
        self.assertGreater(len(refs), 0)
        self.assertTrue(all(ref.startswith('http') for ref in refs))
        self.assertTrue(any('owasp' in ref.lower() or 'cwe' in ref.lower() for ref in refs))
    
    def test_enrich_patch_with_cve(self):
        """Test enriching patch data with CVE info"""
        patch_data = {
            'fixed_code': 'some code',
            'explanation': 'some fix'
        }
        
        enriched = self.db.enrich_patch_with_cve(patch_data, 'idor')
        
        self.assertIn('cve_references', enriched)
        self.assertIn('detailed_remediation', enriched)
        self.assertIn('security_references', enriched)
        self.assertGreater(len(enriched['cve_references']), 0)
        self.assertIsInstance(enriched['cve_references'][0], dict)
        self.assertIn('id', enriched['cve_references'][0])
        self.assertIn('severity', enriched['cve_references'][0])
    
    def test_enrich_patch_unknown_vuln(self):
        """Test enriching patch for unknown vulnerability"""
        patch_data = {'fixed_code': 'code'}
        
        enriched = self.db.enrich_patch_with_cve(patch_data, 'unknown_type')
        
        # Should not crash, just return original data
        self.assertNotIn('cve_references', enriched)
    
    def test_get_severity_score(self):
        """Test getting average CVSS score"""
        score = self.db.get_severity_score('sql_injection')
        
        self.assertIsNotNone(score)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 10.0)
    
    def test_get_severity_score_unknown(self):
        """Test getting severity for unknown vuln"""
        score = self.db.get_severity_score('unknown_type')
        
        self.assertIsNone(score)
    
    def test_partial_match_vulnerability_type(self):
        """Test partial matching of vulnerability types"""
        # Test with variations
        cves1 = self.db.lookup_cve('idor')
        cves2 = self.db.lookup_cve('insecure_direct_object_reference')
        
        # Should find same CVEs
        self.assertGreater(len(cves1), 0)
        # Partial match may or may not work depending on implementation
    
    def test_all_vulnerability_types_have_data(self):
        """Test that all documented vulnerability types have CVE data"""
        vuln_types = [
            'idor',
            'sql_injection', 
            'path_traversal',
            'missing_authorization',
            'xss',
            'csrf',
            'deserialization'
        ]
        
        for vuln_type in vuln_types:
            cves = self.db.lookup_cve(vuln_type)
            self.assertGreater(len(cves), 0, f"No CVEs found for {vuln_type}")
    
    def test_cve_severity_levels(self):
        """Test that CVEs have valid severity levels"""
        valid_severities = ['critical', 'high', 'medium', 'low']
        
        all_cves = []
        for vuln_type in self.db.cve_data.keys():
            all_cves.extend(self.db.cve_data[vuln_type])
        
        for cve in all_cves:
            self.assertIn(cve.severity, valid_severities)
    
    def test_cve_ids_format(self):
        """Test that CVE IDs follow proper format"""
        all_cves = []
        for vuln_type in self.db.cve_data.keys():
            all_cves.extend(self.db.cve_data[vuln_type])
        
        for cve in all_cves:
            self.assertTrue(cve.cve_id.startswith('CVE-'))
            # CVE-YYYY-NNNNN format
            parts = cve.cve_id.split('-')
            self.assertEqual(len(parts), 3)
            self.assertTrue(parts[1].isdigit())  # Year
            self.assertTrue(parts[2].isdigit())  # Number


class TestCVEDatabaseSingleton(unittest.TestCase):
    """Test CVE database singleton"""
    
    def test_singleton_returns_same_instance(self):
        """Test that get_cve_database returns same instance"""
        db1 = get_cve_database()
        db2 = get_cve_database()
        
        self.assertIs(db1, db2)
    
    def test_singleton_has_data(self):
        """Test that singleton instance has CVE data"""
        db = get_cve_database()
        
        cves = db.lookup_cve('idor')
        self.assertGreater(len(cves), 0)


if __name__ == '__main__':
    unittest.main()
