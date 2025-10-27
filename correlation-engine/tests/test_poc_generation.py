"""
Tests for PoC generation
"""

import unittest
import json
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.generate_pocs import PoCGenerator


class TestPoCGeneration(unittest.TestCase):
    """Test PoC generation from exploit proofs"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = PoCGenerator(output_dir=self.temp_dir)
    
    def test_generate_idor_poc(self):
        """Test IDOR PoC generation"""
        proof = {
            'vulnerability_type': 'idor',
            'exploitable': True,
            'attack_vector': {
                'endpoint': '/api/users',
                'attacker_value': 42,
                'attacker_logged_in_as': 1
            },
            'proof': 'User 1 can access user 42 data',
            'confidence': 0.95,
            'missing_check': 'Authorization check required'
        }
        
        poc_file = self.generator.generate_from_proof(proof, 'testIDOR')
        
        # Verify file was created
        self.assertTrue(Path(poc_file).exists())
        
        # Verify content
        content = Path(poc_file).read_text()
        self.assertIn('@Test', content)
        self.assertIn('testIDOR', content)
        self.assertIn('/api/users', content)
        self.assertIn('IDOR', content)
        self.assertIn('assertEquals', content)
    
    def test_generate_missing_auth_poc(self):
        """Test missing authentication PoC generation"""
        proof = {
            'vulnerability_type': 'missing_authentication',
            'exploitable': True,
            'attack_vector': {
                'endpoint': '/api/admin/delete',
                'authentication_required': False
            },
            'proof': 'Endpoint accessible without authentication',
            'confidence': 0.90,
            'missing_check': '@PreAuthorize annotation required'
        }
        
        poc_file = self.generator.generate_from_proof(proof, 'testMissingAuth')
        
        # Verify file was created
        self.assertTrue(Path(poc_file).exists())
        
        # Verify content
        content = Path(poc_file).read_text()
        self.assertIn('@Test', content)
        self.assertIn('testMissingAuth', content)
        self.assertIn('/api/admin/delete', content)
        self.assertIn('authentication', content.lower())
    
    def test_generate_curl_commands_idor(self):
        """Test curl command generation for IDOR"""
        proof = {
            'vulnerability_type': 'idor',
            'attack_vector': {
                'endpoint': '/api/users',
                'method': 'GET',
                'attacker_value': 42,
                'attacker_logged_in_as': 1
            }
        }
        
        curl_commands = self.generator.generate_curl_commands(proof)
        
        self.assertIn('curl', curl_commands)
        self.assertIn('/api/users', curl_commands)
        self.assertIn('IDOR', curl_commands)
        self.assertIn('Login as user 1', curl_commands)
    
    def test_generate_curl_commands_missing_auth(self):
        """Test curl command generation for missing auth"""
        proof = {
            'vulnerability_type': 'missing_authentication',
            'attack_vector': {
                'endpoint': '/api/admin/delete',
                'method': 'POST'
            }
        }
        
        curl_commands = self.generator.generate_curl_commands(proof)
        
        self.assertIn('curl', curl_commands)
        self.assertIn('/api/admin/delete', curl_commands)
        self.assertIn('POST', curl_commands)
        self.assertIn('authentication', curl_commands.lower())
    
    def test_generate_from_analysis_results(self):
        """Test generating PoCs from full analysis results"""
        # Create mock analysis results
        results = {
            'project_path': '/test/project',
            'vulnerabilities': [
                {
                    'vulnerability_type': 'idor',
                    'symbolically_verified': True,
                    'exploit_proof': {
                        'vulnerability_type': 'idor',
                        'exploitable': True,
                        'attack_vector': {
                            'endpoint': '/api/users',
                            'attacker_value': 99,
                            'attacker_logged_in_as': 1
                        },
                        'proof': 'Test proof',
                        'confidence': 0.95,
                        'missing_check': 'Auth check'
                    }
                },
                {
                    'vulnerability_type': 'idor',
                    'symbolically_verified': False,  # Not verified, should skip
                    'exploit_proof': None
                }
            ]
        }
        
        # Write to temp file
        results_file = Path(self.temp_dir) / 'results.json'
        with open(results_file, 'w') as f:
            json.dump(results, f)
        
        # Generate PoCs
        generated = self.generator.generate_from_analysis_results(str(results_file))
        
        # Should only generate 1 PoC (second one not verified)
        self.assertEqual(len(generated), 1)
        self.assertTrue(Path(generated[0]).exists())


if __name__ == "__main__":
    unittest.main()
