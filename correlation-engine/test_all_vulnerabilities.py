"""
Comprehensive test for all vulnerability types with DeepSeek Coder
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext

def test_vulnerability(vuln_type, code, description):
    """Test patch generation for a specific vulnerability type"""
    print(f"\n{'='*70}")
    print(f"Testing: {vuln_type}")
    print(f"{'='*70}")
    
    context = PatchContext(
        vulnerability_type=vuln_type,
        severity="high",
        confidence=0.9,
        file_path="/test/VulnerableCode.java",
        line_number=50,
        vulnerable_code=code,
        description=description
    )
    
    generator = LLMPatchGenerator()
    print(f"Provider: {generator.llm_provider}")
    
    try:
        patch = generator.generate_patch(context, test_patch=False)
        
        if patch:
            print(f"\n✅ SUCCESS - {vuln_type}")
            print(f"\nOriginal Code:\n{code[:200]}...")
            print(f"\nFixed Code:\n{patch.fixed_code[:200]}...")
            print(f"\nExplanation: {patch.explanation[:150]}...")
            print(f"Confidence: {patch.confidence}")
            print(f"Breaking Changes: {patch.breaking_changes}")
            return True
        else:
            print(f"\n❌ FAILED - {vuln_type}")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR - {vuln_type}: {e}")
        return False


def main():
    print("\n" + "="*70)
    print("COMPREHENSIVE VULNERABILITY TESTING WITH DEEPSEEK CODER")
    print("="*70)
    
    results = {}
    
    # Test 1: SQL Injection
    results['SQL Injection'] = test_vulnerability(
        "SQL Injection",
        """
        public User getUserById(String userId) {
            String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
            return jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper<>(User.class));
        }
        """,
        "Direct string concatenation in SQL query allows SQL injection attacks"
    )
    
    # Test 2: XSS (Cross-Site Scripting)
    results['XSS'] = test_vulnerability(
        "Cross-Site Scripting (XSS)",
        """
        @GetMapping("/profile")
        public String showProfile(@RequestParam String username, Model model) {
            model.addAttribute("username", username);
            return "profile";  // Thymeleaf template renders: <h1>Welcome ${username}</h1>
        }
        """,
        "User input rendered without escaping, allowing XSS attacks"
    )
    
    # Test 3: Path Traversal
    results['Path Traversal'] = test_vulnerability(
        "Path Traversal",
        """
        @GetMapping("/download")
        public ResponseEntity<Resource> downloadFile(@RequestParam String filename) {
            Path filePath = Paths.get(UPLOAD_DIR + filename);
            Resource resource = new UrlResource(filePath.toUri());
            return ResponseEntity.ok().body(resource);
        }
        """,
        "Unsanitized file path allows directory traversal attacks like ../../../etc/passwd"
    )
    
    # Test 4: Command Injection
    results['Command Injection'] = test_vulnerability(
        "Command Injection",
        """
        @PostMapping("/ping")
        public String pingHost(@RequestParam String host) {
            String command = "ping -c 4 " + host;
            Process process = Runtime.getRuntime().exec(command);
            return readOutput(process);
        }
        """,
        "Unsanitized command execution allows arbitrary command injection"
    )
    
    # Test 5: Insecure Deserialization
    results['Insecure Deserialization'] = test_vulnerability(
        "Insecure Deserialization",
        """
        @PostMapping("/import")
        public String importData(@RequestParam String data) {
            byte[] bytes = Base64.getDecoder().decode(data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            Object obj = ois.readObject();
            return processObject(obj);
        }
        """,
        "Deserializing untrusted data can lead to remote code execution"
    )
    
    # Test 6: CSRF (Cross-Site Request Forgery)
    results['CSRF'] = test_vulnerability(
        "Cross-Site Request Forgery (CSRF)",
        """
        @PostMapping("/transfer")
        public String transferMoney(@RequestParam String amount, @RequestParam String toAccount) {
            bankService.transfer(getCurrentUser(), toAccount, amount);
            return "redirect:/success";
        }
        """,
        "Missing CSRF token validation allows unauthorized actions"
    )
    
    # Test 7: Hardcoded Credentials
    results['Hardcoded Credentials'] = test_vulnerability(
        "Hardcoded Credentials",
        """
        public class DatabaseConfig {
            private static final String DB_PASSWORD = "MySecretPass123!";
            
            public Connection getConnection() {
                return DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb",
                    "admin",
                    DB_PASSWORD
                );
            }
        }
        """,
        "Hardcoded password in source code is a security risk"
    )
    
    # Test 8: Weak Cryptography
    results['Weak Cryptography'] = test_vulnerability(
        "Weak Cryptography",
        """
        public String hashPassword(String password) {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        }
        """,
        "MD5 is cryptographically broken and should not be used for password hashing"
    )
    
    # Test 9: XML External Entity (XXE)
    results['XXE'] = test_vulnerability(
        "XML External Entity (XXE)",
        """
        @PostMapping("/parse-xml")
        public String parseXml(@RequestParam String xmlData) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
            return processDocument(doc);
        }
        """,
        "XML parser allows external entity processing, enabling XXE attacks"
    )
    
    # Test 10: LDAP Injection
    results['LDAP Injection'] = test_vulnerability(
        "LDAP Injection",
        """
        public boolean authenticate(String username, String password) {
            String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
            SearchControls controls = new SearchControls();
            NamingEnumeration results = context.search("ou=users,dc=example,dc=com", filter, controls);
            return results.hasMore();
        }
        """,
        "Unescaped LDAP filter allows injection attacks"
    )
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for vuln, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {vuln}")
    
    print(f"\nResults: {passed}/{total} passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! DeepSeek Coder handles all vulnerability types!")
    elif passed >= total * 0.8:
        print("\n✅ GOOD! Most vulnerability types handled successfully!")
    else:
        print("\n⚠️  Some vulnerability types need attention")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
