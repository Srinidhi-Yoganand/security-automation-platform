"""
Automated Patch Verification Testing

NOVEL CONTRIBUTION: Auto-generates unit tests to verify patches fix vulnerabilities
without breaking functionality.

Uses LLM to generate:
1. Test that vulnerability is actually fixed
2. Test that functionality still works
3. Edge case tests
4. Regression tests
"""
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TestSuite:
    """Generated test suite"""
    vulnerability_test: str  # Test that vulnerability is fixed
    functionality_test: str  # Test that feature still works
    edge_case_tests: List[str]  # Edge cases
    regression_tests: List[str]  # Prevent regression
    test_framework: str  # JUnit, PyTest, etc.
    setup_code: str  # Test setup
    teardown_code: str  # Test cleanup


class PatchTestGenerator:
    """
    Generate unit tests to verify security patches
    """
    
    def __init__(self, llm_provider: str = "gemini"):
        self.llm_provider = llm_provider
        self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize LLM"""
        try:
            if self.llm_provider == "gemini":
                import google.generativeai as genai
                import os
                genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
                self.model = genai.GenerativeModel('gemini-pro')
            elif self.llm_provider == "ollama":
                import ollama
                self.client = ollama.Client()
                self.model = "deepseek-coder:6.7b-instruct"
            else:
                self.llm_provider = "template"
        except Exception as e:
            logger.warning(f"LLM init failed: {e}")
            self.llm_provider = "template"
    
    def generate_tests(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str,
        language: str = "java",
        class_name: Optional[str] = None,
        method_name: Optional[str] = None
    ) -> TestSuite:
        """
        Generate comprehensive test suite for patch
        
        Args:
            vulnerability_type: Type of vulnerability
            original_code: Code before patch
            patched_code: Code after patch
            language: Programming language
            class_name: Class containing the patched method
            method_name: Patched method name
            
        Returns:
            Complete test suite
        """
        logger.info(f"🧪 Generating tests for {vulnerability_type} patch...")
        
        if self.llm_provider == "template":
            return self._template_tests(
                vulnerability_type,
                original_code,
                patched_code,
                language,
                class_name,
                method_name
            )
        
        prompt = self._build_test_generation_prompt(
            vulnerability_type,
            original_code,
            patched_code,
            language,
            class_name,
            method_name
        )
        
        try:
            response = self._query_llm(prompt)
            return self._parse_test_suite(response, language)
        except Exception as e:
            logger.error(f"Test generation failed: {e}")
            return self._template_tests(
                vulnerability_type,
                original_code,
                patched_code,
                language,
                class_name,
                method_name
            )
    
    def _build_test_generation_prompt(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str,
        language: str,
        class_name: Optional[str],
        method_name: Optional[str]
    ) -> str:
        """Build prompt for test generation"""
        
        framework_map = {
            "java": "JUnit 5",
            "python": "pytest",
            "javascript": "Jest",
            "csharp": "NUnit"
        }
        
        framework = framework_map.get(language, "appropriate test framework")
        
        prompt = f"""You are an expert software test engineer. Generate comprehensive unit tests
to verify a security patch fixes a vulnerability without breaking functionality.

**Language:** {language}
**Test Framework:** {framework}
**Class:** {class_name or 'Unknown'}
**Method:** {method_name or 'Unknown'}
**Vulnerability Type:** {vulnerability_type}

**Original (Vulnerable) Code:**
```{language}
{original_code}
```

**Patched (Fixed) Code:**
```{language}
{patched_code}
```

Generate a complete test suite with:

1. **VULNERABILITY TEST** - Verify the security fix works
   - Test that exploits the original vulnerability
   - Should FAIL on original code
   - Should PASS on patched code
   - Include actual attack payloads

2. **FUNCTIONALITY TEST** - Verify feature still works correctly
   - Test normal/expected use cases
   - Should PASS on both original and patched code
   - Ensure patch doesn't break functionality

3. **EDGE CASE TESTS** (3-5 tests)
   - Boundary conditions
   - Null/empty inputs
   - Special characters
   - Large inputs
   - Unexpected data types

4. **REGRESSION TESTS** (2-3 tests)
   - Related functionality that could be affected
   - Integration with other components
   - Performance impact checks

**Requirements:**
- Use {framework} syntax
- Include setup and teardown
- Add assertions with clear messages
- Include comments explaining what each test verifies
- Make tests runnable and self-contained
- Use mocks/stubs where appropriate

Format your response as:

## Vulnerability Test
```{language}
[code]
```

## Functionality Test
```{language}
[code]
```

## Edge Case Tests
```{language}
[code]
```

## Regression Tests
```{language}
[code]
```

## Setup Code
```{language}
[code]
```

## Teardown Code
```{language}
[code]
```
"""
        
        return prompt
    
    def _query_llm(self, prompt: str) -> str:
        """Query LLM"""
        if self.llm_provider == "gemini":
            response = self.model.generate_content(prompt)
            return response.text
        elif self.llm_provider == "ollama":
            response = self.client.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        return ""
    
    def _parse_test_suite(self, llm_response: str, language: str) -> TestSuite:
        """Parse LLM response into test suite"""
        
        # Simple parsing by section markers
        sections = {
            "vulnerability_test": "",
            "functionality_test": "",
            "edge_case_tests": [],
            "regression_tests": [],
            "setup_code": "",
            "teardown_code": ""
        }
        
        current_section = None
        current_code = []
        in_code_block = False
        
        for line in llm_response.split('\n'):
            if "## Vulnerability Test" in line:
                current_section = "vulnerability_test"
                current_code = []
            elif "## Functionality Test" in line:
                current_section = "functionality_test"
                current_code = []
            elif "## Edge Case Tests" in line:
                current_section = "edge_case_tests"
                current_code = []
            elif "## Regression Tests" in line:
                current_section = "regression_tests"
                current_code = []
            elif "## Setup Code" in line:
                current_section = "setup_code"
                current_code = []
            elif "## Teardown Code" in line:
                current_section = "teardown_code"
                current_code = []
            elif line.startswith("```"):
                in_code_block = not in_code_block
                if not in_code_block and current_code:
                    # End of code block
                    code = '\n'.join(current_code)
                    if isinstance(sections[current_section], list):
                        sections[current_section].append(code)
                    else:
                        sections[current_section] = code
                    current_code = []
            elif in_code_block:
                current_code.append(line)
        
        framework_map = {
            "java": "JUnit 5",
            "python": "pytest",
            "javascript": "Jest"
        }
        
        return TestSuite(
            vulnerability_test=sections["vulnerability_test"],
            functionality_test=sections["functionality_test"],
            edge_case_tests=sections["edge_case_tests"],
            regression_tests=sections["regression_tests"],
            test_framework=framework_map.get(language, "Unknown"),
            setup_code=sections["setup_code"],
            teardown_code=sections["teardown_code"]
        )
    
    def _template_tests(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str,
        language: str,
        class_name: Optional[str],
        method_name: Optional[str]
    ) -> TestSuite:
        """Generate template-based tests"""
        
        if language == "java":
            return self._java_template_tests(vulnerability_type, class_name, method_name)
        elif language == "python":
            return self._python_template_tests(vulnerability_type, class_name, method_name)
        else:
            return self._generic_template_tests(vulnerability_type, language)
    
    def _java_template_tests(
        self,
        vulnerability_type: str,
        class_name: Optional[str],
        method_name: Optional[str]
    ) -> TestSuite:
        """Generate Java/JUnit tests"""
        
        class_name = class_name or "VulnerableClass"
        method_name = method_name or "vulnerableMethod"
        
        vuln_test = f"""
@Test
@DisplayName("Test that {vulnerability_type} is fixed")
void test{vulnerability_type.replace(' ', '')}Fixed() {{
    // Arrange: Prepare malicious input that would exploit the vulnerability
    String maliciousInput = "' OR '1'='1' --";  // SQL injection payload
    {class_name} instance = new {class_name}();
    
    // Act: Call the patched method
    String result = instance.{method_name}(maliciousInput);
    
    // Assert: Verify the attack is blocked
    assertFalse(result.contains("admin"), "Malicious input should be sanitized");
    assertFalse(result.contains("password"), "Should not expose sensitive data");
    
    // Additional verification: Check that input was properly escaped
    assertTrue(result.contains("?") || result.contains("prepared"),
               "Should use parameterized queries");
}}
"""
        
        functionality_test = f"""
@Test
@DisplayName("Test that normal functionality still works")
void testNormalFunctionality() {{
    // Arrange: Prepare valid input
    String validInput = "john_doe";
    {class_name} instance = new {class_name}();
    
    // Act: Call the method with valid input
    String result = instance.{method_name}(validInput);
    
    // Assert: Verify normal operation
    assertNotNull(result, "Should return valid result for legitimate input");
    assertTrue(result.length() > 0, "Should return non-empty result");
    
    // Verify no exceptions thrown
    assertDoesNotThrow(() -> instance.{method_name}(validInput));
}}
"""
        
        edge_cases = [
            f"""
@Test
void testNullInput() {{
    {class_name} instance = new {class_name}();
    assertThrows(IllegalArgumentException.class,
                 () -> instance.{method_name}(null),
                 "Should handle null input gracefully");
}}
""",
            f"""
@Test
void testEmptyInput() {{
    {class_name} instance = new {class_name}();
    String result = instance.{method_name}("");
    assertNotNull(result, "Should handle empty input");
}}
""",
            f"""
@Test
void testSpecialCharacters() {{
    {class_name} instance = new {class_name}();
    String specialInput = "user@test.com';--<script>";
    String result = instance.{method_name}(specialInput);
    assertFalse(result.contains("<script>"), "Should escape special characters");
}}
"""
        ]
        
        regression_tests = [
            f"""
@Test
void testPerformanceImpact() {{
    {class_name} instance = new {class_name}();
    long startTime = System.nanoTime();
    instance.{method_name}("test_input");
    long endTime = System.nanoTime();
    long duration = (endTime - startTime) / 1_000_000;  // Convert to milliseconds
    assertTrue(duration < 1000, "Should complete within 1 second");
}}
"""
        ]
        
        setup = f"""
private {class_name} testInstance;
private Connection mockConnection;

@BeforeEach
void setUp() {{
    testInstance = new {class_name}();
    mockConnection = mock(Connection.class);
    testInstance.setConnection(mockConnection);
}}
"""
        
        teardown = """
@AfterEach
void tearDown() {
    if (mockConnection != null) {
        try {
            mockConnection.close();
        } catch (SQLException e) {
            // Ignore
        }
    }
}
"""
        
        return TestSuite(
            vulnerability_test=vuln_test,
            functionality_test=functionality_test,
            edge_case_tests=edge_cases,
            regression_tests=regression_tests,
            test_framework="JUnit 5",
            setup_code=setup,
            teardown_code=teardown
        )
    
    def _python_template_tests(
        self,
        vulnerability_type: str,
        class_name: Optional[str],
        method_name: Optional[str]
    ) -> TestSuite:
        """Generate Python/pytest tests"""
        
        class_name = class_name or "VulnerableClass"
        method_name = method_name or "vulnerable_method"
        
        vuln_test = f"""
def test_{vulnerability_type.lower().replace(' ', '_')}_fixed():
    '''Test that {vulnerability_type} is fixed'''
    # Arrange: malicious input
    malicious_input = "' OR '1'='1' --"
    instance = {class_name}()
    
    # Act: call patched method
    result = instance.{method_name}(malicious_input)
    
    # Assert: attack blocked
    assert "admin" not in result, "Malicious input should be sanitized"
    assert "password" not in result, "Should not expose sensitive data"
"""
        
        functionality_test = f"""
def test_normal_functionality():
    '''Test that feature still works correctly'''
    instance = {class_name}()
    result = instance.{method_name}("john_doe")
    
    assert result is not None
    assert len(result) > 0
"""
        
        edge_cases = [
            """
def test_null_input():
    instance = {class_name}()
    with pytest.raises(ValueError):
        instance.{method_name}(None)
""",
            """
def test_empty_input():
    instance = {class_name}()
    result = instance.{method_name}("")
    assert result is not None
"""
        ]
        
        return TestSuite(
            vulnerability_test=vuln_test,
            functionality_test=functionality_test,
            edge_case_tests=edge_cases,
            regression_tests=[],
            test_framework="pytest",
            setup_code="@pytest.fixture\ndef instance():\n    return VulnerableClass()",
            teardown_code=""
        )
    
    def _generic_template_tests(self, vulnerability_type: str, language: str) -> TestSuite:
        """Generic fallback tests"""
        return TestSuite(
            vulnerability_test=f"// Test {vulnerability_type} fix\n// TODO: Implement test",
            functionality_test="// Test functionality\n// TODO: Implement test",
            edge_case_tests=[],
            regression_tests=[],
            test_framework="Unknown",
            setup_code="// Setup",
            teardown_code="// Teardown"
        )
    
    def generate_test_file(
        self,
        test_suite: TestSuite,
        class_name: str,
        output_path: str
    ) -> str:
        """Generate complete test file"""
        
        if test_suite.test_framework == "JUnit 5":
            content = f"""
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Automated security patch verification tests
 * Generated to verify vulnerability fix
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class {class_name}PatchVerificationTest {{

    {test_suite.setup_code}
    
    {test_suite.teardown_code}
    
    {test_suite.vulnerability_test}
    
    {test_suite.functionality_test}
    
    {''.join(test_suite.edge_case_tests)}
    
    {''.join(test_suite.regression_tests)}
}}
"""
        elif test_suite.test_framework == "pytest":
            content = f"""
import pytest
from {class_name.lower()} import {class_name}

# Automated security patch verification tests

{test_suite.setup_code}

{test_suite.vulnerability_test}

{test_suite.functionality_test}

{''.join(test_suite.edge_case_tests)}
"""
        else:
            content = f"// Tests for {class_name}\n// Framework: {test_suite.test_framework}\n"
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(content)
        
        logger.info(f"✅ Test file generated: {output_path}")
        return output_path


# Quick test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    generator = PatchTestGenerator(llm_provider="template")
    
    tests = generator.generate_tests(
        vulnerability_type="SQL Injection",
        original_code="String query = \"SELECT * FROM users WHERE id='\" + userId + \"'\";",
        patched_code="PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");\nstmt.setString(1, userId);",
        language="java",
        class_name="UserDAO",
        method_name="getUser"
    )
    
    print("\n" + "="*80)
    print("Generated Test Suite:")
    print("="*80)
    print("\nVulnerability Test:")
    print(tests.vulnerability_test)
    print("\nFunctionality Test:")
    print(tests.functionality_test)
