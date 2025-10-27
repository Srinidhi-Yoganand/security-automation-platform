"""
Intelligent Patch Explainer

Uses LLM to generate detailed, developer-friendly explanations of:
1. WHY the vulnerability exists
2. HOW the patch fixes it
3. WHAT could go wrong without the fix
4. Security implications and best practices
"""
import logging
from typing import Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PatchExplanation:
    """Detailed patch explanation"""
    vulnerability_summary: str
    root_cause_analysis: str
    patch_mechanism: str
    security_impact: str
    best_practices: str
    code_walkthrough: str
    before_after_comparison: str
    potential_pitfalls: str


class PatchExplainer:
    """
    Generate intelligent, developer-friendly patch explanations using LLM
    """
    
    def __init__(self, llm_provider: str = "gemini"):
        self.llm_provider = llm_provider
        self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize LLM client"""
        try:
            if self.llm_provider == "gemini":
                import google.generativeai as genai
                import os
                genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
                self.model = genai.GenerativeModel('gemini-pro')
            elif self.llm_provider == "openai":
                import openai
                import os
                openai.api_key = os.getenv("OPENAI_API_KEY")
                self.model = "gpt-4"
            elif self.llm_provider == "ollama":
                import ollama
                self.client = ollama.Client()
                self.model = "deepseek-coder:6.7b-instruct"
            else:
                logger.warning(f"Unknown LLM provider: {self.llm_provider}, using template")
                self.llm_provider = "template"
        except Exception as e:
            logger.warning(f"Failed to initialize {self.llm_provider}: {e}, falling back to template")
            self.llm_provider = "template"
    
    def explain_patch(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str,
        dataflow: Optional[Dict] = None,
        cve_info: Optional[Dict] = None
    ) -> PatchExplanation:
        """
        Generate comprehensive patch explanation
        
        Args:
            vulnerability_type: Type of vulnerability (SQL Injection, IDOR, etc.)
            original_code: Vulnerable code before patch
            patched_code: Fixed code after patch
            dataflow: Data flow information (optional)
            cve_info: CVE database information (optional)
            
        Returns:
            Detailed patch explanation
        """
        logger.info(f"📚 Generating explanation for {vulnerability_type} patch...")
        
        if self.llm_provider == "template":
            return self._template_explanation(vulnerability_type, original_code, patched_code)
        
        prompt = self._build_explanation_prompt(
            vulnerability_type,
            original_code,
            patched_code,
            dataflow,
            cve_info
        )
        
        try:
            response = self._query_llm(prompt)
            return self._parse_explanation(response)
        except Exception as e:
            logger.error(f"❌ Failed to generate LLM explanation: {e}")
            return self._template_explanation(vulnerability_type, original_code, patched_code)
    
    def _build_explanation_prompt(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str,
        dataflow: Optional[Dict],
        cve_info: Optional[Dict]
    ) -> str:
        """Build comprehensive prompt for LLM"""
        
        prompt = f"""You are a senior security engineer explaining a security patch to a junior developer.
Provide a comprehensive, educational explanation that helps them understand the vulnerability and fix.

**Vulnerability Type:** {vulnerability_type}

**Original (Vulnerable) Code:**
```
{original_code}
```

**Patched (Fixed) Code:**
```
{patched_code}
```
"""
        
        if dataflow:
            prompt += f"""
**Data Flow Analysis:**
- Source: {dataflow.get('source', 'N/A')}
- Sink: {dataflow.get('sink', 'N/A')}
- Taint: {dataflow.get('tainted', 'N/A')}
"""
        
        if cve_info:
            prompt += f"""
**CVE Information:**
- CVE ID: {cve_info.get('cve_id', 'N/A')}
- CVSS Score: {cve_info.get('cvss_score', 'N/A')}
- References: {cve_info.get('references', [])}
"""
        
        prompt += """
Please provide a detailed explanation with the following sections:

1. **VULNERABILITY SUMMARY** (2-3 sentences)
   - What is the vulnerability in simple terms?
   - Why is it dangerous?

2. **ROOT CAUSE ANALYSIS** (detailed)
   - WHY does this vulnerability exist in the original code?
   - What coding mistake or oversight led to this?
   - What assumptions were wrong?

3. **PATCH MECHANISM** (detailed)
   - HOW does the patch fix the vulnerability?
   - What specific changes were made?
   - Why does this approach work?

4. **SECURITY IMPACT** (risk assessment)
   - What could an attacker do with this vulnerability?
   - What data/systems are at risk?
   - Real-world impact scenarios

5. **BEST PRACTICES** (learning)
   - General principles to prevent similar vulnerabilities
   - Secure coding patterns to follow
   - Common pitfalls to avoid

6. **CODE WALKTHROUGH** (line-by-line)
   - Explain key lines in both original and patched code
   - Highlight the critical differences
   - Use numbered annotations

7. **BEFORE/AFTER COMPARISON** (side-by-side analysis)
   - What happens in the vulnerable code flow?
   - What happens in the patched code flow?
   - Visual comparison of execution paths

8. **POTENTIAL PITFALLS** (gotchas)
   - What could go wrong with this patch?
   - Edge cases to consider
   - Testing recommendations

Format your response in Markdown with clear headings for each section.
Be educational, specific, and use code examples where helpful.
"""
        
        return prompt
    
    def _query_llm(self, prompt: str) -> str:
        """Query the configured LLM"""
        
        if self.llm_provider == "gemini":
            response = self.model.generate_content(prompt)
            return response.text
        
        elif self.llm_provider == "openai":
            import openai
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.7
            )
            return response.choices[0].message.content
        
        elif self.llm_provider == "ollama":
            response = self.client.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")
    
    def _parse_explanation(self, llm_response: str) -> PatchExplanation:
        """Parse LLM response into structured explanation"""
        
        # Simple parsing - split by section headers
        sections = {
            "vulnerability_summary": "",
            "root_cause_analysis": "",
            "patch_mechanism": "",
            "security_impact": "",
            "best_practices": "",
            "code_walkthrough": "",
            "before_after_comparison": "",
            "potential_pitfalls": ""
        }
        
        # Extract sections (simplified parsing)
        current_section = None
        for line in llm_response.split('\n'):
            if "VULNERABILITY SUMMARY" in line.upper():
                current_section = "vulnerability_summary"
            elif "ROOT CAUSE" in line.upper():
                current_section = "root_cause_analysis"
            elif "PATCH MECHANISM" in line.upper():
                current_section = "patch_mechanism"
            elif "SECURITY IMPACT" in line.upper():
                current_section = "security_impact"
            elif "BEST PRACTICES" in line.upper():
                current_section = "best_practices"
            elif "CODE WALKTHROUGH" in line.upper():
                current_section = "code_walkthrough"
            elif "BEFORE/AFTER" in line.upper():
                current_section = "before_after_comparison"
            elif "POTENTIAL PITFALLS" in line.upper():
                current_section = "potential_pitfalls"
            elif current_section:
                sections[current_section] += line + "\n"
        
        return PatchExplanation(**sections)
    
    def _template_explanation(
        self,
        vulnerability_type: str,
        original_code: str,
        patched_code: str
    ) -> PatchExplanation:
        """Fallback template-based explanation"""
        
        templates = {
            "SQL Injection": {
                "vulnerability_summary": "SQL Injection occurs when user input is directly concatenated into SQL queries without proper sanitization, allowing attackers to inject malicious SQL code.",
                "root_cause_analysis": "The original code constructs SQL queries using string concatenation with unsanitized user input. This breaks the separation between code and data, allowing attackers to inject SQL syntax.",
                "patch_mechanism": "The patch uses parameterized queries (prepared statements) which treat user input as data, not executable code. Parameters are safely escaped by the database driver.",
                "security_impact": "An attacker could bypass authentication, extract sensitive data, modify database contents, or execute arbitrary SQL commands including DROP TABLE.",
                "best_practices": "Always use parameterized queries or ORM frameworks. Never concatenate user input into SQL. Implement input validation as defense-in-depth. Use least privilege database accounts.",
                "code_walkthrough": "Original code concatenates user input directly into SQL string. Patched code uses ? placeholders and passes parameters separately through executeQuery() method.",
                "before_after_comparison": "Before: Query string built with + operator. After: Query uses placeholders, parameters passed in array.",
                "potential_pitfalls": "Ensure all SQL queries use parameters. Watch for dynamic table/column names (use whitelist). Test with common SQL injection payloads."
            },
            "IDOR": {
                "vulnerability_summary": "Insecure Direct Object Reference (IDOR) allows attackers to access resources by manipulating IDs in URLs without proper authorization checks.",
                "root_cause_analysis": "The application trusts user-provided resource IDs without verifying that the authenticated user has permission to access those resources.",
                "patch_mechanism": "The patch adds authorization check to verify the requesting user owns or has permission to access the requested resource before retrieving it.",
                "security_impact": "Attackers can access other users' private data, documents, or account information by simply changing ID parameters in URLs.",
                "best_practices": "Always verify authorization before accessing resources. Use random/unpredictable IDs. Implement access control matrix. Log unauthorized access attempts.",
                "code_walkthrough": "Original code fetches resource directly using ID from URL. Patched code first checks if currentUser.id matches resource.userId before allowing access.",
                "before_after_comparison": "Before: Direct database lookup by ID. After: Lookup by ID AND user ownership verification.",
                "potential_pitfalls": "Check authorization on ALL resource access, not just some endpoints. Watch for ID enumeration. Consider rate limiting."
            }
        }
        
        template = templates.get(vulnerability_type, {
            "vulnerability_summary": f"{vulnerability_type} vulnerability detected.",
            "root_cause_analysis": "Security vulnerability in code.",
            "patch_mechanism": "Patch fixes the security issue.",
            "security_impact": "Potential security breach.",
            "best_practices": "Follow secure coding guidelines.",
            "code_walkthrough": "Code has been updated.",
            "before_after_comparison": "Original code vs fixed code.",
            "potential_pitfalls": "Test thoroughly."
        })
        
        return PatchExplanation(**template)
    
    def generate_tutorial(self, explanation: PatchExplanation) -> str:
        """Generate interactive tutorial from explanation"""
        
        tutorial = f"""
# Security Patch Tutorial

## 🎯 {explanation.vulnerability_summary}

---

## 🔍 Why This Happened

{explanation.root_cause_analysis}

---

## 🛠️ How We Fixed It

{explanation.patch_mechanism}

---

## ⚠️ What's At Risk

{explanation.security_impact}

---

## ✅ Best Practices Going Forward

{explanation.best_practices}

---

## 👨‍💻 Code Walkthrough

{explanation.code_walkthrough}

---

## 📊 Before & After

{explanation.before_after_comparison}

---

## ⚡ Watch Out For

{explanation.potential_pitfalls}

---

**Next Steps:**
1. Review the patched code carefully
2. Test the fix with various inputs
3. Update documentation
4. Share this learning with your team
5. Apply similar fixes to related code
"""
        
        return tutorial


# Quick test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    explainer = PatchExplainer(llm_provider="template")
    
    original = '''
String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
statement.executeQuery(query);
'''
    
    patched = '''
String query = "SELECT * FROM users WHERE username=? AND password=?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
stmt.setString(2, password);
stmt.executeQuery();
'''
    
    explanation = explainer.explain_patch(
        vulnerability_type="SQL Injection",
        original_code=original,
        patched_code=patched
    )
    
    tutorial = explainer.generate_tutorial(explanation)
    print(tutorial)
