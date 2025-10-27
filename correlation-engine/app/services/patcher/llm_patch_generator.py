"""
LLM-Powered Intelligent Patch Generator
Generates security patches for ANY vulnerability type using LLMs
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False

try:
    from git import Repo
    GITPYTHON_AVAILABLE = True
except ImportError:
    GITPYTHON_AVAILABLE = False


class PatchStatus(str, Enum):
    """Status of generated patch"""
    GENERATED = "generated"
    TESTED = "tested"
    FAILED = "failed"
    APPROVED = "approved"
    APPLIED = "applied"


@dataclass
class PatchContext:
    """Complete context for patch generation"""
    vulnerability_type: str
    file_path: str
    line_number: int
    vulnerable_code: str
    severity: str
    confidence: float
    description: Optional[str] = None
    cwe_id: Optional[str] = None
    tool_name: Optional[str] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    surrounding_context: Optional[str] = None  # Code around vulnerability


@dataclass
class GeneratedPatch:
    """A generated security patch with testing info"""
    vulnerability_id: Optional[int]
    vulnerability_type: str
    file_path: str
    line_number: int
    
    # Patch content
    original_code: str
    fixed_code: str
    explanation: str
    diff: str
    
    # Metadata
    confidence: str  # high/medium/low
    status: PatchStatus
    test_branch: Optional[str] = None
    test_results: Optional[Dict[str, Any]] = None
    manual_review_needed: bool = True
    
    # Additional info
    breaking_changes: List[str] = None
    prerequisites: List[str] = None
    remediation_guide: Optional[str] = None


class LLMPatchGenerator:
    """
    Intelligent patch generator using LLMs
    - Supports ANY vulnerability type
    - Generates contextually appropriate fixes
    - Tests patches in isolated branch
    - Provides human-approval workflow
    """
    
    def __init__(self, repo_path: str = ".", api_key: Optional[str] = None, llm_provider: str = "auto"):
        """
        Initialize LLM patch generator
        
        Args:
            repo_path: Path to git repository
            api_key: API key for LLM provider (or use environment variables)
            llm_provider: "auto", "gemini", "openai", "ollama", or "template"
        """
        self.repo_path = Path(repo_path)
        self.repo = None
        self.llm_provider = llm_provider
        
        # Auto-detect best available LLM
        if llm_provider == "auto":
            self.llm_provider = self._detect_llm_provider()
        
        # Initialize based on provider
        if self.llm_provider == "gemini":
            self._init_gemini(api_key)
        elif self.llm_provider == "openai":
            self._init_openai(api_key)
        elif self.llm_provider == "ollama":
            self._init_ollama()
        else:
            self.llm_provider = "template"
            print(f"[INFO] Using template-based patching (no LLM)")
        
        # Try to load git repo
        if GITPYTHON_AVAILABLE:
            try:
                self.repo = Repo(repo_path)
            except Exception as e:
                print(f"WARNING: Could not load git repository: {e}")
        else:
            print("[INFO] GitPython not available - git features disabled")
    
    def _detect_llm_provider(self) -> str:
        """Auto-detect best available LLM provider"""
        # Priority: Gemini (free) > Ollama (local) > OpenAI (paid) > Template (fallback)
        
        if GEMINI_AVAILABLE and os.getenv("GEMINI_API_KEY"):
            print("[INFO] Using Google Gemini (detected API key)")
            return "gemini"
        
        if OLLAMA_AVAILABLE:
            # Check if Ollama server is running
            try:
                ollama.list()
                print("[INFO] Using Ollama (local LLM detected)")
                return "ollama"
            except:
                pass
        
        if OPENAI_AVAILABLE and os.getenv("OPENAI_API_KEY"):
            print("[INFO] Using OpenAI GPT (detected API key)")
            return "openai"
        
        print("[INFO] No LLM available, using template-based patching")
        return "template"
    
    def _init_gemini(self, api_key: Optional[str] = None):
        """Initialize Google Gemini"""
        if not GEMINI_AVAILABLE:
            print("ERROR: google-generativeai not installed")
            self.llm_provider = "template"
            return
        
        key = api_key or os.getenv("GEMINI_API_KEY")
        if not key:
            print("WARNING: No Gemini API key found. Set GEMINI_API_KEY environment variable.")
            print("         Get free key from: https://makersuite.google.com/app/apikey")
            self.llm_provider = "template"
            return
        
        genai.configure(api_key=key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')  # Fast and free!
        print(f"[OK] Gemini initialized (model: gemini-2.5-flash)")
    
    def _init_openai(self, api_key: Optional[str] = None):
        """Initialize OpenAI"""
        if not OPENAI_AVAILABLE:
            print("ERROR: openai not installed")
            self.llm_provider = "template"
            return
        
        openai.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("WARNING: No OpenAI API key found")
            self.llm_provider = "template"
            return
        
        print(f"[OK] OpenAI initialized (model: gpt-4-turbo-preview)")
    
    def _init_ollama(self):
        """Initialize Ollama (local LLM)"""
        if not OLLAMA_AVAILABLE:
            print("ERROR: ollama not installed")
            self.llm_provider = "template"
            return
        
        try:
            # Check if Ollama is running and has models
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            ollama_client = ollama.Client(host=host)
            models_response = ollama_client.list()
            
            if not models_response or not models_response.get('models'):
                print("WARNING: No Ollama models installed")
                print("         Install with: ollama pull deepseek-coder:6.7b-instruct")
                self.llm_provider = "template"
                return
            
            # Prefer DeepSeek Coder (best for security), then CodeLlama, then any other
            model_names = [m.get('name', m.get('model', '')) for m in models_response['models']]
            preferred_model = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b-instruct")
            
            if any(preferred_model in m for m in model_names):
                self.ollama_model = preferred_model
            elif any('deepseek-coder' in m for m in model_names):
                self.ollama_model = next(m for m in model_names if 'deepseek-coder' in m)
            elif any('codellama' in m for m in model_names):
                self.ollama_model = next(m for m in model_names if 'codellama' in m)
            elif any('llama' in m for m in model_names):
                self.ollama_model = next(m for m in model_names if 'llama' in m)
            else:
                self.ollama_model = model_names[0]
            
            self.ollama_client = ollama_client
            print(f"[OK] Ollama initialized (model: {self.ollama_model})")
        except Exception as e:
            print(f"WARNING: Ollama not running: {e}")
            print("         Start with: ollama serve")
            print("         Or set OLLAMA_HOST env var for remote Ollama")
            self.llm_provider = "template"

    
    def generate_patch(self, context: PatchContext, test_patch: bool = True) -> Optional[GeneratedPatch]:
        """
        Generate intelligent security patch using LLM
        
        Args:
            context: Vulnerability context
            test_patch: Whether to test patch in separate branch
            
        Returns:
            GeneratedPatch object or None if failed
        """
        print(f"[LLM] Generating patch for {context.vulnerability_type}...")
        
        # Step 1: Gather full context
        full_context = self._gather_context(context)
        if not full_context:
            return None
        
        # Step 2: Generate patch using LLM
        patch_data = self._generate_with_llm(full_context)
        if not patch_data:
            return None
        
        # Step 3: Create patch object
        patch = GeneratedPatch(
            vulnerability_id=None,
            vulnerability_type=context.vulnerability_type,
            file_path=context.file_path,
            line_number=context.line_number,
            original_code=full_context['vulnerable_code'],
            fixed_code=patch_data['fixed_code'],
            explanation=patch_data['explanation'],
            diff=self._generate_diff(
                full_context['vulnerable_code'],
                patch_data['fixed_code'],
                context.file_path,
                context.line_number
            ),
            confidence=patch_data['confidence'],
            status=PatchStatus.GENERATED,
            breaking_changes=patch_data.get('breaking_changes', []),
            prerequisites=patch_data.get('prerequisites', []),
            manual_review_needed=True,
            remediation_guide=patch_data.get('remediation_guide')
        )
        
        # Step 4: Test patch in separate branch (if requested)
        if test_patch and self.repo:
            test_result = self._test_patch_in_branch(patch, context)
            patch.test_results = test_result
            patch.status = PatchStatus.TESTED if test_result['success'] else PatchStatus.FAILED
        
        return patch
    
    def _gather_context(self, context: PatchContext) -> Optional[Dict[str, Any]]:
        """
        Gather complete context around vulnerability
        
        Returns:
            Dict with file content, surrounding code, class/method info
        """
        file_path = self.repo_path / context.file_path
        
        if not file_path.exists():
            print(f"ERROR: File not found: {file_path}")
            return None
        
        # Read full file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
                lines = file_content.split('\n')
        except Exception as e:
            print(f"ERROR: Could not read file: {e}")
            return None
        
        # Get surrounding context (20 lines before/after)
        start_line = max(0, context.line_number - 20)
        end_line = min(len(lines), context.line_number + 20)
        surrounding_code = '\n'.join(lines[start_line:end_line])
        
        # Extract method and class information (for Java)
        method_info = self._extract_method_context(file_content, context.line_number)
        
        return {
            'file_path': context.file_path,
            'file_content': file_content,
            'vulnerable_code': context.vulnerable_code or lines[context.line_number - 1] if context.line_number <= len(lines) else "",
            'surrounding_code': surrounding_code,
            'method_name': method_info.get('method_name'),
            'class_name': method_info.get('class_name'),
            'method_signature': method_info.get('method_signature'),
            'vulnerability_type': context.vulnerability_type,
            'severity': context.severity,
            'description': context.description,
            'cwe_id': context.cwe_id,
            'line_number': context.line_number
        }
    
    def _generate_with_llm(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Use LLM to generate intelligent patch
        
        Returns:
            Dict with fixed_code, explanation, confidence, breaking_changes, prerequisites
        """
        if self.llm_provider == "template":
            return self._fallback_template_patch(context)
        
        # Construct prompt for LLM
        prompt = self._build_patch_prompt(context)
        
        try:
            if self.llm_provider == "gemini":
                return self._generate_with_gemini(prompt)
            elif self.llm_provider == "openai":
                return self._generate_with_openai(prompt)
            elif self.llm_provider == "ollama":
                return self._generate_with_ollama(prompt)
            else:
                return self._fallback_template_patch(context)
        except Exception as e:
            print(f"ERROR: LLM patch generation failed: {e}")
            return self._fallback_template_patch(context)
    
    def _generate_with_gemini(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Generate patch using Google Gemini"""
        import json
        import re
        
        try:
            # Configure safety settings to allow security code discussions
            safety_settings = [
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            ]
            
            # Configure for JSON output
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=2000,
                ),
                safety_settings=safety_settings
            )
            
            # Check if response was blocked
            if not response.candidates or not response.candidates[0].content.parts:
                print(f"WARNING: Gemini blocked response (safety filters). Using template fallback.")
                return None
            
            # Extract JSON from response
            text = response.text
            
            # Try to parse JSON (Gemini often wraps in markdown)
            if "```json" in text:
                json_str = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                # Try to find JSON block
                match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
                if match:
                    json_str = match.group(1)
                else:
                    json_str = text.split("```")[1].split("```")[0].strip()
            else:
                # Try to extract JSON object directly
                match = re.search(r'\{.*\}', text, re.DOTALL)
                if match:
                    json_str = match.group(0)
                else:
                    json_str = text.strip()
            
            result = json.loads(json_str)
            print(f"[OK] Gemini generated patch")
            return result
            
        except json.JSONDecodeError as e:
            print(f"ERROR: Gemini JSON parsing failed: {e}")
            try:
                print(f"Response text: {text[:200]}...")
            except:
                pass
            return None
        except Exception as e:
            print(f"ERROR: Gemini generation failed: {e}")
            return None
    
    def _generate_with_openai(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Generate patch using OpenAI GPT"""
        import json
        
        try:
            # Call OpenAI API (GPT-4 for best results)
            response = openai.chat.completions.create(
                model="gpt-4-turbo-preview",  # or gpt-3.5-turbo for faster/cheaper
                messages=[
                    {
                        "role": "system",
                        "content": """You are a security expert specializing in vulnerability remediation. 
Generate secure, production-ready code fixes that:
1. Completely eliminate the vulnerability
2. Follow best practices and coding standards
3. Minimize breaking changes
4. Include proper error handling
5. Are contextually appropriate

Return response in JSON format with:
{
  "fixed_code": "Complete fixed code snippet",
  "explanation": "Clear explanation of the fix",
  "confidence": "high|medium|low",
  "breaking_changes": ["list of potential breaking changes"],
  "prerequisites": ["required dependencies or setup"],
  "remediation_guide": "Additional security recommendations"
}"""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,  # Lower temperature for more consistent code
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response.choices[0].message.content)
            print(f"[OK] OpenAI generated patch")
            return result
            
        except Exception as e:
            print(f"ERROR: OpenAI generation failed: {e}")
            return None
    
    def _generate_with_ollama(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Generate patch using Ollama (local LLM)"""
        import json
        
        try:
            response = self.ollama_client.generate(
                model=self.ollama_model,
                prompt=prompt,
                format='json',
                options={
                    'temperature': 0.3,
                    'num_predict': 2000,
                }
            )
            
            result = json.loads(response['response'])
            print(f"[OK] Ollama ({self.ollama_model}) generated patch")
            return result
            
        except Exception as e:
            print(f"ERROR: Ollama generation failed: {e}")
            print(f"       Model: {self.ollama_model}")
            return None
    
    def _build_patch_prompt(self, context: Dict[str, Any]) -> str:
        """Build detailed prompt for LLM patch generation"""
        
        prompt = f"""
# Code Security Improvement Task

You are helping improve code security. Analyze this Java code and provide a secure version.

## Code Issue
- **Issue Type**: {context['vulnerability_type']}
- **Security Level**: {context['severity']}
- **File**: {context['file_path']}
- **CWE Reference**: {context.get('cwe_id', 'N/A')}

## Current Code (Needs Improvement)
```java
{context['vulnerable_code']}
```

## Code Context
```java
{context['surrounding_code'][:500]}
```

## Task
Provide an improved, secure version of this code that:
1. Follows security best practices
2. Uses parameterized queries for database operations
3. Includes proper input validation
4. Maintains the original functionality
5. Follows Java/Spring Boot conventions

## Required JSON Response Format
Please respond with ONLY a JSON object (no markdown, no explanation outside JSON):
{{
  "fixed_code": "the complete secure code",
  "explanation": "brief explanation of security improvements",
  "confidence": "high",
  "breaking_changes": [],
  "prerequisites": ["any dependencies needed"],
  "remediation_guide": "link to security documentation"
}}
"""
        
        return prompt
    
    def _fallback_template_patch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback to template-based patching if LLM unavailable"""
        vuln_type = context['vulnerability_type'].lower()
        vulnerable_code = context['vulnerable_code']
        
        # Basic template-based fixes
        if 'sql' in vuln_type or 'injection' in vuln_type:
            if '+' in vulnerable_code or 'concat' in vulnerable_code.lower():
                fixed = self._fix_sql_injection_template(vulnerable_code, context)
                return {
                    'fixed_code': fixed,
                    'explanation': 'Converted string concatenation to PreparedStatement with parameterized query',
                    'confidence': 'medium',
                    'breaking_changes': [],
                    'prerequisites': [],
                    'remediation_guide': 'Use PreparedStatement for all SQL queries'
                }
        
        # Generic fallback
        return {
            'fixed_code': vulnerable_code + '\n// TODO: Manual security review required',
            'explanation': f'Automatic patch not available for {context["vulnerability_type"]}. Manual review required.',
            'confidence': 'low',
            'breaking_changes': ['Requires manual implementation'],
            'prerequisites': [],
            'remediation_guide': f'Review OWASP guidelines for {context["vulnerability_type"]}'
        }
    
    def _fix_sql_injection_template(self, code: str, context: Dict[str, Any]) -> str:
        """Template fix for SQL injection"""
        # Simple template - extract query and parameters
        # This is a fallback; LLM will do better
        return code.replace(
            'String query = ',
            'PreparedStatement stmt = connection.prepareStatement('
        ).replace(' + ', '?')
    
    def _extract_method_context(self, file_content: str, line_number: int) -> Dict[str, Any]:
        """Extract method and class context from Java file"""
        if not JAVALANG_AVAILABLE:
            return {'method_name': None, 'class_name': None, 'method_signature': None}
        
        try:
            tree = javalang.parse.parse(file_content)
            
            # Find method containing the line
            for path, node in tree:
                if isinstance(node, javalang.tree.MethodDeclaration):
                    # Get method position (approximate)
                    method_name = node.name
                    
                    # Get class name
                    class_name = None
                    for p, n in tree:
                        if isinstance(n, javalang.tree.ClassDeclaration):
                            class_name = n.name
                            break
                    
                    return {
                        'method_name': method_name,
                        'class_name': class_name,
                        'method_signature': f"{node.return_type} {method_name}({', '.join([p.type.name for p in node.parameters])})"
                    }
        except:
            pass
        
        return {'method_name': None, 'class_name': None, 'method_signature': None}
    
    def _generate_diff(self, original: str, fixed: str, file_path: str, line_number: int) -> str:
        """Generate git-style diff"""
        from diff_match_patch import diff_match_patch
        
        dmp = diff_match_patch()
        patches = dmp.patch_make(original, fixed)
        diff = dmp.patch_toText(patches)
        
        # Format as git diff
        git_diff = f"""--- a/{file_path}
+++ b/{file_path}
@@ -{line_number},{len(original.split(chr(10)))} +{line_number},{len(fixed.split(chr(10)))} @@
"""
        
        for line in original.split('\n'):
            git_diff += f"-{line}\n"
        for line in fixed.split('\n'):
            git_diff += f"+{line}\n"
        
        return git_diff
    
    def _test_patch_in_branch(self, patch: GeneratedPatch, context: PatchContext) -> Dict[str, Any]:
        """
        Test patch in isolated git branch
        
        Returns:
            Dict with success status, build results, test results
        """
        if not self.repo:
            return {
                'success': False,
                'error': 'Git repository not available'
            }
        
        branch_name = f"security-patch-{context.vulnerability_type.lower().replace(' ', '-')}-line-{context.line_number}"
        
        try:
            # Save current branch
            original_branch = self.repo.active_branch.name
            
            # Create new branch
            print(f"🔀 Creating test branch: {branch_name}")
            test_branch = self.repo.create_head(branch_name)
            test_branch.checkout()
            
            # Apply patch
            file_path = self.repo_path / context.file_path
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Replace vulnerable code with fixed code
            new_content = content.replace(patch.original_code, patch.fixed_code)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            # Commit changes
            self.repo.index.add([str(context.file_path)])
            self.repo.index.commit(f"Security fix: {context.vulnerability_type} at line {context.line_number}")
            
            # Run tests (if Maven/Gradle project)
            build_result = self._run_build_tests()
            
            # Store branch name
            patch.test_branch = branch_name
            
            # Return to original branch
            self.repo.heads[original_branch].checkout()
            
            return {
                'success': build_result['success'],
                'branch': branch_name,
                'build_output': build_result.get('output', ''),
                'tests_passed': build_result.get('tests_passed', False),
                'compilation_success': build_result.get('compilation_success', False)
            }
            
        except Exception as e:
            print(f"ERROR: Patch testing failed: {e}")
            # Try to return to original branch
            try:
                self.repo.heads[original_branch].checkout()
            except:
                pass
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def _run_build_tests(self) -> Dict[str, Any]:
        """Run Maven/Gradle build and tests"""
        import subprocess
        
        # Check for Maven
        if (self.repo_path / 'pom.xml').exists():
            print("📦 Running Maven build and tests...")
            try:
                result = subprocess.run(
                    ['mvn', 'clean', 'test'],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                return {
                    'success': result.returncode == 0,
                    'compilation_success': 'BUILD SUCCESS' in result.stdout,
                    'tests_passed': 'Tests run:' in result.stdout and 'Failures: 0' in result.stdout,
                    'output': result.stdout + result.stderr
                }
            except subprocess.TimeoutExpired:
                return {
                    'success': False,
                    'error': 'Build timeout'
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        # Check for Gradle
        elif (self.repo_path / 'build.gradle').exists() or (self.repo_path / 'build.gradle.kts').exists():
            print("📦 Running Gradle build and tests...")
            try:
                result = subprocess.run(
                    ['./gradlew', 'clean', 'test'],
                    cwd=str(self.repo_path),
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                return {
                    'success': result.returncode == 0,
                    'compilation_success': 'BUILD SUCCESSFUL' in result.stdout,
                    'tests_passed': 'BUILD SUCCESSFUL' in result.stdout,
                    'output': result.stdout + result.stderr
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        return {
            'success': False,
            'error': 'No build system found (Maven/Gradle)'
        }
    
    def approve_patch(self, patch: GeneratedPatch) -> bool:
        """
        Approve patch for application
        
        Args:
            patch: Generated and tested patch
            
        Returns:
            True if approved successfully
        """
        if patch.status != PatchStatus.TESTED:
            print("ERROR: Patch must be tested before approval")
            return False
        
        if not patch.test_results or not patch.test_results.get('success'):
            print("WARNING: Patch tests did not pass. Approve anyway? (manual review required)")
        
        patch.status = PatchStatus.APPROVED
        print(f"✅ Patch approved for {patch.file_path}:{patch.line_number}")
        return True
    
    def apply_patch(self, patch: GeneratedPatch, target_branch: str = "main") -> bool:
        """
        Apply approved patch to target branch
        
        Args:
            patch: Approved patch
            target_branch: Branch to apply patch to
            
        Returns:
            True if applied successfully
        """
        if patch.status != PatchStatus.APPROVED:
            print("ERROR: Patch must be approved before application")
            return False
        
        if not self.repo or not patch.test_branch:
            print("ERROR: Git repository or test branch not available")
            return False
        
        try:
            # Checkout target branch
            self.repo.heads[target_branch].checkout()
            
            # Merge test branch
            self.repo.git.merge(patch.test_branch)
            
            patch.status = PatchStatus.APPLIED
            print(f"✅ Patch applied to {target_branch}")
            
            return True
            
        except Exception as e:
            print(f"ERROR: Failed to apply patch: {e}")
            return False
