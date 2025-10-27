"""
Enhanced Context Builder for Semantic-Aware Patch Generation
Integrates CodeQL findings, symbolic execution proofs, and security context
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from pathlib import Path
import json

try:
    import javalang
    JAVALANG_AVAILABLE = True
except ImportError:
    JAVALANG_AVAILABLE = False


@dataclass
class EnhancedPatchContext:
    """
    Extended patch context with semantic analysis and symbolic verification
    """
    # Basic vulnerability info
    vulnerability_type: str
    file_path: str
    line_number: int
    vulnerable_code: str
    severity: str
    confidence: float
    
    # Semantic analysis data (from CodeQL)
    data_flow_path: Optional[Dict[str, Any]] = None
    source_location: Optional[Dict[str, Any]] = None
    sink_location: Optional[Dict[str, Any]] = None
    intermediate_steps: List[Dict[str, Any]] = None
    
    # Security context (from semantic analyzer)
    security_context: Optional[Dict[str, Any]] = None
    authentication_present: bool = False
    authorization_present: bool = False
    security_annotations: List[str] = None
    framework: str = "unknown"
    
    # Symbolic execution proof (if verified)
    symbolically_verified: bool = False
    exploit_proof: Optional[Dict[str, Any]] = None
    attack_vector: Optional[Dict[str, Any]] = None
    missing_check: Optional[str] = None
    
    # Additional context
    description: Optional[str] = None
    cwe_id: Optional[str] = None
    tool_name: Optional[str] = None
    method_name: Optional[str] = None
    class_name: Optional[str] = None
    surrounding_context: Optional[str] = None
    
    def __post_init__(self):
        if self.intermediate_steps is None:
            self.intermediate_steps = []
        if self.security_annotations is None:
            self.security_annotations = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    @classmethod
    def from_semantic_finding(
        cls,
        finding: Dict[str, Any],
        file_content: str = None,
        surrounding_context: str = None
    ) -> 'EnhancedPatchContext':
        """
        Create context from semantic analysis finding
        
        Args:
            finding: Vulnerability finding from semantic analyzer
            file_content: Optional full file content
            surrounding_context: Optional surrounding code
            
        Returns:
            EnhancedPatchContext instance
        """
        # Extract basic info
        vuln_type = finding.get('vulnerability_type', 'unknown')
        sink_loc = finding.get('sink_location', {})
        file_path = sink_loc.get('file_path', '')
        line_number = sink_loc.get('start_line', 0)
        
        # Get vulnerable code (from sink or source)
        vulnerable_code = finding.get('sink', '')
        if not vulnerable_code:
            vulnerable_code = finding.get('source', '')
        
        # Security context
        sec_ctx = finding.get('security_context', {})
        
        # Symbolic verification
        exploit_proof = finding.get('exploit_proof')
        symbolically_verified = finding.get('symbolically_verified', False)
        
        return cls(
            vulnerability_type=vuln_type,
            file_path=file_path,
            line_number=line_number,
            vulnerable_code=vulnerable_code,
            severity=finding.get('severity', 'medium'),
            confidence=finding.get('confidence', 0.5),
            
            # Semantic data
            data_flow_path={
                'source': finding.get('source'),
                'sink': finding.get('sink'),
                'path': finding.get('path', [])
            },
            source_location=finding.get('source_location'),
            sink_location=sink_loc,
            intermediate_steps=finding.get('path', []),
            
            # Security context
            security_context=sec_ctx,
            authentication_present=sec_ctx.get('authentication_present', False),
            authorization_present=sec_ctx.get('authorization_present', False),
            security_annotations=sec_ctx.get('security_annotations', []),
            framework=sec_ctx.get('framework', 'unknown'),
            
            # Symbolic verification
            symbolically_verified=symbolically_verified,
            exploit_proof=exploit_proof,
            attack_vector=exploit_proof.get('attack_vector') if exploit_proof else None,
            missing_check=exploit_proof.get('missing_check') if exploit_proof else None,
            
            # Additional
            description=finding.get('message', ''),
            surrounding_context=surrounding_context
        )


class SemanticContextBuilder:
    """
    Builds rich context for patch generation by combining multiple analysis sources
    """
    
    def __init__(self, repo_path: str = "."):
        """
        Initialize context builder
        
        Args:
            repo_path: Path to repository root
        """
        self.repo_path = Path(repo_path)
    
    def build_context(
        self,
        semantic_finding: Dict[str, Any],
        include_file_content: bool = True,
        context_lines: int = 20
    ) -> EnhancedPatchContext:
        """
        Build complete context from semantic analysis finding
        
        Args:
            semantic_finding: Finding from semantic analyzer with symbolic verification
            include_file_content: Whether to read and include file content
            context_lines: Number of lines before/after to include as context
            
        Returns:
            EnhancedPatchContext with all available information
        """
        # Get file path
        sink_loc = semantic_finding.get('sink_location', {})
        file_path = sink_loc.get('file_path', '')
        line_number = sink_loc.get('start_line', 0)
        
        # Read file content if requested
        surrounding_context = None
        if include_file_content:
            surrounding_context = self._read_surrounding_context(
                file_path, line_number, context_lines
            )
        
        # Create enhanced context
        context = EnhancedPatchContext.from_semantic_finding(
            semantic_finding,
            surrounding_context=surrounding_context
        )
        
        # Extract method/class info from Java
        if file_path.endswith('.java'):
            method_info = self._extract_java_method_info(file_path, line_number)
            context.method_name = method_info.get('method_name')
            context.class_name = method_info.get('class_name')
        
        return context
    
    def _read_surrounding_context(
        self,
        file_path: str,
        line_number: int,
        context_lines: int = 20
    ) -> Optional[str]:
        """
        Read surrounding code context from file
        
        Args:
            file_path: Path to source file
            line_number: Line number of vulnerability
            context_lines: Lines before/after to include
            
        Returns:
            Surrounding code as string
        """
        full_path = self.repo_path / file_path
        
        if not full_path.exists():
            return None
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            # Add line numbers for context
            context_lines_with_numbers = []
            for i in range(start, end):
                prefix = ">>> " if i == line_number - 1 else "    "
                context_lines_with_numbers.append(f"{prefix}{i+1:4d} | {lines[i]}")
            
            return ''.join(context_lines_with_numbers)
        
        except Exception as e:
            print(f"Error reading context from {file_path}: {e}")
            return None
    
    def _extract_java_method_info(
        self,
        file_path: str,
        line_number: int
    ) -> Dict[str, str]:
        """
        Extract method and class information from Java file
        
        Args:
            file_path: Path to Java file
            line_number: Line number
            
        Returns:
            Dict with method_name and class_name
        """
        full_path = self.repo_path / file_path
        
        if not full_path.exists():
            return {}
        
        if not JAVALANG_AVAILABLE:
            return {}
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = javalang.parse.parse(content)
            
            # Find class and method containing the line
            class_name = None
            method_name = None
            
            for path, node in tree.filter(javalang.tree.ClassDeclaration):
                if hasattr(node, 'position') and node.position:
                    class_name = node.name
                    
                    # Find method in this class
                    for method in node.methods:
                        if hasattr(method, 'position') and method.position:
                            if method.position.line <= line_number:
                                method_name = method.name
            
            return {
                'class_name': class_name,
                'method_name': method_name
            }
        
        except Exception as e:
            print(f"Error extracting Java method info: {e}")
            return {}
    
    def format_for_llm_prompt(self, context: EnhancedPatchContext) -> str:
        """
        Format enhanced context as a structured prompt for LLM
        
        Args:
            context: Enhanced patch context
            
        Returns:
            Formatted prompt string
        """
        prompt_parts = []
        
        # Basic vulnerability info
        prompt_parts.append(f"## Vulnerability Analysis")
        prompt_parts.append(f"Type: {context.vulnerability_type.upper()}")
        prompt_parts.append(f"Severity: {context.severity}")
        prompt_parts.append(f"Confidence: {context.confidence * 100:.1f}%")
        prompt_parts.append(f"File: {context.file_path}:{context.line_number}")
        
        if context.description:
            prompt_parts.append(f"\nDescription: {context.description}")
        
        # Data flow information (from CodeQL)
        if context.data_flow_path:
            prompt_parts.append(f"\n## Data Flow Analysis (CodeQL)")
            prompt_parts.append(f"Source: {context.data_flow_path.get('source')}")
            prompt_parts.append(f"Sink: {context.data_flow_path.get('sink')}")
            
            if context.intermediate_steps:
                prompt_parts.append(f"\nData Flow Path:")
                for i, step in enumerate(context.intermediate_steps, 1):
                    prompt_parts.append(f"  {i}. {step}")
        
        # Security context
        if context.framework or context.security_context:
            prompt_parts.append(f"\n## Security Context")
            if context.framework:
                prompt_parts.append(f"Framework: {context.framework}")
            if context.authentication_present is not None:
                prompt_parts.append(f"Authentication Present: {context.authentication_present}")
            if context.authorization_present is not None:
                prompt_parts.append(f"Authorization Present: {context.authorization_present}")
            
            if context.security_annotations:
                prompt_parts.append(f"Security Annotations: {', '.join(context.security_annotations)}")
        
        # Symbolic execution proof (the key insight!)
        if context.symbolically_verified and context.exploit_proof:
            prompt_parts.append(f"\n## Symbolic Execution Proof")
            prompt_parts.append(f"Exploitability: CONFIRMED")
            
            if context.attack_vector:
                prompt_parts.append(f"\nAttack Vector:")
                for key, value in context.attack_vector.items():
                    prompt_parts.append(f"  {key}: {value}")
            
            if context.missing_check:
                prompt_parts.append(f"\nRoot Cause: {context.missing_check}")
            
            proof_desc = context.exploit_proof.get('proof', '')
            if proof_desc:
                prompt_parts.append(f"\nProof Details:")
                prompt_parts.append(f"{proof_desc}")
        
        # Code context
        if context.surrounding_context:
            prompt_parts.append(f"\n## Code Context")
            prompt_parts.append(f"```java")
            prompt_parts.append(context.surrounding_context)
            prompt_parts.append(f"```")
        
        # Method/class info
        if context.method_name or context.class_name:
            prompt_parts.append(f"\n## Code Structure")
            if context.class_name:
                prompt_parts.append(f"Class: {context.class_name}")
            if context.method_name:
                prompt_parts.append(f"Method: {context.method_name}")
        
        return '\n'.join(prompt_parts)


def create_context_from_analysis_results(
    results: Dict[str, Any],
    repo_path: str = "."
) -> List[EnhancedPatchContext]:
    """
    Create patch contexts from full analysis results
    
    Args:
        results: Complete results from semantic analyzer
        repo_path: Repository root path
        
    Returns:
        List of EnhancedPatchContext objects (one per verified vulnerability)
    """
    builder = SemanticContextBuilder(repo_path)
    contexts = []
    
    vulnerabilities = results.get('vulnerabilities', [])
    
    for vuln in vulnerabilities:
        # Only process symbolically verified findings for high-quality patches
        if vuln.get('symbolically_verified', False):
            context = builder.build_context(vuln)
            contexts.append(context)
    
    return contexts
