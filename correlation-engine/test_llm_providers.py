"""
Test LLM Patch Generation with Multiple Providers
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext


def show_setup_instructions():
    """Show how to set up different LLM providers"""
    print("="*80)
    print("LLM PROVIDER SETUP INSTRUCTIONS")
    print("="*80)
    print()
    
    print("Option 1: Google Gemini (FREE - RECOMMENDED)")
    print("-" * 80)
    print("1. Get API key: https://makersuite.google.com/app/apikey")
    print("2. Set environment variable:")
    print("   export GEMINI_API_KEY='your-key-here'")
    print("3. Run test")
    print()
    print("Free tier: 60 requests/minute, 1500/day")
    print()
    
    print("Option 2: Ollama (FREE - LOCAL)")
    print("-" * 80)
    print("1. Install Ollama: https://ollama.ai/download")
    print("2. Start server: ollama serve")
    print("3. Pull model: ollama pull codellama")
    print("4. Run test")
    print()
    print("Runs on your computer - completely private")
    print()
    
    print("Option 3: OpenAI (PAID)")
    print("-" * 80)
    print("1. Get API key: https://platform.openai.com/api-keys")
    print("2. Set environment variable:")
    print("   export OPENAI_API_KEY='sk-...'")
    print("3. Run test")
    print()
    print("Cost: ~$0.05 per patch with GPT-4")
    print()
    
    print("Option 4: Template-based (NO LLM)")
    print("-" * 80)
    print("Falls back automatically if no LLM available")
    print("Works for common vulnerabilities (SQL Injection, etc.)")
    print()


def test_patch_with_provider(provider="auto"):
    """Test patch generation with specific provider"""
    
    print("="*80)
    print(f"TESTING WITH PROVIDER: {provider}")
    print("="*80)
    print()
    
    generator = LLMPatchGenerator(
        repo_path="../vulnerable-app",
        llm_provider=provider
    )
    
    print(f"Active provider: {generator.llm_provider}")
    print()
    
    context = PatchContext(
        vulnerability_type="SQL Injection",
        file_path="src/main/java/com/security/automation/controller/UserController.java",
        line_number=45,
        vulnerable_code='String query = "SELECT * FROM users WHERE username=\'" + username + "\'";',
        severity="high",
        confidence=0.95,
        description="User input directly concatenated into SQL query",
        cwe_id="CWE-89",
        tool_name="CodeQL"
    )
    
    print("Generating patch...")
    patch = generator.generate_patch(context, test_patch=False)
    
    if patch:
        print()
        print("[SUCCESS] Patch Generated!")
        print()
        print("-"*80)
        print("FIXED CODE:")
        print("-"*80)
        print(patch.fixed_code)
        print()
        print("-"*80)
        print("EXPLANATION:")
        print("-"*80)
        print(patch.explanation)
        print()
        print(f"Confidence: {patch.confidence}")
        print(f"Provider used: {generator.llm_provider}")
        print()
        return True
    else:
        print("[FAILED] Could not generate patch")
        return False


if __name__ == "__main__":
    # Show setup instructions
    show_setup_instructions()
    
    # Test with auto-detection
    print("="*80)
    print("AUTO-DETECTING BEST AVAILABLE LLM")
    print("="*80)
    print()
    
    success = test_patch_with_provider("auto")
    
    print()
    print("="*80)
    print(f"Result: {'PASS' if success else 'FAIL'}")
    print("="*80)
    print()
    
    # Show next steps
    if not success or not (os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")):
        print("NEXT STEPS:")
        print()
        print("For best results, set up Gemini (free):")
        print("  1. Visit: https://makersuite.google.com/app/apikey")
        print("  2. Click 'Create API Key'")
        print("  3. Copy the key")
        print("  4. export GEMINI_API_KEY='your-key-here'")
        print("  5. python test_llm_providers.py")
        print()
