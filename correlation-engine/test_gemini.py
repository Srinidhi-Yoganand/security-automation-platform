"""
Test REAL Gemini-Powered Patch Generation
"""
from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext

print('Testing REAL Gemini-Powered Patch Generation')
print('='*70)
print('')

gen = LLMPatchGenerator('../vulnerable-app')
print('')

ctx = PatchContext(
    'SQL Injection',
    'src/main/java/com/security/automation/controller/UserController.java',
    45,
    'String query = "SELECT * FROM users WHERE id=" + userId;',
    'high',
    0.9,
    'SQL injection via string concatenation',
    'CWE-89',
    'CodeQL'
)

print('Generating patch with Gemini AI...')
patch = gen.generate_patch(ctx, test_patch=False)

if patch:
    print('')
    print('='*70)
    print('[SUCCESS] GEMINI-POWERED PATCH GENERATED!')
    print('='*70)
    print('')
    print('FIXED CODE:')
    print('-'*70)
    print(patch.fixed_code)
    print('-'*70)
    print('')
    print('EXPLANATION:')
    print('-'*70)
    print(patch.explanation)
    print('-'*70)
    print('')
    print(f'Confidence: {patch.confidence}')
    print(f'Provider: {gen.llm_provider}')
    print(f'Status: {patch.status.value}')
    print('')
    print('='*70)
    print('[RESULT] LLM-powered patching is WORKING!')
    print('='*70)
else:
    print('[FAILED]')
