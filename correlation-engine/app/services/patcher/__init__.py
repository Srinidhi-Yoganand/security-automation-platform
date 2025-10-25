"""
Automated Security Patch Generator Package
"""

from .patch_generator import (
    PatchGenerator,
    PatchContext,
    GeneratedPatch
)

from .llm_patch_generator import (
    LLMPatchGenerator,
    PatchStatus
)

__all__ = [
    'PatchGenerator',  # Template-based (fallback)
    'LLMPatchGenerator',  # LLM-powered (primary)
    'PatchContext',
    'GeneratedPatch',
    'PatchStatus'
]
__all__ = ['PatchGenerator', 'PatchContext', 'GeneratedPatch']
