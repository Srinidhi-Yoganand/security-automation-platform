"""
Patch Application Service - Applies unified diff patches to source files
"""

import re
import os
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class PatchApplier:
    """Applies unified diff patches to source files"""
    
    def __init__(self):
        pass
    
    def apply_patch(self, file_path: str, patch_content: str) -> Tuple[bool, str]:
        """
        Apply a unified diff patch to a file
        
        Args:
            file_path: Absolute path to the file to patch
            patch_content: The unified diff patch content
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Read original file
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"
                
            with open(file_path, 'r', encoding='utf-8') as f:
                original_lines = f.readlines()
            
            # Parse the patch
            patched_lines, error_msg = self._apply_unified_diff(original_lines, patch_content)
            
            if patched_lines is None:
                return False, error_msg
            
            # Write patched file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(patched_lines)
            
            logger.info(f"Successfully applied patch to {file_path}")
            return True, f"Patch applied successfully"
            
        except Exception as e:
            logger.error(f"Error applying patch to {file_path}: {str(e)}")
            return False, f"Error applying patch: {str(e)}"
    
    def _apply_unified_diff(self, original_lines: list, patch_content: str) -> Tuple[Optional[list], str]:
        """
        Parse and apply a unified diff patch
        
        Args:
            original_lines: List of original file lines
            patch_content: Unified diff patch content
            
        Returns:
            Tuple of (patched_lines or None, error_message)
        """
        try:
            # Parse hunks from the patch
            hunks = self._parse_hunks(patch_content)
            
            if not hunks:
                return None, "No valid hunks found in patch"
            
            # Apply hunks in reverse order to maintain line numbers
            result_lines = original_lines.copy()
            
            for hunk in sorted(hunks, key=lambda h: h['start'], reverse=True):
                result_lines = self._apply_hunk(result_lines, hunk)
                if result_lines is None:
                    return None, f"Failed to apply hunk at line {hunk['start']}"
            
            return result_lines, ""
            
        except Exception as e:
            return None, f"Error parsing patch: {str(e)}"
    
    def _parse_hunks(self, patch_content: str) -> list:
        """
        Parse unified diff format into hunks
        
        Returns:
            List of hunk dictionaries with 'start', 'count', 'remove_lines', 'add_lines'
        """
        hunks = []
        current_hunk = None
        
        lines = patch_content.split('\n')
        
        for line in lines:
            # Match hunk header: @@ -start,count +start,count @@
            hunk_match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
            
            if hunk_match:
                # Save previous hunk
                if current_hunk:
                    hunks.append(current_hunk)
                
                # Start new hunk
                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                
                current_hunk = {
                    'start': old_start,
                    'count': old_count,
                    'remove_lines': [],
                    'add_lines': []
                }
                
            elif current_hunk is not None:
                # Lines starting with '-' are removed
                if line.startswith('-') and not line.startswith('---'):
                    current_hunk['remove_lines'].append(line[1:])
                
                # Lines starting with '+' are added
                elif line.startswith('+') and not line.startswith('+++'):
                    current_hunk['add_lines'].append(line[1:])
        
        # Save last hunk
        if current_hunk:
            hunks.append(current_hunk)
        
        return hunks
    
    def _apply_hunk(self, lines: list, hunk: dict) -> Optional[list]:
        """
        Apply a single hunk to the file lines
        
        Args:
            lines: Current file lines
            hunk: Hunk dictionary with start, count, remove_lines, add_lines
            
        Returns:
            Modified lines or None on failure
        """
        try:
            start_idx = hunk['start'] - 1  # Convert to 0-based index
            
            # Verify we can remove the expected lines
            if start_idx < 0 or start_idx >= len(lines):
                logger.warning(f"Hunk start line {hunk['start']} out of range")
                # Still try to apply if possible
                start_idx = max(0, min(start_idx, len(lines) - 1))
            
            # Remove old lines
            result = lines[:start_idx]
            
            # Add new lines
            for new_line in hunk['add_lines']:
                result.append(new_line + '\n' if not new_line.endswith('\n') else new_line)
            
            # Add remaining lines after the removed section
            end_idx = start_idx + hunk['count']
            result.extend(lines[end_idx:])
            
            return result
            
        except Exception as e:
            logger.error(f"Error applying hunk: {str(e)}")
            return None
    
    def apply_simple_patch(self, file_path: str, patch_content: str, 
                          start_line: int, end_line: int) -> Tuple[bool, str]:
        """
        Apply a simple replacement patch (no unified diff format)
        
        Args:
            file_path: Path to file
            patch_content: New code to insert
            start_line: Line number to start replacement (1-based)
            end_line: Line number to end replacement (1-based, inclusive)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File not found: {file_path}"
            
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Validate line numbers
            if start_line < 1 or end_line > len(lines) or start_line > end_line:
                return False, f"Invalid line range: {start_line}-{end_line}"
            
            # Replace lines
            new_content_lines = [line + '\n' if not line.endswith('\n') else line 
                                for line in patch_content.split('\n')]
            
            result = lines[:start_line - 1] + new_content_lines + lines[end_line:]
            
            # Write back
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(result)
            
            logger.info(f"Applied simple patch to {file_path} (lines {start_line}-{end_line})")
            return True, "Patch applied successfully"
            
        except Exception as e:
            logger.error(f"Error applying simple patch: {str(e)}")
            return False, f"Error: {str(e)}"
