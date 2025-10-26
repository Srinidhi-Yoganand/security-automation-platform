#!/usr/bin/env python3
"""Apply patches to target files"""
import json
import os
from pathlib import Path

def main():
    with open('patches.json', 'r') as f:
        patches = json.load(f)

    applied = 0
    failed = 0

    for patch in patches:
        try:
            file_path = patch.get('file_path', '')
            patched_code = patch.get('patched_code', '')
            
            if file_path and patched_code:
                # Write patched code to file
                with open(file_path, 'w') as f:
                    f.write(patched_code)
                applied += 1
                print(f'✅ Applied patch to {file_path}')
        except Exception as e:
            failed += 1
            print(f'❌ Failed to apply patch to {file_path}: {e}')

    print(f'\nApplied: {applied}, Failed: {failed}')

if __name__ == '__main__':
    main()
