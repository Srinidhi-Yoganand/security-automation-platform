#!/usr/bin/env python3
"""Generate AI patches from security scan results"""
import json
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.patcher.llm_patch_generator import LLMPatchGenerator
from app.core.parsers.semgrep_parser import SemgrepParser

def main():
    # Parse scan results
    parser = SemgrepParser()
    with open('../../scan-results/semgrep-results.sarif', 'r') as f:
        scan_data = json.load(f)

    vulnerabilities = parser.parse(scan_data)
    print(f'Found {len(vulnerabilities)} vulnerabilities')

    # Generate patches for high/critical vulnerabilities
    generator = LLMPatchGenerator()
    patches = []

    for vuln in vulnerabilities:
        if vuln.get('severity') in ['HIGH', 'CRITICAL']:
            try:
                # Read the vulnerable file
                file_path = os.path.join('../../target-app', vuln.get('file', ''))
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        code_snippet = f.read()
                        
                    patch = generator.generate_patch(
                        vuln_id=vuln.get('id', 'unknown'),
                        vuln_type=vuln.get('type', 'unknown'),
                        file_path=vuln.get('file', ''),
                        line_number=vuln.get('line', 0),
                        code_snippet=code_snippet,
                        description=vuln.get('description', '')
                    )
                    patches.append(patch)
                    print(f'Generated patch for {vuln.get("type")} in {vuln.get("file")}')
            except Exception as e:
                print(f'Failed to generate patch for {vuln.get("id")}: {e}')

    # Save patches
    with open('../../patches.json', 'w') as f:
        json.dump(patches, f, indent=2)

    print(f'\nGenerated {len(patches)} patches successfully')

if __name__ == '__main__':
    main()
