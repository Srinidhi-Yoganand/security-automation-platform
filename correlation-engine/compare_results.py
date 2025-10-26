#!/usr/bin/env python3
"""Compare security scan results before and after patching"""
import json
import os
import sys

def main():
    try:
        # Load before results
        with open('scan-results-before/semgrep-results.sarif', 'r') as f:
            before = json.load(f)
            
        # Load after results
        with open('scan-results-after.sarif', 'r') as f:
            after = json.load(f)

        before_count = len(before.get('runs', [{}])[0].get('results', []))
        after_count = len(after.get('runs', [{}])[0].get('results', []))

        improvement = before_count - after_count
        percentage = (improvement / before_count * 100) if before_count > 0 else 0

        print(f'Before: {before_count} vulnerabilities')
        print(f'After: {after_count} vulnerabilities')
        print(f'Improvement: {improvement} ({percentage:.1f}%)')

        # Save for GitHub Actions output
        if 'GITHUB_OUTPUT' in os.environ:
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write(f'before_count={before_count}\n')
                f.write(f'after_count={after_count}\n')
                f.write(f'improvement={improvement}\n')
                f.write(f'percentage={percentage:.1f}\n')
    except Exception as e:
        print(f'Error comparing results: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
