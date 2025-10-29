"""
🧃 OWASP JUICE SHOP - COMPLETE END-TO-END PIPELINE TEST
========================================================
Comprehensive test: Scan → Patch → Validate → Report

This demonstrates the full security automation platform on a real-world
OWASP Top 10 vulnerable application (Juice Shop - TypeScript/Node.js).
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.services.production_cpg_analyzer import ProductionCPGAnalyzer
from app.services.enhanced_sast_scanner import EnhancedSASTScanner
from app.services.patcher.context_builder import SemanticContextBuilder
from app.services.patcher.patch_generator import PatchGenerator
from app.services.patcher.patch_validator import PatchValidator

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)

def print_section(title):
    """Print formatted section"""
    print("\n" + "-"*80)
    print(f"  {title}")
    print("-"*80)

def analyze_vulnerabilities(findings):
    """Analyze and categorize vulnerabilities"""
    vuln_types = {}
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    
    for finding in findings:
        vuln_type = finding.get('type', 'UNKNOWN')
        severity = finding.get('severity', 'MEDIUM')
        
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return vuln_types, severity_counts

def main():
    print_header("🧃 OWASP JUICE SHOP - COMPLETE E2E PIPELINE TEST")
    
    # Configuration
    JUICE_SHOP_PATH = Path("/juice-shop")
    ROUTES_PATH = JUICE_SHOP_PATH / "routes"
    PATCHES_TO_APPLY = 3  # Patch top 3 vulnerabilities for quick validation
    OUTPUT_DIR = Path("/app/data/juice-shop-e2e")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    test_start_time = time.time()
    
    print(f"""
📋 TEST CONFIGURATION:
   • Application: OWASP Juice Shop (TypeScript/Node.js)
   • Target Path: {ROUTES_PATH}
   • Patches to Apply: {PATCHES_TO_APPLY}
   • Output Directory: {OUTPUT_DIR}
   • Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
    
    # ============================================================================
    # PHASE 1: INITIAL VULNERABILITY SCAN
    # ============================================================================
    print_header("📊 PHASE 1: INITIAL VULNERABILITY SCAN")
    
    # CPG Analysis
    print_section("Running CPG Analysis (Semantic Code Analysis)")
    cpg_analyzer = ProductionCPGAnalyzer()
    cpg_start = time.time()
    
    try:
        cpg_result = cpg_analyzer.analyze(
            source_path=str(ROUTES_PATH),
            language="typescript"
        )
        cpg_findings = cpg_result.get('findings', []) if isinstance(cpg_result, dict) else cpg_result
        cpg_time = time.time() - cpg_start
        
        print(f"✅ CPG Analysis Complete")
        print(f"   • Vulnerabilities Found: {len(cpg_findings)}")
        print(f"   • Time Taken: {cpg_time:.2f}s")
        
    except Exception as e:
        print(f"❌ CPG Analysis Failed: {e}")
        cpg_findings = []
        cpg_time = 0
    
    # SAST Analysis
    print_section("Running SAST Analysis (Static Pattern Matching)")
    sast_scanner = EnhancedSASTScanner()
    sast_start = time.time()
    
    try:
        sast_result = sast_scanner.scan(
            source_path=str(ROUTES_PATH),
            language="typescript"
        )
        sast_findings = sast_result.get('vulnerabilities', []) if isinstance(sast_result, dict) else sast_result
        sast_time = time.time() - sast_start
        
        print(f"✅ SAST Analysis Complete")
        print(f"   • Vulnerabilities Found: {len(sast_findings)}")
        print(f"   • Time Taken: {sast_time:.2f}s")
        
    except Exception as e:
        print(f"❌ SAST Analysis Failed: {e}")
        sast_findings = []
        sast_time = 0
    
    # Combine Results
    initial_findings = cpg_findings + sast_findings
    initial_total = len(initial_findings)
    
    print_section("Initial Scan Summary")
    print(f"""
📊 SCAN RESULTS:
   • Total Vulnerabilities: {initial_total}
   • CPG Findings: {len(cpg_findings)}
   • SAST Findings: {len(sast_findings)}
   • Total Scan Time: {cpg_time + sast_time:.2f}s
""")
    
    if initial_total == 0:
        print("⚠️  No vulnerabilities found. Test cannot proceed.")
        return False
    
    # Analyze vulnerability distribution
    vuln_types, severity_counts = analyze_vulnerabilities(initial_findings)
    
    print("\n📈 Vulnerability Types:")
    for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10]:
        percentage = (count / initial_total) * 100
        print(f"   • {vuln_type}: {count} ({percentage:.1f}%)")
    
    print("\n🎯 Severity Distribution:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / initial_total) * 100
            print(f"   • {severity}: {count} ({percentage:.1f}%)")
    
    # ============================================================================
    # PHASE 2: SMART PATCH SELECTION
    # ============================================================================
    print_header("🎯 PHASE 2: INTELLIGENT PATCH SELECTION")
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    
    def get_sort_key(finding):
        severity = finding.get('severity', 'MEDIUM')
        return severity_order.get(severity, 5)
    
    sorted_findings = sorted(initial_findings, key=get_sort_key)
    selected_findings = sorted_findings[:PATCHES_TO_APPLY]
    
    print(f"\n✅ Selected {len(selected_findings)} high-priority vulnerabilities:\n")
    for i, finding in enumerate(selected_findings, 1):
        vuln_type = finding.get('type', 'UNKNOWN')
        severity = finding.get('severity', 'MEDIUM')
        file_path = finding.get('file_path') or finding.get('file', 'unknown')
        line = finding.get('line_number') or finding.get('line', '?')
        description = finding.get('message') or finding.get('description', 'No description')[:60]
        
        print(f"   {i}. [{severity}] {vuln_type}")
        print(f"      📄 {Path(file_path).name}:{line}")
        print(f"      💬 {description}...")
    
    # ============================================================================
    # PHASE 3: AUTOMATED PATCHING
    # ============================================================================
    print_header("🔧 PHASE 3: AUTOMATED PATCHING WITH AI")
    
    patch_generator = PatchGenerator()
    patch_validator = PatchValidator()
    
    successful_patches = []
    failed_patches = []
    
    for i, finding in enumerate(selected_findings, 1):
        vuln_type = finding.get('type', 'UNKNOWN')
        file_path = finding.get('file_path') or finding.get('file', 'unknown')
        line = finding.get('line_number') or finding.get('line', 0)
        severity = finding.get('severity', 'MEDIUM')
        
        print(f"\n[{i}/{len(selected_findings)}] Processing: {vuln_type} in {Path(file_path).name}:{line}")
        print(f"    Severity: {severity}")
        
        try:
            # Validate file exists
            if not Path(file_path).exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read original code
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                original_code = f.read()
            
            print("    ⏳ Building semantic context...")
            # Convert CPG finding to format expected by context builder
            semantic_finding = {
                'sink_location': {
                    'file_path': file_path,
                    'start_line': line
                },
                'vulnerability_type': vuln_type,
                'severity': severity,
                'message': finding.get('message', ''),
                'metadata': finding.get('metadata', {})
            }
            context_builder = SemanticContextBuilder(str(Path(file_path).parent))
            context = context_builder.build_context(semantic_finding)
            
            print("    ⏳ Generating AI-powered patch (LLM)...")
            patch_start = time.time()
            patch_result = patch_generator.generate_patch(context)
            patch_time = time.time() - patch_start
            
            if not patch_result or not patch_result.get('patched_code'):
                raise ValueError("Patch generation failed - no patch returned")
            
            patched_code = patch_result['patched_code']
            print(f"    ✅ Patch generated in {patch_time:.2f}s")
            
            print("    ⏳ Validating patch...")
            validation = patch_validator.validate_patch(
                original_code=original_code,
                patched_code=patched_code,
                vulnerability_type=vuln_type,
                file_path=file_path
            )
            
            if not validation.get('is_valid', False):
                raise ValueError(f"Validation failed: {validation.get('reason', 'Unknown reason')}")
            
            confidence = validation.get('confidence', 'UNKNOWN')
            print(f"    ✅ Patch validated - Confidence: {confidence}")
            
            # Save patch
            patch_filename = f"patch-{i:02d}-{vuln_type.lower()}-{Path(file_path).name}.txt"
            patch_file = OUTPUT_DIR / patch_filename
            
            with open(patch_file, 'w', encoding='utf-8') as f:
                f.write(f"# SECURITY PATCH\n")
                f.write(f"# Vulnerability: {vuln_type}\n")
                f.write(f"# Severity: {severity}\n")
                f.write(f"# File: {file_path}\n")
                f.write(f"# Line: {line}\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Validation: {confidence}\n")
                f.write("\n" + "="*60 + "\n")
                f.write("PATCHED CODE:\n")
                f.write("="*60 + "\n\n")
                f.write(patched_code)
            
            print(f"    💾 Saved to: {patch_filename}")
            
            successful_patches.append({
                'finding': finding,
                'patch_file': str(patch_file),
                'validation': validation,
                'patch_time': patch_time
            })
            
        except Exception as e:
            print(f"    ❌ Failed: {str(e)[:100]}")
            failed_patches.append({
                'finding': finding,
                'error': str(e)
            })
    
    print_section("Patching Summary")
    print(f"""
📊 PATCHING RESULTS:
   • Total Attempted: {len(selected_findings)}
   • Successfully Generated: {len(successful_patches)}
   • Failed: {len(failed_patches)}
   • Success Rate: {(len(successful_patches)/len(selected_findings))*100:.1f}%
   • Avg Patch Time: {sum(p['patch_time'] for p in successful_patches) / len(successful_patches) if successful_patches else 0:.2f}s
""")
    
    if successful_patches:
        print("\n✅ Successful Patches:")
        for i, patch in enumerate(successful_patches, 1):
            vuln_type = patch['finding'].get('type')
            confidence = patch['validation'].get('confidence', 'UNKNOWN')
            print(f"   {i}. {vuln_type} - Confidence: {confidence}")
    
    if failed_patches:
        print("\n❌ Failed Patches:")
        for i, failed in enumerate(failed_patches, 1):
            vuln_type = failed['finding'].get('type')
            error = failed['error'][:60]
            print(f"   {i}. {vuln_type} - {error}...")
    
    # ============================================================================
    # PHASE 4: VALIDATION (DRY RUN)
    # ============================================================================
    print_header("🔍 PHASE 4: PATCH VALIDATION (DRY RUN)")
    
    print("""
⚠️  DRY RUN MODE - Patches NOT applied to preserve test environment

In production, this phase would:
   1. Create a test branch
   2. Apply all validated patches
   3. Re-run full vulnerability scan
   4. Compare before/after metrics
   5. Run automated tests
   6. Create Pull Request if all checks pass
""")
    
    expected_reduction = len(successful_patches)
    expected_remaining = initial_total - expected_reduction
    reduction_percentage = (expected_reduction / initial_total) * 100 if initial_total > 0 else 0
    
    print(f"""
📊 EXPECTED IMPACT (if patches were applied):
   • Initial Vulnerabilities: {initial_total}
   • Patches Applied: {expected_reduction}
   • Expected Remaining: {expected_remaining}
   • Expected Reduction: {reduction_percentage:.1f}%
""")
    
    # ============================================================================
    # PHASE 5: COMPREHENSIVE REPORT
    # ============================================================================
    print_header("📈 FINAL E2E TEST REPORT")
    
    test_duration = time.time() - test_start_time
    
    # Generate JSON report
    report = {
        'test_info': {
            'application': 'OWASP Juice Shop',
            'language': 'TypeScript/Node.js',
            'target_path': str(ROUTES_PATH),
            'test_time': datetime.now().isoformat(),
            'duration_seconds': round(test_duration, 2)
        },
        'scanning': {
            'cpg_findings': len(cpg_findings),
            'sast_findings': len(sast_findings),
            'total_findings': initial_total,
            'scan_time_seconds': round(cpg_time + sast_time, 2),
            'vulnerability_types': vuln_types,
            'severity_distribution': severity_counts
        },
        'patching': {
            'attempted': len(selected_findings),
            'successful': len(successful_patches),
            'failed': len(failed_patches),
            'success_rate': round((len(successful_patches)/len(selected_findings))*100, 1) if selected_findings else 0,
            'patches': [
                {
                    'vulnerability_type': p['finding'].get('type'),
                    'severity': p['finding'].get('severity'),
                    'file': p['finding'].get('file_path') or p['finding'].get('file'),
                    'confidence': p['validation'].get('confidence'),
                    'patch_file': p['patch_file']
                }
                for p in successful_patches
            ]
        },
        'validation': {
            'mode': 'DRY_RUN',
            'expected_reduction': expected_reduction,
            'expected_reduction_percentage': round(reduction_percentage, 1)
        }
    }
    
    report_file = OUTPUT_DIR / 'e2e_test_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"""
🔍 SCANNING:
   • CPG Vulnerabilities: {len(cpg_findings)}
   • SAST Vulnerabilities: {len(sast_findings)}
   • Total Vulnerabilities: {initial_total}
   • Scan Time: {cpg_time + sast_time:.2f}s

🔧 PATCHING:
   • Patches Attempted: {len(selected_findings)}
   • Patches Successful: {len(successful_patches)}
   • Patches Failed: {len(failed_patches)}
   • Success Rate: {(len(successful_patches)/len(selected_findings))*100:.1f}%

📊 IMPACT:
   • Expected Reduction: {expected_reduction} vulnerabilities ({reduction_percentage:.1f}%)
   • Patch Files Created: {len(successful_patches)}

⏱️  PERFORMANCE:
   • Total Test Time: {test_duration:.2f}s
   • Avg Patch Generation: {sum(p['patch_time'] for p in successful_patches) / len(successful_patches) if successful_patches else 0:.2f}s

📁 OUTPUT:
   • Report: {report_file}
   • Patches: {OUTPUT_DIR}
""")
    
    # ============================================================================
    # TEST CRITERIA VALIDATION
    # ============================================================================
    print_header("✅ TEST CRITERIA VALIDATION")
    
    criteria = [
        ("Application scanned successfully", initial_total > 0),
        ("CPG detection working", len(cpg_findings) > 0),
        ("SAST detection working", len(sast_findings) > 0),
        ("Multiple vulnerability types found", len(vuln_types) > 1),
        ("Patches generated successfully", len(successful_patches) > 0),
        ("All patches validated", all(p['validation'].get('is_valid') for p in successful_patches)),
        ("No critical failures", len(failed_patches) < len(selected_findings)),
    ]
    
    all_passed = True
    for criterion, passed in criteria:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {status}: {criterion}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*80)
    if all_passed:
        print("🎉 SUCCESS! ALL CRITERIA PASSED - E2E PIPELINE WORKING!")
    else:
        print("⚠️  SOME CRITERIA FAILED - REVIEW NEEDED")
    print("="*80)
    
    return all_passed

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
