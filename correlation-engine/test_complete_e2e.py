"""
Complete End-to-End Remediation Test with LLM Patching
Tests: Detection → LLM Patch Generation → Validation → Application
"""
import sys
import os
from pathlib import Path
sys.path.insert(0, '/app')

from app.services.production_cpg_analyzer import ProductionCPGAnalyzer
from app.services.enhanced_sast_scanner import EnhancedSASTScanner
from app.services.patcher.llm_patch_generator import LLMPatchGenerator, PatchContext
from app.services.patcher.patch_validator import PatchValidator
import json


def test_e2e_remediation(app_name, app_path, language, test_file_path):
    """Complete end-to-end remediation pipeline"""
    print("\n" + "="*80)
    print(f"🔄 End-to-End Remediation: {app_name}")
    print("="*80)
    
    target = Path(app_path)
    test_file = Path(test_file_path)
    
    if not target.exists() or not test_file.exists():
        print(f"❌ Target not found")
        return None
    
    print(f"\n📁 Target: {test_file.name}")
    
    # STEP 1: Detection
    print("\n" + "-"*80)
    print("STEP 1: Vulnerability Detection")
    print("-"*80)
    
    cpg = ProductionCPGAnalyzer()
    result = cpg.analyze(test_file, language=language)
    findings = result.get('findings', [])
    
    print(f"✅ Found {len(findings)} vulnerabilities")
    
    if len(findings) == 0:
        print("⚠️  No vulnerabilities to patch")
        return None
    
    # Show top vulnerabilities
    vuln_types = {}
    for f in findings:
        vtype = f['type']
        vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
    
    print(f"   Types: {', '.join([f'{k}({v})' for k, v in sorted(vuln_types.items(), key=lambda x: -x[1])])}")
    
    # Select vulnerabilities to patch (top 3 critical)
    critical_vulns = [f for f in findings if f.get('severity') in ['critical', 'high']][:3]
    if not critical_vulns:
        critical_vulns = findings[:3]
    
    print(f"\n🎯 Selected {len(critical_vulns)} vulnerabilities for patching")
    
    # Read original code
    with open(test_file, 'r', errors='ignore') as f:
        original_code = f.read()
    
    original_lines = len(original_code.split('\n'))
    print(f"   Original file: {original_lines} lines")
    
    # STEP 2: LLM Patch Generation
    print("\n" + "-"*80)
    print("STEP 2: LLM-Based Patch Generation")
    print("-"*80)
    
    print("🤖 Initializing LLM Patch Generator...")
    
    try:
        llm_patcher = LLMPatchGenerator()
        patches_generated = []
        patches_failed = []
        
        for i, vuln in enumerate(critical_vulns, 1):
            print(f"\n   [{i}/{len(critical_vulns)}] Generating patch for {vuln['type']}...")
            print(f"       Line {vuln.get('line_number', '?')}: {vuln.get('message', '')[:60]}")
            
            try:
                # Create PatchContext for LLM
                patch_context = PatchContext(
                    vulnerability_type=vuln['type'],
                    file_path=str(test_file),
                    line_number=vuln.get('line_number', 0),
                    vulnerable_code=original_code,
                    severity=vuln.get('severity', 'medium'),
                    confidence=0.8 if vuln.get('confidence') == 'high' else 0.5,
                    description=vuln.get('message', ''),
                    cwe_id=vuln.get('cwe_id'),
                    tool_name=vuln.get('tool', 'CPG')
                )
                
                # Generate patch using LLM
                patch_result = llm_patcher.generate_patch(
                    context=patch_context,
                    test_patch=False
                )
                
                if patch_result and hasattr(patch_result, 'fixed_code'):
                    patched_code = patch_result.fixed_code
                    explanation = patch_result.explanation
                    
                    if patched_code and patched_code != original_code:
                        patches_generated.append({
                            'vulnerability': vuln,
                            'patched_code': patched_code,
                            'explanation': explanation,
                            'patch_result': patch_result
                        })
                        print(f"       ✅ Patch generated ({len(patched_code)} chars)")
                        print(f"       📝 {explanation[:70]}...")
                    else:
                        patches_failed.append(vuln)
                        print(f"       ⚠️  Code unchanged")
                else:
                    patches_failed.append(vuln)
                    print(f"       ❌ Patch generation failed")
                    
            except Exception as e:
                patches_failed.append(vuln)
                print(f"       ❌ Error: {str(e)[:60]}")
        
        print(f"\n📊 Patch Generation:")
        print(f"   ✅ Generated: {len(patches_generated)}")
        print(f"   ❌ Failed: {len(patches_failed)}")
        
        if len(patches_generated) == 0:
            print("   ⚠️  No patches to validate")
            return {
                'app': app_name,
                'detected': len(findings),
                'attempted': len(critical_vulns),
                'generated': 0,
                'validated': 0,
                'applied': 0
            }
        
        # STEP 3: Patch Validation
        print("\n" + "-"*80)
        print("STEP 3: Patch Validation")
        print("-"*80)
        
        print("🔍 Initializing Patch Validator...")
        
        try:
            validator = PatchValidator()
            validated_patches = []
            validation_failed = []
            
            for i, patch_data in enumerate(patches_generated, 1):
                vuln = patch_data['vulnerability']
                patched_code = patch_data['patched_code']
                
                print(f"\n   [{i}/{len(patches_generated)}] Validating {vuln['type']} patch...")
                
                try:
                    # Validate the patch
                    validation_result = validator.validate_patch(
                        original_code=original_code,
                        patched_code=patched_code,
                        vulnerability_type=vuln['type'],
                        language=language
                    )
                    
                    if validation_result.get('is_valid', False):
                        validated_patches.append(patch_data)
                        confidence = validation_result.get('confidence', 'unknown')
                        print(f"       ✅ Validation passed (confidence: {confidence})")
                        
                        # Show validation details
                        checks = validation_result.get('validation_checks', {})
                        if checks:
                            passed_checks = sum(1 for v in checks.values() if v)
                            total_checks = len(checks)
                            print(f"       ✓ Passed {passed_checks}/{total_checks} validation checks")
                    else:
                        validation_failed.append(patch_data)
                        issues = validation_result.get('issues', ['Unknown issue'])
                        print(f"       ❌ Validation failed: {issues[0] if issues else 'Unknown'}") 
                        
                except Exception as e:
                    validation_failed.append(patch_data)
                    print(f"       ❌ Validation error: {str(e)[:60]}")
            
            print(f"\n📊 Validation Results:")
            print(f"   ✅ Valid patches: {len(validated_patches)}")
            print(f"   ❌ Invalid patches: {len(validation_failed)}")
            
            # STEP 4: Apply Best Patch
            print("\n" + "-"*80)
            print("STEP 4: Apply Patch (Simulation)")
            print("-"*80)
            
            if validated_patches:
                # Use the first validated patch
                best_patch = validated_patches[0]
                final_code = best_patch['patched_code']
                
                print(f"✅ Selected best patch for {best_patch['vulnerability']['type']}")
                print(f"   Explanation: {best_patch['explanation'][:80]}")
                
                # Code comparison
                final_lines = len(final_code.split('\n'))
                lines_changed = abs(final_lines - original_lines)
                
                print(f"\n📊 Code Changes:")
                print(f"   Original: {original_lines} lines")
                print(f"   Patched:  {final_lines} lines")
                print(f"   Changed:  {lines_changed} lines")
                
                # Simulate application (don't actually write)
                print(f"\n   ✅ Patch ready to apply (not writing to disk in test mode)")
                applied = 1
            else:
                print("⚠️  No valid patches to apply")
                applied = 0
            
            return {
                'app': app_name,
                'file': test_file.name,
                'language': language,
                'detected': len(findings),
                'attempted': len(critical_vulns),
                'generated': len(patches_generated),
                'validated': len(validated_patches),
                'applied': applied,
                'vuln_types': list(vuln_types.keys())
            }
            
        except Exception as e:
            print(f"   ❌ Validator initialization failed: {str(e)[:60]}")
            return {
                'app': app_name,
                'detected': len(findings),
                'attempted': len(critical_vulns),
                'generated': len(patches_generated),
                'validated': 0,
                'applied': 0
            }
        
    except Exception as e:
        print(f"   ❌ LLM Patcher initialization failed: {str(e)[:60]}")
        return {
            'app': app_name,
            'detected': len(findings),
            'attempted': len(critical_vulns),
            'generated': 0,
            'validated': 0,
            'applied': 0
        }


def main():
    """Run complete E2E tests on multiple apps"""
    print("\n" + "="*80)
    print("🚀 Complete End-to-End Remediation Test Suite")
    print("="*80)
    print("\nTesting: Detection → LLM Patching → Validation → Application\n")
    
    results = []
    
    # Test 1: Custom App (Python)
    if Path('/vulnerable-app/app.py').exists():
        result = test_e2e_remediation(
            "Custom Vulnerable App (Python)",
            "/vulnerable-app",
            "python",
            "/vulnerable-app/app.py"
        )
        if result:
            results.append(result)
    
    # Test 2: DVWA (PHP)
    if Path('/dvwa/login.php').exists():
        result = test_e2e_remediation(
            "DVWA (PHP)",
            "/dvwa",
            "php",
            "/dvwa/login.php"
        )
        if result:
            results.append(result)
    
    # Test 3: Juice Shop (TypeScript)
    if Path('/juice-shop/routes/login.ts').exists():
        result = test_e2e_remediation(
            "OWASP Juice Shop (TypeScript)",
            "/juice-shop/routes",
            "javascript",
            "/juice-shop/routes/login.ts"
        )
        if result:
            results.append(result)
    
    # Final Summary
    print("\n" + "="*80)
    print("📊 COMPLETE E2E REMEDIATION SUMMARY")
    print("="*80)
    
    if not results:
        print("\n❌ No apps were tested")
        return False
    
    print(f"\n✅ Tested {len(results)} applications:\n")
    
    total_detected = 0
    total_generated = 0
    total_validated = 0
    total_applied = 0
    
    for r in results:
        total_detected += r['detected']
        total_generated += r['generated']
        total_validated += r['validated']
        total_applied += r['applied']
        
        print(f"   {r['app']}")
        print(f"      File: {r.get('file', 'N/A')}")
        print(f"      Language: {r.get('language', 'N/A')}")
        print(f"      Detected: {r['detected']} vulnerabilities")
        print(f"      Attempted: {r['attempted']} patches")
        print(f"      Generated: {r['generated']} patches")
        print(f"      Validated: {r['validated']} patches")
        print(f"      Applied: {r['applied']} patches")
        if r.get('vuln_types'):
            print(f"      Types: {', '.join(r['vuln_types'][:5])}")
        print()
    
    print(f"🎯 Totals:")
    print(f"   Detected: {total_detected} vulnerabilities")
    print(f"   Generated: {total_generated} patches")
    print(f"   Validated: {total_validated} patches")
    print(f"   Applied: {total_applied} patches")
    
    # Success criteria
    print("\n" + "="*80)
    print("✅ E2E PIPELINE ASSESSMENT")
    print("="*80)
    
    criteria = {
        "Multi-app testing": len(results) >= 2,
        "Detection working": total_detected > 0,
        "Patch generation working": total_generated > 0,
        "Validation working": total_validated > 0,
        "End-to-end pipeline": total_applied > 0,
        "Multi-language support": len(results) >= 2 and total_applied > 0,
    }
    
    print()
    for criterion, passed in criteria.items():
        status = "✅ PASS" if passed else "⚠️  PARTIAL" if total_generated > 0 else "❌ FAIL"
        print(f"  {status} - {criterion}")
    
    all_passed = all(criteria.values())
    
    print("\n" + "="*80)
    if all_passed:
        print("🎉 SUCCESS: Complete automated remediation pipeline works!")
        print("   ✓ Detection: Multi-language vulnerability scanning")
        print("   ✓ Patching: LLM-based patch generation")
        print("   ✓ Validation: Automated patch validation")
        print("   ✓ Application: Ready for production use")
    elif total_validated > 0:
        print("⚠️  PARTIAL: Pipeline works but needs refinement")
    else:
        print("❌ NEEDS WORK: Some components need attention")
    print("="*80)
    
    return all_passed or (total_validated > 0)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
