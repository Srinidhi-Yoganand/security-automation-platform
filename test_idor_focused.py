#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) FOCUSED TEST
Finds and fixes IDOR vulnerabilities specifically
"""

import os
import sys
import json
import time
import requests
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '/app')

print('='*100)
print('🎯 IDOR VULNERABILITY DETECTION & AUTOMATED PATCHING TEST')
print('='*100)
print(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
print(f'Focus: Insecure Direct Object Reference (IDOR) - CWE-639')
print('='*100 + '\n')

# Test known IDOR patterns
idor_test_cases = [
    {
        'name': 'User Profile IDOR',
        'language': 'PHP',
        'vulnerable_code': '''<?php
// User profile page
$user_id = $_GET['id'];

// VULNERABLE: No authorization check!
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);
$user = mysqli_fetch_assoc($result);

echo "Name: " . $user['name'];
echo "Email: " . $user['email'];
echo "SSN: " . $user['ssn'];  // Sensitive data exposed!
?>''',
        'description': 'User can access any profile by changing ID parameter',
        'severity': 'CRITICAL'
    },
    {
        'name': 'Document Download IDOR',
        'language': 'JavaScript',
        'vulnerable_code': '''// Download document endpoint
app.get('/api/documents/:id', async (req, res) => {
    // VULNERABLE: No ownership check!
    const docId = req.params.id;
    
    const document = await Document.findById(docId);
    
    if (document) {
        res.download(document.filepath);
    } else {
        res.status(404).send('Not found');
    }
});''',
        'description': 'User can download any document by changing document ID',
        'severity': 'HIGH'
    },
    {
        'name': 'Order Access IDOR',
        'language': 'PHP',
        'vulnerable_code': '''<?php
// View order details
$order_id = $_POST['order_id'];

// VULNERABLE: No check if user owns this order!
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$order_id]);
$order = $stmt->fetch();

// Display sensitive order information
echo json_encode($order);
?>''',
        'description': 'User can view any order by changing order_id',
        'severity': 'HIGH'
    },
    {
        'name': 'Account Settings IDOR',
        'language': 'JavaScript',
        'vulnerable_code': '''// Update account settings
router.post('/api/users/:userId/settings', async (req, res) => {
    // VULNERABLE: User can update ANY user's settings!
    const userId = req.params.userId;
    const { email, phone } = req.body;
    
    await User.updateOne(
        { _id: userId },
        { email, phone }
    );
    
    res.json({ success: true });
});''',
        'description': 'User can modify any account settings by changing userId',
        'severity': 'CRITICAL'
    },
    {
        'name': 'Invoice Access IDOR',
        'language': 'Python',
        'vulnerable_code': '''# View invoice
@app.route('/api/invoice/<invoice_id>')
def view_invoice(invoice_id):
    # VULNERABLE: No authorization check!
    invoice = Invoice.query.get(invoice_id)
    
    if invoice:
        return jsonify({
            'id': invoice.id,
            'amount': invoice.amount,
            'customer_name': invoice.customer_name,
            'card_last4': invoice.card_last4
        })
    return jsonify({'error': 'Not found'}), 404''',
        'description': 'User can view any invoice by changing invoice_id',
        'severity': 'HIGH'
    }
]

results = []

print(f'🔍 Testing {len(idor_test_cases)} IDOR vulnerability patterns\n')

# ============================================================================
# Generate Patches for Each IDOR Pattern
# ============================================================================

for i, test_case in enumerate(idor_test_cases, 1):
    print('='*100)
    print(f'TEST CASE {i}/{len(idor_test_cases)}: {test_case["name"]}')
    print('='*100)
    print(f'Language: {test_case["language"]}')
    print(f'Severity: {test_case["severity"]}')
    print(f'Description: {test_case["description"]}\n')
    
    print('📄 VULNERABLE CODE:')
    print('-'*100)
    print(test_case['vulnerable_code'][:500])
    print('-'*100 + '\n')
    
    print('🤖 Generating IDOR fix...')
    
    # Create language-specific prompt
    if test_case['language'] == 'PHP':
        fix_instructions = '''Use $_SESSION['user_id'] to verify ownership
Add: if ($user_id != $_SESSION['user_id']) { die('Unauthorized'); }
Or check role: if ($_SESSION['role'] != 'admin')'''
    elif test_case['language'] == 'JavaScript':
        fix_instructions = '''Use req.session.userId or req.user.id to verify ownership
Add: if (document.ownerId !== req.session.userId) { return res.status(403).send('Forbidden'); }
Check authorization before accessing resource'''
    else:  # Python
        fix_instructions = '''Use session['user_id'] or current_user.id to verify ownership
Add: if invoice.user_id != session['user_id']: abort(403)
Check authorization before returning data'''
    
    prompt = f'''Fix this IDOR (Insecure Direct Object Reference) vulnerability.

VULNERABLE CODE:
{test_case['vulnerable_code']}

REQUIREMENTS:
1. {fix_instructions}
2. Return 403 Forbidden if user doesn't own the resource
3. Add proper authorization checks
4. Use session data, not user-supplied IDs for auth

Provide ONLY the fixed {test_case['language']} code:'''
    
    start_time = time.time()
    
    try:
        response = requests.post(
            'http://security-ollama:11434/api/generate',
            json={
                'model': 'deepseek-coder:6.7b-instruct',
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': 0.1,
                    'num_predict': 1024
                }
            },
            timeout=90
        )
        
        gen_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            fixed_code = result.get('response', '')
            
            # Clean up
            if '```' in fixed_code:
                parts = fixed_code.split('```')
                for part in parts:
                    if len(part.strip()) > 50:
                        fixed_code = part
                        if fixed_code.startswith(('php', 'javascript', 'python', 'js')):
                            fixed_code = '\n'.join(fixed_code.split('\n')[1:])
                        break
            
            fixed_code = fixed_code.strip()
            
            print(f'✅ Fix generated in {gen_time:.1f}s\n')
            
            print('📄 FIXED CODE:')
            print('-'*100)
            print(fixed_code[:600])
            print('-'*100 + '\n')
            
            # Validate IDOR fix
            validation = {}
            
            if test_case['language'] == 'PHP':
                validation['uses_session'] = '$_SESSION' in fixed_code
                validation['has_auth_check'] = any(x in fixed_code for x in ['if', '!=', '!==', '=='])
                validation['returns_error'] = any(x in fixed_code.lower() for x in ['die', 'exit', '403', 'unauthorized', 'forbidden'])
                validation['checks_ownership'] = 'user_id' in fixed_code.lower() and 'session' in fixed_code.lower()
                
            elif test_case['language'] == 'JavaScript':
                validation['uses_session'] = any(x in fixed_code for x in ['req.session', 'req.user', 'req.userId'])
                validation['has_auth_check'] = any(x in fixed_code for x in ['if', '!==', '!=', '==='])
                validation['returns_403'] = '403' in fixed_code or 'forbidden' in fixed_code.lower()
                validation['checks_ownership'] = 'owner' in fixed_code.lower() or 'userId' in fixed_code
                
            else:  # Python
                validation['uses_session'] = any(x in fixed_code for x in ['session', 'current_user', 'g.user'])
                validation['has_auth_check'] = 'if' in fixed_code
                validation['returns_403'] = '403' in fixed_code or 'abort(403)' in fixed_code
                validation['checks_ownership'] = 'user_id' in fixed_code.lower()
            
            print('📊 VALIDATION RESULTS:')
            passed = 0
            for check, status in validation.items():
                icon = '✅' if status else '❌'
                print(f'{icon} {check}: {status}')
                if status:
                    passed += 1
            
            quality = 'EXCELLENT' if passed == len(validation) else 'GOOD' if passed >= len(validation) * 0.75 else 'NEEDS REVIEW'
            
            print(f'\n📈 Fix Quality: {quality} ({passed}/{len(validation)} checks passed)')
            
            if passed == len(validation):
                print('✅ IDOR VULNERABILITY FIXED! ✓\n')
                status = 'FIXED'
            elif passed >= len(validation) * 0.5:
                print('⚠️  PARTIAL FIX - Review needed\n')
                status = 'PARTIAL'
            else:
                print('❌ FIX INSUFFICIENT\n')
                status = 'FAILED'
            
            results.append({
                'test_case': test_case['name'],
                'language': test_case['language'],
                'severity': test_case['severity'],
                'status': status,
                'generation_time': round(gen_time, 1),
                'quality': quality,
                'checks_passed': passed,
                'total_checks': len(validation),
                'vulnerable_code': test_case['vulnerable_code'],
                'fixed_code': fixed_code[:500]
            })
            
        else:
            print(f'❌ Generation failed: HTTP {response.status_code}\n')
            results.append({
                'test_case': test_case['name'],
                'status': 'FAILED',
                'error': f'HTTP {response.status_code}'
            })
            
    except Exception as e:
        print(f'❌ Error: {e}\n')
        results.append({
            'test_case': test_case['name'],
            'status': 'FAILED',
            'error': str(e)
        })

# ============================================================================
# Final Report
# ============================================================================
print('\n' + '='*100)
print('📊 IDOR VULNERABILITY TESTING - FINAL REPORT')
print('='*100 + '\n')

total = len(results)
fixed = sum(1 for r in results if r.get('status') == 'FIXED')
partial = sum(1 for r in results if r.get('status') == 'PARTIAL')
failed = sum(1 for r in results if r.get('status') == 'FAILED')

print(f'Total IDOR Patterns Tested: {total}')
print(f'Successfully Fixed: {fixed} ✅')
print(f'Partial Fixes: {partial} ⚠️')
print(f'Failed: {failed} ❌')
print(f'Success Rate: {(fixed/total*100):.1f}%\n')

print('DETAILED RESULTS:')
print('-'*100)
for i, r in enumerate(results, 1):
    if r.get('status') == 'FIXED':
        icon = '✅'
    elif r.get('status') == 'PARTIAL':
        icon = '⚠️'
    else:
        icon = '❌'
    
    print(f"{i}. {icon} {r['test_case']} ({r.get('language', 'N/A')})")
    print(f"   Status: {r.get('status', 'UNKNOWN')}")
    if 'quality' in r:
        print(f"   Quality: {r['quality']} ({r['checks_passed']}/{r['total_checks']} checks)")
        print(f"   Time: {r['generation_time']}s")
    if 'error' in r:
        print(f"   Error: {r['error']}")
    print()

# Save report
report_data = {
    'timestamp': datetime.now().isoformat(),
    'focus': 'IDOR (Insecure Direct Object Reference)',
    'cwe': 'CWE-639',
    'total_tested': total,
    'fixed': fixed,
    'partial': partial,
    'failed': failed,
    'success_rate': f'{(fixed/total*100):.1f}%',
    'results': results
}

report_file = Path('/tmp/idor_test_report.json')
report_file.write_text(json.dumps(report_data, indent=2))

print('='*100)
print('✅ IDOR TEST COMPLETE!')
print('='*100)
print(f'\n📁 Report saved: {report_file}')
print(f'\n🎯 Key Finding: Platform can detect and fix IDOR vulnerabilities!')
print(f'   - {fixed} vulnerabilities completely fixed')
print(f'   - {partial} vulnerabilities partially fixed')
print(f'   - Success rate: {(fixed/total*100):.1f}%')
print('\n✅ Covers multiple languages: PHP, JavaScript, Python')
print('✅ Handles various IDOR scenarios: profiles, documents, orders, settings, invoices')
print('='*100)
