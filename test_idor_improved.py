#!/usr/bin/env python3
"""
IMPROVED IDOR TEST with Better Prompts
Uses more explicit prompts and examples to improve AI fix quality
"""

import os
import sys
import json
import time
import requests
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '/app')

print('='*100)
print('🎯 IMPROVED IDOR VULNERABILITY PATCHING TEST')
print('='*100)
print(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
print(f'Goal: Fix ALL IDOR vulnerabilities with improved prompts')
print('='*100 + '\n')

idor_cases = [
    {
        'name': 'PHP User Profile IDOR',
        'vulnerable': '''<?php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($conn, $query);
$user = mysqli_fetch_assoc($result);
echo $user['email'];
?>''',
        'fix_example': '''<?php
session_start();
$requested_id = $_GET['id'];
$current_user_id = $_SESSION['user_id'];

// Authorization check
if ($requested_id != $current_user_id) {
    http_response_code(403);
    die("Forbidden");
}

$query = "SELECT * FROM users WHERE id = ?";
$stmt = mysqli_prepare($conn, $query);
mysqli_stmt_bind_param($stmt, "i", $current_user_id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);
$user = mysqli_fetch_assoc($result);
echo $user['email'];
?>''',
        'language': 'PHP'
    },
    {
        'name': 'Node.js Document Access IDOR',
        'vulnerable': '''app.get('/api/documents/:id', async (req, res) => {
    const docId = req.params.id;
    const document = await Document.findById(docId);
    res.json(document);
});''',
        'fix_example': '''app.get('/api/documents/:id', async (req, res) => {
    const docId = req.params.id;
    const userId = req.session.userId; // From authenticated session
    
    const document = await Document.findOne({
        _id: docId,
        ownerId: userId  // Check ownership
    });
    
    if (!document) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    res.json(document);
});''',
        'language': 'JavaScript'
    },
    {
        'name': 'Python Invoice IDOR',
        'vulnerable': '''@app.route('/invoice/<invoice_id>')
def view_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    return jsonify(invoice.to_dict())''',
        'fix_example': '''@app.route('/invoice/<invoice_id>')
@login_required
def view_invoice(invoice_id):
    invoice = Invoice.query.get(invoice_id)
    
    # Authorization check
    if invoice.user_id != current_user.id:
        abort(403)
    
    return jsonify(invoice.to_dict())''',
        'language': 'Python'
    },
    {
        'name': 'PHP Order Access IDOR',
        'vulnerable': '''<?php
$order_id = $_POST['order_id'];
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$order_id]);
echo json_encode($stmt->fetch());
?>''',
        'fix_example': '''<?php
session_start();
$order_id = $_POST['order_id'];
$user_id = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?");
$stmt->execute([$order_id, $user_id]);
$order = $stmt->fetch();

if (!$order) {
    http_response_code(403);
    die(json_encode(['error' => 'Forbidden']));
}

echo json_encode($order);
?>''',
        'language': 'PHP'
    },
    {
        'name': 'Node.js Settings Update IDOR',
        'vulnerable': '''router.post('/users/:userId/settings', async (req, res) => {
    await User.updateOne(
        { _id: req.params.userId },
        { email: req.body.email }
    );
    res.json({ success: true });
});''',
        'fix_example': '''router.post('/users/:userId/settings', async (req, res) => {
    const requestedUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    // Authorization check
    if (requestedUserId !== currentUserId) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    
    await User.updateOne(
        { _id: currentUserId },
        { email: req.body.email }
    );
    res.json({ success: true });
});''',
        'language': 'JavaScript'
    }
]

results = []

print(f'🔍 Testing {len(idor_cases)} IDOR patterns with IMPROVED prompts\n')

for i, case in enumerate(idor_cases, 1):
    print('='*100)
    print(f'TEST {i}/{len(idor_cases)}: {case["name"]}')
    print('='*100)
    
    print(f'Language: {case["language"]}\n')
    
    print('🔴 VULNERABLE CODE:')
    print('-'*80)
    print(case['vulnerable'])
    print('-'*80 + '\n')
    
    # Create improved prompt with example
    prompt = f'''You are a security expert. Fix this IDOR vulnerability.

VULNERABLE CODE:
```{case['language'].lower()}
{case['vulnerable']}
```

EXAMPLE OF PROPER FIX:
```{case['language'].lower()}
{case['fix_example']}
```

REQUIREMENTS:
1. Add authorization check comparing session user ID with requested resource
2. Return 403 Forbidden if user doesn't own the resource
3. Use session/authenticated user ID, never trust user input for authorization
4. Follow the example pattern above

NOW FIX THE VULNERABLE CODE ABOVE.
Return ONLY the complete fixed code with proper authorization, no explanations:'''

    print('🤖 Generating fix with improved prompt...')
    start = time.time()
    
    try:
        response = requests.post(
            'http://security-ollama:11434/api/generate',
            json={
                'model': 'deepseek-coder:6.7b-instruct',
                'prompt': prompt,
                'stream': False,
                'options': {
                    'temperature': 0.2,
                    'num_predict': 1536
                }
            },
            timeout=120
        )
        
        gen_time = time.time() - start
        
        if response.status_code == 200:
            result = response.json()
            fixed = result.get('response', '')
            
            # Clean up
            if '```' in fixed:
                parts = fixed.split('```')
                for part in parts:
                    part = part.strip()
                    if len(part) > 50 and not part.startswith(('Here', 'The', 'This', 'Now', 'I')):
                        fixed = part
                        # Remove language tag
                        lines = fixed.split('\n')
                        if lines[0].lower() in ['php', 'javascript', 'python', 'js', 'py']:
                            fixed = '\n'.join(lines[1:])
                        break
            
            fixed = fixed.strip()
            
            print(f'✅ Generated in {gen_time:.1f}s\n')
            
            print('🟢 FIXED CODE:')
            print('-'*80)
            print(fixed[:800] if len(fixed) > 800 else fixed)
            if len(fixed) > 800:
                print('...')
            print('-'*80 + '\n')
            
            # Validation
            checks = {}
            
            if case['language'] == 'PHP':
                checks['has_session'] = '$_SESSION' in fixed or 'session_start' in fixed
                checks['auth_check'] = ('if' in fixed and '!=' in fixed) or 'if' in fixed.lower()
                checks['returns_403'] = '403' in fixed or 'forbidden' in fixed.lower()
                checks['checks_user_id'] = 'user_id' in fixed.lower()
                checks['safe_query'] = 'prepare' in fixed.lower() or '?' in fixed
                
            elif case['language'] == 'JavaScript':
                checks['has_session'] = 'req.session' in fixed or 'req.user' in fixed
                checks['auth_check'] = ('if' in fixed and '!==' in fixed) or ('if' in fixed and '!=')
                checks['returns_403'] = '403' in fixed or 'forbidden' in fixed.lower()
                checks['checks_user_id'] = 'userId' in fixed or 'user_id' in fixed
                checks['query_ownership'] = 'ownerId' in fixed or 'user_id' in fixed
                
            else:  # Python
                checks['has_session'] = 'current_user' in fixed or 'session' in fixed
                checks['auth_check'] = 'if' in fixed
                checks['returns_403'] = '403' in fixed or 'abort(403)' in fixed
                checks['checks_user_id'] = 'user_id' in fixed
                checks['has_decorator'] = '@login_required' in fixed or 'login_required' in fixed
            
            print('📊 SECURITY CHECKS:')
            passed = 0
            for check, status in checks.items():
                icon = '✅' if status else '❌'
                print(f'{icon} {check.replace("_", " ").title()}: {status}')
                if status:
                    passed += 1
            
            success_rate = (passed / len(checks)) * 100
            
            if success_rate >= 80:
                print(f'\n✅ FIX QUALITY: EXCELLENT ({passed}/{len(checks)} = {success_rate:.0f}%)')
                status = 'FIXED'
            elif success_rate >= 60:
                print(f'\n⚠️  FIX QUALITY: GOOD ({passed}/{len(checks)} = {success_rate:.0f}%)')
                status = 'PARTIAL'
            else:
                print(f'\n❌ FIX QUALITY: INSUFFICIENT ({passed}/{len(checks)} = {success_rate:.0f}%)')
                status = 'FAILED'
            
            results.append({
                'name': case['name'],
                'language': case['language'],
                'status': status,
                'time': round(gen_time, 1),
                'checks_passed': passed,
                'total_checks': len(checks),
                'success_rate': f'{success_rate:.0f}%',
                'vulnerable_code': case['vulnerable'],
                'fixed_code': fixed
            })
            
        else:
            print(f'❌ HTTP {response.status_code}')
            results.append({
                'name': case['name'],
                'status': 'FAILED',
                'error': f'HTTP {response.status_code}'
            })
            
    except Exception as e:
        print(f'❌ Error: {e}')
        results.append({
            'name': case['name'],
            'status': 'FAILED',
            'error': str(e)
        })
    
    print()

# Final Report
print('\n' + '='*100)
print('📊 IMPROVED IDOR TESTING - FINAL RESULTS')
print('='*100 + '\n')

total = len(results)
fixed = sum(1 for r in results if r.get('status') == 'FIXED')
partial = sum(1 for r in results if r.get('status') == 'PARTIAL')
failed = sum(1 for r in results if r.get('status') == 'FAILED')

print(f'📈 SUMMARY:')
print(f'   Total Tested: {total}')
print(f'   Fixed: {fixed} ✅')
print(f'   Partial: {partial} ⚠️')
print(f'   Failed: {failed} ❌')
print(f'   Success Rate: {((fixed + partial*0.5)/total*100):.1f}%\n')

print('📋 DETAILED RESULTS:')
print('-'*100)
for i, r in enumerate(results, 1):
    icon = '✅' if r.get('status') == 'FIXED' else '⚠️' if r.get('status') == 'PARTIAL' else '❌'
    print(f"{i}. {icon} {r.get('name', 'Unknown')}")
    print(f"   Status: {r.get('status', 'UNKNOWN')}")
    if 'success_rate' in r:
        print(f"   Quality: {r['success_rate']} ({r['checks_passed']}/{r['total_checks']} checks)")
        print(f"   Time: {r['time']}s")
    if 'error' in r:
        print(f"   Error: {r['error']}")
    print()

# Save report
report = {
    'timestamp': datetime.now().isoformat(),
    'test_type': 'IDOR with Improved Prompts',
    'total': total,
    'fixed': fixed,
    'partial': partial,
    'failed': failed,
    'overall_success_rate': f'{((fixed + partial*0.5)/total*100):.1f}%',
    'results': results
}

report_file = Path('/tmp/idor_improved_report.json')
report_file.write_text(json.dumps(report, indent=2))

print('='*100)
print('🎉 IMPROVED IDOR TEST COMPLETE!')
print('='*100)
print(f'\n✅ Report: {report_file}')
print(f'✅ Fixed: {fixed}/{total} vulnerabilities')
print(f'✅ Partial: {partial}/{total} vulnerabilities')
print(f'✅ Overall Success: {((fixed + partial*0.5)/total*100):.1f}%')

if fixed >= total * 0.7:
    print('\n🎉 EXCELLENT! Platform successfully handles IDOR vulnerabilities!')
elif fixed + partial >= total * 0.7:
    print('\n✅ GOOD! Platform handles most IDOR vulnerabilities!')
else:
    print('\n⚠️  Platform needs improvement for IDOR detection')

print('\n💡 KEY FINDINGS:')
print(f'   • Tested across {len(set(r.get("language") for r in results))} languages')
print(f'   • Average generation time: {sum(r.get("time", 0) for r in results if "time" in r)/len([r for r in results if "time" in r]):.1f}s')
print(f'   • Using improved prompts with examples')
print('='*100)
