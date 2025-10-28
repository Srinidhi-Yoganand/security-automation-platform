#!/usr/bin/env python3
"""Test DeepSeek Coder's ability to generate SQL injection fix"""

import requests
import json

# Vulnerable SQL injection code from DVWA low.php
vulnerable_code = """<?php
if( isset( $_REQUEST[ 'Submit' ] ) ) {
        // Get input
        $id = $_REQUEST[ 'id' ];

        // Check database
        $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
        $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
        
        // Get results
        while( $row = mysqli_fetch_assoc( $result ) ) {
                $first = $row["first_name"];
                $last  = $row["last_name"];
                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
        }
        mysqli_close($GLOBALS["___mysqli_ston"]);
}
?>"""

# Create prompt for DeepSeek
prompt = f"""You are a security expert. Fix this PHP SQL injection vulnerability.

VULNERABLE CODE:
{vulnerable_code}

VULNERABILITY: SQL Injection (CWE-89)
ISSUE: User input '$id' is directly concatenated into SQL query without sanitization
SEVERITY: Critical

Generate a SECURE fix using prepared statements or parameterized queries.

Provide your response in this format:

EXPLANATION:
[Brief explanation of the fix]

FIXED CODE:
```php
[Complete fixed code here]
```

SECURITY IMPROVEMENTS:
- [List improvements]
"""

print("=" * 80)
print("🔍 Testing DeepSeek Coder on REAL SQL Injection")
print("=" * 80)
print()
print("📝 Vulnerable Code:")
print("-" * 80)
print(vulnerable_code[:200] + "...")
print()
print("🤖 Asking DeepSeek to generate secure fix...")
print()

# Call Ollama API directly
try:
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "deepseek-coder:6.7b-instruct",
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Lower temperature for more deterministic security fixes
                "top_p": 0.9
            }
        },
        timeout=120
    )
    
    if response.status_code == 200:
        result = response.json()
        generated_text = result.get("response", "")
        
        print("✅ DEEPSEEK RESPONSE:")
        print("=" * 80)
        print(generated_text)
        print("=" * 80)
        print()
        
        # Check if it mentions prepared statements or mysqli_prepare
        if "prepare" in generated_text.lower() or "bindparam" in generated_text.lower() or "bind_param" in generated_text.lower():
            print("✅ FIX LOOKS GOOD: Uses prepared statements!")
        else:
            print("⚠️  WARNING: Fix may not use proper prepared statements")
            
    else:
        print(f"❌ Error: HTTP {response.status_code}")
        print(response.text)
        
except Exception as e:
    print(f"❌ Error calling Ollama: {e}")
