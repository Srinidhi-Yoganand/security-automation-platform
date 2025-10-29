#!/bin/bash
# Initialize DVWA Database

echo "Initializing DVWA database..."

# Get setup page and extract CSRF token
SETUP_PAGE=$(curl -s -c /tmp/dvwa_cookies.txt http://localhost:8888/setup.php)
USER_TOKEN=$(echo "$SETUP_PAGE" | grep -oP "user_token' value='\K[^']+")

echo "Got user token: $USER_TOKEN"

# Submit database creation with token
curl -s -b /tmp/dvwa_cookies.txt -X POST http://localhost:8888/setup.php \
  -d "create_db=Create+%2F+Reset+Database&user_token=$USER_TOKEN" \
  -L > /tmp/dvwa_setup_result.txt

# Check result
if grep -q "Database has been created" /tmp/dvwa_setup_result.txt; then
    echo "✅ DVWA database created successfully!"
elif grep -q "already exists" /tmp/dvwa_setup_result.txt; then
    echo "ℹ️  DVWA database already exists"
else
    echo "⚠️  Setup result:"
    head -50 /tmp/dvwa_setup_result.txt | grep -i "success\|error\|database"
fi

# Clean up
rm -f /tmp/dvwa_cookies.txt /tmp/dvwa_setup_result.txt

echo "Done!"
