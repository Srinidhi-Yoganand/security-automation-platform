#!/bin/bash
# Script to copy DVWA source code into correlation engine for SAST scanning

echo "📋 Copying DVWA source code for SAST scanning..."

# Copy DVWA source from running container
docker cp dvwa-app:/var/www/html/vulnerabilities /tmp/dvwa-vuln-source 2>/dev/null
docker cp dvwa-app:/var/www/html/login.php /tmp/dvwa-vuln-source/ 2>/dev/null
docker cp dvwa-app:/var/www/html/security.php /tmp/dvwa-vuln-source/ 2>/dev/null

# Copy into correlation engine
docker cp /tmp/dvwa-vuln-source/. security-correlation-engine:/tmp/DVWA/

# Verify
echo ""
echo "✅ Verifying DVWA files in correlation engine..."
docker exec security-correlation-engine bash -c 'find /tmp/DVWA -name "*.php" | wc -l'
echo "PHP files found"

echo ""
echo "✅ DVWA source code ready for SAST scanning!"
echo "   Location: /tmp/DVWA in correlation-engine container"
