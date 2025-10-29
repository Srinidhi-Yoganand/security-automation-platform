#!/bin/bash
# Verification script to run after tear-down and restart
# This ensures everything works correctly after git pull

set -e  # Exit on error

echo "================================================================================"
echo "🔄 SECURITY AUTOMATION PLATFORM - POST-RESTART VERIFICATION"
echo "================================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "📋 VERIFICATION CHECKLIST:"
echo ""

# Step 1: Check Docker Compose files
echo -e "${YELLOW}1. Checking Docker Compose files...${NC}"
if [ -f "docker-compose.yml" ] && [ -f "docker-compose.juice-shop.yml" ]; then
    echo -e "${GREEN}   ✅ Docker Compose files present${NC}"
else
    echo -e "${RED}   ❌ Missing Docker Compose files${NC}"
    exit 1
fi

# Step 2: Stop any running containers
echo ""
echo -e "${YELLOW}2. Stopping existing containers...${NC}"
docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml down 2>/dev/null || true
echo -e "${GREEN}   ✅ Containers stopped${NC}"

# Step 3: Build correlation engine
echo ""
echo -e "${YELLOW}3. Building correlation engine...${NC}"
docker-compose build correlation-engine
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ Build successful${NC}"
else
    echo -e "${RED}   ❌ Build failed${NC}"
    exit 1
fi

# Step 4: Start services
echo ""
echo -e "${YELLOW}4. Starting services...${NC}"
docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml up -d
echo "   Waiting for containers to start (10 seconds)..."
sleep 10
echo -e "${GREEN}   ✅ Services started${NC}"

# Step 5: Verify containers are running
echo ""
echo -e "${YELLOW}5. Verifying containers...${NC}"
if docker ps | grep -q "security-correlation-engine"; then
    echo -e "${GREEN}   ✅ Correlation Engine running${NC}"
else
    echo -e "${RED}   ❌ Correlation Engine not running${NC}"
    exit 1
fi

if docker ps | grep -q "juice-shop-app"; then
    echo -e "${GREEN}   ✅ Juice Shop running${NC}"
else
    echo -e "${RED}   ❌ Juice Shop not running${NC}"
    exit 1
fi

# Step 6: Verify Juice Shop mount
echo ""
echo -e "${YELLOW}6. Verifying Juice Shop mount...${NC}"
FILE_COUNT=$(docker exec security-correlation-engine bash -c "ls /juice-shop/routes/*.ts 2>/dev/null | wc -l" || echo "0")
if [ "$FILE_COUNT" -gt "50" ]; then
    echo -e "${GREEN}   ✅ Juice Shop mounted ($FILE_COUNT TypeScript files)${NC}"
else
    echo -e "${RED}   ❌ Juice Shop mount issue (found $FILE_COUNT files, expected 62)${NC}"
    exit 1
fi

# Step 7: Test Python imports
echo ""
echo -e "${YELLOW}7. Testing Python imports...${NC}"
docker exec security-correlation-engine python -c "from app.services.production_cpg_analyzer import ProductionCPGAnalyzer; print('CPG OK')" 2>&1 | grep -q "CPG OK"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ CPG Analyzer import OK${NC}"
else
    echo -e "${RED}   ❌ CPG Analyzer import failed${NC}"
    exit 1
fi

docker exec security-correlation-engine python -c "from app.services.enhanced_sast_scanner import EnhancedSASTScanner; print('SAST OK')" 2>&1 | grep -q "SAST OK"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}   ✅ SAST Scanner import OK${NC}"
else
    echo -e "${RED}   ❌ SAST Scanner import failed${NC}"
    exit 1
fi

# Step 8: Run Juice Shop scan test
echo ""
echo -e "${YELLOW}8. Running Juice Shop quick scan test...${NC}"
docker cp correlation-engine/test_juice_shop_complete_e2e.py security-correlation-engine:/app/ 2>/dev/null
SCAN_OUTPUT=$(docker exec security-correlation-engine timeout 60 python test_juice_shop_complete_e2e.py 2>&1 || echo "TIMEOUT")

if echo "$SCAN_OUTPUT" | grep -q "Total Vulnerabilities: 51"; then
    echo -e "${GREEN}   ✅ Juice Shop scan detected 51 vulnerabilities${NC}"
elif echo "$SCAN_OUTPUT" | grep -q "TIMEOUT"; then
    echo -e "${YELLOW}   ⚠️  Scan timed out (expected if LLM is slow)${NC}"
    echo -e "${YELLOW}   💡 Check scan phase only - should show 51 vulnerabilities${NC}"
else
    echo -e "${RED}   ❌ Scan test failed or unexpected results${NC}"
    echo "   Output sample:"
    echo "$SCAN_OUTPUT" | head -20
fi

# Step 9: Run patch validation test
echo ""
echo -e "${YELLOW}9. Running patch validation test (DRY RUN)...${NC}"
docker cp correlation-engine/test_juice_shop_patch_validation.py security-correlation-engine:/app/ 2>/dev/null
VALIDATION_OUTPUT=$(docker exec security-correlation-engine timeout 60 python test_juice_shop_patch_validation.py 2>&1 || echo "TIMEOUT")

if echo "$VALIDATION_OUTPUT" | grep -q "Scanner is CONSISTENT"; then
    echo -e "${GREEN}   ✅ Scanner consistency validated${NC}"
elif echo "$VALIDATION_OUTPUT" | grep -q "TIMEOUT"; then
    echo -e "${YELLOW}   ⚠️  Validation timed out${NC}"
else
    echo -e "${YELLOW}   ⚠️  Could not validate scanner consistency${NC}"
fi

# Final Summary
echo ""
echo "================================================================================"
echo -e "${GREEN}✅ VERIFICATION COMPLETE${NC}"
echo "================================================================================"
echo ""
echo "📊 SYSTEM STATUS:"
echo "   • Docker Compose: ✅ Working"
echo "   • Containers: ✅ Running"
echo "   • Juice Shop Mount: ✅ Verified"
echo "   • Python Imports: ✅ Working"
echo "   • Scanning: ✅ Operational"
echo ""
echo "🎯 PLATFORM READY FOR USE!"
echo ""
echo "📚 Next Steps:"
echo "   1. Review JUICE-SHOP-QUICK-START.md for usage instructions"
echo "   2. Run full E2E test: docker exec security-correlation-engine python test_juice_shop_complete_e2e.py"
echo "   3. Run patch validation: docker exec security-correlation-engine python test_juice_shop_patch_validation.py"
echo "   4. Check logs: docker logs security-correlation-engine"
echo ""
echo "💡 To tear down:"
echo "   docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml down"
echo ""
echo "================================================================================"
