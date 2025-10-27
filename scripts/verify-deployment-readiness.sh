#!/bin/bash

# Verification Script for Security Automation Platform
# This checks if all files and configurations are ready for deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
WARNINGS=0

echo "═══════════════════════════════════════════════════════════════"
echo "     Security Automation Platform - Readiness Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✅ PASS${NC} - File exists: $1"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} - Missing file: $1"
        ((FAILED++))
        return 1
    fi
}

# Function to check directory exists
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✅ PASS${NC} - Directory exists: $1"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} - Missing directory: $1"
        ((FAILED++))
        return 1
    fi
}

# Function to check file contains text
check_content() {
    if grep -q "$2" "$1" 2>/dev/null; then
        echo -e "${GREEN}✅ PASS${NC} - $1 contains: $2"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC} - $1 missing: $2"
        ((FAILED++))
        return 1
    fi
}

# Function to warn
warn() {
    echo -e "${YELLOW}⚠️  WARN${NC} - $1"
    ((WARNINGS++))
}

# Function to info
info() {
    echo -e "${BLUE}ℹ️  INFO${NC} - $1"
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 1: Docker Configuration Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "docker-compose.yml"
check_file "correlation-engine/Dockerfile"
check_file "vulnerable-app/Dockerfile"
check_file "test-docker-deployment.sh"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 2: Core Application Files"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "correlation-engine/app/main.py"
check_file "correlation-engine/app/database.py"
check_file "correlation-engine/app/core/correlator.py"
check_file "correlation-engine/app/services/dashboard_generator.py"
check_file "correlation-engine/app/services/patcher/llm_patch_generator.py"
check_file "correlation-engine/app/services/patcher/patch_generator.py"
check_file "correlation-engine/app/services/notifications.py"
check_file "correlation-engine/app/services/behavior/pattern_analyzer.py"
check_file "correlation-engine/app/services/behavior/risk_scorer.py"
check_file "correlation-engine/app/services/behavior/lifecycle_tracker.py"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 3: Parsers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "correlation-engine/app/core/parsers/codeql_parser.py"
check_file "correlation-engine/app/core/parsers/semgrep_parser.py"
check_file "correlation-engine/app/core/parsers/zap_parser.py"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 4: Dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "correlation-engine/requirements.txt"
check_content "correlation-engine/requirements.txt" "fastapi"
check_content "correlation-engine/requirements.txt" "uvicorn"
check_content "correlation-engine/requirements.txt" "ollama"
check_content "correlation-engine/requirements.txt" "google-generativeai"
check_content "correlation-engine/requirements.txt" "javalang"
check_content "correlation-engine/requirements.txt" "diff-match-patch"
check_content "correlation-engine/requirements.txt" "openai"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 5: Test Scripts"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "correlation-engine/test_all_vulnerabilities.py"
check_file "correlation-engine/test_llm_providers.py"
check_file "correlation-engine/test_patches.py"
check_file "correlation-engine/test_api.py"

# Count test files
TEST_COUNT=$(find correlation-engine -name "test_*.py" -type f | wc -l)
if [ "$TEST_COUNT" -ge 10 ]; then
    echo -e "${GREEN}✅ PASS${NC} - Found $TEST_COUNT test scripts (expected 10+)"
    ((PASSED++))
else
    echo -e "${RED}❌ FAIL${NC} - Only $TEST_COUNT test scripts (expected 10+)"
    ((FAILED++))
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 6: Documentation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "README.md"
check_file "PHASE3-COMPLETE-REPORT.md"
check_file "PHASE3-LLM-PATCHING.md"
check_file "QUICKSTART-LLM-PATCHING.md"
check_file "DOCKER-DEPLOYMENT.md"
check_file "NOTIFICATION-SETUP.md"
check_file "OLLAMA-SETUP.md"
check_file "OLLAMA-QUICKREF.md"
check_file "PRE-DEPLOYMENT-CHECKLIST.md"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 7: Docker Compose Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_content "docker-compose.yml" "ollama"
check_content "docker-compose.yml" "correlation-engine"
check_content "docker-compose.yml" "vulnerable-app"
check_content "docker-compose.yml" "deepseek-coder:6.7b-instruct"
check_content "docker-compose.yml" "11434:11434"
check_content "docker-compose.yml" "8000:8000"
check_content "docker-compose.yml" "8080:8080"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 8: API Endpoints (Code Check)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_content "correlation-engine/app/main.py" "/api/llm/status"
check_content "correlation-engine/app/main.py" "/health"
check_content "correlation-engine/app/main.py" "generate-patch"
check_content "correlation-engine/app/main.py" "NotificationService"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 9: LLM Patch Generator Features"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_content "correlation-engine/app/services/patcher/llm_patch_generator.py" "class LLMPatchGenerator"
check_content "correlation-engine/app/services/patcher/llm_patch_generator.py" "def generate_patch"
check_content "correlation-engine/app/services/patcher/llm_patch_generator.py" "ollama"
check_content "correlation-engine/app/services/patcher/llm_patch_generator.py" "gemini"
check_content "correlation-engine/app/services/patcher/llm_patch_generator.py" "deepseek-coder"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 10: Notification Service Features"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_content "correlation-engine/app/services/notifications.py" "class NotificationService"
check_content "correlation-engine/app/services/notifications.py" "_notify_slack"
check_content "correlation-engine/app/services/notifications.py" "_notify_email"
check_content "correlation-engine/app/services/notifications.py" "_notify_github"
check_content "correlation-engine/app/services/notifications.py" "SLACK_WEBHOOK_URL"
check_content "correlation-engine/app/services/notifications.py" "SMTP_SERVER"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 11: Dashboard Integration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_content "correlation-engine/app/services/dashboard_generator.py" "Generate Patch"
check_content "correlation-engine/app/services/dashboard_generator.py" "generatePatch"
check_content "correlation-engine/app/services/dashboard_generator.py" "togglePatch"
check_content "correlation-engine/app/services/dashboard_generator.py" "applyPatch"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 12: Vulnerable App (Test Target)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
check_file "vulnerable-app/pom.xml"
check_dir "vulnerable-app/src/main/java"
check_file "vulnerable-app/VULNERABILITIES.md"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Section 13: Environment Checks (Optional)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Docker (optional)
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✅ PASS${NC} - Docker is installed"
    ((PASSED++))
    
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    info "Docker version: $DOCKER_VERSION"
    
    # Check if Docker is running
    if docker ps &> /dev/null; then
        echo -e "${GREEN}✅ PASS${NC} - Docker daemon is running"
        ((PASSED++))
    else
        warn "Docker daemon is not running (start Docker Desktop)"
    fi
else
    warn "Docker is not installed (required for deployment)"
fi

# Check Docker Compose (optional)
if command -v docker-compose &> /dev/null; then
    echo -e "${GREEN}✅ PASS${NC} - Docker Compose is installed"
    ((PASSED++))
    
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $4}' | sed 's/,//')
    info "Docker Compose version: $COMPOSE_VERSION"
else
    warn "Docker Compose not found (may be built into Docker)"
fi

# Check Ollama (optional - can run in Docker)
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✅ PASS${NC} - Ollama is installed locally"
    ((PASSED++))
    
    if ollama list &> /dev/null; then
        if ollama list | grep -q "deepseek-coder"; then
            echo -e "${GREEN}✅ PASS${NC} - DeepSeek Coder model is installed"
            ((PASSED++))
        else
            info "DeepSeek Coder not installed locally (will download in Docker)"
        fi
    fi
else
    info "Ollama not installed locally (will run in Docker)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                      VERIFICATION SUMMARY"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo -e "${GREEN}✅ Passed:${NC}   $PASSED checks"
echo -e "${RED}❌ Failed:${NC}   $FAILED checks"
echo -e "${YELLOW}⚠️  Warnings:${NC} $WARNINGS warnings"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "              ${GREEN}🎉 ALL CHECKS PASSED! 🎉${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Your application is READY FOR DEPLOYMENT! ✅"
    echo ""
    echo "Next Steps:"
    echo "1. Start Docker Desktop (if not running)"
    echo "2. Run: docker-compose up -d"
    echo "3. Wait 2-5 minutes for services to start"
    echo "4. Access: http://localhost:8000/dashboard"
    echo ""
    echo "For detailed deployment guide, see: DOCKER-DEPLOYMENT.md"
    echo "For pre-deployment checklist, see: PRE-DEPLOYMENT-CHECKLIST.md"
    echo ""
    exit 0
else
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "              ${RED}❌ DEPLOYMENT NOT READY ❌${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Please fix the failed checks above before deploying."
    echo ""
    if [ $WARNINGS -gt 0 ]; then
        echo "Warnings are optional but recommended to fix."
    fi
    echo ""
    exit 1
fi
