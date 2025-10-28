#!/bin/bash
# Quick Start Script for Presentation Demo

echo "================================================================================================="
echo "🚀 SECURITY AUTOMATION PLATFORM - PRESENTATION SETUP"
echo "================================================================================================="
echo ""

# Check if Docker is running
echo "1️⃣  Checking Docker..."
if ! docker ps > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "✅ Docker is running"
echo ""

# Check if containers are running
echo "2️⃣  Checking containers..."
if ! docker ps | grep -q "security-correlation-engine-local"; then
    echo "⚠️  Containers not running. Starting..."
    docker-compose -f docker-compose.local.yml up -d
    echo "⏳ Waiting for services to be ready (30 seconds)..."
    sleep 30
else
    echo "✅ Containers already running"
fi
echo ""

# Verify Ollama
echo "3️⃣  Checking AI model..."
docker exec security-ollama bash -c "ollama list" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ AI model (Ollama) is ready"
else
    echo "⚠️  AI model loading... this may take a minute"
fi
echo ""

# Copy test scripts
echo "4️⃣  Preparing test scripts..."
docker cp test_idor_improved.py security-correlation-engine-local:/tmp/ > /dev/null 2>&1
docker cp test_complete_workflow.py security-correlation-engine-local:/tmp/ > /dev/null 2>&1
docker cp validate_patches.py security-correlation-engine-local:/tmp/ > /dev/null 2>&1
docker cp demo_real_app.py security-correlation-engine-local:/tmp/ > /dev/null 2>&1
echo "✅ Test scripts ready"
echo ""

# Start dashboard (optional)
echo "5️⃣  Starting web dashboard..."
docker exec -d security-correlation-engine-local bash -c "cd /app && python3 correlation-engine/dashboard_app.py" > /dev/null 2>&1
sleep 3
echo "✅ Dashboard starting at http://localhost:8080"
echo ""

# Run a quick test
echo "6️⃣  Running quick health check..."
docker exec security-correlation-engine-local bash -c "cd /tmp && python3 -c 'import sys; sys.path.insert(0, \"/app\"); print(\"✅ Python environment OK\")'" 2>/dev/null
echo ""

# Display URLs
echo "================================================================================================="
echo "✅ SETUP COMPLETE! Open these URLs:"
echo "================================================================================================="
echo ""
echo "📊 Web Dashboard:       http://localhost:8080"
echo "📖 API Documentation:   http://localhost:8000/docs"
echo "🖥️  Platform Status:     docker ps"
echo ""
echo "================================================================================================="
echo "🎯 QUICK DEMO COMMANDS:"
echo "================================================================================================="
echo ""
echo "1. IDOR Test (100% success, 5 vulnerabilities):"
echo "   docker exec security-correlation-engine-local bash -c \"cd /tmp && python3 test_idor_improved.py\""
echo ""
echo "2. E2E Workflow (Complete automation demo):"
echo "   docker exec security-correlation-engine-local bash -c \"cd /tmp && python3 test_complete_workflow.py\""
echo ""
echo "3. Validate Patches (Verify fixes work):"
echo "   docker exec security-correlation-engine-local bash -c \"cd /tmp && python3 validate_patches.py\""
echo ""
echo "4. 🎯 COMPLETE REAL APP DEMO (RECOMMENDED FOR PRESENTATION):"
echo "   docker exec -it security-correlation-engine-local bash -c \"cd /tmp && python3 demo_real_app.py\""
echo "   Shows: Scan → Detect → Patch → Validate → Create PR on DVWA"
echo ""
echo "================================================================================================="
echo "📁 PRESENTATION FILES:"
echo "================================================================================================="
echo ""
echo "📄 COMPLETE-DEMO-GUIDE.md        - 🎯 Real app demo guide (Scan→Patch→PR)"
echo "📄 PRESENTATION-GUIDE.md         - Complete presentation guide"
echo "📄 IDOR-TEST-SUCCESS.md          - IDOR test detailed results"
echo "📄 E2E-WORKFLOW-COMPLETE.md      - E2E workflow documentation"
echo "📄 IDOR-COMPLETE-SUMMARY.txt     - Quick IDOR summary"
echo "📊 idor-report.json              - JSON results"
echo ""
echo "================================================================================================="
echo "💡 TIPS:"
echo "================================================================================================="
echo ""
echo "• Dashboard auto-refreshes every 30 seconds"
echo "• All tests save reports in /tmp/ inside containers"
echo "• Use 'docker exec' commands above for live demos"
echo "• Check PRESENTATION-GUIDE.md for full demo script"
echo ""
echo "🎤 Ready to present! Good luck! 🚀"
echo "================================================================================================="
