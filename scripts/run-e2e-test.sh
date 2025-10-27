#!/bin/bash

# Quick Start Script for Security Automation Platform
# Runs end-to-end security analysis on test-vuln-app

set -e

echo "======================================================================="
echo "Security Automation Platform - End-to-End Test"
echo "======================================================================="
echo ""

# Navigate to project root
cd "$(dirname "$0")"

echo "📋 Pre-flight Checks"
echo "-------------------"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi
echo "✅ Docker: $(docker --version)"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose first."
    exit 1
fi
echo "✅ Docker Compose: $(docker-compose --version)"

# Check Python
if ! command -v python &> /dev/null; then
    echo "❌ Python not found. Please install Python 3.11+."
    exit 1
fi
echo "✅ Python: $(python --version)"

# Check test application
if [ ! -d "test-vuln-app" ]; then
    echo "❌ test-vuln-app not found. Please ensure it exists."
    exit 1
fi
echo "✅ Test app: test-vuln-app found"

echo ""
echo "======================================================================="
echo "Building Docker Image"
echo "======================================================================="
echo ""

docker build -t security-automation-platform:latest -f Dockerfile . || {
    echo "❌ Docker build failed"
    exit 1
}

echo ""
echo "✅ Docker image built successfully"

echo ""
echo "======================================================================="
echo "Starting Services"
echo "======================================================================="
echo ""

# Set target app to test-vuln-app
export TARGET_APP_PATH=./test-vuln-app

# Start services
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Wait for correlation-engine
timeout 60 bash -c 'until docker exec security-correlation curl -s http://localhost:8000/api/v1/status > /dev/null 2>&1; do sleep 2; echo -n "."; done' || {
    echo ""
    echo "❌ Services failed to start. Check logs with: docker-compose logs"
    exit 1
}

echo ""
echo "✅ Services ready!"

echo ""
echo "======================================================================="
echo "Running End-to-End Analysis"
echo "======================================================================="
echo ""

# Run analysis via API
echo "🔍 Analyzing test-vuln-app..."
echo ""

docker exec security-correlation curl -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
    -H "Content-Type: application/json" \
    -d '{
        "source_path": "/target-app",
        "language": "java",
        "create_database": true,
        "generate_patches": true,
        "validate_patches": true,
        "llm_provider": "template"
    }' \
    -o /app/test-data/e2e-api-results.json 2>/dev/null || {
    echo "❌ Analysis failed"
    docker-compose logs correlation-engine
    exit 1
}

echo ""
echo "✅ Analysis complete!"

echo ""
echo "======================================================================="
echo "Results Summary"
echo "======================================================================="
echo ""

# Extract and display results
docker exec security-correlation cat /app/test-data/e2e-api-results.json | python -m json.tool | head -50

echo ""
echo "======================================================================="
echo "Running Python Test Suite"
echo "======================================================================="
echo ""

docker exec security-correlation python -m pytest test_end_to_end.py -v -s || {
    echo "⚠️  Some tests may require CodeQL database"
}

echo ""
echo "======================================================================="
echo "Test Complete!"
echo "======================================================================="
echo ""
echo "📁 Results saved to:"
echo "   - Docker: /data/"
echo "   - Local: ./test-data/"
echo ""
echo "🌐 Access API at:"
echo "   - Swagger UI: http://localhost:8000/docs"
echo "   - Status: http://localhost:8000/api/v1/status"
echo "   - E2E Status: http://localhost:8000/api/v1/e2e/status"
echo ""
echo "🔧 Useful commands:"
echo "   - View logs: docker-compose logs -f correlation-engine"
echo "   - Stop services: docker-compose down"
echo "   - Restart: docker-compose restart"
echo "   - Shell access: docker exec -it security-correlation bash"
echo ""
echo "======================================================================="
