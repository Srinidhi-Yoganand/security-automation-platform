#!/bin/bash
# Docker Deployment Test Script

set -e

echo "==========================================="
echo "Docker Deployment Test"
echo "==========================================="
echo ""

# Test 1: Check Docker is running
echo "[1/8] Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "✅ Docker is running"

# Test 2: Check docker-compose.yml exists
echo ""
echo "[2/8] Checking docker-compose.yml..."
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml not found"
    exit 1
fi
echo "✅ docker-compose.yml found"

# Test 3: Validate docker-compose.yml
echo ""
echo "[3/8] Validating configuration..."
if ! docker-compose config > /dev/null 2>&1; then
    echo "❌ Invalid docker-compose.yml"
    docker-compose config
    exit 1
fi
echo "✅ Configuration valid"

# Test 4: Build images
echo ""
echo "[4/8] Building images (this may take a few minutes)..."
docker-compose build || {
    echo "❌ Build failed"
    exit 1
}
echo "✅ Images built successfully"

# Test 5: Start services
echo ""
echo "[5/8] Starting services..."
docker-compose up -d || {
    echo "❌ Failed to start services"
    exit 1
}
echo "✅ Services started"

# Test 6: Wait for services to be healthy
echo ""
echo "[6/8] Waiting for services to be healthy (60s)..."
sleep 10
echo "  - Waiting... (10s)"
sleep 10
echo "  - Waiting... (20s)"
sleep 10
echo "  - Waiting... (30s)"
sleep 10
echo "  - Waiting... (40s)"
sleep 10
echo "  - Waiting... (50s)"
sleep 10
echo "  - Waiting... (60s)"

# Test 7: Check service health
echo ""
echo "[7/8] Checking service health..."

# Check Ollama
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama is responding"
else
    echo "⚠️  Ollama not responding yet (may still be starting)"
fi

# Check API
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ API is responding"
else
    echo "⚠️  API not responding yet"
fi

# Check vulnerable app
if curl -s http://localhost:8080/actuator/health > /dev/null 2>&1; then
    echo "✅ Vulnerable app is responding"
else
    echo "⚠️  Vulnerable app not responding yet"
fi

# Test 8: Test LLM status
echo ""
echo "[8/8] Testing LLM provider status..."
LLM_STATUS=$(curl -s http://localhost:8000/api/llm/status 2>/dev/null || echo "error")
if echo "$LLM_STATUS" | grep -q "provider"; then
    echo "✅ LLM status endpoint working"
    echo "$LLM_STATUS" | python3 -m json.tool 2>/dev/null || echo "$LLM_STATUS"
else
    echo "⚠️  LLM status not available yet"
fi

# Summary
echo ""
echo "==========================================="
echo "Deployment Test Complete!"
echo "==========================================="
echo ""
echo "Service URLs:"
echo "  - API:           http://localhost:8000"
echo "  - API Docs:      http://localhost:8000/docs"
echo "  - Ollama:        http://localhost:11434"
echo "  - Vulnerable App: http://localhost:8080"
echo ""
echo "Check logs:"
echo "  docker-compose logs -f"
echo ""
echo "Stop services:"
echo "  docker-compose down"
echo ""
