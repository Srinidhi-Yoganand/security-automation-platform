#!/bin/bash
# Docker diagnostics and auto-fix script for Security Automation Platform

set -e

echo "======================================================================"
echo "🔍 Security Automation Platform - Docker Diagnostics"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track issues
ISSUES_FOUND=0

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# 1. Check Docker is installed
echo "1️⃣  Checking Docker installation..."
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    print_status 0 "Docker is installed: $DOCKER_VERSION"
else
    print_status 1 "Docker is not installed"
    echo "   Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/"
    exit 1
fi

echo ""

# 2. Check Docker is running
echo "2️⃣  Checking if Docker daemon is running..."
if docker ps &> /dev/null; then
    print_status 0 "Docker daemon is running"
else
    print_status 1 "Docker daemon is not running"
    echo "   Please start Docker Desktop"
    echo ""
    echo "   Windows: Search for 'Docker Desktop' in Start Menu"
    echo "   Mac: Open Docker Desktop from Applications"
    echo "   Linux: sudo systemctl start docker"
    exit 1
fi

echo ""

# 3. Check Docker Compose
echo "3️⃣  Checking Docker Compose..."
if docker compose version &> /dev/null; then
    COMPOSE_VERSION=$(docker compose version)
    print_status 0 "Docker Compose available: $COMPOSE_VERSION"
else
    print_status 1 "Docker Compose not available"
fi

echo ""

# 4. Check ports availability
echo "4️⃣  Checking port availability..."

check_port() {
    PORT=$1
    if nc -z localhost $PORT 2>/dev/null || netstat -an 2>/dev/null | grep -q ":$PORT "; then
        print_status 1 "Port $PORT is in use"
        echo "   To find what's using it:"
        echo "     Windows: netstat -ano | findstr :$PORT"
        echo "     Linux/Mac: lsof -i :$PORT"
        return 1
    else
        print_status 0 "Port $PORT is available"
        return 0
    fi
}

check_port 8000
check_port 11434

echo ""

# 5. Check Docker images
echo "5️⃣  Checking Docker images..."
if docker images | grep -q "srinidhiyoganand/security-automation-platform"; then
    IMAGE_ID=$(docker images srinidhiyoganand/security-automation-platform:latest -q)
    print_status 0 "Platform image exists (ID: ${IMAGE_ID:0:12})"
else
    print_warning "Platform image not found locally - will be pulled on first run"
fi

if docker images | grep -q "ollama/ollama"; then
    print_status 0 "Ollama image exists"
else
    print_warning "Ollama image not found - will be pulled on first run"
fi

echo ""

# 6. Check existing containers
echo "6️⃣  Checking existing containers..."
if docker ps -a | grep -q "security-correlation-engine"; then
    CONTAINER_STATUS=$(docker ps -a --filter "name=security-correlation-engine" --format "{{.Status}}")
    echo "   Container exists: $CONTAINER_STATUS"
    
    if docker ps | grep -q "security-correlation-engine"; then
        print_status 0 "Container is running"
    else
        print_warning "Container exists but is not running"
        echo "   To start: docker compose up -d"
    fi
else
    print_warning "No existing containers found (this is OK for first run)"
fi

echo ""

# 7. Check volumes
echo "7️⃣  Checking Docker volumes..."
for volume in security-ollama-models security-correlation-data security-codeql-cache; do
    if docker volume ls | grep -q "$volume"; then
        print_status 0 "Volume '$volume' exists"
    else
        print_warning "Volume '$volume' not found (will be created on first run)"
    fi
done

echo ""

# 8. Check disk space
echo "8️⃣  Checking disk space..."
DISK_USAGE=$(docker system df 2>/dev/null || echo "Unable to check")
echo "$DISK_USAGE"

echo ""

# 9. Check memory
echo "9️⃣  Checking Docker resources..."
if docker info 2>/dev/null | grep -q "Total Memory"; then
    MEMORY=$(docker info 2>/dev/null | grep "Total Memory" | awk '{print $3 $4}')
    print_status 0 "Available memory: $MEMORY"
    
    # Check if memory is sufficient (at least 4GB)
    MEM_GB=$(docker info 2>/dev/null | grep "Total Memory" | awk '{print $3}' | sed 's/GiB//')
    if (( $(echo "$MEM_GB < 4" | bc -l 2>/dev/null || echo "0") )); then
        print_warning "Docker has less than 4GB RAM - may cause issues with Ollama"
        echo "   Increase memory in Docker Desktop → Settings → Resources"
    fi
fi

echo ""

# 10. Test connectivity to Docker Hub
echo "🔟 Checking Docker Hub connectivity..."
if timeout 5 docker pull hello-world:latest &> /dev/null; then
    print_status 0 "Can pull images from Docker Hub"
    docker rmi hello-world:latest &> /dev/null
else
    print_warning "Unable to pull from Docker Hub - check internet connection"
fi

echo ""

# Summary
echo "======================================================================"
echo "📊 Diagnostic Summary"
echo "======================================================================"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ All checks passed! Your environment is ready.${NC}"
    echo ""
    echo "To start the platform:"
    echo "  docker compose up -d"
    echo ""
    echo "To check status:"
    echo "  docker compose ps"
    echo ""
    echo "To view logs:"
    echo "  docker compose logs -f"
    echo ""
    echo "To access:"
    echo "  Dashboard: http://localhost:8000/api/v1/e2e/dashboard"
    echo "  API Docs:  http://localhost:8000/docs"
    echo ""
else
    echo -e "${RED}❌ Found $ISSUES_FOUND issue(s) that need attention.${NC}"
    echo ""
    echo "Please address the issues above before starting the platform."
fi

echo ""
echo "For more help, see: DOCKER-SETUP-GUIDE.md"
echo "======================================================================"
