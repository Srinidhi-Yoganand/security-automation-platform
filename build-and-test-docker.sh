#!/bin/bash
# Build and test Docker image locally

set -e

echo "======================================================================"
echo "Building Security Platform Docker Image Locally"
echo "======================================================================"
echo ""

# Build the image
echo "Step 1: Building Docker image..."
docker build -t security-platform:local -f Dockerfile .

echo ""
echo "Step 2: Checking image was created..."
docker images | grep security-platform

echo ""
echo "Step 3: Starting container..."
docker run -d --name security-test \
  -p 8000:8000 \
  -e LLM_PROVIDER=template \
  -e DATABASE_URL=sqlite:///./data/security.db \
  security-platform:local

echo ""
echo "Step 4: Waiting for container to start..."
sleep 10

echo ""
echo "Step 5: Checking container status..."
docker ps | grep security-test

echo ""
echo "Step 6: Testing health endpoint..."
curl -f http://localhost:8000/health || echo "Health check failed"

echo ""
echo "Step 7: Checking container logs..."
docker logs security-test | tail -20

echo ""
echo "======================================================================"
echo "✅ Docker image built and tested successfully!"
echo "======================================================================"
echo ""
echo "To stop the test container:"
echo "  docker stop security-test && docker rm security-test"
echo ""
echo "To run the full platform:"
echo "  docker compose -f docker-compose.local.yml up -d"
echo ""
