#!/bin/bash
# Docker build with progress tracking

echo "======================================================================"
echo "Building Security Automation Platform Docker Image"
echo "======================================================================"
echo ""
echo "This will take 10-15 minutes (downloading CodeQL, building layers)..."
echo ""

# Build with progress
docker build \
  --progress=plain \
  --tag security-platform:local \
  --file Dockerfile \
  . 2>&1 | tee docker-build.log

echo ""
echo "======================================================================"
echo "Build Complete!"
echo "======================================================================"
echo ""
echo "Check the image:"
echo "  docker images | grep security-platform"
echo ""
echo "Run the container:"
echo "  docker run -d -p 8000:8000 --name test-platform security-platform:local"
echo ""
echo "Test the API:"
echo "  curl http://localhost:8000/health"
echo ""
