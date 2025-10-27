#!/bin/bash
# Build and push Docker image to Docker Hub

set -e

echo "🐳 Building Security Automation Platform Docker Image..."

# Build the image
docker build -t srinidhiyoganand/security-automation-platform:latest \
             -t srinidhiyoganand/security-automation-platform:v1.0 \
             -f Dockerfile \
             --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
             --build-arg VCS_REF=$(git rev-parse --short HEAD) \
             .

echo "✅ Image built successfully!"
echo ""
echo "📊 Image details:"
docker images srinidhiyoganand/security-automation-platform

echo ""
echo "🔑 Logging into Docker Hub..."
echo "Please enter your Docker Hub credentials:"
docker login

echo ""
echo "📤 Pushing to Docker Hub..."
docker push srinidhiyoganand/security-automation-platform:latest
docker push srinidhiyoganand/security-automation-platform:v1.0

echo ""
echo "✅ Successfully pushed to Docker Hub!"
echo ""
echo "🎉 Your image is now available at:"
echo "   docker pull srinidhiyoganand/security-automation-platform:latest"
echo ""
echo "Users can now run:"
echo "   docker-compose up -d"
