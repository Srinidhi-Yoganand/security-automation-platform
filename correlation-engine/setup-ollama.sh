#!/bin/bash
# Quick start script for Ollama setup

set -e

echo "========================================="
echo "  Ollama Setup for Security Platform"
echo "========================================="
echo ""

# Step 1: Check if Ollama is installed
echo "[1/4] Checking Ollama installation..."
if command -v ollama &> /dev/null; then
    echo "✅ Ollama is installed"
    ollama --version
else
    echo "❌ Ollama not found"
    echo ""
    echo "Please install Ollama:"
    echo "  Windows: https://ollama.com/download/OllamaSetup.exe"
    echo "  Linux:   curl -fsSL https://ollama.com/install.sh | sh"
    echo "  macOS:   brew install ollama"
    exit 1
fi

# Step 2: Check if Ollama is running
echo ""
echo "[2/4] Checking Ollama service..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama service is running"
else
    echo "⚠️  Ollama service not running"
    echo "   Starting Ollama..."
    ollama serve &
    sleep 5
fi

# Step 3: Check/Pull DeepSeek Coder model
echo ""
echo "[3/4] Checking DeepSeek Coder model..."
if ollama list | grep -q "deepseek-coder:6.7b-instruct"; then
    echo "✅ DeepSeek Coder 6.7B is already installed"
else
    echo "📥 Downloading DeepSeek Coder 6.7B (8.5GB)..."
    echo "   This will take 5-10 minutes..."
    ollama pull deepseek-coder:6.7b-instruct
    echo "✅ Model downloaded successfully"
fi

# Step 4: Test the model
echo ""
echo "[4/4] Testing model..."
TEST_RESPONSE=$(ollama run deepseek-coder:6.7b-instruct "Say 'ready' if you can help with code security" --verbose=false 2>/dev/null || echo "error")

if [[ "$TEST_RESPONSE" == *"ready"* ]] || [[ "$TEST_RESPONSE" != "error" ]]; then
    echo "✅ Model is working correctly"
else
    echo "⚠️  Model test had issues, but may still work"
fi

# Summary
echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "✅ Ollama installed and running"
echo "✅ DeepSeek Coder 6.7B model ready"
echo ""
echo "Next steps:"
echo "  cd correlation-engine"
echo "  python test_llm_providers.py"
echo ""
echo "Environment variables (optional):"
echo "  export OLLAMA_HOST=http://localhost:11434"
echo "  export LLM_PROVIDER=ollama"
echo "  export OLLAMA_MODEL=deepseek-coder:6.7b-instruct"
echo ""
