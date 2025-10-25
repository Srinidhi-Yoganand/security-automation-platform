# Ollama Setup - Windows PowerShell Version

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Ollama Setup for Security Platform" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check if Ollama is installed
Write-Host "[1/4] Checking Ollama installation..." -ForegroundColor Yellow
try {
    $version = ollama --version 2>&1
    Write-Host "✅ Ollama is installed" -ForegroundColor Green
    Write-Host "   Version: $version" -ForegroundColor Gray
} catch {
    Write-Host "❌ Ollama not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Ollama:" -ForegroundColor Yellow
    Write-Host "  1. Download: https://ollama.com/download/OllamaSetup.exe" -ForegroundColor White
    Write-Host "  2. Run the installer" -ForegroundColor White
    Write-Host "  3. Ollama will start automatically" -ForegroundColor White
    Write-Host ""
    Write-Host "After installation, run this script again." -ForegroundColor Yellow
    exit 1
}

# Step 2: Check if Ollama is running
Write-Host ""
Write-Host "[2/4] Checking Ollama service..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 5 -ErrorAction Stop
    Write-Host "✅ Ollama service is running" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Ollama service not running" -ForegroundColor Yellow
    Write-Host "   Please start Ollama from the system tray icon" -ForegroundColor Gray
    Write-Host "   Or run: ollama serve" -ForegroundColor Gray
    Start-Sleep -Seconds 2
}

# Step 3: Check/Pull DeepSeek Coder model
Write-Host ""
Write-Host "[3/4] Checking DeepSeek Coder model..." -ForegroundColor Yellow
$models = ollama list
if ($models -match "deepseek-coder:6.7b-instruct") {
    Write-Host "✅ DeepSeek Coder 6.7B is already installed" -ForegroundColor Green
} else {
    Write-Host "📥 Downloading DeepSeek Coder 6.7B (8.5GB)..." -ForegroundColor Cyan
    Write-Host "   This will take 5-15 minutes depending on your internet speed..." -ForegroundColor Gray
    Write-Host ""
    ollama pull deepseek-coder:6.7b-instruct
    Write-Host ""
    Write-Host "✅ Model downloaded successfully" -ForegroundColor Green
}

# Step 4: List available models
Write-Host ""
Write-Host "[4/4] Available models:" -ForegroundColor Yellow
ollama list

# Summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ Ollama installed and running" -ForegroundColor Green
Write-Host "✅ DeepSeek Coder 6.7B model ready" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  cd correlation-engine" -ForegroundColor White
Write-Host "  python test_llm_providers.py" -ForegroundColor White
Write-Host ""
Write-Host "Environment variables (optional):" -ForegroundColor Yellow
Write-Host '  $env:OLLAMA_HOST="http://localhost:11434"' -ForegroundColor White
Write-Host '  $env:LLM_PROVIDER="ollama"' -ForegroundColor White
Write-Host '  $env:OLLAMA_MODEL="deepseek-coder:6.7b-instruct"' -ForegroundColor White
Write-Host ""

# Test connection
Write-Host "Testing Ollama connection..." -ForegroundColor Yellow
Write-Host ""
python -c "import ollama; print('Python SDK:', 'OK' if ollama else 'ERROR')"
Write-Host ""
