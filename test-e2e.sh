#!/bin/bash
# Comprehensive End-to-End Testing Script for Security Automation Platform

echo "=========================================="
echo "SECURITY AUTOMATION PLATFORM - E2E TESTS"
echo "=========================================="
echo ""

# Test 1: Health Check
echo "[TEST 1] Health Check..."
curl -s http://localhost:8000/health | jq '.'
echo ""

# Test 2: Scan Python File (No AI)
echo "[TEST 2] Scanning vulnerable_python.py (Pattern Matching)..."
curl -s -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{"source_path":"/app/test_vuln.py","output_dir":"/tmp/patches","enable_ai_patching":false}' | \
jq '{success, vulnerabilities_found, results: [.results[] | {type, line: .line_number, severity}]}'
echo ""

# Test 3: Check Ollama Availability
echo "[TEST 3] Checking Ollama Model..."
curl -s http://localhost:11434/api/tags | jq '.models[] | {name, size}'
echo ""

# Test 4: Scan with AI Patching (if Ollama available)
echo "[TEST 4] Scanning with AI Patching Enabled..."
curl -s -X POST http://localhost:8000/api/v1/e2e/analyze-and-fix \
  -H "Content-Type: application/json" \
  -d '{"source_path":"/app/vuln_complete.py","output_dir":"/tmp/patches","enable_ai_patching":true,"llm_provider":"ollama"}' | \
jq '{success, vulnerabilities_found, vulnerabilities_fixed}'
echo ""

# Test 5: Dashboard Check
echo "[TEST 5] Dashboard Accessibility..."
curl -s http://localhost:8000/api/v1/e2e/dashboard | grep -o '<title>.*</title>'
echo "Dashboard: http://localhost:8000/api/v1/e2e/dashboard"
echo ""

echo "=========================================="
echo "E2E TESTS COMPLETED"
echo "=========================================="
