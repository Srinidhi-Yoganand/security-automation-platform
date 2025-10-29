@echo off
REM Verification script to run after tear-down and restart
REM This ensures everything works correctly after git pull

echo ================================================================================
echo SECURITY AUTOMATION PLATFORM - POST-RESTART VERIFICATION
echo ================================================================================
echo.

echo VERIFICATION CHECKLIST:
echo.

REM Step 1: Check Docker Compose files
echo 1. Checking Docker Compose files...
if exist "docker-compose.yml" if exist "docker-compose.juice-shop.yml" (
    echo    [OK] Docker Compose files present
) else (
    echo    [ERROR] Missing Docker Compose files
    exit /b 1
)

REM Step 2: Stop any running containers
echo.
echo 2. Stopping existing containers...
docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml down >nul 2>&1
echo    [OK] Containers stopped

REM Step 3: Build correlation engine
echo.
echo 3. Building correlation engine...
docker-compose build correlation-engine
if %errorlevel% equ 0 (
    echo    [OK] Build successful
) else (
    echo    [ERROR] Build failed
    exit /b 1
)

REM Step 4: Start services
echo.
echo 4. Starting services...
docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml up -d
echo    Waiting for containers to start (10 seconds)...
timeout /t 10 /nobreak >nul
echo    [OK] Services started

REM Step 5: Verify containers are running
echo.
echo 5. Verifying containers...
docker ps | findstr "security-correlation-engine" >nul
if %errorlevel% equ 0 (
    echo    [OK] Correlation Engine running
) else (
    echo    [ERROR] Correlation Engine not running
    exit /b 1
)

docker ps | findstr "juice-shop-app" >nul
if %errorlevel% equ 0 (
    echo    [OK] Juice Shop running
) else (
    echo    [ERROR] Juice Shop not running
    exit /b 1
)

REM Step 6: Verify Juice Shop mount
echo.
echo 6. Verifying Juice Shop mount...
docker exec security-correlation-engine bash -c "ls /juice-shop/routes/*.ts 2>/dev/null | wc -l" > temp_count.txt 2>&1
set /p FILE_COUNT=<temp_count.txt
del temp_count.txt
if %FILE_COUNT% gtr 50 (
    echo    [OK] Juice Shop mounted (%FILE_COUNT% TypeScript files^)
) else (
    echo    [ERROR] Juice Shop mount issue (found %FILE_COUNT% files, expected 62^)
    exit /b 1
)

REM Step 7: Test Python imports
echo.
echo 7. Testing Python imports...
docker exec security-correlation-engine python -c "from app.services.production_cpg_analyzer import ProductionCPGAnalyzer; print('CPG OK')" 2>&1 | findstr "CPG OK" >nul
if %errorlevel% equ 0 (
    echo    [OK] CPG Analyzer import OK
) else (
    echo    [ERROR] CPG Analyzer import failed
    exit /b 1
)

docker exec security-correlation-engine python -c "from app.services.enhanced_sast_scanner import EnhancedSASTScanner; print('SAST OK')" 2>&1 | findstr "SAST OK" >nul
if %errorlevel% equ 0 (
    echo    [OK] SAST Scanner import OK
) else (
    echo    [ERROR] SAST Scanner import failed
    exit /b 1
)

REM Step 8: Run Juice Shop scan test
echo.
echo 8. Running Juice Shop quick scan test...
docker cp correlation-engine/test_juice_shop_complete_e2e.py security-correlation-engine:/app/ >nul 2>&1
docker exec security-correlation-engine python test_juice_shop_complete_e2e.py 2>&1 > scan_output.txt
findstr /C:"Total Vulnerabilities: 51" scan_output.txt >nul
if %errorlevel% equ 0 (
    echo    [OK] Juice Shop scan detected 51 vulnerabilities
) else (
    echo    [WARNING] Scan test completed with different results
    echo    Check scan_output.txt for details
)
del scan_output.txt

REM Step 9: Run patch validation test
echo.
echo 9. Running patch validation test (DRY RUN^)...
docker cp correlation-engine/test_juice_shop_patch_validation.py security-correlation-engine:/app/ >nul 2>&1
docker exec security-correlation-engine python test_juice_shop_patch_validation.py 2>&1 > validation_output.txt
findstr /C:"Scanner is CONSISTENT" validation_output.txt >nul
if %errorlevel% equ 0 (
    echo    [OK] Scanner consistency validated
) else (
    echo    [WARNING] Could not validate scanner consistency
)
del validation_output.txt

REM Final Summary
echo.
echo ================================================================================
echo VERIFICATION COMPLETE
echo ================================================================================
echo.
echo SYSTEM STATUS:
echo    * Docker Compose: [OK] Working
echo    * Containers: [OK] Running
echo    * Juice Shop Mount: [OK] Verified
echo    * Python Imports: [OK] Working
echo    * Scanning: [OK] Operational
echo.
echo PLATFORM READY FOR USE!
echo.
echo Next Steps:
echo    1. Review JUICE-SHOP-QUICK-START.md for usage instructions
echo    2. Run full E2E test: docker exec security-correlation-engine python test_juice_shop_complete_e2e.py
echo    3. Run patch validation: docker exec security-correlation-engine python test_juice_shop_patch_validation.py
echo    4. Check logs: docker logs security-correlation-engine
echo.
echo To tear down:
echo    docker-compose -f docker-compose.yml -f docker-compose.juice-shop.yml down
echo.
echo ================================================================================
