@echo off
rem =============================================================================
rem  IdentityNet Windows Launcher Script
rem =============================================================================

echo =====================================================================
echo  Starting IdentityNet Gateway Server via Python...
echo =====================================================================

set PORT=8080
if not "%~1"=="" set PORT=%~1

python src\main.py --dry-run --gateway-ip 127.0.0.1 --port %PORT%
