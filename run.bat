@echo off
rem =============================================================================
rem  IdentityNet Windows Launcher Script
rem =============================================================================

echo =====================================================================
echo  Starting IdentityNet Gateway Server via Python...
echo =====================================================================

set PORT=8080
if not "%~1"=="" set PORT=%~1

python src/main.py --port %PORT%
