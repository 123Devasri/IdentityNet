@echo off
rem =============================================================================
rem  IdentityNet Windows C Gateway Build Script (GCC / MinGW)
rem =============================================================================

echo =====================================================================
echo  Compiling IdentityNet Windows C Gateway Server...
echo =====================================================================

where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set CC=gcc
) else if exist "D:\FOLDER\CodeBlocks\MinGW\bin\gcc.exe" (
    set CC="D:\FOLDER\CodeBlocks\MinGW\bin\gcc.exe"
) else (
    echo [ERROR] gcc.exe was not found on PATH.
    exit /b 1
)

if not exist bin mkdir bin

echo Compiling C source files...
%CC% -O2 -std=c11 ^
  src/main.c ^
  src/network.c ^
  src/policy.c ^
  src/clients.c ^
  src/logger.c ^
  src/dns_server.c ^
  src/contest_server.c ^
  wfp/wfp_manager.c ^
  -I. -Isrc -Iwfp ^
  -lws2_32 -liphlpapi ^
  -o bin/IdentityNet.exe

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo =====================================================================
echo  Build Successful! Output binary: bin/IdentityNet.exe
echo  Run IdentityNet Gateway:
echo    bin\IdentityNet.exe 80
echo =====================================================================
