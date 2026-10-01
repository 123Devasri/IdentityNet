@echo off
rem =============================================================================
rem  IdentityNet Windows C Gateway Build Script (GCC / MinGW)
rem =============================================================================

echo =====================================================================
echo  Compiling IdentityNet Windows C Gateway Server...
echo =====================================================================

set GCC_PATH="C:\Program Files\CodeBlocks\MinGW\bin\gcc.exe"

if exist %GCC_PATH% (
    set CC=%GCC_PATH%
) else (
    set CC=gcc
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
