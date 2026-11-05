@echo off
setlocal enabledelayedexpansion
title SPECTRA // Multi-Platform Cross-Compiler
cd /d "%~dp0"

echo ================================================================================
echo    SPECTRA // MULTI-PLATFORM CROSS-COMPILATION BUILD SUITE
echo    Pure Go - CGo Disabled - Zero External C-Libraries - Static Binaries
echo ================================================================================
echo.

if not exist "%~dp0bin" mkdir "%~dp0bin"

set "GO_BIN=go"
where go >nul 2>&1
if %errorlevel% neq 0 (
    if exist "C:\Program Files\Go\bin\go.exe" (
        set "GO_BIN=C:\Program Files\Go\bin\go.exe"
    ) else (
        echo [-] Error: Go compiler not found!
        exit /b 1
    )
)

echo [*] Go Compiler: %GO_BIN%
echo.

set "LDFLAGS=-s -w"
set CGO_ENABLED=0

echo [+] 1/5 Compiling: Windows AMD64 (spectra-windows-amd64.exe)...
set GOOS=windows
set GOARCH=amd64
"%GO_BIN%" build -ldflags "%LDFLAGS%" -o "%~dp0bin\spectra-windows-amd64.exe" ./cmd/spectra
if %errorlevel% equ 0 (
    echo     [OK] bin\spectra-windows-amd64.exe created.
    copy /y "%~dp0bin\spectra-windows-amd64.exe" "%~dp0spectra.exe" >nul 2>&1
) else (
    echo     [FAIL] Windows AMD64 compilation failed!
)

echo [+] 2/5 Compiling: Linux AMD64 (spectra-linux-amd64)...
set GOOS=linux
set GOARCH=amd64
"%GO_BIN%" build -ldflags "%LDFLAGS%" -o "%~dp0bin\spectra-linux-amd64" ./cmd/spectra
if %errorlevel% equ 0 (
    echo     [OK] bin\spectra-linux-amd64 created.
) else (
    echo     [FAIL] Linux AMD64 compilation failed!
)

echo [+] 3/5 Compiling: Linux ARM64 / Termux (spectra-linux-arm64)...
set GOOS=linux
set GOARCH=arm64
"%GO_BIN%" build -ldflags "%LDFLAGS%" -o "%~dp0bin\spectra-linux-arm64" ./cmd/spectra
if %errorlevel% equ 0 (
    echo     [OK] bin\spectra-linux-arm64 created.
) else (
    echo     [FAIL] Linux ARM64 compilation failed!
)

echo [+] 4/5 Compiling: macOS Intel (spectra-darwin-amd64)...
set GOOS=darwin
set GOARCH=amd64
"%GO_BIN%" build -ldflags "%LDFLAGS%" -o "%~dp0bin\spectra-darwin-amd64" ./cmd/spectra
if %errorlevel% equ 0 (
    echo     [OK] bin\spectra-darwin-amd64 created.
) else (
    echo     [FAIL] macOS Intel compilation failed!
)

echo [+] 5/5 Compiling: macOS Apple Silicon (spectra-darwin-arm64)...
set GOOS=darwin
set GOARCH=arm64
"%GO_BIN%" build -ldflags "%LDFLAGS%" -o "%~dp0bin\spectra-darwin-arm64" ./cmd/spectra
if %errorlevel% equ 0 (
    echo     [OK] bin\spectra-darwin-arm64 created.
) else (
    echo     [FAIL] macOS Apple Silicon compilation failed!
)

echo.
echo ================================================================================
echo    CROSS-COMPILATION COMPLETE
echo ================================================================================
dir "%~dp0bin"
echo.
echo [*] Semua binary tersedia di direktori bin/ dan siap di-serve via /bin/ endpoint.
echo [*] Jalankan: spectra.exe -port 8888
echo [*] Lalu klien dapat menggunakan:
echo     curl -sSL http://^<IP^>:8888/install.sh ^| bash
echo     iwr -useb http://^<IP^>:8888/install.ps1 ^| iex
echo.
