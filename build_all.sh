#!/usr/bin/env bash
# ==============================================================================
#    SPECTRA // MULTI-PLATFORM CROSS-COMPILATION BUILD SUITE (BASH)
#    Pure Go - CGo Disabled - Zero External C-Libraries - Static Binaries
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p bin

LDFLAGS="-s -w -X main.Version=2.0-hackathon"
export CGO_ENABLED=0

echo "================================================================================"
echo "   SPECTRA // MULTI-PLATFORM CROSS-COMPILATION BUILD SUITE"
echo "================================================================================"

echo "[+] 1/5 Compiling Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/spectra-windows-amd64.exe ./cmd/spectra
cp -f bin/spectra-windows-amd64.exe spectra.exe 2>/dev/null || true

echo "[+] 2/5 Compiling Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/spectra-linux-amd64 ./cmd/spectra

echo "[+] 3/5 Compiling Linux ARM64 (Termux/RPi)..."
GOOS=linux GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/spectra-linux-arm64 ./cmd/spectra

echo "[+] 4/5 Compiling macOS Intel (Darwin AMD64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o bin/spectra-darwin-amd64 ./cmd/spectra

echo "[+] 5/5 Compiling macOS Apple Silicon (Darwin ARM64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o bin/spectra-darwin-arm64 ./cmd/spectra

echo "================================================================================"
echo "   CROSS-COMPILATION COMPLETE! ALL ARTIFACTS IN bin/:"
echo "================================================================================"
ls -lh bin/
