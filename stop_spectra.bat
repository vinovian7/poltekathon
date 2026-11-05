@echo off
title SPECTRA Tactical Shutdown
cd /d "%~dp0"

echo [*] Mematikan seluruh proses SPECTRA dan Cloudflare Tunnel...
taskkill /F /IM spectra.exe >nul 2>&1
taskkill /F /IM cloudflared.exe >nul 2>&1

if exist "%~dp0public_url.txt" del /f /q "%~dp0public_url.txt"
if exist "%~dp0tunnel_session.log" del /f /q "%~dp0tunnel_session.log"

echo.
echo ================================================================================
echo   [OK] Seluruh layanan SPECTRA dan Cloudflare Tunnel berhasil dimatikan bersih.
echo   Memori dan sumber daya sistem telah dikembalikan sepenuhnya.
echo ================================================================================
echo.
ping -n 3 127.0.0.1 >nul
