@echo off
setlocal enabledelayedexpansion
title SPECTRA Tactical Suite Launcher
cd /d "%~dp0"

echo ================================================================================
echo    SPECTRA // TACTICAL AIR-GAPPED FORENSIC SUITE LAUNCHER
echo    Pure Go - Zero Persistence - Standalone Binary Execution
echo ================================================================================
echo.

echo [*] 1. Menghentikan sesi lama jika ada...
taskkill /F /IM spectra.exe >nul 2>&1
taskkill /F /IM cloudflared.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul

echo [*] 2. Memeriksa biner SPECTRA (spectra.exe)...
if not exist "%~dp0spectra.exe" (
    echo [!] spectra.exe belum dikompilasi. Mengompilasi sekarang...
    call "%~dp0build_all.bat"
    if not exist "%~dp0spectra.exe" (
        echo [-] Error: Gagal mengompilasi spectra.exe.
        pause
        exit /b 1
    )
)

echo [+] 3. Menjalankan SPECTRA Core Engine (Web: 8888, SSH: 2222)...
start "SPECTRA Tactical Engine" "%~dp0spectra.exe" -port 8888 -ssh-port 2222
ping -n 3 127.0.0.1 >nul

echo [+] 4. Membuka Dashboard Taktis di Browser Default...
start http://127.0.0.1:8888/dashboard

echo.
echo [*] 5. Memeriksa Cloudflare Tunnel (Opsional untuk Akses Publik)...
set "CF_BIN="
if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" set "CF_BIN=C:\Program Files (x86)\cloudflared\cloudflared.exe"
if not defined CF_BIN (
    if exist "C:\Program Files\cloudflared\cloudflared.exe" set "CF_BIN=C:\Program Files\cloudflared\cloudflared.exe"
)
if not defined CF_BIN (
    where cloudflared >nul 2>&1
    if !errorlevel! equ 0 set "CF_BIN=cloudflared"
)

if defined CF_BIN (
    echo     [+] Cloudflare binary ditemukan. Mengaktifkan terowongan publik...
    if exist "%~dp0tunnel_session.log" del /f /q "%~dp0tunnel_session.log"
    if exist "%~dp0public_url.txt" del /f /q "%~dp0public_url.txt"
    start "Cloudflare Tunnel" /min cmd /c ""!CF_BIN!" tunnel --url http://127.0.0.1:8888 > "%~dp0tunnel_session.log" 2>&1"
    
    echo     [*] Menghubungkan ke Cloudflare Edge (5 detik)...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$url = ''; for ($i=0; $i -lt 8; $i++) { Start-Sleep -Seconds 1; if (Test-Path '%~dp0tunnel_session.log') { $m = Select-String -Path '%~dp0tunnel_session.log' -Pattern 'https://[a-zA-Z0-9-]+\.trycloudflare\.com'; if ($m) { $url = $m.Matches[0].Value; break } } }; if ($url) { Set-Content -Path '%~dp0public_url.txt' -Value $url }"
) else (
    echo     [i] Cloudflare Tunnel tidak terpasang (Mode Offline / Air-Gapped Lokal Aktif).
)

cls
echo ================================================================================
echo          SPECTRA // TACTICAL AIR-GAPPED SUITE ONLINE
echo ================================================================================
echo.
echo   [★] LOCAL WEB DASHBOARD     : http://127.0.0.1:8888/dashboard
echo   [★] LOCAL WEB LANDING PAGE  : http://127.0.0.1:8888/
echo   [★] LOCAL SSH GATEWAY       : ssh -p 2222 spectra@127.0.0.1
echo.

if exist "%~dp0public_url.txt" (
    set /p PUBLIC_URL=<"%~dp0public_url.txt"
    echo   [★] PUBLIC CLOUD TUNNEL     : !PUBLIC_URL!/dashboard
    echo   [★] PUBLIC TERMINAL API     : curl -F "pcap_file=@capture.pcap" !PUBLIC_URL!/api/cli
    echo.
)

echo --------------------------------------------------------------------------------
echo   FITUR TERSEDIA PADA SESI INI:
echo   • 1-Click Multi-Vector Attack Simulation (Ctrl+D)
echo   • 📢 Executive War-Room Briefing (Naratif Bahasa Manusia untuk Pimpinan)
echo   • 📋 Tactical Incident Containment Playbook (P1/P2/P3 Action Steps)
echo   • 🛡️ Auto Blocklist Generator (iptables, Windows Firewall, Suricata)
echo   • ⚡ Universal One-Liner Deployer (Linux, Windows, Termux)
echo --------------------------------------------------------------------------------
echo.
echo [*] SPECTRA aktif di latar belakang. Tekan tombol apa saja untuk mematikan layanan.
echo.
pause

echo.
echo [*] Mematikan seluruh proses SPECTRA...
taskkill /F /IM spectra.exe >nul 2>&1
taskkill /F /IM cloudflared.exe >nul 2>&1
echo [✓] Seluruh layanan SPECTRA berhasil dinonaktifkan.
timeout /t 2 /nobreak >nul
exit /b 0
