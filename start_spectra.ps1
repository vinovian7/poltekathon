# SPECTRA Tactical Launcher with Cloudflare Tunnel
$Host.UI.RawUI.WindowTitle = "SPECTRA // Tactical Cloudflare Tunnel Launcher"
Clear-Host

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   SPECTRA // TACTICAL AIR-GAPPED SUITE - CLOUDFLARE TUNNEL LAUNCHER" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[*] Menghentikan proses lama jika ada..." -ForegroundColor Yellow

Stop-Process -Name "spectra" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "cloudflared" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Write-Host "[+] 1. Menjalankan Engine SPECTRA (Web: 8888, SSH: 2222)..." -ForegroundColor Green
$spectraProc = Start-Process -FilePath "$PSScriptRoot\spectra.exe" -ArgumentList "-port 8888 -ssh-port 2222" -PassThru -NoNewWindow

Start-Sleep -Seconds 1

Write-Host "[+] 2. Membuka Cloudflare Quick Tunnel ke Internet..." -ForegroundColor Green
$cloudflaredBin = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflaredBin)) {
    $found = (Get-Command cloudflared -ErrorAction SilentlyContinue)
    if ($found) { $cloudflaredBin = $found.Source }
}

$logFile = "$PSScriptRoot\tunnel_session.log"
if (Test-Path $logFile) { Remove-Item $logFile -Force }

$cfProc = Start-Process -FilePath $cloudflaredBin -ArgumentList "tunnel --url http://127.0.0.1:8888" -PassThru -NoNewWindow -RedirectStandardError $logFile

Write-Host "[*] Menghubungkan ke Cloudflare Edge Servers (menunggu URL publik)..." -ForegroundColor Yellow

$tunnelUrl = ""
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $logFile) {
        $match = Select-String -Path $logFile -Pattern "https://[a-zA-Z0-9-]+\.trycloudflare\.com"
        if ($match) {
            $tunnelUrl = $match.Matches[0].Value
            break
        }
    }
}

Clear-Host
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "          SPECTRA // TACTICAL SUITE ONLINE - CLOUDFLARE TUNNEL ACTIVE" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
if ($tunnelUrl) {
    Write-Host "  [★] PUBLIC WEB LANDING PAGE : " -NoNewline -ForegroundColor Yellow
    Write-Host "$tunnelUrl" -ForegroundColor Cyan
    Write-Host "  [★] PUBLIC TACTICAL HUD     : " -NoNewline -ForegroundColor Yellow
    Write-Host "$tunnelUrl/dashboard" -ForegroundColor Green
} else {
    Write-Host "  [!] Cloudflare Tunnel sedang memproses. Cek file tunnel_session.log" -ForegroundColor Red
}
Write-Host "  [★] LOCAL WEB DASHBOARD     : " -NoNewline -ForegroundColor Yellow
Write-Host "http://127.0.0.1:8888/dashboard" -ForegroundColor White
Write-Host "  [★] LOCAL SSH GATEWAY       : " -NoNewline -ForegroundColor Yellow
Write-Host "ssh -p 2222 spectra@127.0.0.1" -ForegroundColor Magenta
Write-Host ""
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  [CARA MENGAKSES & MENGIRIM PCAP DARI PERANGKAT CLIENT / LAPTOP LAIN]:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Akses Web UI di Browser (Semua Device / HP / Laptop):" -ForegroundColor White
Write-Host "     Buka link publik: $tunnelUrl/dashboard" -ForegroundColor Cyan
Write-Host ""
Write-Host "  2. Kirim File PCAP dari Terminal (Windows / Mac / Linux) via Curl Stream:" -ForegroundColor White
Write-Host ('     curl -F "pcap_file=@file_anda.pcap" ' + $tunnelUrl + '/api/cli') -ForegroundColor Green
Write-Host ""
Write-Host "  3. Kirim File PCAP Langsung via Native SSH (Di Jaringan Lokal / Host):" -ForegroundColor White
Write-Host '     cmd /c "ssh -p 2222 spectra@127.0.0.1 < file_anda.pcap"' -ForegroundColor Magenta
Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host ">>> TEKAN TOMBOL [ENTER] KAPAN SAJA UNTUK MEMATIKAN SPECTRA & TUNNEL <<<" -ForegroundColor Yellow
[void][System.Console]::ReadLine()

Write-Host "[*] Mematikan SPECTRA dan Cloudflare Tunnel..." -ForegroundColor Yellow
Stop-Process -Id $cfProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $spectraProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Name "cloudflared" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "spectra" -Force -ErrorAction SilentlyContinue
if (Test-Path $logFile) { Remove-Item $logFile -Force }

Write-Host "[OK] Layanan berhasil dimatikan secara bersih. Misi selesai." -ForegroundColor Green
Start-Sleep -Seconds 2
