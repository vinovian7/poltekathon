$ErrorActionPreference = 'Stop'
$proc = Start-Process -FilePath ".\spectra.exe" -ArgumentList @("-port", "8899", "-ssh-port", "2299") -NoNewWindow -PassThru
Start-Sleep -Seconds 2
$base = "http://127.0.0.1:8899"

Write-Host "=== Testing /install.sh ===" -ForegroundColor Cyan
try {
    $r1 = Invoke-WebRequest -Uri ($base + "/install.sh") -UseBasicParsing -TimeoutSec 5
    Write-Host ("Status: " + $r1.StatusCode)
    $r1.Content.Split("`n") | Select-Object -First 12 | ForEach-Object { Write-Host $_ }
} catch {
    Write-Host ("FAIL: " + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Testing /install.ps1 ===" -ForegroundColor Cyan
try {
    $r2 = Invoke-WebRequest -Uri ($base + "/install.ps1") -UseBasicParsing -TimeoutSec 5
    Write-Host ("Status: " + $r2.StatusCode)
    $r2.Content.Split("`n") | Select-Object -First 10 | ForEach-Object { Write-Host $_ }
} catch {
    Write-Host ("FAIL: " + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Testing /bin/spectra-linux-amd64 download ===" -ForegroundColor Cyan
try {
    $r3 = Invoke-WebRequest -Uri ($base + "/bin/spectra-linux-amd64") -UseBasicParsing -TimeoutSec 10
    Write-Host ("Status: " + $r3.StatusCode + " | Size: " + $r3.RawContentLength + " bytes")
} catch {
    Write-Host ("FAIL: " + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Testing landing page contains quick-deploy ===" -ForegroundColor Cyan
try {
    $r4 = Invoke-WebRequest -Uri ($base + "/") -UseBasicParsing -TimeoutSec 5
    $hasQD = $r4.Content -match "quick-deploy"
    $hasDeployModal = $r4.Content -match "deployModal"
    Write-Host ("Has quick-deploy section: " + $hasQD)
    Write-Host ("Has deployModal: " + $hasDeployModal)
} catch {
    Write-Host ("FAIL: " + $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Testing dashboard has deploy button ===" -ForegroundColor Cyan
try {
    $r5 = Invoke-WebRequest -Uri ($base + "/dashboard") -UseBasicParsing -TimeoutSec 5
    $hasQD = $r5.Content -match "openDeployModal"
    Write-Host ("Dashboard has openDeployModal: " + $hasQD)
} catch {
    Write-Host ("FAIL: " + $_.Exception.Message) -ForegroundColor Red
}

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Host "" 
Write-Host "All endpoint tests completed!" -ForegroundColor Green
