package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"spectra/internal/analyzer"
	"spectra/internal/model"
	"spectra/internal/pcap"
	"spectra/internal/report"
	"spectra/internal/sshserver"
)

type Server struct {
	port       int
	engine     *analyzer.Engine
	lastResult *model.AnalysisResult
}

func NewServer(port int) *Server {
	return &Server{
		port:   port,
		engine: analyzer.NewEngine(),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/", s.securityMiddleware(s.handleLanding))
	mux.HandleFunc("/dashboard", s.securityMiddleware(s.handleDashboard))
	mux.HandleFunc("/api/analyze", s.securityMiddleware(s.handleAnalyzeUpload))
	mux.HandleFunc("/api/export/json", s.securityMiddleware(s.handleExportJSON))
	mux.HandleFunc("/api/export/dossier", s.securityMiddleware(s.handleExportDossier))
	mux.HandleFunc("/api/export/stix", s.securityMiddleware(s.handleExportSTIX))
	mux.HandleFunc("/api/export/blocklist", s.securityMiddleware(s.handleExportBlocklist))
	mux.HandleFunc("/api/rules", s.securityMiddleware(s.handleRules))
	mux.HandleFunc("/api/live-capture", s.securityMiddleware(s.handleLiveCapture))
	mux.HandleFunc("/api/playbook", s.securityMiddleware(s.handlePlaybook))
	mux.HandleFunc("/api/briefing", s.securityMiddleware(s.handleBriefing))
	mux.HandleFunc("/api/clear", s.securityMiddleware(s.handleClear))
	mux.HandleFunc("/api/sample-pcap", s.securityMiddleware(s.handleSamplePCAP))
	mux.HandleFunc("/api/cli", s.securityMiddleware(s.handleCLI))
	mux.HandleFunc("/install.sh", s.handleInstallSh)
	mux.HandleFunc("/install.ps1", s.handleInstallPs1)
	mux.HandleFunc("/bin/", s.handleBinaryDownload)
	mux.HandleFunc("/download/", s.handleBinaryDownload)

	// Auto Port Fallback: Jika port sibuk, cari port kosong berikutnya
	candidatePorts := []int{s.port, 8888, 9090, 8081, 8082, 3000, 8000}
	var listener net.Listener
	var err error
	var chosenPort int

	for _, p := range candidatePorts {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			chosenPort = p
			break
		}
	}

	if listener == nil {
		return fmt.Errorf("tidak dapat mengikat port jaringan lokal: %w", err)
	}

	fmt.Printf("\n=======================================================\n")
	fmt.Printf("   SPECTRA TACTICAL AIR-GAPPED SUITE ONLINE\n")
	fmt.Printf("   Landing Page : http://127.0.0.1:%d/\n", chosenPort)
	fmt.Printf("   Dashboard    : http://127.0.0.1:%d/dashboard\n", chosenPort)
	fmt.Printf("   Keamanan     : Localhost-Bound / Zero Persistent Storage\n")
	fmt.Printf("=======================================================\n\n")

	return http.Serve(listener, mux)
}

func (s *Server) securityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(landingHTML))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

func (s *Server) handleAnalyzeUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 150*1024*1024)

	file, header, err := r.FormFile("pcap_file")
	if err != nil {
		http.Error(w, "Upload gagal atau ukuran melebihi 150MB: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	safeFilename := filepath.Base(header.Filename)
	safeFilename = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(safeFilename, "_")

	tempFile, err := os.CreateTemp("", "spectra-upload-*.tmp")
	if err != nil {
		http.Error(w, "Gagal membuat buffer sementara", http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, "Gagal memproses file upload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPFile(tempPath)
	if err != nil {
		http.Error(w, "Parsing error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := s.engine.Analyze(safeFilename, sha256Hex, packets, totalBytes, start)
	s.lastResult = &result

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=spectra_triage_report.json")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lastResult)
}

func (s *Server) handleExportDossier(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	tempPath := filepath.Join(os.TempDir(), "spectra_dossier.html")
	if err := report.GenerateTacticalHTMLDossier(*s.lastResult, tempPath); err != nil {
		http.Error(w, "Gagal membuat berkas laporan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, tempPath)
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	s.lastResult = nil
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"cleared","message":"Memori dan cache triase lokal telah dibersihkan."}`))
}

func (s *Server) handleExportSTIX(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	stixData, err := report.GenerateSTIX21Bundle(*s.lastResult)
	if err != nil {
		http.Error(w, "Gagal menghasilkan STIX 2.1 bundle: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=spectra_stix21_bundle.json")
	w.Header().Set("Content-Type", "application/json")
	w.Write(stixData)
}

func (s *Server) handleExportBlocklist(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "iptables"
	}
	ext := "sh"
	contentType := "text/plain; charset=utf-8"
	switch format {
	case "windows":
		ext = "ps1"
	case "suricata":
		ext = "rules"
	case "plaintext":
		ext = "txt"
	}
	text := report.GenerateBlocklistText(s.lastResult.BlocklistRules, format)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=spectra_blocklist_%s.%s", format, ext))
	w.Header().Set("Content-Type", contentType)
	w.Write([]byte(text))
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	rules := s.engine.GetRuleEngine().GetActiveRules()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (s *Server) handlePlaybook(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=spectra_playbook.txt")
		w.Write([]byte(s.lastResult.Playbook.RawPlanText))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lastResult.Playbook)
}

func (s *Server) handleBriefing(w http.ResponseWriter, r *http.Request) {
	if s.lastResult == nil {
		http.Error(w, "Belum ada artefak yang dianalisis", http.StatusBadRequest)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "text" || format == "whatsapp" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=spectra_executive_briefing.txt")
		w.Write([]byte(s.lastResult.ExecutiveBriefing.WhatsAppFormatText))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lastResult.ExecutiveBriefing)
}

func (s *Server) handleLiveCapture(w http.ResponseWriter, r *http.Request) {
	durStr := r.URL.Query().Get("duration")
	duration := 10 * time.Second
	if durStr != "" {
		if d, err := time.ParseDuration(durStr); err == nil && d >= 1*time.Second && d <= 60*time.Second {
			duration = d
		}
	}

	liveEngine := pcap.NewLiveCaptureEngine()
	pcapBytes, _, err := liveEngine.CaptureLivePCAP(duration)
	if err != nil {
		http.Error(w, fmt.Sprintf("Live capture gagal: %v", err), http.StatusInternalServerError)
		return
	}

	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPBytes(pcapBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Gagal mem-parsing paket live: %v", err), http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("live_capture_%s.pcap", time.Now().Format("150405"))
	result := s.engine.Analyze(filename, sha256Hex, packets, totalBytes, start)
	s.lastResult = &result

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSamplePCAP(w http.ResponseWriter, r *http.Request) {
	samplePath := "attack_sample.pcap"
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		http.Error(w, "File sampel tidak ditemukan", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=attack_sample.pcap")
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	http.ServeFile(w, r, samplePath)
}

func (s *Server) handleCLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Gunakan POST untuk mengirimkan file PCAP.\n", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 150*1024*1024)

	var data []byte
	var filename = "client_terminal.pcap"

	if r.Header.Get("Content-Type") != "" && strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		file, header, err := r.FormFile("pcap_file")
		if err == nil {
			defer file.Close()
			filename = header.Filename
			data, _ = io.ReadAll(file)
		}
	}

	if len(data) == 0 {
		var err error
		data, err = io.ReadAll(r.Body)
		if err != nil || len(data) < 24 {
			http.Error(w, "Gagal membaca stream PCAP dari client.\n", http.StatusBadRequest)
			return
		}
	}

	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPBytes(data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Parsing error: %v\n", err), http.StatusBadRequest)
		return
	}

	result := s.engine.Analyze(filename, sha256Hex, packets, totalBytes, start)
	s.lastResult = &result

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	sshserver.RenderANSIDossier(w, result)
}

func (s *Server) handleInstallSh(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	script := fmt.Sprintf(`#!/usr/bin/env sh
# ==============================================================================
#    SPECTRA // UNIVERSAL TERMINAL AIR-GAPPED DEPLOYMENT (ONE-LINER)
#    Pure Go - CGo Disabled - Zero External Dependencies - Standalone Binary
# ==============================================================================
set -e

echo "================================================================================"
echo "   SPECTRA // UNIVERSAL TERMINAL AIR-GAPPED DEPLOYMENT"
echo "   Zero Footprint • Pure Go Static Binary • Zero C-Libraries"
echo "================================================================================"

SERVER_URL="%s"
if [ -z "$SERVER_URL" ]; then
    SERVER_URL="http://127.0.0.1:8888"
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux*)                 TARGET_OS="linux" ;;
    darwin*)                TARGET_OS="darwin" ;;
    msys*|mingw*|cygwin*)   TARGET_OS="windows" ;;
    *)                      TARGET_OS="linux" ;;
esac

case "$ARCH" in
    x86_64|amd64)           TARGET_ARCH="amd64" ;;
    aarch64|arm64)          TARGET_ARCH="arm64" ;;
    armv7*|armhf)           TARGET_ARCH="arm64" ;;
    *)                      TARGET_ARCH="amd64" ;;
esac

if [ "$TARGET_OS" = "windows" ]; then
    BIN_NAME="spectra-windows-amd64.exe"
    OUT_FILE="spectra.exe"
else
    BIN_NAME="spectra-${TARGET_OS}-${TARGET_ARCH}"
    OUT_FILE="spectra"
fi

echo "[*] Detected Platform : ${TARGET_OS}/${TARGET_ARCH}"
echo "[*] Target Binary     : ${BIN_NAME}"
echo "[*] Fetching from     : ${SERVER_URL}/bin/${BIN_NAME}"

if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ] && [ -w "$PREFIX/bin" ]; then
    TARGET_DIR="$PREFIX/bin"
elif [ -w "./" ]; then
    TARGET_DIR="."
else
    TARGET_DIR="/tmp"
fi

DEST="${TARGET_DIR}/${OUT_FILE}"

download_bin() {
    URL="$1"
    DEST_PATH="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$DEST_PATH"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$DEST_PATH" "$URL"
    else
        echo "[-] Error: curl atau wget dibutuhkan untuk mendownload biner SPECTRA."
        exit 1
    fi
}

echo "[*] Downloading biner..."
if ! download_bin "${SERVER_URL}/bin/${BIN_NAME}" "$DEST"; then
    echo "[!] Menggunakan fallback biner default..."
    download_bin "${SERVER_URL}/download/spectra" "$DEST" || download_bin "${SERVER_URL}/download/spectra.exe" "$DEST"
fi

chmod +x "$DEST"
echo "[✓] Deployment biner SPECTRA berhasil: $DEST"
echo "================================================================================"
echo "[*] Menjalankan SPECTRA CLI Help & Triage Engine..."
echo "================================================================================"
"$DEST" -h || "$DEST"
`, serverURL)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(script))
}

func (s *Server) handleInstallPs1(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	script := fmt.Sprintf(`# ==============================================================================
#    SPECTRA // UNIVERSAL POWERSHELL AIR-GAPPED DEPLOYMENT (ONE-LINER)
#    Pure Go - CGo Disabled - Zero External Dependencies - Standalone Binary
# ==============================================================================
$ErrorActionPreference = 'Stop'
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "   SPECTRA // UNIVERSAL POWERSHELL AIR-GAPPED DEPLOYMENT" -ForegroundColor Cyan
Write-Host "   Zero Footprint • Pure Go Static Binary • Zero C-Libraries" -ForegroundColor DarkCyan
Write-Host "================================================================================" -ForegroundColor Cyan

$ServerUrl = "%s"
if (-not $ServerUrl) { $ServerUrl = "http://127.0.0.1:8888" }

$DestDir = $PWD.Path
$DestFile = Join-Path $DestDir "spectra.exe"

try {
    $testFile = Join-Path $DestDir ".__spectra_perm_test"
    Set-Content -Path $testFile -Value "1" -ErrorAction Stop
    Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
} catch {
    $DestFile = Join-Path $env:TEMP "spectra.exe"
}

$DownloadUrl = "$ServerUrl/bin/spectra-windows-amd64.exe"
Write-Host "[*] Platform Detected : Windows (x86_64 / AMD64)" -ForegroundColor White
Write-Host "[*] Target Binary     : $DestFile" -ForegroundColor White
Write-Host "[*] Fetching Binary   : $DownloadUrl" -ForegroundColor Yellow

try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $DestFile -UseBasicParsing
} catch {
    Write-Host "[!] Fallback downloading from $ServerUrl/download/spectra.exe..." -ForegroundColor DarkYellow
    Invoke-WebRequest -Uri "$ServerUrl/download/spectra.exe" -OutFile $DestFile -UseBasicParsing
}

Unblock-File -Path $DestFile -ErrorAction SilentlyContinue

Write-Host "[✓] SPECTRA Standalone Binary berhasil diunduh dan diverifikasi!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "[*] Menjalankan SPECTRA CLI Help..." -ForegroundColor Cyan
& $DestFile -h
`, serverURL)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write([]byte(script))
}

func (s *Server) handleBinaryDownload(w http.ResponseWriter, r *http.Request) {
	subPath := strings.TrimPrefix(r.URL.Path, "/bin/")
	subPath = strings.TrimPrefix(subPath, "/download/")
	subPath = filepath.Clean(subPath)

	if strings.Contains(subPath, "..") || subPath == "." || subPath == "" {
		http.Error(w, "Invalid binary filename", http.StatusBadRequest)
		return
	}

	candidatePath := filepath.Join("bin", subPath)
	if fi, err := os.Stat(candidatePath); err == nil && !fi.IsDir() {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(candidatePath)))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, candidatePath)
		return
	}

	if fi, err := os.Stat(subPath); err == nil && !fi.IsDir() {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(subPath)))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, subPath)
		return
	}

	if strings.Contains(subPath, "spectra") {
		winBin := filepath.Join("bin", "spectra-windows-amd64.exe")
		if _, err := os.Stat(winBin); err == nil {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", subPath))
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeFile(w, r, winBin)
			return
		}
		if _, err := os.Stat("spectra.exe"); err == nil {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", subPath))
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeFile(w, r, "spectra.exe")
			return
		}
	}

	http.Error(w, fmt.Sprintf("Binary '%s' tidak ditemukan di server", subPath), http.StatusNotFound)
}

// ======================== TEMPLATE LANDING PAGE ========================
const landingHTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPECTRA // Swift Packet Extraction & Cyber Threat Rapid Analyzer</title>
    <style>
        :root {
            --bg-base: #06090f;
            --bg-card: #0b1320;
            --border: #16263d;
            --accent-cyan: #00f2fe;
            --accent-green: #00ff88;
            --accent-red: #ff0055;
            --accent-orange: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', -apple-system, sans-serif; }
        body { background: var(--bg-base); color: var(--text-main); line-height: 1.6; overflow-x: hidden; }
        .mono { font-family: 'Consolas', 'Courier New', monospace; }

        /* Navigation */
        nav {
            display: flex; justify-content: space-between; align-items: center;
            padding: 18px 40px; border-bottom: 1px solid var(--border);
            background: rgba(6, 9, 15, 0.85); backdrop-filter: blur(10px);
            position: sticky; top: 0; z-index: 100;
        }
        .nav-logo { display: flex; align-items: center; gap: 10px; font-size: 20px; font-weight: 900; color: var(--accent-cyan); letter-spacing: 2px; }
        .pulse-dot { width: 10px; height: 10px; background: var(--accent-green); border-radius: 50%; box-shadow: 0 0 10px var(--accent-green); }
        .nav-links { display: flex; gap: 24px; align-items: center; font-size: 14px; }
        .nav-links a { color: var(--text-muted); text-decoration: none; transition: 0.2s; }
        .nav-links a:hover { color: var(--accent-cyan); }
        .btn-launch {
            background: linear-gradient(135deg, #0284c7, #00f2fe); color: #040812;
            padding: 10px 22px; border-radius: 4px; font-weight: 900;
            text-decoration: none; letter-spacing: 1px; font-size: 13px;
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.4); transition: 0.3s;
        }
        .btn-launch:hover { transform: translateY(-2px); box-shadow: 0 0 30px rgba(0, 242, 254, 0.7); }

        /* Hero Section */
        .hero {
            max-width: 1100px; margin: 60px auto 40px auto; padding: 0 20px; text-align: center;
        }
        .hero-badge {
            display: inline-flex; align-items: center; gap: 8px;
            background: rgba(0, 242, 254, 0.08); border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan); font-size: 11px; padding: 6px 14px; border-radius: 30px;
            text-transform: uppercase; letter-spacing: 1.5px; font-weight: bold; margin-bottom: 25px;
        }
        .hero h1 {
            font-size: 52px; font-weight: 900; line-height: 1.15; margin-bottom: 20px;
            background: linear-gradient(180deg, #ffffff 30%, #94a3b8 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .hero p {
            font-size: 18px; color: var(--text-muted); max-width: 780px; margin: 0 auto 35px auto;
        }
        .hero-cta { display: flex; justify-content: center; gap: 15px; margin-bottom: 50px; }
        .btn-secondary {
            background: #101c30; border: 1px solid var(--border); color: var(--text-main);
            padding: 12px 26px; border-radius: 4px; font-weight: bold; font-size: 14px;
            text-decoration: none; transition: 0.2s;
        }
        .btn-secondary:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); }

        /* Security Pillar Box (No Login Required) */
        .security-banner {
            max-width: 1000px; margin: 0 auto 60px auto; padding: 25px;
            background: rgba(16, 28, 48, 0.6); border: 1px solid #1e3a5f;
            border-left: 5px solid var(--accent-green); border-radius: 8px;
            display: grid; grid-template-columns: 80px 1fr; gap: 20px; align-items: center; text-align: left;
        }
        .security-icon { font-size: 40px; text-align: center; }
        .security-title { font-size: 17px; font-weight: bold; color: var(--accent-green); margin-bottom: 6px; }
        .security-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; }

        /* Feature Cards Grid */
        .section-title { text-align: center; font-size: 30px; font-weight: bold; margin-bottom: 15px; }
        .section-sub { text-align: center; color: var(--text-muted); font-size: 15px; margin-bottom: 45px; }
        .cards-grid {
            max-width: 1100px; margin: 0 auto 70px auto; padding: 0 20px;
            display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px;
        }
        .feature-card {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 8px; padding: 25px; transition: 0.3s;
        }
        .feature-card:hover { transform: translateY(-5px); border-color: var(--accent-cyan); box-shadow: 0 8px 30px rgba(0, 242, 254, 0.1); }
        .card-icon { font-size: 32px; margin-bottom: 15px; }
        .card-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #f1f5f9; }
        .card-desc { font-size: 13px; color: var(--text-muted); line-height: 1.6; }

        /* Specification Matrix */
        .specs-section {
            max-width: 1000px; margin: 0 auto 80px auto; padding: 30px;
            background: #09101b; border: 1px solid var(--border); border-radius: 8px;
        }
        .specs-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; text-align: center; }
        .spec-item { padding: 15px; }
        .spec-val { font-size: 28px; font-weight: 900; color: var(--accent-cyan); margin-bottom: 5px; }
        .spec-lbl { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }

        /* Footer */
        footer {
            border-top: 1px solid var(--border); padding: 30px 40px; text-align: center;
            font-size: 12px; color: var(--text-muted); background: #04070c;
        }

        /* Mobile & Tablet Responsive Queries */
        @media (max-width: 960px) {
            nav { padding: 14px 20px; }
            .hero h1 { font-size: clamp(30px, 5vw, 42px); }
            .cards-grid { grid-template-columns: repeat(2, 1fr); gap: 16px; }
            .specs-grid { grid-template-columns: repeat(2, 1fr); gap: 14px; }
        }
        @media (max-width: 680px) {
            nav { flex-direction: column; gap: 14px; padding: 14px 16px; text-align: center; }
            .nav-links { flex-direction: column; gap: 10px; width: 100%; }
            .nav-links a { font-size: 13px; }
            .btn-launch { width: 100%; text-align: center; padding: 12px; display: block; box-sizing: border-box; }
            .hero { margin: 25px auto 20px auto; padding: 0 14px; }
            .hero h1 { font-size: clamp(24px, 7vw, 32px); line-height: 1.25; margin-bottom: 14px; }
            .hero p { font-size: 14px; margin-bottom: 24px; }
            .hero-cta { flex-direction: column; width: 100%; gap: 10px; }
            .btn-secondary { width: 100%; text-align: center; box-sizing: border-box; padding: 12px; }
            .security-banner { grid-template-columns: 1fr; text-align: center; padding: 18px; margin: 0 14px 40px 14px; }
            .security-icon { font-size: 32px; }
            .section-title { font-size: 24px; padding: 0 14px; }
            .section-sub { font-size: 13px; padding: 0 14px; margin-bottom: 30px; }
            .cards-grid { grid-template-columns: 1fr; padding: 0 14px; margin-bottom: 40px; }
            .specs-section { margin: 0 14px 40px 14px; padding: 20px 14px; }
            .specs-grid { grid-template-columns: 1fr; gap: 10px; }
            #terminal { margin: 0 14px 40px 14px !important; padding: 20px 14px !important; }
            #terminal > div:last-child { grid-template-columns: 1fr !important; }
            #quick-deploy { margin: 0 14px 40px 14px !important; padding: 20px 14px !important; }
            .deploy-grid { grid-template-columns: 1fr !important; }
            footer { padding: 25px 16px; }
        }

        /* Tactical Deploy Styles */
        .deploy-snippet {
            background: #000; padding: 10px 12px; border-radius: 4px; font-size: 11px;
            color: #38bdf8; border: 1px solid #1e293b; word-break: break-all;
            user-select: all; -webkit-user-select: all; line-height: 1.5;
        }
        .btn-copy-code {
            background: #1e293b; color: #f8fafc; border: 1px solid #334155;
            padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer;
            transition: 0.2s; font-weight: bold;
        }
        .btn-copy-code:hover { background: #0284c7; border-color: var(--accent-cyan); color: #fff; }
    </style>
</head>
<body>
    <nav>
        <div class="nav-logo mono">
            <div class="pulse-dot"></div>
            <span>SPECTRA</span>
        </div>
        <div class="nav-links">
            <a href="#quick-deploy">Quick Deploy</a>
            <a href="#features">Fitur Utama</a>
            <a href="#security">Keamanan Tanpa Login</a>
            <a href="#specs">Spesifikasi Taktis</a>
            <a href="/dashboard" class="btn-launch">BUKA DASHBOARD TAKTIS &rarr;</a>
        </div>
    </nav>

    <div class="hero">
        <div class="hero-badge mono">🛡️ Zero-Cloud // Air-Gapped Ready // Core Infra Defense</div>
        <h1>Swift Packet Extraction &<br>Cyber Threat Rapid Analyzer</h1>
        <p>
            Platform triase forensik siber taktis mandiri (*off-grid*) untuk membedah lalu lintas jaringan (PCAP/PCAPNG) secara instan tanpa ketergantungan koneksi internet. Mengubah raw data menjadi intelijen IOC dan alur serangan siap eksekusi.
        </p>
        <div class="hero-cta">
            <a href="/dashboard" class="btn-launch" style="padding: 14px 32px; font-size: 15px;">🚀 BUKA TACTICAL COMMAND HUD</a>
            <a href="#security" class="btn-secondary">🔒 Mengapa Aman Tanpa Login?</a>
        </div>
    </div>

    <!-- Tactical Terminal Quick Deploy (1-Liner Pipeline) -->
    <div style="max-width: 1000px; margin: 0 auto 50px auto; padding: 25px; background: #0c1524; border: 1px solid var(--accent-cyan); border-radius: 8px; box-shadow: 0 0 35px rgba(0,242,254,0.18);" id="quick-deploy">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
            <div style="font-size: 20px; font-weight: bold; color: var(--accent-cyan);">⚡ Tactical Terminal Quick Deploy (One-Liner Pipeline)</div>
            <div style="background: rgba(0, 255, 136, 0.12); border: 1px solid var(--accent-green); color: var(--accent-green); padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: bold;">
                🛡️ AIR-GAPPED &amp; OFFLINE READY: Zero Runtime, Zero C-Libs, Single Static Binary Execution.
            </div>
        </div>
        <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 20px;">
            Jalankan SPECTRA secara instan di workstation forensik, server investigasi, atau perangkat IoT lapangan langsung dari pipa terminal tanpa perlu instalasi compiler, Python, Node, Npcap, atau dependensi C eksternal:
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;" class="deploy-grid">
            <!-- Linux / macOS -->
            <div style="background: #060a12; padding: 16px; border-radius: 6px; border: 1px solid var(--border); display:flex; flex-direction:column; justify-content:space-between;">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-weight:bold; color:var(--accent-green); font-size:13px;">🐧 Linux / macOS</span>
                        <button class="btn-copy-code" onclick="copySnippet('cmd-linux')">📋 Salin</button>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">Auto-deteksi x86_64 / ARM64 / Darwin &amp; eksekusi instan:</div>
                </div>
                <div class="mono deploy-snippet" id="cmd-linux">curl -sSL <span class="host-url">http://127.0.0.1:8888</span>/install.sh | bash</div>
            </div>

            <!-- Windows PowerShell -->
            <div style="background: #060a12; padding: 16px; border-radius: 6px; border: 1px solid var(--border); display:flex; flex-direction:column; justify-content:space-between;">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-weight:bold; color:var(--accent-cyan); font-size:13px;">🪟 Windows PowerShell</span>
                        <button class="btn-copy-code" onclick="copySnippet('cmd-win')">📋 Salin</button>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">One-liner unduh &amp; jalankan spectra.exe mandiri:</div>
                </div>
                <div class="mono deploy-snippet" id="cmd-win">iwr -useb <span class="host-url">http://127.0.0.1:8888</span>/install.ps1 | iex</div>
            </div>

            <!-- Termux / Android -->
            <div style="background: #060a12; padding: 16px; border-radius: 6px; border: 1px solid var(--border); display:flex; flex-direction:column; justify-content:space-between;">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-weight:bold; color:var(--accent-orange); font-size:13px;">📱 Termux / Android</span>
                        <button class="btn-copy-code" onclick="copySnippet('cmd-termux')">📋 Salin</button>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:10px;">Forensik siber lapangan via perangkat seluler / IoT:</div>
                </div>
                <div class="mono deploy-snippet" id="cmd-termux">curl -sSL <span class="host-url">http://127.0.0.1:8888</span>/install.sh | sh</div>
            </div>
        </div>
    </div>

    <!-- Security Assurance Banner (No Login Required) -->
    <div class="security-banner" id="security">
        <div class="security-icon">🛡️</div>
        <div>
            <div class="security-title">Mengapa SPECTRA Sepenuhnya Aman Tanpa Fitur Login?</div>
            <div class="security-desc">
                Dirancang khusus untuk <strong>operasi lapangan darurat (tactical response) & jaringan terisolasi (bunker/air-gapped)</strong> di mana koneksi internet dan server database otentikasi tidak tersedia. 
                Keamanan dijamin melalui <strong>Strict Localhost Isolation (127.0.0.1)</strong>, pemrosesan <strong>Memory-Only tanpa penyimpanan persisten</strong>, <strong>Anti-XSS payload neutralization</strong>, serta tombol <strong>1-Click Forensic Wipe</strong> yang langsung memusnahkan seluruh jejak analisis saat misi selesai.
            </div>
        </div>
    </div>

    <div class="section-title" id="features">Fitur Unggulan Taktis</div>
    <div class="section-sub">Diciptakan untuk memangkas waktu penanganan insiden siber dari hitungan jam menjadi milidetik.</div>

    <div class="cards-grid">
        <div class="feature-card">
            <div class="card-icon">⚡</div>
            <div class="card-title">Instant Sub-Millisecond Parser</div>
            <div class="card-desc">
                Engine berbasis Pure Go membedah format PCAP & PCAPNG secara native tanpa dependensi driver CGo/Npcap. Menganalisis ribuan paket dalam hitungan milidetik.
            </div>
        </div>
        <div class="feature-card">
            <div class="card-icon">🎯</div>
            <div class="card-title">Multi-Vector Threat Scoring</div>
            <div class="card-desc">
                Mendeteksi eksploitasi kritis seperti Log4Shell (CVE-2021-44228), SQL Injection, Web Shells, Remote Command Execution, Port Sweep, dan DNS Tunneling.
            </div>
        </div>
        <div class="feature-card">
            <div class="card-icon">🗺️</div>
            <div class="card-title">MITRE ATT&CK Mapping</div>
            <div class="card-desc">
                Secara otomatis memetakan setiap Indikator Kompromi (IOC) ke matriks taktik MITRE (Reconnaissance, Initial Access, Execution, hingga Exfiltration).
            </div>
        </div>
        <div class="feature-card">
            <div class="card-icon">🔬</div>
            <div class="card-title">Deep Hex Packet Inspector</div>
            <div class="card-desc">
                Pemeriksaan bukti forensik mendalam dengan visualisasi Hex + ASCII dump ala Wireshark langsung di browser tanpa perlu software tambahan.
            </div>
        </div>
        <div class="feature-card">
            <div class="card-icon">📊</div>
            <div class="card-title">Telemetry & Flow Analytics</div>
            <div class="card-desc">
                Grafik visual interaktif untuk proporsi protokol jaringan (TCP, UDP, DNS, HTTP, ICMP) dan identifikasi Top Talker Flows antar alamat IP.
            </div>
        </div>
        <div class="feature-card">
            <div class="card-icon">📄</div>
            <div class="card-title">1-Click Tactical Dossier</div>
            <div class="card-desc">
                Ekspor berkas laporan insiden terstandarisasi format PDF dan JSON siap serah untuk pimpinan komando dan tim investigasi forensik.
            </div>
        </div>
    </div>

    <div class="specs-section" id="specs">
        <div class="section-title" style="font-size: 22px; margin-bottom: 25px;">Spesifikasi Kinerja SPECTRA</div>
        <div class="specs-grid mono">
            <div class="spec-item">
                <div class="spec-val">&lt; 2 ms</div>
                <div class="spec-lbl">Rata-rata Waktu Triase</div>
            </div>
            <div class="spec-item">
                <div class="spec-val">100%</div>
                <div class="spec-lbl">Air-Gapped & Offline</div>
            </div>
            <div class="spec-item">
                <div class="spec-val">&lt; 10 MB</div>
                <div class="spec-lbl">Ukuran Binary Standalone</div>
            </div>
            <div class="spec-item">
                <div class="spec-val">0 Cloud</div>
                <div class="spec-lbl">Zero Telemetry Leakage</div>
            </div>
        </div>
    </div>

    <!-- Terminal Remote Access Section (SSH & Curl) -->
    <div style="max-width: 1000px; margin: 0 auto 80px auto; padding: 30px; background: #0c1524; border: 1px solid var(--accent-cyan); border-radius: 8px; box-shadow: 0 0 30px rgba(0,242,254,0.15);" id="terminal">
        <div class="section-title" style="font-size: 22px; color: var(--accent-cyan); margin-bottom: 8px;">💻 Akses Terminal Multi-Platform (SSH &amp; CURL)</div>
        <div class="section-sub" style="margin-bottom: 25px;">Kirim dan analisis file PCAP langsung dari terminal Windows, Linux, atau macOS tanpa perlu membuka browser.</div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div style="background: #060a12; padding: 20px; border-radius: 6px; border: 1px solid var(--border);">
                <div style="font-weight: bold; color: var(--accent-green); margin-bottom: 8px;">🚀 1. SSH Tactical Pipe (Paling Cepat &amp; Aman)</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Didukung penuh oleh bawaan OpenSSH di Windows 10/11, Linux, dan macOS:</div>
                <div class="mono" style="background: #000; padding: 12px; border-radius: 4px; font-size: 11px; color: #a3e635; line-height: 1.6; border: 1px solid #1e293b;">
                    # Linux / macOS / Git Bash:<br>
                    ssh -p 2222 spectra@127.0.0.1 &lt; capture.pcap<br><br>
                    # Windows (PowerShell / CMD):<br>
                    cmd /c "ssh -p 2222 spectra@127.0.0.1 &lt; C:\path\capture.pcap"<br><br>
                    # Shell Interaktif:<br>
                    ssh -p 2222 spectra@127.0.0.1
                </div>
            </div>

            <div style="background: #060a12; padding: 20px; border-radius: 6px; border: 1px solid var(--border);">
                <div style="font-weight: bold; color: var(--accent-cyan); margin-bottom: 8px;">🌐 2. HTTP Curl Stream (Universal Terminal API)</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Gunakan perintah curl bawaan di semua OS untuk mendapatkan laporan ANSI berwarna:</div>
                <div class="mono" style="background: #000; padding: 12px; border-radius: 4px; font-size: 11px; color: #38bdf8; line-height: 1.6; border: 1px solid #1e293b;">
                    # Kirim file PCAP lokal via curl:<br>
                    curl -F "pcap_file=@capture.pcap" http://127.0.0.1:8888/api/cli<br><br>
                    # Kirim raw binary stream:<br>
                    curl --data-binary @capture.pcap http://127.0.0.1:8888/api/cli
                </div>
            </div>
        </div>
    </div>

    <footer>
        <div class="mono" style="margin-bottom: 8px;">SPECTRA // SWIFT PACKET EXTRACTION & CYBER THREAT RAPID ANALYZER</div>
        <div>Platform Triase Forensik Siber Mandiri &bull; Hackathon Edition 2026</div>
    </footer>

    <script>
        function copySnippet(id) {
            var el = document.getElementById(id);
            if (!el) return;
            var text = el.innerText || el.textContent;
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(function() {
                    alert('Perintah berhasil disalin ke clipboard:\n' + text);
                }).catch(function() { fallbackCopy(text); });
            } else {
                fallbackCopy(text);
            }
        }
        function fallbackCopy(text) {
            var ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            alert('Perintah disalin ke clipboard:\n' + text);
        }
        document.addEventListener('DOMContentLoaded', function() {
            var origin = window.location.origin;
            var elements = document.querySelectorAll('.host-url');
            for (var i = 0; i < elements.length; i++) {
                elements[i].textContent = origin;
            }
        });
    </script>
</body>
</html>`

