# SPECTRA // MASTER COLLABORATION & PROJECT PROGRESS LOG
> **File Panduan Tim & AI Agent (Single Source of Truth)**  
> *Wajib dibaca oleh pengembang manusia dan AI Agent setiap kali sesi dimulai dan diperbarui otomatis di setiap akhir sesi.*

---

## 📌 Ringkasan Status Proyek

| Parameter | Keterangan |
|---|---|
| **Nama Proyek** | SPECTRA (Swift Packet Extraction & Cyber Threat Rapid Analyzer) |
| **Versi Saat Ini** | **v2.1-hackathon** |
| **Bahasa & Runtime** | **Pure Go (Golang 1.27)** &bull; `CGO_ENABLED=0` |
| **Arsitektur Utama** | **Zero Persistence (In-Memory Only)** &bull; Air-Gapped Ready (Tanpa CDN / DB Eksternal) |
| **Ukuran Biner** | **~8.3 MB** (Standalone Single Executable) |
| **Port Default** | **8888** (Web Dashboard / API) &bull; **2222** (SSH Tactical Gateway) |
| **Status Build** | ✅ **Clean Compile** (`go vet` 0 warnings, cross-platform bin ready) |
| **Terakhir Diperbarui** | **06 November 2026** |

---

## 🤖 INSTRUKSI WAJIB UNTUK AI AGENT (MANDATORY AUTONOMOUS DIRECTIVE)

> [!IMPORTANT]
> **Kepada seluruh AI Agent (Antigravity, Cursor, Claude Code, Copilot, Cline, Windsurf, dll.):**
> 1. **BACA DULU SEBELUM BERTINDAK**: Sebelum memulai tugas atau membuat kode baru, baca file `PROJECT_LOG.md` ini terlebih dahulu untuk memahami checkpoint terakhir, batasan arsitektur, dan task yang tertunda.
> 2. **WAJIB PERBARUI LOG SECARA OTOMATIS**: Setiap kali Anda selesai mengubah kode, memperbaiki bug, atau menambahkan fitur baru, Anda **WAJIB secara otomatis mengedit dan menambahkan entri riwayat pada bagian `## 📜 Riwayat Sesi & Changelog Kolaboratif` di bagian bawah file ini**.
> 3. **JANGAN MENUNGGU PROMPT PENGGUNA**: Jangan menunggu pengguna meminta Anda untuk mencatat log. Pengisian log ini adalah kewajiban otonom Anda agar kedua rekan tim yang bekerja dari rumah berbeda tidak bingung dan tidak kehilangan jejak perkembangan (*zero confusion handoff*).
> 4. **PATUHI 4 PILAR UTAMA SPECTRA**:
>    - **Pure Go**: Dilarang menggunakan driver C (libpcap/Npcap/WinPcap). Semua socket dan parser harus native Go.
>    - **In-Memory**: Dilarang menyimpan data PCAP atau analisis ke database disk (MySQL, SQLite, file dump). Sesi harus musnah saat `Wipe/Clear`.
>    - **Air-Gapped Ready**: Dilarang menyematkan link CDN internet pada HTML/JS. Semua asset/library (Vis.js, Chart.js) wajib ter-embed di biner.
>    - **Lightweight Binary**: Jaga ukuran biner tetap di bawah ~10 MB.

---

## 🗺️ Peta Arsitektur Berkas (Source Code Map)

```
d:\hackathon\
├── cmd/
│   └── spectra/
│       └── main.go                  # CLI Entry point: flag parser (-web, -file, -live, -benchmark, -gen-attack-pcap)
├── internal/
│   ├── analyzer/
│   │   ├── engine.go                # Core analyzer: orchestrator triase, RAG scoring, throughput, timeline
│   │   ├── rules.go                 # Dynamic Custom Rule Engine (Regex, ExactString, HexBytes) + default rules
│   │   ├── playbook.go              # Tactical Incident Containment Playbook Generator (P1/P2/P3 Containment)
│   │   └── briefing.go              # Executive War-Room Briefing Generator (Storytelling bahasa manusia non-teknis)
│   ├── model/
│   │   └── types.go                 # Seluruh data struct: AnalysisResult, IOC, Rule, Playbook, ExecutiveBriefing
│   ├── pcap/
│   │   ├── parser.go                # Pure Go PCAP parser (Global header, Packet header, Ethernet, IPv4, TCP/UDP/DNS/HTTP)
│   │   └── live.go                  # Pure Go raw socket packet capture & in-memory PCAP encapsulator
│   ├── report/
│   │   └── dossier.go               # Generator HTML Standalone Dossier (Anti-XSS, STIX 2.1 JSON, Blocklist generator)
│   ├── server/
│   │   ├── ui.go                    # HTTP Mux router, REST API (/api/analyze, /api/briefing, /install.sh, /install.ps1)
│   │   └── dashboard_template.go    # Single-page HTML/CSS/JS: Attack Graph (Vis.js), Live Sniff HUD, Modals, Filter
│   └── sshserver/
│       └── server.go                # Embedded Pure Go SSH Server (Port 2222, Pipe PCAP stream & ANSI triage output)
├── bin/                             # Output biner cross-platform (Windows, Linux AMD64/ARM64, macOS AMD64/ARM64)
├── rules.json                       # File aturan deteksi eksternal dinamis (hot-loadable tanpa recompile)
├── attack_sample.pcap               # Sampel PCAP uji coba multi-vektor (Log4Shell, SQLi, RCE, Shell, DNS Exfil)
├── build_all.bat / build_all.sh     # Skrip kompilasi otomatis ke 5 platform target
├── start_spectra.bat                # Launcher utama Windows: auto-open browser, auto-kill old proc, Cloudflare fallback
├── stop_spectra.bat                 # Pemati seluruh proses SPECTRA & Cloudflare
└── PROJECT_LOG.md                   # File ini (Master Progress & Handoff Log)
```

---

## ✅ Matriks Fitur & Status Implementasi

| Fitur | Status | Lokasi Kode | Keterangan |
|---|---|---|---|
| **Sub-Millisecond PCAP Parser** | ✅ Selesai | `internal/pcap/parser.go` | Parse paket native Go <3 ms (TCP, UDP, DNS, HTTP, ICMP) |
| **Shannon Entropy Analysis** | ✅ Selesai | `internal/pcap/parser.go` | Deteksi payload terenkripsi/obfuscated (>7.2 indikasi malware) |
| **Interactive Attack Graph** | ✅ Selesai | `internal/server/dashboard_template.go` | Graf relasi IP Asal -> Target dengan Vis.js embedded |
| **Dynamic Custom Rule Engine** | ✅ Selesai | `internal/analyzer/rules.go` | 8 default rules + auto-load `rules.json` (Regex/Exact/Hex) |
| **Tactical Incident Playbook** | ✅ Selesai | `internal/analyzer/playbook.go` | Checklist respon insiden P1/P2/P3 + perintah CLI siap eksekusi |
| **Executive War-Room Briefing** | ✅ Selesai | `internal/analyzer/briefing.go` | Narasi ramah orang awam + 1-klik salin WhatsApp/Email Direksi |
| **Firewall Blocklist Generator** | ✅ Selesai | `internal/report/dossier.go` | Ekspor 1-klik: iptables, PowerShell NetFirewallRule, Suricata |
| **STIX 2.1 CTI Export** | ✅ Selesai | `internal/report/dossier.go` | Standar industri Cyber Threat Intelligence (/api/export/stix) |
| **Pure Go Live Traffic Capture**| ✅ Selesai | `internal/pcap/live.go` | Tombol "🔴 Live Sniffing (10s)" via raw socket tanpa Npcap |
| **Universal Terminal Deployer** | ✅ Selesai | `internal/server/ui.go` | One-liner `install.sh` (Linux/Mac/Termux) & `install.ps1` (Win) |
| **Benchmark Suite & HUD Metrics**| ✅ Selesai | `cmd/spectra/main.go` | Flag `-benchmark` (>15,000 pkts/sec throughput evaluation) |
| **Embedded SSH Gateway** | ✅ Selesai | `internal/sshserver/server.go` | Port 2222 direct terminal pipe `< file.pcap` |
| **Standalone Dossier HTML/PDF** | ✅ Selesai | `internal/report/dossier.go` | 1-Click laporan cetak/PDF berstandar audit forensik |

---

## 🎯 Rencana Kerja / Backlog Selanjutnya (Task Queue)

Jika teman atau AI Agent Anda ingin melanjutkan peningkatan nilai hackathon, berikut daftar prioritas fitur yang siap dikerjakan:

- [ ] **Task A: In-Memory File Carving & Artifact Extractor**
  - *Deskripsi*: Rekonstruksi otomatis file yang ditransfer lewat HTTP POST/GET (misal: webshell `.php`, file `.exe`, script base64) langsung di memori, menampilkan hash MD5/SHA256 dan tombol preview/download aman.
  - *Target File*: `internal/pcap/carver.go`, `internal/model/types.go`, UI modal baru.
- [ ] **Task B: Universal Threat Hunting Query Exporter**
  - *Deskripsi*: Tombol salin 1-klik untuk filter Wireshark display, Splunk SPL query, Elasticsearch KQL, dan Sigma Rules YAML berdasarkan temuan IOC saat ini.
  - *Target File*: `internal/report/hunting.go`, UI Dashboard.
- [ ] **Task C: Offline Network Origin & Lateral Movement Detector**
  - *Deskripsi*: Klasifikasi otomatis apakah IP penyerang berasal dari RFC 1918 (Internal LAN / Lateral Movement) atau Public WAN.
  - *Target File*: `internal/analyzer/engine.go`, visual badge di UI.

---

## 🛠️ Cara Menjalankan, Menguji, dan Membangun Proyek

### 1. Menjalankan Server Lokal (Dashboard & SSH)
```powershell
cd d:\hackathon
.\spectra.exe -port 8888 -ssh-port 2222
# Buka di browser: http://localhost:8888/dashboard
```
*Atau klik ganda `start_spectra.bat` untuk otomatis membuka browser.*

### 2. Menganalisis File PCAP via CLI
```powershell
.\spectra.exe -file attack_sample.pcap
```

### 3. Menjalankan Uji Performa Benchmark
```powershell
.\spectra.exe -benchmark
```

### 4. Mengompilasi Ulang Biner untuk Semua Platform
```cmd
build_all.bat
```
*(Menghasilkan biner Windows, Linux AMD64, Linux ARM64/Termux, macOS Intel, dan macOS Apple Silicon di folder `bin/`).*

---

## 📜 Riwayat Sesi & Changelog Kolaboratif (Session Handoff History)

*(AI Agent dan developer WAJIB menambahkan baris baru di bawah setiap kali menyelesaikan sesi pekerjaan)*

| Tanggal & Waktu | Pelaksana (Author / Agent) | Fitur / Perubahan yang Dilakukan | File Terdampak | Status & Verifikasi |
|---|---|---|---|---|
| **04 Nov 2026, 11:05** | Antigravity AI | Integrasi Fitur 4: Executive War-Room Briefing Generator (Narasi ramah orang awam, penilaian dampak bisnis, 1-klik copy WhatsApp/Email Direksi, modal interaktif, dossier update). | `internal/model/types.go`<br>`internal/analyzer/briefing.go`<br>`internal/analyzer/engine.go`<br>`internal/server/ui.go`<br>`internal/server/dashboard_template.go`<br>`internal/report/dossier.go` | ✅ Sukses compile `spectra.exe`, verifikasi CLI `attack_sample.pcap` & `triage_dossier.html`. |
| **04 Nov 2026, 11:20** | Antigravity AI | Perbaikan launcher `start_spectra.bat` (mencegah force close, auto-launch browser, graceful offline fallback), dan optimasi empty state modal briefing di Dashboard. | `start_spectra.bat`<br>`internal/server/dashboard_template.go`<br>`spectra.exe` | ✅ `go vet` lulus 0 warnings, biner terkompilasi ulang dan stabil. |
| **06 Nov 2026, 07:30** | Antigravity AI | Pembuatan sistem kolaborasi Git multi-developer & multi-agent: Master progress log (`PROJECT_LOG.md`), aturan otonom agent (`.agent/rules/collab-log.md`, `AGENT.md`, `.cursorrules`), dan `.gitignore`. | `PROJECT_LOG.md`<br>`.agent/rules/collab-log.md`<br>`AGENT.md`<br>`.cursorrules`<br>`.gitignore` | ✅ Terintegrasi siap sinkronisasi Git antar rumah. |
<!-- [AI AGENT: TAMBAHKAN ENTRI SESI ANDA DI BAWAH INI SECARA OTOMATIS] -->
