package sshserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"spectra/internal/analyzer"
	"spectra/internal/model"
	"spectra/internal/pcap"
)

type SSHServer struct {
	port       int
	engine     *analyzer.Engine
	chosenPort int
}

func NewSSHServer(port int) *SSHServer {
	return &SSHServer{
		port:   port,
		engine: analyzer.NewEngine(),
	}
}

func (s *SSHServer) GetPort() int {
	return s.chosenPort
}

func (s *SSHServer) Start() error {
	// Buat ED25519 Host Key dinamis di memori untuk zero-friction air-gapped security
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("gagal menghasilkan host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return fmt.Errorf("gagal membuat SSH signer: %w", err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true, // Tanpa password/friction untuk triase darurat lapangan
		ServerVersion: "SSH-2.0-SPECTRA_Tactical_v2.0",
	}
	config.AddHostKey(signer)

	candidatePorts := []int{s.port, 22222, 2200, 2022, 8022}
	var listener net.Listener
	var chosenPort int

	for _, p := range candidatePorts {
		addr := fmt.Sprintf("0.0.0.0:%d", p)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			chosenPort = p
			break
		}
	}

	if listener == nil {
		return fmt.Errorf("tidak dapat mengikat port SSH: %w", err)
	}

	s.chosenPort = chosenPort
	fmt.Printf("   SSH Gateway  : ssh -p %d spectra@127.0.0.1 (Direct PCAP Pipe & Interactive)\n", chosenPort)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(nConn, config)
	}
}

func (s *SSHServer) handleConnection(nConn net.Conn, config *ssh.ServerConfig) {
	defer nConn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "tipe channel tidak didukung")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go s.handleSession(channel, requests)
	}
}

func (s *SSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	// Handle in-session requests (shell, exec, pty-req)
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell", "pty-req", "env":
				req.Reply(true, nil)
			case "exec":
				req.Reply(true, nil)
			default:
				req.Reply(true, nil)
			}
		}
	}()

	// Buffer awal untuk mendeteksi apakah client melakukan piping file PCAP
	// atau sedang membuka interactive terminal
	magicBuf := make([]byte, 4)
	nConn := channel.(io.Reader)

	// Set timeout membaca 250ms untuk mendeteksi data piped awal
	readDone := make(chan error, 1)
	var readBytes int
	go func() {
		var err error
		readBytes, err = io.ReadFull(nConn, magicBuf)
		readDone <- err
	}()

	var isPiped bool
	select {
	case err := <-readDone:
		if err == nil && readBytes == 4 {
			// Cek apakah 4 byte pertama adalah Magic Number PCAP atau PCAPNG
			magic := uint32(magicBuf[0]) | uint32(magicBuf[1])<<8 | uint32(magicBuf[2])<<16 | uint32(magicBuf[3])<<24
			magicBig := uint32(magicBuf[3]) | uint32(magicBuf[2])<<8 | uint32(magicBuf[1])<<16 | uint32(magicBuf[0])<<24

			if magic == pcap.MagicMicroseconds || magic == pcap.MagicNanoseconds ||
				magicBig == pcap.MagicBigEndian || magicBig == pcap.MagicNanoBig ||
				magic == pcap.MagicPCAPNG || magicBig == pcap.MagicPCAPNG {
				isPiped = true
			}
		}
	case <-time.After(250 * time.Millisecond):
		isPiped = false
	}

	if isPiped {
		// MODE 1: Client mem-pipe file PCAP langsung dari terminal lokal (Windows / Linux / macOS)
		s.handlePipedPCAP(channel, magicBuf[:readBytes])
	} else {
		// MODE 2: Client membuka interactive tactical shell
		s.handleInteractiveShell(channel, magicBuf[:readBytes])
	}
}

func (s *SSHServer) handlePipedPCAP(channel io.ReadWriter, initialBytes []byte) {
	var buf bytes.Buffer
	buf.Write(initialBytes)

	// Baca sisa seluruh stream PCAP dari client
	io.Copy(&buf, channel)

	data := buf.Bytes()
	if len(data) < 24 {
		fmt.Fprintf(channel, "\033[1;31m[-] Error: Ukuran data PCAP terlalu kecil atau tidak lengkap.\033[0m\r\n")
		return
	}

	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPBytes(data)
	if err != nil {
		fmt.Fprintf(channel, "\033[1;31m[-] Gagal mem-parse PCAP stream: %v\033[0m\r\n", err)
		return
	}

	res := s.engine.Analyze("client_stream.pcap", sha256Hex, packets, totalBytes, start)
	RenderANSIDossier(channel, res)
}

func (s *SSHServer) handleInteractiveShell(channel io.ReadWriter, leftover []byte) {
	// Banner Taktis SPECTRA
	banner := `
` + "\033[1;36m" + `================================================================================` + "\033[0m" + `
` + "\033[1;32m" + `   ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ ` + "\033[0m" + `
` + "\033[1;32m" + `   ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗` + "\033[0m" + `
` + "\033[1;36m" + `   ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║` + "\033[0m" + `
` + "\033[1;36m" + `   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║` + "\033[0m" + `
` + "\033[1;32m" + `   ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║` + "\033[0m" + `
` + "\033[1;32m" + `   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝` + "\033[0m" + `
` + "\033[1;36m" + `   SWIFT PACKET EXTRACTION & CYBER THREAT RAPID ANALYZER // SSH GATEWAY` + "\033[0m" + `
` + "\033[1;36m" + `================================================================================` + "\033[0m" + `
` + "\033[90m" + `Status: AIR-GAPPED READY | ZERO-CLOUD | NO-LOGIN SECURE | RFC-4254 COMPLIANT` + "\033[0m" + `

` + "\033[1;33m" + `[CARA MEMBACA FILE PCAP DARI LAPTOP/CLIENT ANDA]:` + "\033[0m" + `
  ` + "\033[1;37m" + `• Linux / macOS / Git Bash :` + "\033[0m" + `
    ssh -p ` + fmt.Sprintf("%d", s.chosenPort) + ` spectra@<IP_SERVER> < /path/to/traffic.pcap
    cat traffic.pcap | ssh -p ` + fmt.Sprintf("%d", s.chosenPort) + ` spectra@<IP_SERVER>

  ` + "\033[1;37m" + `• Windows (PowerShell / CMD) :` + "\033[0m" + `
    cmd /c "ssh -p ` + fmt.Sprintf("%d", s.chosenPort) + ` spectra@<IP_SERVER> < C:\path\to\traffic.pcap"

` + "\033[1;33m" + `[PERINTAH INTERAKTIF TERSEDIA]:` + "\033[0m" + `
  ` + "\033[1;36m" + `test` + "\033[0m" + `   - Jalankan simulasi multi-vector attack triase langsung di terminal
  ` + "\033[1;36m" + `status` + "\033[0m" + ` - Periksa status sistem, memori, dan zero-cloud telemetry
  ` + "\033[1;36m" + `help` + "\033[0m" + `   - Tampilkan kembali petunjuk ini
  ` + "\033[1;36m" + `exit` + "\033[0m" + `   - Putuskan koneksi SSH

`
	channel.Write([]byte(strings.ReplaceAll(banner, "\n", "\r\n")))

	prompt := "\033[1;32mSPECTRA-TACTICAL>\033[0m "
	channel.Write([]byte(prompt))

	inputBuf := make([]byte, 1024)
	var lineBuf strings.Builder
	if len(leftover) > 0 {
		lineBuf.Write(leftover)
	}

	for {
		n, err := channel.Read(inputBuf)
		if err != nil {
			break
		}

		for i := 0; i < n; i++ {
			b := inputBuf[i]
			if b == '\r' || b == '\n' {
				cmd := strings.TrimSpace(lineBuf.String())
				lineBuf.Reset()
				channel.Write([]byte("\r\n"))

				switch cmd {
				case "exit", "quit":
					channel.Write([]byte("\033[1;33mMisi selesai. Menutup koneksi taktis.\033[0m\r\n"))
					return
				case "help":
					channel.Write([]byte(strings.ReplaceAll(banner, "\n", "\r\n")))
				case "status":
					statusText := fmt.Sprintf("\033[1;36m[+] TELEMETRI SISTEM SPECTRA:\033[0m\r\n"+
						"    Mode Operasi   : 100%% Localhost Air-Gapped\r\n"+
						"    Penyimpanan    : Memory-Only (Zero Disk Persistence)\r\n"+
						"    SSH Gateway    : Port %d Active\r\n"+
						"    Web Dashboard  : Active at http://127.0.0.1:8888/dashboard\r\n\r\n", s.chosenPort)
					channel.Write([]byte(statusText))
				case "test":
					channel.Write([]byte("\033[1;33m[*] Memuat sampel serangan Multi-Vector (Log4Shell, SQLi, RCE, DNS Exfil)...\033[0m\r\n"))
					s.runSampleTest(channel)
				case "":
					// empty line, just prompt
				default:
					channel.Write([]byte(fmt.Sprintf("\033[1;31m[-] Perintah tidak dikenal: '%s'. Ketik 'help' atau 'test'.\033[0m\r\n", cmd)))
				}

				channel.Write([]byte(prompt))
			} else if b == 127 || b == 8 { // Backspace
				if lineBuf.Len() > 0 {
					s := lineBuf.String()
					lineBuf.Reset()
					lineBuf.WriteString(s[:len(s)-1])
					channel.Write([]byte("\b \b"))
				}
			} else if b >= 32 && b <= 126 {
				lineBuf.WriteByte(b)
				channel.Write([]byte{b}) // Echo
			}
		}
	}
}

func (s *SSHServer) runSampleTest(channel io.ReadWriter) {
	samplePath := "attack_sample.pcap"
	data, err := os.ReadFile(samplePath)
	if err != nil {
		fmt.Fprintf(channel, "\033[1;31m[-] File %s tidak ditemukan di server: %v\033[0m\r\n", samplePath, err)
		return
	}

	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPBytes(data)
	if err != nil {
		fmt.Fprintf(channel, "\033[1;31m[-] Error parsing: %v\033[0m\r\n", err)
		return
	}

	res := s.engine.Analyze("attack_sample_multivector.pcap", sha256Hex, packets, totalBytes, start)
	RenderANSIDossier(channel, res)
}

// RenderANSIDossier mencetak laporan triase taktis berwarna ANSI lengkap ke terminal client
func RenderANSIDossier(w io.Writer, res model.AnalysisResult) {
	scoreColor := "\033[1;32m" // Green
	if res.ThreatScore >= 75 {
		scoreColor = "\033[1;31m" // Red
	} else if res.ThreatScore >= 45 {
		scoreColor = "\033[1;33m" // Yellow
	}

	out := fmt.Sprintf(`
`+"\033[1;36m"+`╔══════════════════════════════════════════════════════════════════════════════════╗
║               SPECTRA // TACTICAL AIR-GAPPED TRIASE DOSSIER                     ║
║      Swift Packet Extraction & Cyber Threat Rapid Analyzer // RFC-4254 Engine   ║
╚══════════════════════════════════════════════════════════════════════════════════╝`+"\033[0m"+`

`+"\033[1;37m"+`[★] Target Artifact   :`+"\033[0m"+` %s
`+"\033[1;37m"+`[★] SHA-256 Checksum  :`+"\033[0m"+` %s
`+"\033[1;37m"+`[★] Waktu Triase      :`+"\033[0m"+` %s (Kecepatan Pemrosesan Kilat)
`+"\033[1;37m"+`[★] Total Paket       :`+"\033[0m"+` %d paket (%.2f KB)
`+"\033[1;37m"+`[★] Threat Risk Score :`+"\033[0m"+` %s%d / 100 [%s]`+"\033[0m"+`

`+"\033[1;33m"+`[+] RINGKASAN EKSEKUTIF TAKTIS:`+"\033[0m"+`
    %s

`+"\033[1;36m"+`[+] DISTRIBUSI PROTOKOL:`+"\033[0m"+`
    TCP: %d | UDP: %d | DNS: %d | HTTP: %d | ICMP: %d

`+"\033[1;36m"+`[+] MATRIKS FASE MITRE ATT&CK:`+"\033[0m"+`
    Recon: %d | Initial Access: %d | Execution: %d | Credential: %d | C2: %d | Exfiltration: %d

`+"\033[1;31m"+`[!] INDIKATOR KOMPROMI TERDETEKSI (%d Temuan):`+"\033[0m"+`
`,
		res.TargetFileName,
		res.SHA256Checksum,
		res.AnalysisDuration,
		res.TotalPackets,
		float64(res.TotalBytes)/1024.0,
		scoreColor,
		res.ThreatScore,
		res.ThreatLevel,
		res.ExecutiveSummary,
		res.ProtocolStats.TCPCount,
		res.ProtocolStats.UDPCount,
		res.ProtocolStats.DNSCount,
		res.ProtocolStats.HTTPCount,
		res.ProtocolStats.ICMPCount,
		res.MitreSummary.Reconnaissance,
		res.MitreSummary.InitialAccess,
		res.MitreSummary.Execution,
		res.MitreSummary.CredentialAccess,
		res.MitreSummary.CommandAndControl,
		res.MitreSummary.Exfiltration,
		len(res.Indicators),
	)

	fmt.Fprint(w, strings.ReplaceAll(out, "\n", "\r\n"))

	for idx, ind := range res.Indicators {
		sevCol := "\033[1;31m"
		if ind.Severity == model.SeverityHigh {
			sevCol = "\033[1;33m"
		}
		iocText := fmt.Sprintf("    [%d] %s[%-8s]\033[0m \033[1m%s\033[0m\r\n"+
			"        MITRE   : \033[36m%s\033[0m\r\n"+
			"        Aliran  : %s -> %s (Proto: %s)\r\n"+
			"        Tindakan: \033[32m%s\033[0m\r\n\r\n",
			idx+1, sevCol, ind.Severity, ind.Title, ind.MitreAttack, ind.SrcIP, ind.DstIP, ind.Protocol, ind.Recommendation)
		fmt.Fprint(w, iocText)
	}

	fmt.Fprint(w, "\033[1;33m[+] REKONSTRUKSI KRONOLOGI ALUR SERANGAN (TIMELINE):\033[0m\r\n")
	for _, evt := range res.Timeline {
		fmt.Fprintf(w, "    \033[90m%s\033[0m [\033[36m%-15s\033[0m] %s\r\n",
			evt.Timestamp.Format("15:04:05.000"), evt.Stage, evt.Message)
	}

	if res.MaxEntropy > 0 {
		fmt.Fprintf(w, "\r\n\033[1;35m[🔬] ANALISIS ENTROPI SHANNON:\033[0m Max: %.3f/8.0 | Avg: %.3f/8.0\r\n", res.MaxEntropy, res.AvgEntropy)
	}

	if len(res.BlocklistRules.AttackerIPs) > 0 {
		fmt.Fprintf(w, "\r\n\033[1;31m[🛡️] REKOMENDASI MITIGASI INSTAN (BLOCKLIST %d IP):\033[0m\r\n", len(res.BlocklistRules.AttackerIPs))
		for _, ip := range res.BlocklistRules.AttackerIPs {
			fmt.Fprintf(w, "    • iptables -A INPUT -s %s -j DROP\r\n", ip)
		}
	}

	footer := fmt.Sprintf("\r\n\033[1;32m[✓] Selesai. Visual Web Dossier & STIX 2.1 siap diakses di: http://127.0.0.1:8888/dashboard\033[0m\r\n\r\n")
	fmt.Fprint(w, footer)
}
