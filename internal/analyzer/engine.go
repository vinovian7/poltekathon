package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"spectra/internal/model"
	"spectra/internal/pcap"
)

type Engine struct {
	portScanThreshold int
	ruleEngine        *RuleEngine
}

func NewEngine() *Engine {
	return &Engine{
		portScanThreshold: 6,
		ruleEngine:        NewRuleEngine(),
	}
}

func (e *Engine) GetRuleEngine() *RuleEngine {
	return e.ruleEngine
}

func (e *Engine) Analyze(filename, sha256Hex string, packets []model.ParsedPacket, totalBytes int64, startTime time.Time) model.AnalysisResult {
	result := model.AnalysisResult{
		TargetFileName:  filename,
		SHA256Checksum:  sha256Hex,
		AnalyzedAt:      time.Now(),
		TotalPackets:    len(packets),
		TotalBytes:      totalBytes,
		TopSources:      make(map[string]int),
		TopDestinations: make(map[string]int),
		AirGappedStatus: "VERIFIED_OFFLINE_READY",
	}

	synTracker := make(map[string]map[uint16]bool)
	flowMap := make(map[string]*model.NetworkFlow)
	rawIndicators := []model.ThreatIndicator{}

	// Ambil sampel maksimal 50 paket untuk visualisasi Packet Inspector
	sampleLimit := len(packets)
	if sampleLimit > 50 {
		sampleLimit = 50
	}
	result.SamplePackets = make([]model.ParsedPacket, sampleLimit)
	copy(result.SamplePackets, packets[:sampleLimit])

	// Tracking entropi & IOC per IP untuk attack graph
	attackerIPs := make(map[string]bool)
	var totalEntropy float64
	var maxEntropy float64
	entropyCount := 0

	for _, p := range packets {
		if p.SrcIP != "" {
			result.TopSources[p.SrcIP]++
		}
		if p.DstIP != "" {
			result.TopDestinations[p.DstIP]++
		}

		// Akumulasi statistik entropi
		if p.Entropy > 0 {
			totalEntropy += p.Entropy
			entropyCount++
			if p.Entropy > maxEntropy {
				maxEntropy = p.Entropy
			}
		}

		// Agregasi Aliran Komunikasi (Network Flows)
		if p.SrcIP != "" && p.DstIP != "" {
			flowKey := fmt.Sprintf("%s->%s (%s)", p.SrcIP, p.DstIP, p.Protocol)
			if f, exists := flowMap[flowKey]; exists {
				f.Packets++
				f.Bytes += int64(p.Length)
			} else {
				flowMap[flowKey] = &model.NetworkFlow{
					SrcIP:    p.SrcIP,
					DstIP:    p.DstIP,
					Protocol: p.Protocol,
					Packets:  1,
					Bytes:    int64(p.Length),
				}
			}
		}

		switch p.Protocol {
		case "TCP":
			result.ProtocolStats.TCPCount++
			if strings.Contains(p.Summary, "SYN") && !strings.Contains(p.Summary, "ACK") {
				if synTracker[p.SrcIP] == nil {
					synTracker[p.SrcIP] = make(map[uint16]bool)
				}
				synTracker[p.SrcIP][p.DstPort] = true
			}
		case "UDP":
			result.ProtocolStats.UDPCount++
		case "DNS":
			result.ProtocolStats.DNSCount++
			e.checkDNSAnomaly(p, &rawIndicators)
		case "HTTP":
			result.ProtocolStats.HTTPCount++
			e.checkHTTPPayload(p, &rawIndicators)
		case "ICMP":
			result.ProtocolStats.ICMPCount++
		default:
			result.ProtocolStats.Other++
		}

		// Deteksi port berbahaya & C2 listeners
		e.checkDangerousPorts(p, &rawIndicators)

		// Evaluasi aturan kustom dinamis (YAML/JSON Custom Rule Engine)
		if customFindings := e.ruleEngine.Evaluate(p); len(customFindings) > 0 {
			rawIndicators = append(rawIndicators, customFindings...)
		}

		// Deteksi high-entropy payload (obfuscation/encryption anomaly)
		if len(p.Payload) >= 16 && p.Entropy >= 7.2 {
			e.checkHighEntropy(p, &rawIndicators)
		}
	}

	result.MaxEntropy = maxEntropy
	if entropyCount > 0 {
		result.AvgEntropy = totalEntropy / float64(entropyCount)
	}

	// Evaluasi Port Scanning (Reconnaissance)
	for ip, ports := range synTracker {
		if len(ports) >= e.portScanThreshold {
			rawIndicators = append(rawIndicators, model.ThreatIndicator{
				ID:             "IOC-RECON-PORT-SCAN",
				Timestamp:      time.Now(),
				Title:          "Active TCP Port Scanning / Sweep",
				Description:    fmt.Sprintf("Host sumber %s melakukan probing agresif ke %d port target berbeda.", ip, len(ports)),
				Severity:       model.SeverityHigh,
				MitreTactic:    "Reconnaissance",
				MitreAttack:    "T1046 - Network Service Discovery",
				SrcIP:          ip,
				ScoreWeight:    10,
				Evidence:       fmt.Sprintf("Probed %d destination ports within session", len(ports)),
				Recommendation: fmt.Sprintf("Blokir IP %s pada firewall perimeter dan amankan port-port target terbuka.", ip),
			})
		}
	}

	// Konversi flow map ke slice top flows
	for _, f := range flowMap {
		result.NetworkFlows = append(result.NetworkFlows, *f)
	}
	sort.Slice(result.NetworkFlows, func(i, j int) bool {
		return result.NetworkFlows[i].Packets > result.NetworkFlows[j].Packets
	})
	if len(result.NetworkFlows) > 10 {
		result.NetworkFlows = result.NetworkFlows[:10]
	}

	// ============ MODUL 3: RAG THREAT SCORING SYSTEM ============
	// Hitung Threat Risk Index berbasis bobot kategori ancaman
	breakdown := model.RiskScoreBreakdown{}
	mitreSummary := model.MitreMatrixSummary{}

	for _, ind := range rawIndicators {
		switch ind.Severity {
		case model.SeverityCritical:
			breakdown.CriticalCount++
			breakdown.CriticalPoints += 35
		case model.SeverityHigh:
			breakdown.HighCount++
			breakdown.HighPoints += 20
		case model.SeverityMedium:
			breakdown.MediumCount++
			breakdown.MediumPoints += 10
		}

		switch ind.MitreTactic {
		case "Reconnaissance":
			mitreSummary.Reconnaissance++
		case "Initial Access":
			mitreSummary.InitialAccess++
		case "Execution":
			mitreSummary.Execution++
		case "Credential Access":
			mitreSummary.CredentialAccess++
		case "Command and Control":
			mitreSummary.CommandAndControl++
		case "Exfiltration":
			mitreSummary.Exfiltration++
		}

		// Kumpulkan attacker IPs dari IOC High/Critical
		if (ind.Severity == model.SeverityCritical || ind.Severity == model.SeverityHigh) && ind.SrcIP != "" {
			attackerIPs[ind.SrcIP] = true
		}
	}

	rawScore := breakdown.CriticalPoints + breakdown.HighPoints + breakdown.MediumPoints
	breakdown.RawScore = rawScore
	if rawScore > 100 {
		rawScore = 100
	}
	breakdown.FinalScore = rawScore

	result.ThreatScore = rawScore
	result.RiskBreakdown = breakdown
	result.MitreSummary = mitreSummary

	// Klasifikasi RAG
	if result.ThreatScore >= 70 {
		result.ThreatLevel = model.SeverityCritical
	} else if result.ThreatScore >= 30 {
		result.ThreatLevel = model.SeverityHigh
	} else if result.ThreatScore >= 10 {
		result.ThreatLevel = model.SeverityMedium
	} else {
		result.ThreatLevel = model.SeverityLow
	}

	result.Indicators = rawIndicators
	result.Timeline = e.buildTimeline(rawIndicators)
	result.AnalysisDuration = fmt.Sprintf("%.2f ms", float64(time.Since(startTime).Microseconds())/1000.0)

	// ============ MODUL 1: ATTACK GRAPH BUILDER ============
	result.AttackGraph = e.buildAttackGraph(packets, rawIndicators, attackerIPs, flowMap)

	// ============ MODUL 4: BLOCKLIST GENERATOR ============
	result.BlocklistRules = e.generateBlocklist(attackerIPs, rawIndicators)

	// ============ MODUL 2 (NEW): TACTICAL INCIDENT PLAYBOOK ============
	var victimIPList []string
	for _, ind := range rawIndicators {
		if ind.DstIP != "" && !attackerIPs[ind.DstIP] {
			victimIPList = append(victimIPList, ind.DstIP)
		}
	}
	result.Playbook = GeneratePlaybook(rawIndicators, result.BlocklistRules.AttackerIPs, victimIPList)

	// ============ MODUL 4 (NEW): THROUGHPUT & PERFORMANCE METRICS ============
	durationMicro := float64(time.Since(startTime).Microseconds())
	if durationMicro > 0 {
		durationSec := durationMicro / 1000000.0
		result.ThroughputMBps = (float64(totalBytes) / (1024.0 * 1024.0)) / durationSec
		result.ThroughputPktsSec = float64(len(packets)) / durationSec
	}
	result.ActiveRulesCount = len(e.ruleEngine.GetActiveRules())

	// Rekonstruksi Ringkasan Eksekutif Taktis
	result.ExecutiveSummary = e.generateExecutiveSummary(result)

	// ============ MODUL: EXECUTIVE WAR-ROOM BRIEFING (NON-TEKNIS) ============
	result.ExecutiveBriefing = GenerateExecutiveBriefing(result)

	return result
}

// ============ MODUL 1: INTERACTIVE ATTACK GRAPH ============
func (e *Engine) buildAttackGraph(packets []model.ParsedPacket, indicators []model.ThreatIndicator, attackerIPs map[string]bool, flowMap map[string]*model.NetworkFlow) model.AttackGraph {
	nodeMap := make(map[string]*model.AttackGraphNode)
	edgeMap := make(map[string]*model.AttackGraphEdge)

	// Kumpulkan set IP yang terkena IOC (target/victim)
	victimIPs := make(map[string]bool)
	for _, ind := range indicators {
		if ind.DstIP != "" && !attackerIPs[ind.DstIP] {
			victimIPs[ind.DstIP] = true
		}
	}

	// Buat node dari semua flow
	for _, flow := range flowMap {
		// Node source
		if _, exists := nodeMap[flow.SrcIP]; !exists {
			role := "normal"
			color := "#00f2fe"
			if attackerIPs[flow.SrcIP] {
				role = "attacker"
				color = "#ff0055"
			}
			nodeMap[flow.SrcIP] = &model.AttackGraphNode{
				ID:      flow.SrcIP,
				Label:   flow.SrcIP,
				Role:    role,
				Color:   color,
				Packets: flow.Packets,
				IsIOC:   attackerIPs[flow.SrcIP],
				Tooltip: fmt.Sprintf("IP: %s | Role: %s | Packets: %d", flow.SrcIP, role, flow.Packets),
			}
		} else {
			nodeMap[flow.SrcIP].Packets += flow.Packets
		}

		// Node destination
		if _, exists := nodeMap[flow.DstIP]; !exists {
			role := "normal"
			color := "#00f2fe"
			if victimIPs[flow.DstIP] {
				role = "victim"
				color = "#ff9900"
			}
			nodeMap[flow.DstIP] = &model.AttackGraphNode{
				ID:      flow.DstIP,
				Label:   flow.DstIP,
				Role:    role,
				Color:   color,
				Packets: flow.Packets,
				IsIOC:   victimIPs[flow.DstIP],
				Tooltip: fmt.Sprintf("IP: %s | Role: %s | Packets: %d", flow.DstIP, role, flow.Packets),
			}
		} else {
			nodeMap[flow.DstIP].Packets += flow.Packets
		}

		// Edge
		isIOCEdge := attackerIPs[flow.SrcIP] && (victimIPs[flow.DstIP] || flow.DstIP != "")
		edgeColor := "#00f2fe44"
		edgeWidth := 1
		if isIOCEdge {
			edgeColor = "#ff005588"
			edgeWidth = 3
		}
		edgeKey := fmt.Sprintf("%s->%s", flow.SrcIP, flow.DstIP)
		if _, exists := edgeMap[edgeKey]; !exists {
			edgeMap[edgeKey] = &model.AttackGraphEdge{
				From:     flow.SrcIP,
				To:       flow.DstIP,
				Protocol: flow.Protocol,
				Packets:  flow.Packets,
				IsIOC:    isIOCEdge,
				Color:    edgeColor,
				Width:    edgeWidth,
				Tooltip:  fmt.Sprintf("%s -> %s | Proto: %s | Pkts: %d", flow.SrcIP, flow.DstIP, flow.Protocol, flow.Packets),
			}
		} else {
			edgeMap[edgeKey].Packets += flow.Packets
		}
	}

	graph := model.AttackGraph{}
	for _, n := range nodeMap {
		graph.Nodes = append(graph.Nodes, *n)
	}
	for _, ed := range edgeMap {
		graph.Edges = append(graph.Edges, *ed)
	}
	return graph
}

// ============ MODUL 2: SHANNON ENTROPY DETECTION ============
func (e *Engine) checkHighEntropy(p model.ParsedPacket, indicators *[]model.ThreatIndicator) {
	label := pcap.EntropyLabel(p.Entropy)
	*indicators = append(*indicators, model.ThreatIndicator{
		ID:             fmt.Sprintf("IOC-ENTROPY-%s-%d", p.SrcIP, p.Index),
		Timestamp:      p.Timestamp,
		Title:          "High-Entropy Payload — Potential Encrypted C2 / Packed Malware",
		Description:    fmt.Sprintf("Payload paket #%d menunjukkan entropi Shannon %.2f/8.0 — %s", p.Index, p.Entropy, label),
		Severity:       model.SeverityHigh,
		MitreTactic:    "Command and Control",
		MitreAttack:    "T1573 - Encrypted Channel / T1027 - Obfuscated Files",
		SrcIP:          p.SrcIP,
		DstIP:          p.DstIP,
		Protocol:       p.Protocol,
		ScoreWeight:    20,
		Entropy:        p.Entropy,
		EntropyLabel:   label,
		Evidence:       fmt.Sprintf("Shannon Entropy: %.4f | Payload size: %d bytes", p.Entropy, len(p.Payload)),
		EvidenceHex:    p.HexDump,
		Recommendation: "Analisis payload dengan alat dekripsi/deobfuskasi. Periksa proses yang berkomunikasi ke IP tujuan. Pertimbangkan isolasi host.",
	})
}

// ============ MODUL 4: BLOCKLIST GENERATOR ============
func (e *Engine) generateBlocklist(attackerIPs map[string]bool, indicators []model.ThreatIndicator) model.BlocklistRules {
	rules := model.BlocklistRules{}
	seen := make(map[string]bool)

	for ip := range attackerIPs {
		if seen[ip] || ip == "" {
			continue
		}
		seen[ip] = true
		rules.AttackerIPs = append(rules.AttackerIPs, ip)
		rules.IPtablesRules = append(rules.IPtablesRules,
			fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip),
			fmt.Sprintf("iptables -A OUTPUT -d %s -j DROP", ip),
		)
		rules.WindowsRules = append(rules.WindowsRules,
			fmt.Sprintf(`New-NetFirewallRule -DisplayName "SPECTRA-BLOCK-%s" -Direction Inbound -RemoteAddress %s -Action Block`, ip, ip),
			fmt.Sprintf(`New-NetFirewallRule -DisplayName "SPECTRA-BLOCK-OUT-%s" -Direction Outbound -RemoteAddress %s -Action Block`, ip, ip),
		)
		sid := 9000000 + len(rules.SuricataRules) + 1
		rules.SuricataRules = append(rules.SuricataRules,
			fmt.Sprintf(`drop ip [%s] any -> any any (msg:"SPECTRA Auto-Block Inbound %s"; sid:%d; rev:1;)`, ip, ip, sid),
			fmt.Sprintf(`drop ip any any -> [%s] any (msg:"SPECTRA Auto-Block Outbound %s"; sid:%d; rev:1;)`, ip, ip, sid+1),
		)
	}

	rules.PlainIPList = strings.Join(rules.AttackerIPs, "\n")
	return rules
}

func (e *Engine) checkDangerousPorts(p model.ParsedPacket, indicators *[]model.ThreatIndicator) {
	badPorts := map[uint16]struct {
		name   string
		tactic string
		mitre  string
		weight int
	}{
		4444: {"Metasploit Default C2 Listener", "Command and Control", "T1571 - Non-Standard Port C2", 35},
		1337: {"Common Elite Backdoor Port", "Command and Control", "T1571 - Non-Standard Port C2", 30},
		6667: {"IRC Botnet Channel Communication", "Command and Control", "T1071.001 - Web/IRC Service", 30},
		5555: {"Unauthenticated Android ADB Debug Bridge", "Initial Access", "T1190 - Exploit Public-Facing Application", 25},
		9001: {"Tor Darknet Relay Traffic", "Command and Control", "T1090.003 - Multi-hop Proxy", 25},
	}

	if info, ok := badPorts[p.DstPort]; ok {
		*indicators = append(*indicators, model.ThreatIndicator{
			ID:             fmt.Sprintf("IOC-PORT-%d", p.DstPort),
			Timestamp:      p.Timestamp,
			Title:          fmt.Sprintf("Malicious / C2 Port Activity: %d", p.DstPort),
			Description:    fmt.Sprintf("Koneksi keluar mengarah ke port berisiko tinggi (%s).", info.name),
			Severity:       model.SeverityHigh,
			MitreTactic:    info.tactic,
			MitreAttack:    info.mitre,
			SrcIP:          p.SrcIP,
			DstIP:          p.DstIP,
			Protocol:       p.Protocol,
			ScoreWeight:    info.weight,
			Evidence:       fmt.Sprintf("Traffic directed to port %d (%s)", p.DstPort, info.name),
			Recommendation: fmt.Sprintf("Isolasi perangkat sumber %s dan periksa proses sistem yang membuka port %d.", p.SrcIP, p.DstPort),
		})
	}
}

func (e *Engine) checkDNSAnomaly(p model.ParsedPacket, indicators *[]model.ThreatIndicator) {
	summary := p.Summary
	if strings.Contains(summary, "DNS Query:") {
		parts := strings.Split(summary, "DNS Query: ")
		if len(parts) > 1 {
			query := strings.Split(parts[1], " ")[0]

			// Deteksi DNS Tunneling / Exfiltration (Subdomain sangat panjang atau base64)
			if len(query) > 35 {
				*indicators = append(*indicators, model.ThreatIndicator{
					ID:             "IOC-DNS-EXFILTRATION",
					Timestamp:      p.Timestamp,
					Title:          "Suspicious DNS Data Exfiltration / Tunneling",
					Description:    fmt.Sprintf("Query DNS dengan panjang payload abnormal (%d karakter): %s", len(query), query),
					Severity:       model.SeverityCritical,
					MitreTactic:    "Exfiltration",
					MitreAttack:    "T1071.004 - DNS Data Exfiltration",
					SrcIP:          p.SrcIP,
					DstIP:          p.DstIP,
					Protocol:       "DNS",
					ScoreWeight:    45,
					Evidence:       query,
					EvidenceHex:    p.HexDump,
					Recommendation: "Blokir domain resolver di level DNS server lokal dan periksa malware exfiltrator di host sumber.",
				})
			}
		}
	}
}

func (e *Engine) checkHTTPPayload(p model.ParsedPacket, indicators *[]model.ThreatIndicator) {
	if len(p.Payload) == 0 {
		return
	}
	payloadStr := string(p.Payload)
	lowerPayload := strings.ToLower(payloadStr)

	// Signature Detection Catalog
	type Rule struct {
		keyword   string
		title     string
		desc      string
		tactic    string
		mitre     string
		severity  model.Severity
		weight    int
		recommend string
	}

	rules := []Rule{
		// Log4Shell (CVE-2021-44228)
		{
			keyword:   "${jndi:",
			title:     "Log4Shell Zero-Day Exploitation Attempt (CVE-2021-44228)",
			desc:      "Ditemukan string JNDI injection payload untuk memicu Remote Code Execution pada Log4j.",
			tactic:    "Initial Access",
			mitre:     "T1190 - Exploit Public-Facing Application",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Segera patching dependensi Apache Log4j ke versi >=2.17.1 dan isolasi server target.",
		},
		{
			keyword:   "${${lower:j}",
			title:     "Obfuscated Log4Shell JNDI Payload",
			desc:      "Ditemukan payload JNDI terobfuskasi untuk melewati Web Application Firewall (WAF).",
			tactic:    "Initial Access",
			mitre:     "T1190 - Exploit Public-Facing Application",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Periksa WAF logs dan perbarui aturan deteksi regex untuk payload terobfuskasi.",
		},

		// Web Shell & Remote Command Execution
		{
			keyword:   "/bin/sh",
			title:     "Unix Shell Invocation Payload (/bin/sh)",
			desc:      "Perintah eksekusi shell Linux terdeteksi dalam payload HTTP.",
			tactic:    "Execution",
			mitre:     "T1059.004 - Unix Shell",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Hentikan proses web server terkait dan periksa direktori webroot untuk file webshell.",
		},
		{
			keyword:   "cmd.exe",
			title:     "Windows Command Shell Execution (cmd.exe)",
			desc:      "Perintah eksekusi shell Windows terdeteksi dalam payload HTTP.",
			tactic:    "Execution",
			mitre:     "T1059.003 - Windows Command Shell",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Audit event log Windows (Event ID 4688) untuk eksekusi proses mencurigakan.",
		},
		{
			keyword:   "powershell -enc",
			title:     "Encoded PowerShell Execution Attempt",
			desc:      "Skrip PowerShell terenkripsi Base64 terdeteksi pada aliran data lalu lintas.",
			tactic:    "Execution",
			mitre:     "T1059.001 - PowerShell",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Decode string Base64 terkait untuk menganalisis malware dropper.",
		},

		// SQL Injection
		{
			keyword:   "union select",
			title:     "SQL Injection Attempt (UNION SELECT)",
			desc:      "Percobaan eksfiltrasi data database via SQL Injection dalam HTTP stream.",
			tactic:    "Initial Access",
			mitre:     "T1190 - Exploit Public-Facing Application",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Gunakan parameterized queries (Prepared Statements) pada endpoint database aplikasi.",
		},
		{
			keyword:   "' or '1'='1",
			title:     "Classic SQL Injection Authentication Bypass",
			desc:      "Bypass otentikasi menggunakan pola logika tautologi SQL.",
			tactic:    "Initial Access",
			mitre:     "T1190 - Exploit Public-Facing Application",
			severity:  model.SeverityHigh,
			weight:    20,
			recommend: "Implementasikan validasi input ketat dan ORM terstandar.",
		},

		// Path Traversal / LFI
		{
			keyword:   "../",
			title:     "Path Traversal / Local File Inclusion Attempt",
			desc:      "Pola directory climbing (../) untuk mengakses file sensitif di luar web root.",
			tactic:    "Initial Access",
			mitre:     "T1083 - File and Directory Discovery",
			severity:  model.SeverityHigh,
			weight:    20,
			recommend: "Batasi hak akses file server dan cegah path resolution langsung dari parameter input.",
		},
		{
			keyword:   "/etc/passwd",
			title:     "System Credential File Access (/etc/passwd)",
			desc:      "Percobaan membaca file identitas pengguna sistem Unix.",
			tactic:    "Credential Access",
			mitre:     "T1003 - OS Credential Dumping",
			severity:  model.SeverityCritical,
			weight:    35,
			recommend: "Tinjau izin baca sistem (chmod/chown) dan terapkan AppArmor/SELinux.",
		},

		// Malicious Scanner User-Agents
		{
			keyword:   "sqlmap",
			title:     "Automated Exploitation Scanner (sqlmap)",
			desc:      "Header User-Agent menunjukkan pemindaian database otomatis oleh framework sqlmap.",
			tactic:    "Reconnaissance",
			mitre:     "T1595.002 - Vulnerability Scanning",
			severity:  model.SeverityHigh,
			weight:    20,
			recommend: "Tambahkan alamat IP penyerang ke daftar blokir perimeter firewall.",
		},
		{
			keyword:   "nikto",
			title:     "Web Server Vulnerability Scanner (Nikto)",
			desc:      "Pemindaian kelemahan web server otomatis terdeteksi via signature Nikto.",
			tactic:    "Reconnaissance",
			mitre:     "T1595.002 - Vulnerability Scanning",
			severity:  model.SeverityMedium,
			weight:    10,
			recommend: "Blokir User-Agent scanner dan sembunyikan banner versi web server.",
		},

		// Cleartext Credential Leakage
		{
			keyword:   "password=",
			title:     "Cleartext Credential Transmission",
			desc:      "Kredensial kata sandi ditransmisikan tanpa enkripsi dalam lalu lintas jaringan.",
			tactic:    "Credential Access",
			mitre:     "T1552 - Unsecured Credentials",
			severity:  model.SeverityMedium,
			weight:    10,
			recommend: "Paksa penggunaan protokol terenkripsi (HTTPS/TLS) untuk seluruh form transmisi kredensial.",
		},
	}

	for _, rule := range rules {
		if strings.Contains(lowerPayload, rule.keyword) {
			entropyVal := 0.0
			entropyLbl := ""
			if len(p.Payload) > 0 {
				entropyVal = p.Entropy
				entropyLbl = pcap.EntropyLabel(entropyVal)
			}
			*indicators = append(*indicators, model.ThreatIndicator{
				ID:             fmt.Sprintf("IOC-%s", strings.ToUpper(strings.ReplaceAll(rule.keyword, "/", "_"))),
				Timestamp:      p.Timestamp,
				Title:          rule.title,
				Description:    rule.desc,
				Severity:       rule.severity,
				MitreTactic:    rule.tactic,
				MitreAttack:    rule.mitre,
				SrcIP:          p.SrcIP,
				DstIP:          p.DstIP,
				Protocol:       "HTTP",
				ScoreWeight:    rule.weight,
				Entropy:        entropyVal,
				EntropyLabel:   entropyLbl,
				Evidence:       fmt.Sprintf("Matched substring: %s", rule.keyword),
				EvidenceHex:    p.HexDump,
				Recommendation: rule.recommend,
			})
		}
	}
}

func (e *Engine) buildTimeline(indicators []model.ThreatIndicator) []model.TimelineEvent {
	var events []model.TimelineEvent

	for _, ind := range indicators {
		events = append(events, model.TimelineEvent{
			Timestamp:   ind.Timestamp,
			Stage:       ind.MitreTactic,
			Severity:    ind.Severity,
			Source:      ind.SrcIP,
			Destination: ind.DstIP,
			Tactic:      ind.MitreAttack,
			Message:     fmt.Sprintf("[%s] %s (%s)", ind.MitreAttack, ind.Title, ind.Evidence),
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events
}

func (e *Engine) generateExecutiveSummary(res model.AnalysisResult) string {
	if res.ThreatScore == 0 {
		return fmt.Sprintf("Artefak jaringan '%s' (SHA-256: %s...) berhasil dianalisis dalam %s di bawah kondisi air-gapped mandiri. Tidak ditemukan anomali lalu lintas maupun indikator eksploitasi siber. Lalu lintas tergolong BERSIH (NORMAL) dengan integritas jaringan terjaga.",
			res.TargetFileName, res.SHA256Checksum[:8], res.AnalysisDuration)
	}

	return fmt.Sprintf("PERINGATAN TAKTIS: Artefak '%s' menunjukkan tingkat risiko %s (Skor Ancaman: %d/100 — CRITICAL:%d HIGH:%d MEDIUM:%d). Ditemukan %d Indikator Kompromi (IOC) meliputi fase %d Reconnaissance, %d Initial Access/Exploitation, dan %d Exfiltration. Max Entropi Payload: %.2f/8.0. Diperlukan tindakan isolasi darurat terhadap %d host penyerang teridentifikasi.",
		res.TargetFileName, res.ThreatLevel, res.ThreatScore,
		res.RiskBreakdown.CriticalCount, res.RiskBreakdown.HighCount, res.RiskBreakdown.MediumCount,
		len(res.Indicators),
		res.MitreSummary.Reconnaissance, res.MitreSummary.InitialAccess+res.MitreSummary.Execution, res.MitreSummary.Exfiltration,
		res.MaxEntropy, len(res.BlocklistRules.AttackerIPs))
}
