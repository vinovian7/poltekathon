package analyzer

import (
	"fmt"
	"strings"
	"time"

	"spectra/internal/model"
)

// GeneratePlaybook menyusun rencana aksi penanganan insiden otomatis berbasis temuan IOC
func GeneratePlaybook(indicators []model.ThreatIndicator, attackerIPs []string, victimIPs []string) model.IncidentPlaybook {
	playbook := model.IncidentPlaybook{
		GeneratedAt: time.Now(),
		Steps:       []model.PlaybookStep{},
	}

	stepCounter := 1

	// Catat teknik-teknik MITRE yang terdeteksi
	detectedTechniques := make(map[string]bool)
	for _, ind := range indicators {
		detectedTechniques[ind.MitreAttack] = true
	}

	// -------------------------------------------------------------
	// FASE 1: IMMEDIATE CONTAINMENT (P1-CRITICAL)
	// -------------------------------------------------------------
	for _, ip := range attackerIPs {
		playbook.Steps = append(playbook.Steps, model.PlaybookStep{
			StepNumber: stepCounter,
			Phase:      "Phase 1: Immediate Containment",
			Priority:   "P1-CRITICAL",
			Action:     fmt.Sprintf("Isolasi lalu lintas jaringan dari host penyerang %s pada perimeter gateway.", ip),
			Command:    fmt.Sprintf("iptables -A INPUT -s %s -j DROP && iptables -A OUTPUT -d %s -j DROP", ip, ip),
			TargetHost: ip,
			MitreRef:   "T1046 / T1190",
		})
		stepCounter++
	}

	for tech := range detectedTechniques {
		lowerTech := strings.ToLower(tech)

		// 1. Log4Shell
		if strings.Contains(lowerTech, "log4j") || strings.Contains(lowerTech, "log4shell") {
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P1-CRITICAL",
				Action:     "Mitigasi Zero-Day Log4j: Nonaktifkan pencarian pesan JNDI secara paksa pada seluruh JVM worker.",
				Command:    "export LOG4J_FORMAT_MSG_NO_LOOKUPS=true && java -Dlog4j2.formatMsgNoLookups=true -jar app.jar",
				MitreRef:   "T1190 - Exploit Public-Facing Application",
			})
			stepCounter++
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P1-CRITICAL",
				Action:     "Blokir egress outbound connection ke server LDAP (port 389, 636) dan RMI (port 1099) dari backend subnet.",
				Command:    "iptables -A OUTPUT -p tcp -m multiport --dports 389,636,1099,1389 -j REJECT",
				MitreRef:   "T1071 - Application Layer Protocol",
			})
			stepCounter++
		}

		// 2. Web Shell / RCE
		if strings.Contains(lowerTech, "shell") || strings.Contains(lowerTech, "rce") || strings.Contains(lowerTech, "command") {
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P1-CRITICAL",
				Action:     "Hentikan worker proses web server yang memunculkan subprocess shell Linux (/bin/sh atau cmd.exe).",
				Command:    "pkill -9 -f '/bin/sh' || taskkill /F /IM cmd.exe",
				MitreRef:   "T1059.004 - Unix Shell",
			})
			stepCounter++
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P1-CRITICAL",
				Action:     "Kunci izin tulis direktori webroot publik menjadi Read-Only untuk mencegah dropper webshell baru.",
				Command:    "chmod -R 555 /var/www/html/ && chown -R root:root /var/www/html/",
				MitreRef:   "T1505.003 - Web Shell",
			})
			stepCounter++
		}

		// 3. SQL Injection
		if strings.Contains(lowerTech, "sql") {
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P2-URGENT",
				Action:     "Aktifkan aturan WAF SQLi signature blocking pada reverse proxy (Nginx/ModSecurity/Cloudflare).",
				Command:    "SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_FILENAME|ARGS_NAMES|ARGS \"(?i:(?:union.*select|'\\s*or\\s*'1'='1))\" \"id:1001,phase:2,deny,status:403\"",
				MitreRef:   "T1190 - SQL Injection",
			})
			stepCounter++
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P2-URGENT",
				Action:     "Kunci hak akses pengguna database aplikasi (DB Least Privilege) dan nonaktifkan izin FILE / SUPERUSER.",
				Command:    "REVOKE FILE, SUPER, PROCESS ON *.* FROM 'webapp_user'@'localhost';",
				MitreRef:   "T1078 - Valid Accounts",
			})
			stepCounter++
		}

		// 4. DNS Exfiltration / Tunneling
		if strings.Contains(lowerTech, "dns") {
			playbook.Steps = append(playbook.Steps, model.PlaybookStep{
				StepNumber: stepCounter,
				Phase:      "Phase 1: Immediate Containment",
				Priority:   "P1-CRITICAL",
				Action:     "Pasang DNS Sinkhole (RPZ - Response Policy Zone) untuk domain tunneling dan batasi recursive lookup.",
				Command:    "echo 'zone \"attacker.net\" { type master; file \"/etc/bind/db.sinkhole\"; };' >> /etc/bind/named.conf.local",
				MitreRef:   "T1071.004 - DNS Data Exfiltration",
			})
			stepCounter++
		}
	}

	// -------------------------------------------------------------
	// FASE 2: ERADICATION & FORENSICS (P2-URGENT)
	// -------------------------------------------------------------
	playbook.Steps = append(playbook.Steps, model.PlaybookStep{
		StepNumber: stepCounter,
		Phase:      "Phase 2: Eradication & Forensics",
		Priority:   "P2-URGENT",
		Action:     "Amankan memory volatile dump (RAM) dan daftar koneksi jaringan aktif sebelum reboot mesin target.",
		Command:    "netstat -tulnp > /tmp/active_sockets.txt && ps auxwf > /tmp/process_tree.txt",
	})
	stepCounter++

	playbook.Steps = append(playbook.Steps, model.PlaybookStep{
		StepNumber: stepCounter,
		Phase:      "Phase 2: Eradication & Forensics",
		Priority:   "P2-URGENT",
		Action:     "Audit file baru atau termodifikasi dalam 60 menit terakhir di direktori sistem dan cron jobs.",
		Command:    "find / -mmin -60 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null",
	})
	stepCounter++

	// -------------------------------------------------------------
	// FASE 3: RECOVERY & HARDENING (P3-STANDARD)
	// -------------------------------------------------------------
	playbook.Steps = append(playbook.Steps, model.PlaybookStep{
		StepNumber: stepCounter,
		Phase:      "Phase 3: Recovery & Hardening",
		Priority:   "P3-STANDARD",
		Action:     "Rotasi kredensial administratif (SSH root keys, API tokens, database passwords) yang berpotensi bocor.",
		Command:    "passwd root && rm -f ~/.ssh/authorized_keys",
	})
	stepCounter++

	playbook.Steps = append(playbook.Steps, model.PlaybookStep{
		StepNumber: stepCounter,
		Phase:      "Phase 3: Recovery & Hardening",
		Priority:   "P3-STANDARD",
		Action:     "Deploy patch keamanan aplikasi dan verifikasi integritas hash biner SPECTRA secara berkala.",
		Command:    "apt update && apt upgrade -y --only-upgrade",
	})

	// Bangun format teks siap salin
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("   SPECTRA TACTICAL INCIDENT RESPONSE PLAYBOOK // AUTOMATED CONTAINMENT PLAN   \n")
	sb.WriteString(fmt.Sprintf("   Generated At: %s | Total Actions: %d\n", playbook.GeneratedAt.Format("2006-01-02 15:04:05 MST"), len(playbook.Steps)))
	sb.WriteString("================================================================================\n\n")

	currentPhase := ""
	for _, s := range playbook.Steps {
		if s.Phase != currentPhase {
			currentPhase = s.Phase
			sb.WriteString(fmt.Sprintf("\n--- [%s] ---\n", strings.ToUpper(currentPhase)))
		}
		sb.WriteString(fmt.Sprintf("\n[STEP %02d] [%s] %s\n", s.StepNumber, s.Priority, s.Action))
		if s.MitreRef != "" {
			sb.WriteString(fmt.Sprintf("  Ref MITRE : %s\n", s.MitreRef))
		}
		if s.Command != "" {
			sb.WriteString(fmt.Sprintf("  Command   : %s\n", s.Command))
		}
	}
	sb.WriteString("\n================================================================================\n")

	playbook.Summary = fmt.Sprintf("Playbook insiden otomatis disusun dengan %d langkah tindakan terkoordinasi (Fase Isolasi, Eradikasi, dan Pemulihan).", len(playbook.Steps))
	playbook.RawPlanText = sb.String()
	return playbook
}
