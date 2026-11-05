package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"spectra/internal/model"
)

// ExportJSON mengekspor hasil ke JSON terstruktur (Anti-tamper / SIEM ready)
func ExportJSON(res model.AnalysisResult, outputPath string) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// ============ MODUL 5: STIX 2.1 EXPORT ============

// STIXBundle merepresentasikan STIX 2.1 Bundle Object
type STIXBundle struct {
	Type        string        `json:"type"`
	ID          string        `json:"id"`
	SpecVersion string        `json:"spec_version"`
	Objects     []interface{} `json:"objects"`
}

// GenerateSTIX21Bundle menghasilkan bundle JSON valid berstandar STIX 2.1 dari hasil analisis
func GenerateSTIX21Bundle(res model.AnalysisResult) ([]byte, error) {
	bundleID := fmt.Sprintf("bundle--spectra-%d", time.Now().UnixNano())
	objects := []interface{}{}

	now := res.AnalyzedAt.UTC().Format(time.RFC3339)

	// 1. Buat Identity Object (SPECTRA sebagai pelapor)
	identity := map[string]interface{}{
		"type":                "identity",
		"spec_version":        "2.1",
		"id":                  "identity--spectra-tactical-suite",
		"name":                "SPECTRA Tactical Cyber Triage Suite",
		"identity_class":      "tool",
		"description":         "Swift Packet Extraction & Cyber Threat Rapid Analyzer — Air-Gapped Forensic Platform",
		"created":             now,
		"modified":            now,
	}
	objects = append(objects, identity)

	// 2. Petakan setiap IOC ke STIX Indicator + Observed-Data + Attack-Pattern
	for i, ind := range res.Indicators {
		ts := ind.Timestamp.UTC().Format(time.RFC3339)

		// STIX Indicator
		pattern := fmt.Sprintf("[network-traffic:src_ref.type = 'ipv4-addr' AND network-traffic:src_ref.value = '%s']", ind.SrcIP)
		if ind.Evidence != "" {
			sanitized := strings.ReplaceAll(ind.Evidence, "'", "\\'")
			pattern = fmt.Sprintf("[network-traffic:src_ref.value = '%s' AND network-traffic:dst_ref.value = '%s' AND network-traffic:extensions.'http-request-ext'.request_value LIKE '%%%s%%']",
				ind.SrcIP, ind.DstIP, sanitized[:min(len(sanitized), 80)])
		}

		indicator := map[string]interface{}{
			"type":                "indicator",
			"spec_version":        "2.1",
			"id":                  fmt.Sprintf("indicator--spectra-ioc-%d", i),
			"name":                ind.Title,
			"description":         ind.Description,
			"pattern":             pattern,
			"pattern_type":        "stix",
			"valid_from":          ts,
			"created":             ts,
			"modified":            ts,
			"labels":              []string{string(ind.Severity), "malicious-activity"},
			"indicator_types":     []string{"malicious-activity"},
			"created_by_ref":      "identity--spectra-tactical-suite",
			"confidence":          scoreToConfidence(ind.ScoreWeight),
			"extensions": map[string]interface{}{
				"x-spectra-entropy": map[string]interface{}{
					"entropy_score": ind.Entropy,
					"entropy_label": ind.EntropyLabel,
				},
			},
		}
		objects = append(objects, indicator)

		// STIX Observed-Data
		observedData := map[string]interface{}{
			"type":             "observed-data",
			"spec_version":     "2.1",
			"id":               fmt.Sprintf("observed-data--spectra-%d", i),
			"created":          ts,
			"modified":         ts,
			"first_observed":   ts,
			"last_observed":    ts,
			"number_observed":  1,
			"created_by_ref":   "identity--spectra-tactical-suite",
			"object_refs":      []string{fmt.Sprintf("indicator--spectra-ioc-%d", i)},
			"objects": map[string]interface{}{
				"0": map[string]interface{}{
					"type":  "ipv4-addr",
					"value": ind.SrcIP,
				},
				"1": map[string]interface{}{
					"type":  "ipv4-addr",
					"value": ind.DstIP,
				},
				"2": map[string]interface{}{
					"type":          "network-traffic",
					"src_ref":       "0",
					"dst_ref":       "1",
					"protocols":     []string{strings.ToLower(ind.Protocol)},
					"src_port":      0,
					"dst_port":      0,
				},
			},
		}
		objects = append(objects, observedData)

		// STIX Attack-Pattern (MITRE ATT&CK)
		attackPattern := map[string]interface{}{
			"type":             "attack-pattern",
			"spec_version":     "2.1",
			"id":               fmt.Sprintf("attack-pattern--spectra-%d", i),
			"created":          ts,
			"modified":         ts,
			"name":             ind.MitreAttack,
			"description":      fmt.Sprintf("Tactic: %s | Technique: %s", ind.MitreTactic, ind.MitreAttack),
			"created_by_ref":   "identity--spectra-tactical-suite",
			"kill_chain_phases": []map[string]interface{}{
				{
					"kill_chain_name": "mitre-attack",
					"phase_name":      strings.ToLower(strings.ReplaceAll(ind.MitreTactic, " ", "-")),
				},
			},
			"external_references": []map[string]interface{}{
				{
					"source_name":   "mitre-attack",
					"external_id":   extractMITREID(ind.MitreAttack),
					"description":   ind.MitreAttack,
				},
			},
		}
		objects = append(objects, attackPattern)
	}

	// 3. Tambahkan Course-of-Action (COA) / Rekomendasi Mitigasi
	if len(res.BlocklistRules.AttackerIPs) > 0 {
		coa := map[string]interface{}{
			"type":           "course-of-action",
			"spec_version":   "2.1",
			"id":             "course-of-action--spectra-blocklist",
			"name":           "SPECTRA Auto-Generated Blocklist Mitigation",
			"description":    fmt.Sprintf("Block %d attacker IPs identified by SPECTRA triage. IPtables rules, Windows Firewall rules, and Suricata IDS rules generated.", len(res.BlocklistRules.AttackerIPs)),
			"created":        now,
			"modified":       now,
			"created_by_ref": "identity--spectra-tactical-suite",
			"extensions": map[string]interface{}{
				"x-spectra-blocklist": map[string]interface{}{
					"attacker_ips":    res.BlocklistRules.AttackerIPs,
					"iptables_rules":  res.BlocklistRules.IPtablesRules,
					"windows_rules":   res.BlocklistRules.WindowsRules,
					"suricata_rules":  res.BlocklistRules.SuricataRules,
				},
			},
		}
		objects = append(objects, coa)
	}

	bundle := STIXBundle{
		Type:        "bundle",
		ID:          bundleID,
		SpecVersion: "2.1",
		Objects:     objects,
	}

	return json.MarshalIndent(bundle, "", "  ")
}

func scoreToConfidence(weight int) int {
	switch {
	case weight >= 35:
		return 90
	case weight >= 20:
		return 75
	case weight >= 10:
		return 55
	default:
		return 35
	}
}

func extractMITREID(mitreAttack string) string {
	parts := strings.Split(mitreAttack, " - ")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return mitreAttack
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============ MODUL 4: BLOCKLIST TEXT EXPORT ============

// GenerateBlocklistText menghasilkan teks siap salin/unduh untuk berbagai format firewall
func GenerateBlocklistText(rules model.BlocklistRules, format string) string {
	var sb strings.Builder
	header := fmt.Sprintf("# SPECTRA Auto-Generated Blocklist | Generated: %s\n# Format: %s\n# Total IPs: %d\n\n",
		time.Now().Format("2006-01-02 15:04:05"), format, len(rules.AttackerIPs))
	sb.WriteString(header)

	switch format {
	case "iptables":
		sb.WriteString("#!/bin/bash\n# Apply with: sudo bash blocklist_iptables.sh\n\n")
		for _, r := range rules.IPtablesRules {
			sb.WriteString(r + "\n")
		}
		sb.WriteString("\necho \"[SPECTRA] Blocklist applied successfully.\"\n")
	case "windows":
		sb.WriteString("# Run in PowerShell as Administrator\n# Apply with: powershell -ExecutionPolicy Bypass -File blocklist_windows.ps1\n\n")
		for _, r := range rules.WindowsRules {
			sb.WriteString(r + "\n")
		}
		sb.WriteString("\nWrite-Host \"[SPECTRA] Windows Firewall blocklist applied.\"\n")
	case "suricata":
		sb.WriteString("# Add to /etc/suricata/rules/spectra-blocklist.rules\n# Reload with: suricatasc -c reload-rules\n\n")
		for _, r := range rules.SuricataRules {
			sb.WriteString(r + "\n")
		}
	case "plaintext":
		sb.WriteString("# Plain IP List — Use for DNS blocklists, SIEM, SOAR, or manual blocking\n\n")
		sb.WriteString(rules.PlainIPList)
	default:
		sb.WriteString(rules.PlainIPList)
	}

	return sb.String()
}

// GenerateTacticalHTMLDossier menghasilkan laporan insiden komando taktis mandiri (Anti-XSS Sanitized)
func GenerateTacticalHTMLDossier(res model.AnalysisResult, outputPath string) error {
	badgeColor := "#10b981"
	badgeText := "#000000"
	scoreColor := "#10b981"
	if res.ThreatLevel == model.SeverityCritical {
		badgeColor = "#ef4444"
		badgeText = "#ffffff"
		scoreColor = "#ef4444"
	} else if res.ThreatLevel == model.SeverityHigh {
		badgeColor = "#f97316"
		badgeText = "#ffffff"
		scoreColor = "#f97316"
	} else if res.ThreatLevel == model.SeverityMedium {
		badgeColor = "#eab308"
		badgeText = "#000000"
		scoreColor = "#eab308"
	}

	var iocRows strings.Builder
	for idx, ind := range res.Indicators {
		sevColor := "#f87171"
		if ind.Severity == model.SeverityHigh {
			sevColor = "#fb923c"
		} else if ind.Severity == model.SeverityMedium {
			sevColor = "#facc15"
		}

		entropyBadge := ""
		if ind.Entropy > 0 {
			entColor := "#10b981"
			if ind.Entropy >= 7.2 {
				entColor = "#ef4444"
			} else if ind.Entropy >= 6.0 {
				entColor = "#f97316"
			}
			entropyBadge = fmt.Sprintf(`<span style="background:%s22; color:%s; border:1px solid %s; padding:2px 6px; border-radius:3px; font-size:10px; margin-left:6px;">H=%.2f</span>`,
				entColor, entColor, entColor, ind.Entropy)
		}

		iocRows.WriteString(fmt.Sprintf(`
		<tr style="border-bottom: 1px solid #1e293b;">
			<td style="padding: 10px; font-family: monospace; color: #94a3b8;">#%d</td>
			<td style="padding: 10px; font-weight: bold; color: %s;">%s</td>
			<td style="padding: 10px;">
				<div style="font-weight: bold; color: #f1f5f9;">%s%s</div>
				<div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">%s</div>
				<div style="font-size: 11px; color: #38bdf8; margin-top: 4px;"><strong>Rekomendasi:</strong> %s</div>
			</td>
			<td style="padding: 10px; font-family: monospace; font-size: 11px; color: #cbd5e1;">%s &rarr; %s<br><span style="color:#64748b;">Proto: %s</span></td>
			<td style="padding: 10px; font-family: monospace; font-size: 11px; color: #a3e635;">%s</td>
		</tr>`,
			idx+1,
			sevColor,
			html.EscapeString(string(ind.Severity)),
			html.EscapeString(ind.Title),
			entropyBadge,
			html.EscapeString(ind.Description),
			html.EscapeString(ind.Recommendation),
			html.EscapeString(ind.SrcIP),
			html.EscapeString(ind.DstIP),
			html.EscapeString(ind.Protocol),
			html.EscapeString(ind.MitreAttack),
		))
	}

	var timelineRows strings.Builder
	for _, evt := range res.Timeline {
		timelineRows.WriteString(fmt.Sprintf(`
		<li style="margin-bottom: 12px; position: relative; padding-left: 20px; border-left: 2px solid #38bdf8;">
			<div style="font-size: 11px; color: #94a3b8; font-family: monospace;">%s // Taktik: %s</div>
			<div style="font-weight: bold; color: #f1f5f9; font-size: 13px;">[%s] %s</div>
			<div style="font-size: 12px; color: #cbd5e1; margin-top: 2px;">%s &rarr; %s</div>
		</li>`,
			evt.Timestamp.Format("15:04:05.000"),
			html.EscapeString(evt.Stage),
			html.EscapeString(string(evt.Severity)),
			html.EscapeString(evt.Message),
			html.EscapeString(evt.Source),
			html.EscapeString(evt.Destination),
		))
	}

	var flowRows strings.Builder
	for _, f := range res.NetworkFlows {
		flowRows.WriteString(fmt.Sprintf(`
		<tr style="border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 11px;">
			<td style="padding: 6px 10px; color: #38bdf8;">%s</td>
			<td style="padding: 6px 10px; color: #cbd5e1;">%s</td>
			<td style="padding: 6px 10px; color: #a3e635;">%s</td>
			<td style="padding: 6px 10px; text-align: right;">%d</td>
			<td style="padding: 6px 10px; text-align: right;">%.2f KB</td>
		</tr>`,
			html.EscapeString(f.SrcIP),
			html.EscapeString(f.DstIP),
			html.EscapeString(f.Protocol),
			f.Packets,
			float64(f.Bytes)/1024.0,
		))
	}

	// Blocklist section
	blocklistSection := ""
	if len(res.BlocklistRules.AttackerIPs) > 0 {
		var blSb strings.Builder
		blSb.WriteString(`<h3 style="color: #ff0055; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">4. AUTO-GENERATED MITIGATION RULES (BLOCKLIST)</h3>`)
		blSb.WriteString(fmt.Sprintf(`<div style="background:#0c1524; border:1px solid #ff005533; border-left:3px solid #ff0055; border-radius:6px; padding:14px; margin-bottom:20px; font-size:11px; font-family:monospace;">
			<div style="color:#ff0055; font-weight:bold; margin-bottom:8px;">🛡️ %d Attacker IP(s) Identified — Auto-Generated Firewall Rules:</div>`,
			len(res.BlocklistRules.AttackerIPs)))
		blSb.WriteString(`<div style="color:#94a3b8; margin-bottom:6px;">Linux iptables:</div>`)
		blSb.WriteString(`<pre style="background:#060a12; padding:10px; border-radius:4px; color:#a3e635; overflow-x:auto;">`)
		for _, r := range res.BlocklistRules.IPtablesRules {
			blSb.WriteString(html.EscapeString(r) + "\n")
		}
		blSb.WriteString(`</pre>`)
		blSb.WriteString(`<div style="color:#94a3b8; margin-top:8px; margin-bottom:6px;">Windows PowerShell:</div>`)
		blSb.WriteString(`<pre style="background:#060a12; padding:10px; border-radius:4px; color:#38bdf8; overflow-x:auto;">`)
		for _, r := range res.BlocklistRules.WindowsRules {
			blSb.WriteString(html.EscapeString(r) + "\n")
		}
		blSb.WriteString(`</pre>`)
		blSb.WriteString(`<div style="color:#94a3b8; margin-top:8px; margin-bottom:6px;">Suricata / Snort IDS:</div>`)
		blSb.WriteString(`<pre style="background:#060a12; padding:10px; border-radius:4px; color:#f59e0b; overflow-x:auto;">`)
		for _, r := range res.BlocklistRules.SuricataRules {
			blSb.WriteString(html.EscapeString(r) + "\n")
		}
		blSb.WriteString(`</pre></div>`)
		blocklistSection = blSb.String()
	}

	// Playbook section
	playbookSection := ""
	if len(res.Playbook.Steps) > 0 {
		var pbSb strings.Builder
		pbSb.WriteString(`<h3 style="color: #a78bfa; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">5. TACTICAL INCIDENT CONTAINMENT PLAYBOOK</h3>`)
		pbSb.WriteString(`<div style="background:#0c1524; border:1px solid #7c3aed33; border-left:3px solid #7c3aed; border-radius:6px; padding:14px; margin-bottom:20px; font-size:11px;">`)
		pbSb.WriteString(fmt.Sprintf(`<div style="color:#a78bfa; font-weight:bold; margin-bottom:8px;">📋 %s</div>`, html.EscapeString(res.Playbook.Summary)))
		pbSb.WriteString(`<ol style="padding-left:18px; margin:0; line-height:1.7;">`)
		for _, s := range res.Playbook.Steps {
			prioCol := "#ef4444"
			if s.Priority == "P2-URGENT" {
				prioCol = "#f97316"
			} else if s.Priority == "P3-STANDARD" {
				prioCol = "#38bdf8"
			}
			pbSb.WriteString(fmt.Sprintf(`<li style="margin-bottom:8px;"><strong style="color:%s;">[%s]</strong> %s`, prioCol, s.Priority, html.EscapeString(s.Action)))
			if s.Command != "" {
				pbSb.WriteString(fmt.Sprintf(`<br><code style="background:#060a12; color:#a3e635; padding:2px 6px; border-radius:3px; font-size:10px;">%s</code>`, html.EscapeString(s.Command)))
			}
			pbSb.WriteString(`</li>`)
		}
		pbSb.WriteString(`</ol></div>`)
		playbookSection = pbSb.String()
	}

	// Executive War-Room Briefing section
	briefingSection := ""
	if res.ExecutiveBriefing.Headline != "" {
		var brSb strings.Builder
		brSb.WriteString(`<h3 style="color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">6. EXECUTIVE WAR-ROOM BRIEFING (RINGKASAN EKSEKUTIF PIMPINAN)</h3>`)
		brSb.WriteString(`<div style="background:#0c1524; border:1px solid #38bdf833; border-left:4px solid #38bdf8; border-radius:6px; padding:16px; margin-bottom:20px; font-size:12px; line-height:1.6;">`)
		brSb.WriteString(fmt.Sprintf(`<div style="color:#f8fafc; font-weight:bold; font-size:13px; margin-bottom:4px;">%s</div>`, html.EscapeString(res.ExecutiveBriefing.Headline)))
		brSb.WriteString(fmt.Sprintf(`<div style="color:#94a3b8; font-size:11px; margin-bottom:12px;"><strong>Tingkat Dampak Bisnis:</strong> <span style="color:#f59e0b;">%s</span> | <strong>Sasaran:</strong> %s | <strong>Asal Penyerang:</strong> %s</div>`,
			html.EscapeString(res.ExecutiveBriefing.BusinessImpactLevel),
			html.EscapeString(res.ExecutiveBriefing.PrimaryTarget),
			html.EscapeString(res.ExecutiveBriefing.AttackerIdentity)))
		brSb.WriteString(`<div style="margin-bottom:12px;"><strong style="color:#38bdf8;">📖 Apa yang Sebenarnya Terjadi? (Bahasa Manusia):</strong><div style="background:#060a12; padding:10px; border-radius:4px; margin-top:4px; color:#cbd5e1; white-space:pre-wrap;">` + html.EscapeString(res.ExecutiveBriefing.WhatHappenedStory) + `</div></div>`)
		brSb.WriteString(`<div style="margin-bottom:12px;"><strong style="color:#f59e0b;">📊 Status Kebocoran Data:</strong><div style="background:#060a12; padding:10px; border-radius:4px; margin-top:4px; color:#cbd5e1;">` + html.EscapeString(res.ExecutiveBriefing.DataIntegrityStatus) + `</div></div>`)
		brSb.WriteString(`<div><strong style="color:#00ff88;">🎯 Arahan Keputusan Pimpinan:</strong><ul style="padding-left:18px; margin-top:4px; color:#cbd5e1;">`)
		for _, dec := range res.ExecutiveBriefing.RecommendedDecisions {
			brSb.WriteString(fmt.Sprintf(`<li style="margin-bottom:4px;">%s</li>`, html.EscapeString(dec)))
		}
		brSb.WriteString(`</ul></div></div>`)
		briefingSection = brSb.String()
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>SPECTRA Incident Dossier - %s</title>
	<style>
		body { background: #070b12; color: #e2e8f0; font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; padding: 25px; margin: 0; }
		.container { max-width: 950px; margin: auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 30px; box-shadow: 0 10px 40px rgba(0,0,0,0.8); }
		.top-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 15px; margin-bottom: 20px; }
		.badge { background: %s; color: %s; padding: 4px 14px; border-radius: 4px; font-weight: 900; letter-spacing: 1px; font-size: 14px; }
		.meta-box { background: #1e293b; padding: 15px; border-radius: 6px; margin-bottom: 25px; font-size: 12px; line-height: 1.6; }
		.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 25px; }
		.stat-card { background: #131d31; padding: 12px; border-radius: 6px; border-left: 3px solid #38bdf8; }
		.stat-num { font-size: 22px; font-weight: bold; font-family: monospace; color: #f8fafc; }
		.stat-label { font-size: 11px; color: #94a3b8; text-transform: uppercase; }
		.risk-bar-container { background: #1e293b; border-radius: 6px; margin-bottom: 20px; padding: 14px; }
		.risk-bar-track { background: #0d1726; border-radius: 4px; height: 16px; width: 100%%; overflow: hidden; }
		.risk-bar-fill { height: 100%%; border-radius: 4px; transition: width 0.5s ease; background: %s; }
		.mitre-bar { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; margin-bottom: 25px; }
		.mitre-badge { background: #131d31; border: 1px solid #1e293b; padding: 8px; text-align: center; border-radius: 4px; }
		.mitre-val { font-size: 18px; font-weight: bold; color: #38bdf8; font-family: monospace; }
		.mitre-name { font-size: 9px; color: #94a3b8; text-transform: uppercase; margin-top: 2px; }
		table { width: 100%%; border-collapse: collapse; text-align: left; font-size: 12px; margin-bottom: 25px; }
		th { background: #1e293b; padding: 8px 10px; color: #94a3b8; text-transform: uppercase; font-size: 11px; }
		.btn-print { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; }
		.btn-print:hover { background: #0369a1; }
		.table-responsive { width: 100%%; overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 25px; }
		.table-responsive table { min-width: 650px; margin-bottom: 0; }
		@media (max-width: 768px) {
			body { padding: 12px; }
			.container { padding: 16px; }
			.top-header { flex-direction: column; align-items: flex-start; gap: 12px; }
			.btn-print { width: 100%%; text-align: center; padding: 12px; font-size: 14px; }
			.stats-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
			.mitre-bar { grid-template-columns: repeat(3, 1fr); gap: 6px; }
		}
		@media print {
			body { background: white !important; color: black !important; padding: 0; }
			.container { box-shadow: none !important; border: none !important; padding: 0 !important; }
			.btn-print { display: none !important; }
			.meta-box, .stat-card, .mitre-badge, th { background: #f1f5f9 !important; color: black !important; border: 1px solid #cbd5e1 !important; }
			.stat-num, .mitre-val { color: black !important; }
			td { border-bottom: 1px solid #e2e8f0 !important; color: black !important; }
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="top-header">
			<div>
				<div style="font-size: 11px; color: #38bdf8; font-weight: bold; letter-spacing: 2px;">TACTICAL FORENSIC TRIAGE REPORT // AIR-GAPPED READY</div>
				<h1 style="margin: 4px 0 0 0; color: #f8fafc; font-size: 24px; letter-spacing: 1px;">SPECTRA INCIDENT DOSSIER</h1>
			</div>
			<div>
				<button class="btn-print" onclick="window.print()">🖨️ CETAK / SIMPAN SEBAGAI PDF</button>
			</div>
		</div>

		<div class="meta-box">
			<div style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
				<div>
					<strong>Target Artifact:</strong> <span style="font-family: monospace; color: #facc15;">%s</span><br>
					<strong>SHA-256 Hash:</strong> <span style="font-family: monospace; color: #94a3b8;">%s</span><br>
					<strong>Waktu Eksekusi:</strong> %s | <strong>Durasi Triase:</strong> %s
				</div>
				<div style="text-align: right;">
					<div style="font-size: 11px; color: #94a3b8;">SKOR ANCAMAN TOTAL</div>
					<div style="font-size: 32px; font-weight: 900; font-family: monospace; color: %s;">
						%d / 100 <span class="badge">%s</span>
					</div>
					<div style="font-size: 10px; color: #64748b; margin-top: 4px;">
						CRITICAL×%d(+%dp) HIGH×%d(+%dp) MEDIUM×%d(+%dp)
					</div>
				</div>
			</div>
			<div style="margin-top: 12px;">
				<div class="risk-bar-container" style="padding: 8px 14px;">
					<div style="font-size: 10px; color: #64748b; margin-bottom: 4px;">THREAT RISK INDEX</div>
					<div class="risk-bar-track">
						<div class="risk-bar-fill" style="width: %d%%;"></div>
					</div>
				</div>
			</div>
			<div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #334155; font-size: 12px; color: #cbd5e1;">
				<strong>Ringkasan Eksekutif:</strong> %s
			</div>
			<div style="margin-top: 8px; font-size: 11px; color: #38bdf8; background: #0c1524; padding: 8px 12px; border-radius: 4px; border-left: 3px solid #38bdf8;">
				<strong>Deployment Model:</strong> Universal Portable Binary (Zero Footprint, Executable on Windows, Linux, macOS, and Termux directly via Terminal Pipe without Internet Access).
			</div>
		</div>

		<div class="stats-grid">
			<div class="stat-card">
				<div class="stat-label">Total Paket</div>
				<div class="stat-num">%d</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Volume Data</div>
				<div class="stat-num">%.2f KB</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">TCP / UDP Streams</div>
				<div class="stat-num">%d / %d</div>
			</div>
			<div class="stat-card">
				<div class="stat-label">Indikator Kompromi (IOC)</div>
				<div class="stat-num" style="color: %s;">%d</div>
			</div>
		</div>

		<div style="font-size: 12px; font-weight: bold; color: #38bdf8; margin-bottom: 8px;">PEMETAAN FASE MITRE ATT&CK:</div>
		<div class="mitre-bar">
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Reconnaissance</div>
			</div>
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Initial Access</div>
			</div>
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Execution</div>
			</div>
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Credential Acc.</div>
			</div>
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Command &amp; C2</div>
			</div>
			<div class="mitre-badge">
				<div class="mitre-val">%d</div>
				<div class="mitre-name">Exfiltration</div>
			</div>
		</div>

		<h3 style="color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">1. INDIKATOR SERANGAN TERIDENTIFIKASI (IOC)</h3>
		<div class="table-responsive">
			<table>
				<thead>
					<tr>
						<th>#</th>
						<th>Severity</th>
						<th>Detail Ancaman &amp; Tindakan Lapangan</th>
						<th>Arus Lalu Lintas</th>
						<th>MITRE ATT&CK</th>
					</tr>
				</thead>
				<tbody>
					%s
				</tbody>
			</table>
		</div>

		<h3 style="color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">2. TOP NETWORK FLOWS (ALIRAN KOMUNIKASI HOST)</h3>
		<div class="table-responsive">
			<table>
				<thead>
					<tr>
						<th>Source IP</th>
						<th>Destination IP</th>
						<th>Protocol</th>
						<th style="text-align: right;">Packets</th>
						<th style="text-align: right;">Bytes</th>
					</tr>
				</thead>
				<tbody>
					%s
				</tbody>
			</table>
		</div>

		<h3 style="color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 6px; font-size: 14px;">3. REKONSTRUKSI KRONOLOGI ALUR SERANGAN (KILLCHAIN TIMELINE)</h3>
		<ul style="list-style: none; padding-left: 0; margin-top: 15px;">
			%s
		</ul>

		%s

		%s

		%s

		<div style="margin-top: 35px; font-size: 11px; text-align: center; color: #64748b; border-top: 1px solid #1e293b; padding-top: 15px;">
			SPECTRA v2.0 // Swift Packet Extraction &amp; Cyber Threat Rapid Analyzer // 100%% Local / Zero-Cloud Verified
		</div>
	</div>
</body>
</html>`,
		html.EscapeString(res.TargetFileName),
		badgeColor,
		badgeText,
		scoreColor,
		html.EscapeString(filepath.Base(res.TargetFileName)),
		res.SHA256Checksum,
		res.AnalyzedAt.Format("02 Jan 2006, 15:04:05 MST"),
		res.AnalysisDuration,
		scoreColor,
		res.ThreatScore,
		html.EscapeString(string(res.ThreatLevel)),
		res.RiskBreakdown.CriticalCount, res.RiskBreakdown.CriticalPoints,
		res.RiskBreakdown.HighCount, res.RiskBreakdown.HighPoints,
		res.RiskBreakdown.MediumCount, res.RiskBreakdown.MediumPoints,
		res.ThreatScore,
		html.EscapeString(res.ExecutiveSummary),
		res.TotalPackets,
		float64(res.TotalBytes)/1024.0,
		res.ProtocolStats.TCPCount,
		res.ProtocolStats.UDPCount,
		badgeColor,
		len(res.Indicators),
		res.MitreSummary.Reconnaissance,
		res.MitreSummary.InitialAccess,
		res.MitreSummary.Execution,
		res.MitreSummary.CredentialAccess,
		res.MitreSummary.CommandAndControl,
		res.MitreSummary.Exfiltration,
		iocRows.String(),
		flowRows.String(),
		timelineRows.String(),
		blocklistSection,
		playbookSection,
		briefingSection,
	)

	return os.WriteFile(outputPath, []byte(htmlContent), 0644)
}
