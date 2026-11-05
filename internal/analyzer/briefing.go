package analyzer

import (
	"fmt"
	"strings"
	"time"

	"spectra/internal/model"
)

// GenerateExecutiveBriefing menyusun narasi kejadian siber dalam bahasa manusia non-teknis
func GenerateExecutiveBriefing(res model.AnalysisResult) model.ExecutiveBriefing {
	var b model.ExecutiveBriefing

	// 1. Tentukan Headline dan Tingkat Bahaya Bisnis
	switch res.ThreatLevel {
	case model.SeverityCritical:
		b.Headline = "🚨 INSIDEN KEAMANAN SIBER KRITIS: Percobaan Pembobolan Server Terdeteksi"
		b.SeverityLabel = "KRITIS / BAHAYA TINGGI"
		b.BusinessImpactLevel = "TINGGI (Potensi Pengambilalihan Kontrol Server & Kebocoran Data Penting)"
	case model.SeverityHigh:
		b.Headline = "⚠️ PERINGATAN KEAMANAN: Aktivitas Eksploitasi Mencurigakan Terdeteksi"
		b.SeverityLabel = "WASPADA / TINGGI"
		b.BusinessImpactLevel = "SEDANG KE TINGGI (Ancaman Penetrasi Perimeter Jaringan)"
	case model.SeverityMedium:
		b.Headline = "ℹ️ ANOMALI LALU LINTAS: Terdeteksi Percobaan Pemindaian Jaringan"
		b.SeverityLabel = "PERHATIAN / SEDANG"
		b.BusinessImpactLevel = "RENDAH HINGGA SEDANG (Aktivitas Pengintaian / Reconnaissance)"
	default:
		b.Headline = "✅ SISTEM AMAN: Tidak Ditemukan Indikasi Serangan Berbahaya"
		b.SeverityLabel = "NORMAL / BERSIH"
		b.BusinessImpactLevel = "TIDAK ADA DAMPAK (Operasional Berjalan Normal)"
	}

	// 2. Identifikasi Sasaran dan Penyerang
	if len(res.BlocklistRules.AttackerIPs) > 0 {
		b.AttackerIdentity = fmt.Sprintf("%d Host Penyerang Teridentifikasi (%s)",
			len(res.BlocklistRules.AttackerIPs),
			strings.Join(res.BlocklistRules.AttackerIPs, ", "))
	} else if len(res.TopSources) > 0 {
		// Ambil top source
		var topSrc string
		for ip := range res.TopSources {
			topSrc = ip
			break
		}
		b.AttackerIdentity = fmt.Sprintf("Aktivitas Dominan dari IP %s", topSrc)
	} else {
		b.AttackerIdentity = "Tidak ada penyerang terisolasi"
	}

	if len(res.NetworkFlows) > 0 {
		b.PrimaryTarget = fmt.Sprintf("Server Internal (%s)", res.NetworkFlows[0].DstIP)
	} else {
		b.PrimaryTarget = "Seluruh Subnet Terpantau"
	}

	// 3. Rekonstruksi Cerita (Storytelling Bahasa Manusia)
	var storyParts []string
	var hasRCE, hasSQLi, hasShell, hasDNSExfil, hasScan, hasObfuscation bool

	if res.MaxEntropy >= 7.2 {
		hasObfuscation = true
	}

	for _, ind := range res.Indicators {
		titleLower := strings.ToLower(ind.Title)
		switch {
		case strings.Contains(titleLower, "log4shell") || strings.Contains(titleLower, "rce") || strings.Contains(titleLower, "struts") || strings.Contains(titleLower, "spring4shell"):
			hasRCE = true
		case strings.Contains(titleLower, "sql"):
			hasSQLi = true
		case strings.Contains(titleLower, "shell") || strings.Contains(titleLower, "cmd"):
			hasShell = true
		case strings.Contains(titleLower, "dns") || strings.Contains(titleLower, "tunnel") || strings.Contains(titleLower, "exfiltration"):
			hasDNSExfil = true
		case strings.Contains(titleLower, "scan") || strings.Contains(titleLower, "sweep") || strings.Contains(titleLower, "discovery"):
			hasScan = true
		}
	}

	if res.ThreatScore == 0 {
		storyParts = append(storyParts, "Seluruh paket jaringan yang diperiksa berada dalam batas wajar dan aman. Tidak ditemukan upaya intrusi, aktivitas mencurigakan, atau pola eksploitasi.")
	} else {
		if hasScan {
			storyParts = append(storyParts, "• Penyerang terlebih dahulu memetakan dan mengetuk seluruh pintu masuk server (pemindaian port aktif) untuk mencari celah yang terbuka dan belum dijaga.")
		}
		if hasRCE {
			storyParts = append(storyParts, "• Penyerang mengeksploitasi celah kelemahan perangkat lunak server (seperti Log4Shell/RCE) dengan maksud menyuntikkan instruksi kendali ilegal dari jarak jauh.")
		}
		if hasShell {
			storyParts = append(storyParts, "• Terdeteksi adanya percobaan membuka terminal perintah sistem operasi (/bin/sh atau shell console) agar penyerang dapat menjalankan program berbahaya di dalam server kita.")
		}
		if hasSQLi {
			storyParts = append(storyParts, "• Penyerang mencoba memanipulasi formulir aplikasi web untuk memaksa basis data membocorkan catatan rahasia perusahaan (SQL Injection).")
		}
		if hasDNSExfil {
			storyParts = append(storyParts, "• Ditemukan indikasi penyelundupan paket data tersembunyi ke luar kantor melalui jalur penamaan domain internet (DNS Tunneling / Exfiltration).")
		}
		if hasObfuscation {
			storyParts = append(storyParts, "• Ditemukan paket terenkripsi/disamarkan dengan Entropi Tinggi (>7.2) yang lazim digunakan malware/ransomware untuk menyembunyikan jejak aktivitas jahat.")
		}

		if len(storyParts) == 0 {
			storyParts = append(storyParts, fmt.Sprintf("• Terdeteksi %d indikator anomali keamanan jaringan yang memicu peningkatan skor risiko ancaman.", len(res.Indicators)))
		}
	}
	b.WhatHappenedStory = strings.Join(storyParts, "\n")

	// 4. Status Kebocoran Data (Data Integrity)
	if hasDNSExfil || hasSQLi {
		b.DataIntegrityStatus = "⚠️ RISIKO TINGGI: Terdapat indikasi kuat upaya pengambilan dan penyelundupan data keluar jaringan. Disarankan menganggap data pada endpoint terdampak berpotensi terekspos sampai audit forensik selesai."
	} else if hasRCE || hasShell {
		b.DataIntegrityStatus = "⚠️ RISIKO SEDANG-TINGGI: Server berhasil diakses tanpa izin, namun belum ada indikasi kuat data dalam volume besar berhasil dilarikan keluar jaringan."
	} else if res.ThreatScore > 0 {
		b.DataIntegrityStatus = "ℹ️ DALAM PENGAWASAN: Ada aktivitas mencurigakan, namun integritas data utama masih terjaga."
	} else {
		b.DataIntegrityStatus = "✅ AMAN: Integritas data perusahaan terjaga penuh. Tidak ada indikasi kebocoran, perusakan, atau modifikasi data ilegal."
	}

	// 5. Arahan Keputusan Pimpinan (Actionable Executive Decisions)
	var decisions []string
	if res.ThreatLevel == model.SeverityCritical || res.ThreatLevel == model.SeverityHigh {
		decisions = append(decisions, "1. [ISOLASI DARURAT] Perintahkan tim IT untuk memutus sementara akses publik pada server target guna mencegah kendali jarak jauh penyerang.")
		decisions = append(decisions, "2. [ROTASI KUNCI AKSES] Instruksikan penggantian seluruh kata sandi admin dan kredensial database yang terhubung ke server terkait.")
		decisions = append(decisions, "3. [BLOKIR PERIMETER] Terapkan aturan firewall pemblokiran IP penyerang yang telah disediakan secara otomatis oleh sistem SPECTRA.")
		decisions = append(decisions, "4. [KEBIJAKAN RILIS] Tunda seluruh pembaruan sistem dan rilis produksi hingga verifikasi forensik menyatakan server 100% steril.")
	} else if res.ThreatLevel == model.SeverityMedium {
		decisions = append(decisions, "1. Perketat aturan akses firewall pada port-port yang sempat dipindai.")
		decisions = append(decisions, "2. Tingkatkan frekuensi pemantauan telemetri jaringan selama 24 jam ke depan.")
		decisions = append(decisions, "3. Pastikan security patch mingguan telah terpasang pada semua server pendukung.")
	} else {
		decisions = append(decisions, "1. Pertahankan kebijakan keamanan jaringan yang sedang berjalan.")
		decisions = append(decisions, "2. Lakukan audit berkala secara rutin pada arsip lalu lintas PCAP mingguan.")
	}
	b.RecommendedDecisions = decisions

	// 6. Template Teks Siap Kirim WhatsApp / Email Direksi
	nowStr := time.Now().Format("02 Jan 2006, 15:04 WIB")
	b.WhatsAppFormatText = fmt.Sprintf(
`*🚨 BRIEFING INSIDEN KEAMANAN SIBER // SPECTRA TACTICAL*
*Waktu Laporan:* %s
*Tingkat Bahaya:* %s (Skor Ancaman: %d/100)
*Status Ringkas:* %s

*1. Apa yang Sebenarnya Terjadi?*
%s

*2. Sasaran & Asal Penyerang:*
• *Target:* %s
• *Penyerang:* %s

*3. Apakah Data Perusahaan Bocor?*
%s

*4. Rekomendasi Keputusan Pimpinan:*
%s

_Laporan ini dibuat otomatis secara instan oleh SPECTRA Tactical Air-Gapped Engine._`,
		nowStr,
		b.SeverityLabel,
		res.ThreatScore,
		b.Headline,
		b.WhatHappenedStory,
		b.PrimaryTarget,
		b.AttackerIdentity,
		b.DataIntegrityStatus,
		strings.Join(b.RecommendedDecisions, "\n"),
	)

	return b
}
