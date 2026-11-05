package analyzer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"spectra/internal/model"
)

// CompiledRule representasi aturan yang telah dikompilasi ke memori
type CompiledRule struct {
	Rule     model.CustomRule
	Regex    *regexp.Regexp
	HexBytes []byte
}

// RuleEngine mesin evaluasi aturan deteksi dinamis
type RuleEngine struct {
	mu            sync.RWMutex
	rules         []CompiledRule
	activeRuleRaw []model.CustomRule
}

// NewRuleEngine menginisialisasi rule engine dengan katalog default bawaan
func NewRuleEngine() *RuleEngine {
	re := &RuleEngine{}
	re.loadDefaultRules()
	// Coba muat aturan kustom dari file rules.json jika tersedia
	_ = re.LoadRulesFromFile("rules.json")
	return re
}

func (re *RuleEngine) loadDefaultRules() {
	defaults := []model.CustomRule{
		{
			ID:             "RULE-SHELLSHOCK-01",
			Name:           "GNU Bash Shellshock Environment Exploit (CVE-2014-6271)",
			RiskLevel:      model.SeverityCritical,
			TargetProtocol: "HTTP",
			MatchType:      "Regex",
			Pattern:        `\(\)\s*\{\s*:;\s*\};`,
			MitreID:        "T1059.004",
			MitreTactic:    "Execution",
			Recommendation: "Update paket bash di server Linux segera ke versi yang telah ditambal dan tinjau environment variable HTTP.",
			ScoreWeight:    35,
			Enabled:        true,
		},
		{
			ID:             "RULE-STRUTS-02",
			Name:           "Apache Struts Jakarta Multipart OGNL RCE (CVE-2017-5638)",
			RiskLevel:      model.SeverityCritical,
			TargetProtocol: "HTTP",
			MatchType:      "ExactString",
			Pattern:        "#_memberAccess",
			MitreID:        "T1190",
			MitreTactic:    "Initial Access",
			Recommendation: "Upgrade framework Apache Struts ke versi >=2.3.32 atau >=2.5.10.1 dan batasi header Content-Type.",
			ScoreWeight:    35,
			Enabled:        true,
		},
		{
			ID:             "RULE-SPRING4SHELL-03",
			Name:           "Spring4Shell DataBinder ClassLoader RCE (CVE-2022-22965)",
			RiskLevel:      model.SeverityCritical,
			TargetProtocol: "HTTP",
			MatchType:      "ExactString",
			Pattern:        "class.module.classLoader",
			MitreID:        "T1190",
			MitreTactic:    "Initial Access",
			Recommendation: "Upgrade Spring Framework ke versi 5.3.18+/5.2.20+ dan pastikan berjalan di Java 9+ dengan patching.",
			ScoreWeight:    35,
			Enabled:        true,
		},
		{
			ID:             "RULE-WEBSHELL-PHP-04",
			Name:           "Obfuscated PHP WebShell / Eval Dropper",
			RiskLevel:      model.SeverityCritical,
			TargetProtocol: "HTTP",
			MatchType:      "Regex",
			Pattern:        `(?i)(eval\s*\(\s*base64_decode|assert\s*\(\s*\$_POST|passthru\s*\()`,
			MitreID:        "T1505.003",
			MitreTactic:    "Persistence",
			Recommendation: "Karantina file PHP terkait, disable dangerous functions (eval, passthru, system) di php.ini.",
			ScoreWeight:    35,
			Enabled:        true,
		},
		{
			ID:             "RULE-CS-BEACON-05",
			Name:           "Cobalt Strike Default Malleable C2 Beaconing Signature",
			RiskLevel:      model.SeverityCritical,
			TargetProtocol: "HTTP",
			MatchType:      "ExactString",
			Pattern:        "__cfduid=d",
			MitreID:        "T1071.001",
			MitreTactic:    "Command and Control",
			Recommendation: "Blokir komunikasi ke server C2 di level perimeter firewall dan periksa memori host untuk injeksi DLL Beacon.",
			ScoreWeight:    35,
			Enabled:        true,
		},
		{
			ID:             "RULE-PS-CRADLE-06",
			Name:           "PowerShell In-Memory Download Cradle (IEX DownloadString)",
			RiskLevel:      model.SeverityHigh,
			TargetProtocol: "HTTP",
			MatchType:      "Regex",
			Pattern:        `(?i)IEX\s*\(\s*New-Object\s+Net\.WebClient\s*\)\.DownloadString`,
			MitreID:        "T1059.001",
			MitreTactic:    "Execution",
			Recommendation: "Aktifkan ScriptBlock Logging (Event ID 4104) dan terapkan PowerShell Constrained Language Mode.",
			ScoreWeight:    25,
			Enabled:        true,
		},
		{
			ID:             "RULE-XSS-INJECT-07",
			Name:           "Cross-Site Scripting (XSS) Tag Injection",
			RiskLevel:      model.SeverityMedium,
			TargetProtocol: "HTTP",
			MatchType:      "Regex",
			Pattern:        `(?i)<\s*script[^>]*>|javascript:\s*alert`,
			MitreID:        "T1189",
			MitreTactic:    "Initial Access",
			Recommendation: "Gunakan Content-Security-Policy (CSP) ketat dan escape seluruh output HTML dinamis.",
			ScoreWeight:    15,
			Enabled:        true,
		},
		{
			ID:             "RULE-DNS-TXT-C2-08",
			Name:           "Suspicious DNS TXT Record Command Staging",
			RiskLevel:      model.SeverityHigh,
			TargetProtocol: "DNS",
			MatchType:      "ExactString",
			Pattern:        "c2stage",
			MitreID:        "T1071.004",
			MitreTactic:    "Command and Control",
			Recommendation: "Audit log DNS query dan blokir domain C2 staging di DNS firewall.",
			ScoreWeight:    20,
			Enabled:        true,
		},
	}

	for _, rule := range defaults {
		re.compileAndAddRule(rule)
	}
}

func (re *RuleEngine) compileAndAddRule(rule model.CustomRule) {
	cr := CompiledRule{Rule: rule}
	switch strings.ToLower(rule.MatchType) {
	case "regex":
		if reg, err := regexp.Compile(rule.Pattern); err == nil {
			cr.Regex = reg
		}
	case "hexbytes":
		cleanHex := strings.ReplaceAll(rule.Pattern, " ", "")
		if b, err := hex.DecodeString(cleanHex); err == nil {
			cr.HexBytes = b
		}
	}
	re.rules = append(re.rules, cr)
	re.activeRuleRaw = append(re.activeRuleRaw, rule)
}

// LoadRulesFromFile memuat aturan dari file JSON
func (re *RuleEngine) LoadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var customList []model.CustomRule
	if err := json.Unmarshal(data, &customList); err != nil {
		return fmt.Errorf("format JSON rules tidak valid: %w", err)
	}

	re.mu.Lock()
	defer re.mu.Unlock()

	for _, rule := range customList {
		if !rule.Enabled {
			continue
		}
		re.compileAndAddRule(rule)
	}
	return nil
}

// GetActiveRules mengembalikan daftar aturan yang saat ini aktif
func (re *RuleEngine) GetActiveRules() []model.CustomRule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	res := make([]model.CustomRule, len(re.activeRuleRaw))
	copy(res, re.activeRuleRaw)
	return res
}

// Evaluate memeriksa apakah paket memicu salah satu aturan kustom
func (re *RuleEngine) Evaluate(p model.ParsedPacket) []model.ThreatIndicator {
	re.mu.RLock()
	defer re.mu.RUnlock()

	var findings []model.ThreatIndicator
	if len(p.Payload) == 0 {
		return findings
	}

	payloadBytes := p.Payload
	payloadStr := string(p.Payload)

	for _, cr := range re.rules {
		if !cr.Rule.Enabled {
			continue
		}
		// Saring protokol jika dispesifikasikan
		if cr.Rule.TargetProtocol != "" && cr.Rule.TargetProtocol != "RAW" {
			if !strings.EqualFold(p.Protocol, cr.Rule.TargetProtocol) {
				continue
			}
		}

		matched := false
		matchEvidence := ""

		switch strings.ToLower(cr.Rule.MatchType) {
		case "exactstring":
			if strings.Contains(payloadStr, cr.Rule.Pattern) {
				matched = true
				matchEvidence = fmt.Sprintf("Exact string match: %s", cr.Rule.Pattern)
			}
		case "regex":
			if cr.Regex != nil && cr.Regex.MatchString(payloadStr) {
				matched = true
				matchEvidence = fmt.Sprintf("Regex pattern match: %s", cr.Rule.Pattern)
			}
		case "hexbytes":
			if len(cr.HexBytes) > 0 && strings.Contains(string(payloadBytes), string(cr.HexBytes)) {
				matched = true
				matchEvidence = fmt.Sprintf("Hex bytes matched: %s", cr.Rule.Pattern)
			}
		}

		if matched {
			findings = append(findings, model.ThreatIndicator{
				ID:             fmt.Sprintf("IOC-%s", cr.Rule.ID),
				Timestamp:      p.Timestamp,
				Title:          cr.Rule.Name,
				Description:    fmt.Sprintf("Terdeteksi kecocokan aturan kustom [%s]: %s", cr.Rule.ID, cr.Rule.Name),
				Severity:       cr.Rule.RiskLevel,
				MitreTactic:    cr.Rule.MitreTactic,
				MitreAttack:    fmt.Sprintf("%s - %s", cr.Rule.MitreID, cr.Rule.Name),
				SrcIP:          p.SrcIP,
				DstIP:          p.DstIP,
				Protocol:       p.Protocol,
				ScoreWeight:    cr.Rule.ScoreWeight,
				Evidence:       matchEvidence,
				EvidenceHex:    p.HexDump,
				Recommendation: cr.Rule.Recommendation,
				Entropy:        p.Entropy,
			})
		}
	}

	return findings
}
