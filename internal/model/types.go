package model

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ParsedPacket represents a normalized network packet
type ParsedPacket struct {
	Index        int       `json:"index"`
	Timestamp    time.Time `json:"timestamp"`
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	Protocol     string    `json:"protocol"`
	Length       uint32    `json:"length"`
	Payload      []byte    `json:"-"`
	HexDump      string    `json:"hex_dump,omitempty"`
	Summary      string    `json:"summary"`
	IsSuspicious bool      `json:"is_suspicious"`
	Entropy      float64   `json:"entropy,omitempty"`
}

// ThreatIndicator merepresentasikan temuan ancaman dengan pemetaan MITRE ATT&CK & rekomendasi tindakan
type ThreatIndicator struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       Severity  `json:"severity"`
	MitreTactic    string    `json:"mitre_tactic"`
	MitreAttack    string    `json:"mitre_attack"`
	SrcIP          string    `json:"src_ip"`
	DstIP          string    `json:"dst_ip"`
	Protocol       string    `json:"protocol"`
	Evidence       string    `json:"evidence"`
	EvidenceHex    string    `json:"evidence_hex,omitempty"`
	Recommendation string    `json:"recommendation"`
	ScoreWeight    int       `json:"score_weight"`
	Entropy        float64   `json:"entropy,omitempty"`
	EntropyLabel   string    `json:"entropy_label,omitempty"`
}

// TimelineEvent merepresentasikan urutan kronologi kejadian insiden
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Stage       string    `json:"stage"`
	Severity    Severity  `json:"severity"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Message     string    `json:"message"`
	Tactic      string    `json:"tactic"`
}

// ProtocolStats rekapitulasi volume protokol
type ProtocolStats struct {
	TCPCount  int `json:"tcp_count"`
	UDPCount  int `json:"udp_count"`
	DNSCount  int `json:"dns_count"`
	HTTPCount int `json:"http_count"`
	ICMPCount int `json:"icmp_count"`
	Other     int `json:"other_count"`
}

// NetworkFlow rekap aliran komunikasi host ke host
type NetworkFlow struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol string `json:"protocol"`
	Packets  int    `json:"packets"`
	Bytes    int64  `json:"bytes"`
}

// MitreMatrixSummary rekapitulasi jumlah temuan per fase taktis MITRE ATT&CK
type MitreMatrixSummary struct {
	Reconnaissance    int `json:"reconnaissance"`
	InitialAccess     int `json:"initial_access"`
	Execution         int `json:"execution"`
	CredentialAccess  int `json:"credential_access"`
	CommandAndControl int `json:"command_and_control"`
	Exfiltration      int `json:"exfiltration"`
}

// AttackGraphNode merepresentasikan node dalam graf relasi serangan
type AttackGraphNode struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Role    string `json:"role"`
	Color   string `json:"color"`
	Packets int    `json:"packets"`
	IsIOC   bool   `json:"is_ioc"`
	Tooltip string `json:"tooltip"`
}

// AttackGraphEdge merepresentasikan koneksi/relasi antar node dalam graf
type AttackGraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Packets  int    `json:"packets"`
	IsIOC    bool   `json:"is_ioc"`
	Color    string `json:"color"`
	Width    int    `json:"width"`
	Tooltip  string `json:"tooltip"`
}

// AttackGraph representasi lengkap graf relasi serangan
type AttackGraph struct {
	Nodes []AttackGraphNode `json:"nodes"`
	Edges []AttackGraphEdge `json:"edges"`
}

// RiskScoreBreakdown rincian komponen perhitungan skor risiko taktis
type RiskScoreBreakdown struct {
	CriticalCount  int `json:"critical_count"`
	CriticalPoints int `json:"critical_points"`
	HighCount      int `json:"high_count"`
	HighPoints     int `json:"high_points"`
	MediumCount    int `json:"medium_count"`
	MediumPoints   int `json:"medium_points"`
	RawScore       int `json:"raw_score"`
	FinalScore     int `json:"final_score"`
}

// BlocklistRules hasil generasi script mitigasi/blocklist otomatis
type BlocklistRules struct {
	AttackerIPs   []string `json:"attacker_ips"`
	IPtablesRules []string `json:"iptables_rules"`
	WindowsRules  []string `json:"windows_rules"`
	SuricataRules []string `json:"suricata_rules"`
	PlainIPList   string   `json:"plain_ip_list"`
}

// CustomRule model aturan deteksi dinamis berbasis JSON/YAML
type CustomRule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	RiskLevel      Severity `json:"risk_level"`
	TargetProtocol string   `json:"target_protocol"` // HTTP, DNS, TCP, RAW
	MatchType      string   `json:"match_type"`      // ExactString, Regex, HexBytes
	Pattern        string   `json:"pattern"`
	MitreID        string   `json:"mitre_id"`
	MitreTactic    string   `json:"mitre_tactic"`
	Recommendation string   `json:"recommendation"`
	ScoreWeight    int      `json:"score_weight"`
	Enabled        bool     `json:"enabled"`
}

// PlaybookStep langkah terperinci rencana mitigasi darurat
type PlaybookStep struct {
	StepNumber  int    `json:"step_number"`
	Phase       string `json:"phase"` // Containment, Eradication, Recovery
	Priority    string `json:"priority"` // P1-CRITICAL, P2-URGENT, P3-STANDARD
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	TargetHost  string `json:"target_host,omitempty"`
	MitreRef    string `json:"mitre_ref,omitempty"`
}

// IncidentPlaybook rencana aksi mitigasi insiden otomatis
type IncidentPlaybook struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Summary     string         `json:"summary"`
	Steps       []PlaybookStep `json:"steps"`
	RawPlanText string         `json:"raw_plan_text"`
}

// LiveCaptureStatus status penangkapan paket real-time
type LiveCaptureStatus struct {
	IsCapturing     bool   `json:"is_capturing"`
	DurationSec     int    `json:"duration_sec"`
	CapturedPackets int    `json:"captured_packets"`
	CapturedBytes   int64  `json:"captured_bytes"`
	InterfaceName   string `json:"interface_name"`
	Message         string `json:"message"`
}

// ExecutiveBriefing merepresentasikan ringkasan naratif ramah pimpinan non-teknis
type ExecutiveBriefing struct {
	Headline             string   `json:"headline"`
	SeverityLabel        string   `json:"severity_label"`
	BusinessImpactLevel  string   `json:"business_impact_level"`
	PrimaryTarget        string   `json:"primary_target"`
	AttackerIdentity     string   `json:"attacker_identity"`
	WhatHappenedStory    string   `json:"what_happened_story"`
	DataIntegrityStatus  string   `json:"data_integrity_status"`
	RecommendedDecisions []string `json:"recommended_decisions"`
	WhatsAppFormatText   string   `json:"whatsapp_format_text"`
}

// AnalysisResult hasil akhir seluruh proses triase taktis
type AnalysisResult struct {
	TargetFileName    string             `json:"target_file_name"`
	SHA256Checksum    string             `json:"sha256_checksum"`
	AnalyzedAt        time.Time          `json:"analyzed_at"`
	AnalysisDuration  string             `json:"analysis_duration"`
	TotalPackets      int                `json:"total_packets"`
	TotalBytes        int64              `json:"total_bytes"`
	ThreatScore       int                `json:"threat_score"`
	ThreatLevel       Severity           `json:"threat_level"`
	ExecutiveSummary  string             `json:"executive_summary"`
	ProtocolStats     ProtocolStats      `json:"protocol_stats"`
	TopSources        map[string]int     `json:"top_sources"`
	TopDestinations   map[string]int     `json:"top_destinations"`
	NetworkFlows      []NetworkFlow      `json:"network_flows"`
	MitreSummary      MitreMatrixSummary `json:"mitre_summary"`
	Indicators        []ThreatIndicator  `json:"indicators"`
	Timeline          []TimelineEvent    `json:"timeline"`
	SamplePackets     []ParsedPacket     `json:"sample_packets"`
	AirGappedStatus   string             `json:"air_gapped_status"`
	AttackGraph       AttackGraph        `json:"attack_graph"`
	RiskBreakdown     RiskScoreBreakdown `json:"risk_breakdown"`
	BlocklistRules    BlocklistRules     `json:"blocklist_rules"`
	MaxEntropy        float64            `json:"max_entropy"`
	AvgEntropy        float64            `json:"avg_entropy"`
	ThroughputMBps    float64            `json:"throughput_mbps"`
	ThroughputPktsSec float64            `json:"throughput_pkts_sec"`
	ActiveRulesCount  int                `json:"active_rules_count"`
	Playbook          IncidentPlaybook   `json:"playbook"`
	ExecutiveBriefing ExecutiveBriefing  `json:"executive_briefing"`
}
