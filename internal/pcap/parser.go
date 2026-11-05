package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"spectra/internal/model"
)

// Magic Numbers
const (
	MagicMicroseconds = 0xa1b2c3d4
	MagicNanoseconds  = 0xa1b23c4d
	MagicBigEndian    = 0xd4c3b2a1
	MagicNanoBig      = 0x4d3cb2a1
	MagicPCAPNG       = 0x0a0d0d0a // Section Header Block
)

// GlobalHeader PCAP file format (24 bytes)
type GlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

// RecordHeader setiap packet (16 bytes)
type RecordHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// ShannonEntropy menghitung Shannon Entropy (0.0 - 8.0) dari raw bytes.
// Nilai tinggi (> 7.2) mengindikasikan payload terenkripsi, terkompresi, packed malware, atau C2 obfuscation.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// EntropyLabel mengklasifikasikan nilai entropi ke dalam label deskriptif taktis
func EntropyLabel(entropy float64) string {
	switch {
	case entropy >= 7.5:
		return "🔴 HIGHLY SUSPICIOUS — Encrypted/Packed Payload"
	case entropy >= 7.2:
		return "🟠 HIGH ENTROPY — Possible C2 / Obfuscation"
	case entropy >= 6.0:
		return "🟡 ELEVATED — Compressed or Encoded Data"
	case entropy >= 3.5:
		return "🟢 NORMAL — Plaintext/Structured Data"
	default:
		return "⚪ LOW — Sparse or Repetitive Payload"
	}
}

// ParsePCAPFile membaca raw PCAP atau PCAPNG secara aman tanpa CGo
func ParsePCAPFile(filePath string) ([]model.ParsedPacket, int64, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, "", fmt.Errorf("gagal membuka artefak jaringan: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, 0, "", err
	}
	totalSize := stat.Size()

	// Batas keamanan ukuran file (Maks 150 MB untuk triase instan lokal)
	if totalSize > 150*1024*1024 {
		return nil, 0, "", fmt.Errorf("ukuran file melebihi batas triase taktis aman (maks 150 MB)")
	}

	// Hitung SHA-256 hash artefak untuk integritas forensik
	hasher := sha256.New()
	teeReader := io.TeeReader(file, hasher)

	// Baca 4 byte pertama untuk deteksi format (PCAP vs PCAPNG)
	var magic uint32
	if err := binary.Read(teeReader, binary.LittleEndian, &magic); err != nil {
		return nil, 0, "", fmt.Errorf("file kosong atau format tidak valid")
	}

	var packets []model.ParsedPacket

	if magic == MagicPCAPNG {
		packets, err = parsePCAPNG(file, teeReader)
	} else if magic == MagicMicroseconds || magic == MagicNanoseconds || magic == MagicBigEndian || magic == MagicNanoBig {
		packets, err = parseClassicPCAP(file, teeReader, magic)
	} else {
		return nil, 0, "", fmt.Errorf("bukan format PCAP atau PCAPNG yang valid (Magic: 0x%08X)", magic)
	}

	if err != nil && len(packets) == 0 {
		return nil, 0, "", err
	}

	// Baca sisa file untuk menyelesaikan hash jika parsing selesai lebih awal
	io.Copy(hasher, file)
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	return packets, totalSize, sha256Hex, nil
}

// ParsePCAPBytes membaca raw PCAP atau PCAPNG langsung dari memori byte slice
func ParsePCAPBytes(data []byte) ([]model.ParsedPacket, int64, string, error) {
	totalSize := int64(len(data))
	if totalSize > 150*1024*1024 {
		return nil, 0, "", fmt.Errorf("ukuran data melebihi batas triase taktis aman (maks 150 MB)")
	}

	hasher := sha256.New()
	hasher.Write(data)
	sha256Hex := hex.EncodeToString(hasher.Sum(nil))

	reader := bytes.NewReader(data)
	var magic uint32
	if err := binary.Read(reader, binary.LittleEndian, &magic); err != nil {
		return nil, 0, "", fmt.Errorf("data kosong atau format tidak valid")
	}

	var packets []model.ParsedPacket
	var err error

	if magic == MagicPCAPNG {
		packets, err = parsePCAPNG(nil, reader)
	} else if magic == MagicMicroseconds || magic == MagicNanoseconds || magic == MagicBigEndian || magic == MagicNanoBig {
		packets, err = parseClassicPCAP(nil, reader, magic)
	} else {
		return nil, 0, "", fmt.Errorf("bukan format PCAP atau PCAPNG yang valid (Magic: 0x%08X)", magic)
	}

	if err != nil && len(packets) == 0 {
		return nil, 0, "", err
	}

	return packets, totalSize, sha256Hex, nil
}

// parseClassicPCAP membedah format libpcap standar
func parseClassicPCAP(file *os.File, r io.Reader, magic uint32) ([]model.ParsedPacket, error) {
	byteOrder := binary.ByteOrder(binary.LittleEndian)
	isNano := false

	if magic == MagicMicroseconds {
		byteOrder = binary.LittleEndian
	} else if magic == MagicBigEndian {
		byteOrder = binary.BigEndian
	} else if magic == MagicNanoseconds {
		byteOrder = binary.LittleEndian
		isNano = true
	} else if magic == MagicNanoBig {
		byteOrder = binary.BigEndian
		isNano = true
	}

	// Sisa header global: 20 bytes
	restHeader := make([]byte, 20)
	if _, err := io.ReadFull(r, restHeader); err != nil {
		return nil, fmt.Errorf("header PCAP tidak lengkap")
	}

	var packets []model.ParsedPacket
	packetIndex := 1

	for {
		var rh RecordHeader
		err := binary.Read(r, byteOrder, &rh)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			break
		}

		// Validasi keamanan panjang paket (Sanity & Bounds Check)
		if rh.InclLen == 0 || rh.InclLen > 65535 {
			continue
		}

		packetData := make([]byte, rh.InclLen)
		_, err = io.ReadFull(r, packetData)
		if err != nil {
			break
		}

		var ts time.Time
		if isNano {
			ts = time.Unix(int64(rh.TsSec), int64(rh.TsUsec))
		} else {
			ts = time.Unix(int64(rh.TsSec), int64(rh.TsUsec)*1000)
		}

		pkt := dissectEthernet(packetData, ts, packetIndex)
		packets = append(packets, pkt)
		packetIndex++
	}

	return packets, nil
}

// parsePCAPNG membedah format PCAP Next Generation
func parsePCAPNG(file *os.File, r io.Reader) ([]model.ParsedPacket, error) {
	var blockLen uint32
	if err := binary.Read(r, binary.LittleEndian, &blockLen); err != nil {
		return nil, err
	}

	var bom uint32
	if err := binary.Read(r, binary.LittleEndian, &bom); err != nil {
		return nil, err
	}

	byteOrder := binary.ByteOrder(binary.LittleEndian)
	if bom == 0x4D3C2B1A {
		byteOrder = binary.BigEndian
	}

	if blockLen > 12 {
		skip := make([]byte, blockLen-12)
		io.ReadFull(r, skip)
	}

	var packets []model.ParsedPacket
	packetIndex := 1

	for {
		var blockType, curBlockLen uint32
		if err := binary.Read(r, byteOrder, &blockType); err != nil {
			break
		}
		if err := binary.Read(r, byteOrder, &curBlockLen); err != nil {
			break
		}

		if curBlockLen < 12 || curBlockLen > 1000000 {
			break
		}

		bodyLen := curBlockLen - 8
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			break
		}

		// Enhanced Packet Block (EPB: Type 0x00000006)
		if blockType == 0x00000006 && len(body) >= 20 {
			capLen := byteOrder.Uint32(body[12:16])
			if capLen > 0 && capLen <= 65535 && int(20+capLen) <= len(body) {
				packetData := body[20 : 20+capLen]
				tsHigh := uint64(byteOrder.Uint32(body[4:8]))
				tsLow := uint64(byteOrder.Uint32(body[8:12]))
				tsMicros := (tsHigh<<32 | tsLow) / 1000000
				ts := time.Unix(int64(tsMicros), 0)

				pkt := dissectEthernet(packetData, ts, packetIndex)
				packets = append(packets, pkt)
				packetIndex++
			}
		}

		// Simple Packet Block (SPB: Type 0x00000003)
		if blockType == 0x00000003 && len(body) >= 8 {
			origLen := byteOrder.Uint32(body[0:4])
			capLen := origLen
			if capLen > 65535 {
				capLen = 65535
			}
			if int(4+capLen) <= len(body) {
				packetData := body[4 : 4+capLen]
				pkt := dissectEthernet(packetData, time.Now(), packetIndex)
				packets = append(packets, pkt)
				packetIndex++
			}
		}
	}

	return packets, nil
}

func dissectEthernet(data []byte, ts time.Time, idx int) model.ParsedPacket {
	pkt := model.ParsedPacket{
		Index:     idx,
		Timestamp: ts,
		Length:    uint32(len(data)),
		Protocol:  "RAW",
		Summary:   "Raw Ethernet Frame",
	}

	if len(data) < 14 {
		return pkt
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != 0x0800 { // Bukan IPv4
		if etherType == 0x86DD {
			pkt.Protocol = "IPv6"
			pkt.Summary = "IPv6 Traffic Frame"
		} else if etherType == 0x0806 {
			pkt.Protocol = "ARP"
			pkt.Summary = "ARP Address Resolution Protocol"
		}
		return pkt
	}

	// Dissect IPv4
	ipData := data[14:]
	if len(ipData) < 20 {
		return pkt
	}

	ihl := int(ipData[0]&0x0F) * 4
	if len(ipData) < ihl || ihl < 20 {
		return pkt
	}

	protocolNum := ipData[9]
	pkt.SrcIP = net.IP(ipData[12:16]).String()
	pkt.DstIP = net.IP(ipData[16:20]).String()

	payload := ipData[ihl:]

	switch protocolNum {
	case 1: // ICMP
		pkt.Protocol = "ICMP"
		if len(payload) >= 2 {
			icmpType := payload[0]
			icmpCode := payload[1]
			pkt.Summary = fmt.Sprintf("ICMP Type %d Code %d (%s -> %s)", icmpType, icmpCode, pkt.SrcIP, pkt.DstIP)
		}

	case 6: // TCP
		pkt.Protocol = "TCP"
		if len(payload) >= 20 {
			pkt.SrcPort = binary.BigEndian.Uint16(payload[0:2])
			pkt.DstPort = binary.BigEndian.Uint16(payload[2:4])
			tcpHeaderLen := int((payload[12] >> 4) * 4)
			flags := payload[13]

			isSyn := (flags & 0x02) != 0
			isAck := (flags & 0x10) != 0
			isRst := (flags & 0x04) != 0
			isFin := (flags & 0x01) != 0
			isPsh := (flags & 0x08) != 0

			flagDesc := []string{}
			if isSyn {
				flagDesc = append(flagDesc, "SYN")
			}
			if isAck {
				flagDesc = append(flagDesc, "ACK")
			}
			if isRst {
				flagDesc = append(flagDesc, "RST")
			}
			if isFin {
				flagDesc = append(flagDesc, "FIN")
			}
			if isPsh {
				flagDesc = append(flagDesc, "PSH")
			}

			pkt.Summary = fmt.Sprintf("TCP %s:%d -> %s:%d [%s]",
				pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, strings.Join(flagDesc, ","))

			if len(payload) > tcpHeaderLen && tcpHeaderLen >= 20 {
				tcpPayload := payload[tcpHeaderLen:]
				pkt.Payload = tcpPayload
				pkt.HexDump = FormatHexDump(tcpPayload, 128)
				// Hitung entropi payload TCP
				pkt.Entropy = ShannonEntropy(tcpPayload)

				if isHTTP(tcpPayload) {
					pkt.Protocol = "HTTP"
					line := strings.Split(string(tcpPayload), "\r\n")[0]
					if len(line) > 70 {
						line = line[:70] + "..."
					}
					pkt.Summary = fmt.Sprintf("HTTP %s:%d -> %s:%d | %s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, line)
				}
			}
		}

	case 17: // UDP
		pkt.Protocol = "UDP"
		if len(payload) >= 8 {
			pkt.SrcPort = binary.BigEndian.Uint16(payload[0:2])
			pkt.DstPort = binary.BigEndian.Uint16(payload[2:4])
			udpPayload := payload[8:]
			pkt.Payload = udpPayload
			pkt.HexDump = FormatHexDump(udpPayload, 128)
			pkt.Entropy = ShannonEntropy(udpPayload)
			pkt.Summary = fmt.Sprintf("UDP %s:%d -> %s:%d (len: %d)", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, len(udpPayload))

			if pkt.SrcPort == 53 || pkt.DstPort == 53 {
				pkt.Protocol = "DNS"
				dnsQuery := extractDNSQuery(udpPayload)
				if dnsQuery != "" {
					pkt.Summary = fmt.Sprintf("DNS Query: %s from %s", dnsQuery, pkt.SrcIP)
				}
			}
		}

	default:
		pkt.Protocol = fmt.Sprintf("IP-Proto-%d", protocolNum)
	}

	return pkt
}

func isHTTP(data []byte) bool {
	prefixes := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1.0", "HTTP/1.1", "HTTP/2"}
	for _, p := range prefixes {
		if bytes.HasPrefix(data, []byte(p)) {
			return true
		}
	}
	return false
}

func extractDNSQuery(data []byte) string {
	if len(data) < 13 {
		return ""
	}
	idx := 12
	var parts []string
	for idx < len(data) {
		length := int(data[idx])
		if length == 0 {
			break
		}
		idx++
		if idx+length > len(data) {
			break
		}
		parts = append(parts, string(data[idx:idx+length]))
		idx += length
	}
	return strings.Join(parts, ".")
}

// FormatHexDump memformat slice byte ke representasi Hex + ASCII terstandar Wireshark/tcpdump
func FormatHexDump(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return ""
	}
	if maxBytes > 0 && len(data) > maxBytes {
		data = data[:maxBytes]
	}

	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]

		// Offset
		sb.WriteString(fmt.Sprintf("%04x  ", i))

		// Hex bytes
		for j := 0; j < 16; j++ {
			if j < len(chunk) {
				sb.WriteString(fmt.Sprintf("%02x ", chunk[j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}

		sb.WriteString(" |")
		// ASCII characters
		for _, b := range chunk {
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}

	return sb.String()
}
