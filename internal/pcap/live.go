package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"spectra/internal/model"
)

// LiveCaptureEngine menangani penangkapan paket jaringan langsung (Pure Go tanpa Npcap/libpcap)
type LiveCaptureEngine struct {
	mu          sync.Mutex
	isCapturing bool
	stopChan    chan struct{}
}

// NewLiveCaptureEngine menginisialisasi engine penangkapan langsung
func NewLiveCaptureEngine() *LiveCaptureEngine {
	return &LiveCaptureEngine{
		stopChan: make(chan struct{}),
	}
}

// IsCapturing mengecek status penangkapan aktif
func (lce *LiveCaptureEngine) IsCapturing() bool {
	lce.mu.Lock()
	defer lce.mu.Unlock()
	return lce.isCapturing
}

// CaptureLivePCAP menangkap paket live selama durasi tertentu dan menghasilkan slice byte berformat PCAP
func (lce *LiveCaptureEngine) CaptureLivePCAP(duration time.Duration) ([]byte, int, error) {
	lce.mu.Lock()
	if lce.isCapturing {
		lce.mu.Unlock()
		return nil, 0, fmt.Errorf("sesi live capture sedang berjalan")
	}
	lce.isCapturing = true
	lce.stopChan = make(chan struct{})
	lce.mu.Unlock()

	defer func() {
		lce.mu.Lock()
		lce.isCapturing = false
		lce.mu.Unlock()
	}()

	// Buffer PCAP in-memory
	pcapBuffer := new(bytes.Buffer)
	gh := GlobalHeader{
		MagicNumber:  MagicMicroseconds,
		VersionMajor: 2,
		VersionMinor: 4,
		ThisZone:     0,
		SigFigs:      0,
		SnapLen:      65535,
		Network:      1, // Ethernet (LINKTYPE_ETHERNET)
	}
	if err := binary.Write(pcapBuffer, binary.LittleEndian, &gh); err != nil {
		return nil, 0, err
	}

	packetCount := 0
	bufLock := sync.Mutex{}

	appendPacket := func(rawPkt []byte, ts time.Time) {
		bufLock.Lock()
		defer bufLock.Unlock()

		rh := RecordHeader{
			TsSec:   uint32(ts.Unix()),
			TsUsec:  uint32(ts.Nanosecond() / 1000),
			InclLen: uint32(len(rawPkt)),
			OrigLen: uint32(len(rawPkt)),
		}
		_ = binary.Write(pcapBuffer, binary.LittleEndian, &rh)
		pcapBuffer.Write(rawPkt)
		packetCount++
	}

	// Coba buka Raw Socket Listener (ip4:icmp atau ip4:tcp)
	var rawConn net.PacketConn
	var rawErr error

	// Prioritaskan ICMP/TCP raw listener
	rawConn, rawErr = net.ListenPacket("ip4:icmp", "0.0.0.0")
	if rawErr != nil {
		rawConn, rawErr = net.ListenPacket("ip4:tcp", "0.0.0.0")
	}

	// Listener UDP cadangan untuk menangkap traffic DNS/broadcast lokal
	udpConn, _ := net.ListenPacket("udp4", "0.0.0.0:0")
	if udpConn != nil {
		defer udpConn.Close()
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(duration):
		case <-lce.stopChan:
		}
		close(done)
		if rawConn != nil {
			rawConn.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
	}()

	// Goroutine pembaca paket raw
	if rawConn != nil {
		go func() {
			buf := make([]byte, 65535)
			for {
				n, addr, err := rawConn.ReadFrom(buf)
				if err != nil {
					return
				}
				if n > 0 {
					// Bungkus IP packet dengan Ethernet header sintetis (14 bytes)
					ethPkt := buildSyntheticEthernet(buf[:n], addr.String(), "127.0.0.1", 0x0800)
					appendPacket(ethPkt, time.Now())
				}
			}
		}()
	}

	// Tunggu durasi selesai
	<-done

	// Jika izin raw socket ditolak oleh OS (misal: non-admin di Windows/Linux)
	if packetCount == 0 && rawErr != nil {
		var osHint string
		if runtime.GOOS == "windows" {
			osHint = "Di Windows, jalankan CMD/PowerShell sebagai Administrator untuk hak akses Raw Socket."
		} else {
			osHint = "Di Linux, jalankan dengan hak akses root atau 'sudo setcap cap_net_raw+ep spectra'."
		}
		return nil, 0, fmt.Errorf("live raw socket gagal terikat (%v). %s", rawErr, osHint)
	}

	return pcapBuffer.Bytes(), packetCount, nil
}

// buildSyntheticEthernet membungkus payload IP ke frame Ethernet standar
func buildSyntheticEthernet(ipData []byte, srcIP, dstIP string, etherType uint16) []byte {
	eth := make([]byte, 14+len(ipData))
	// Dummy MAC Addresses
	copy(eth[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // Dst MAC
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) // Src MAC
	binary.BigEndian.PutUint16(eth[12:14], etherType)
	copy(eth[14:], ipData)
	return eth
}

// SaveCapturedPCAP menyimpan byte live capture ke file PCAP sementara
func SaveCapturedPCAP(data []byte, filename string) error {
	return os.WriteFile(filename, data, 0644)
}

// ConvertCapturedToParsed mengonversi byte PCAP live langsung ke parsed packets
func ConvertCapturedToParsed(data []byte) ([]model.ParsedPacket, int64, string, error) {
	return ParsePCAPBytes(data)
}
