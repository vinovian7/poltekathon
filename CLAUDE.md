# CLAUDE.md - SPECTRA Project Guide

## Mandatory Autonomous Rule:
Whenever any changes or additions are made to the codebase, you MUST autonomously update `PROJECT_LOG.md` under `## 📜 Riwayat Sesi & Changelog Kolaboratif` without waiting for the user to prompt you.

## Architecture:
- Pure Go (Golang 1.27), CGO_ENABLED=0
- Zero persistence (in-memory only, no disk databases)
- Air-gapped (zero external CDN or web dependencies)
- Port 8888 (Web), Port 2222 (SSH)
- Build: `go build -ldflags "-s -w" -o spectra.exe ./cmd/spectra`
- Verify: `go vet ./...` and `.\spectra.exe -file attack_sample.pcap`
