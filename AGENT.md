# SPECTRA // AI AGENT OPERATIONAL DIRECTIVE & COLLABORATION PROTOCOL

> **ATTENTION ALL AI AGENTS (Antigravity, Cursor, Claude Code, Copilot, Cline, Windsurf, Aider, etc.):**  
> This file contains mandatory directives for any AI assistant working on this codebase. You must follow these instructions autonomously without requiring manual prompts from the user.

---

## 1. MANDATORY PROTOCOL: AUTONOMOUS PROGRESS LOGGING (WAJIB)

Whenever you make any changes to this codebase (features, bugfixes, refactoring, configurations), you **MUST AUTONOMOUSLY UPDATE `PROJECT_LOG.md`** before completing your response:

1. **Do NOT wait for the user to ask.** Update the log automatically as part of your work.
2. Go to `PROJECT_LOG.md` under `## 📜 Riwayat Sesi & Changelog Kolaboratif (Session Handoff History)`.
3. Append a new table row with:
   - **Timestamp**: Current date & time.
   - **Author / Agent**: Name of agent and model.
   - **Changes**: Clear description of what was changed or added.
   - **Files Touched**: Exact paths of created or modified files.
   - **Verification**: Tests run, build status, exit codes.
4. Update the task status in `## 🎯 Rencana Kerja / Backlog Selanjutnya` (mark `[x]` for finished tasks or add new ones).
5. Always remind the user to commit and push to Git so their remote teammate receives the latest progress.

---

## 2. STRICT ARCHITECTURAL CONSTRAINTS (DO NOT VIOLATE)

1. **Pure Go (Zero CGo)**:
   - Must compile with `CGO_ENABLED=0`.
   - Never import external C libraries or drivers (`libpcap`, `Npcap`, `WinPcap`).
   - All network socket capture, parsing, and analysis must be implemented in 100% native Go.
2. **Zero Persistence (In-Memory Only)**:
   - No persistent disk storage or database engines (SQLite, MySQL, MongoDB, permanent dumps).
   - Artifacts reside in memory buffers and must be purged completely upon user session reset (`/api/clear`).
3. **Air-Gapped Ready**:
   - Zero external CDN links or internet assets in frontend templates.
   - All JavaScript libraries (e.g., Vis.js, Chart.js) and styles must be embedded directly inside the Go binary.
4. **Lightweight Standalone Binary**:
   - Keep the compiled standalone executable under ~10 MB (~8.3 MB current baseline).

---

## 3. HOW TO VERIFY CODE CHANGES

Before declaring any task complete:
```powershell
# 1. Static check
go vet ./...

# 2. Compile check
go build -ldflags "-s -w" -o spectra.exe ./cmd/spectra

# 3. Test CLI analysis
.\spectra.exe -file attack_sample.pcap
```
