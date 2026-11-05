# Autonomous Collaboration & Progress Tracking Rule

## Purpose
This repository is developed collaboratively by multiple team members and AI Agents working from different environments via Git. To prevent context drift, duplicated work, and confusion between teammates, every AI agent working in this repository MUST adhere to the following autonomous protocol.

---

## 1. Initial Context Ingestion (Every Task)
At the start of ANY task or user request:
- Always read `PROJECT_LOG.md` first to understand the current project checkpoint, active features, and architectural boundaries.
- Adhere strictly to SPECTRA's Core Architecture:
  1. **Pure Go (`CGO_ENABLED=0`)**: No CGo, no C-libraries, no Npcap/libpcap.
  2. **Zero Persistence**: In-memory only. Do NOT introduce disk databases (SQLite, MySQL, permanent JSON dumps).
  3. **Air-Gapped Ready**: No external internet CDNs in HTML/JS templates. Embed all CSS/JS dependencies.
  4. **Standalone Single Binary**: Maintain executable size under ~10 MB.

---

## 2. Mandatory Autonomous Log Update (Zero-Prompt Requirement)
**CRITICAL**: You MUST update `PROJECT_LOG.md` automatically at the end of your turn whenever you modify code, add a feature, or fix a bug. **Do NOT wait for the user to prompt or remind you to update the log.**

### How to Update:
1. Locate the table under `## 📜 Riwayat Sesi & Changelog Kolaboratif (Session Handoff History)` in `PROJECT_LOG.md`.
2. Append a new row with:
   - Current Date & Time
   - Author / AI Agent Name
   - Clear summary of what was implemented or fixed
   - Files modified or created
   - Verification status (e.g. `go vet`, `go build`, or CLI tests executed)
3. If an item in `## 🎯 Rencana Kerja / Backlog Selanjutnya` was completed, change `[ ]` to `[x]`. If a new task was discovered, add it to the backlog.
4. If a new milestone was achieved, update the `Matriks Fitur & Status Implementasi` table.

---

## 3. Git Handoff Readiness
When finishing your response to the user:
- Mention that `PROJECT_LOG.md` has been updated.
- Provide a ready-to-run Git commit message snippet (e.g., `git add . && git commit -m "feat: ..." && git push`) so the user can easily push the work to remote Git for their teammate.
