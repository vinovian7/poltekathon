package server

// ======================== TEMPLATE DASHBOARD ========================
const dashboardHTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <title>SPECTRA // TACTICAL CYBER TRIAGE COMMAND HUD</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-base: #060a12;
            --bg-card: #0b1320;
            --border: #182842;
            --accent-cyan: #00f2fe;
            --accent-green: #00ff88;
            --accent-red: #ff0055;
            --accent-orange: #ff9900;
            --text-main: #f1f5f9;
            --text-muted: #64748b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Consolas', 'Courier New', monospace; }
        html { scroll-behavior: smooth; }
        body { background: var(--bg-base); color: var(--text-main); min-height: 100vh; padding: 18px; }

        /* ── TOP HUD ── */
        .top-hud {
            display: flex; justify-content: space-between; align-items: center;
            background: rgba(11,19,32,0.92); backdrop-filter: blur(10px);
            border: 1px solid var(--border); border-left: 4px solid var(--accent-cyan);
            border-radius: 6px; padding: 12px 20px; margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }
        .logo-box { display: flex; align-items: center; gap: 12px; }
        .radar-pulse {
            width: 12px; height: 12px; background: var(--accent-green);
            border-radius: 50%; box-shadow: 0 0 10px var(--accent-green);
            animation: pulseAnim 1.8s infinite; flex-shrink: 0;
        }
        @keyframes pulseAnim {
            0% { transform: scale(0.9); opacity: 0.8; }
            50% { transform: scale(1.3); opacity: 1; }
            100% { transform: scale(0.9); opacity: 0.8; }
        }
        .logo-title { font-size: 19px; font-weight: 900; letter-spacing: 2px; color: var(--accent-cyan); }
        .hud-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .btn-nav-home {
            background: #101c30; border: 1px solid var(--border); color: var(--text-main);
            padding: 8px 14px; border-radius: 4px; font-size: 11px; text-decoration: none; font-weight: bold;
            transition: 0.2s;
        }
        .btn-nav-home:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); }
        
        /* Pulse glow animation pada status badge */
        .status-badge {
            font-size: 10px; background: rgba(0,255,136,0.1); color: var(--accent-green);
            border: 1px solid var(--accent-green); padding: 7px 12px; border-radius: 4px; font-weight: bold;
            animation: airGappedPulse 2.4s infinite ease-in-out;
        }
        @keyframes airGappedPulse {
            0% { box-shadow: 0 0 6px rgba(0,255,136,0.2); }
            50% { box-shadow: 0 0 18px rgba(0,255,136,0.6); border-color: #a7f3d0; }
            100% { box-shadow: 0 0 6px rgba(0,255,136,0.2); }
        }

        .perf-badge {
            font-size: 10px; color: var(--accent-cyan); background: rgba(0,242,254,0.08);
            border: 1px solid var(--accent-cyan); padding: 7px 12px; border-radius: 4px; font-weight: bold;
            letter-spacing: 0.5px;
        }

        /* ── MOBILE JUMP BAR ── */
        .mobile-jump-bar {
            display: none; position: sticky; top: 0; z-index: 100;
            background: rgba(6,10,18,0.97); backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border); padding: 8px 4px; margin-bottom: 15px;
            overflow-x: auto; white-space: nowrap; -webkit-overflow-scrolling: touch; gap: 8px;
        }
        .jump-pill {
            display: inline-flex; align-items: center; gap: 5px;
            background: #0d1726; border: 1px solid var(--border); color: var(--text-main);
            padding: 7px 12px; border-radius: 20px; font-size: 11px; text-decoration: none; font-weight: bold;
            transition: 0.2s; flex-shrink: 0;
        }
        .jump-pill:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); background: rgba(0,242,254,0.08); }
        .pill-count {
            background: var(--accent-red); color: white; padding: 1px 6px; border-radius: 10px; font-size: 9px; font-weight: 900;
        }

        /* ── LAYOUT ── */
        .main-grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; align-items: start; }
        .panel {
            background: var(--bg-card); border: 1px solid var(--border);
            border-radius: 8px; padding: 18px; margin-bottom: 20px;
            box-shadow: 0 4px 25px rgba(0,0,0,0.6); scroll-margin-top: 60px;
        }
        .panel-header {
            display: flex; justify-content: space-between; align-items: center;
            font-size: 11px; font-weight: bold; color: var(--accent-cyan);
            text-transform: uppercase; letter-spacing: 1.5px;
            border-bottom: 1px solid var(--border); padding-bottom: 10px; margin-bottom: 15px;
        }

        /* ── DROPZONE ── */
        .dropzone {
            border: 2px dashed #233554; border-radius: 8px; padding: 24px 15px;
            text-align: center; cursor: pointer; transition: all 0.25s ease;
            background: rgba(0,0,0,0.25); user-select: none;
        }
        .dropzone:hover, .dropzone.dragover {
            border-color: var(--accent-cyan); background: rgba(0,242,254,0.06);
            box-shadow: 0 0 20px rgba(0,242,254,0.2);
        }

        /* ── BUTTONS ── */
        .btn {
            display: flex; justify-content: center; align-items: center; gap: 6px;
            width: 100%; padding: 11px 14px; margin-top: 10px;
            border-radius: 5px; font-size: 11px; font-weight: bold;
            text-transform: uppercase; letter-spacing: 1px; cursor: pointer;
            transition: all 0.2s; text-align: center; border: none; text-decoration: none;
        }
        .btn-cyan  { background: #0284c7; color: white; border: 1px solid #38bdf8; }
        .btn-cyan:hover  { background: #0369a1; box-shadow: 0 0 15px rgba(56,189,248,0.4); }
        .btn-green { background: #059669; color: white; border: 1px solid #10b981; }
        .btn-green:hover { background: #047857; box-shadow: 0 0 15px rgba(16,185,129,0.4); }
        .btn-purple { background: #7c3aed; color: white; border: 1px solid #a78bfa; }
        .btn-purple:hover { background: #6d28d9; box-shadow: 0 0 15px rgba(167,139,250,0.4); }
        .btn-red { background: #dc2626; color: white; border: 1px solid #ef4444; }
        .btn-red:hover { background: #b91c1c; box-shadow: 0 0 15px rgba(239,68,68,0.4); }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-main); }
        .btn-outline:hover { border-color: var(--accent-cyan); color: var(--accent-cyan); background: rgba(0,242,254,0.05); }
        .btn-panic { background: rgba(255,0,85,0.1); border: 1px solid var(--accent-red); color: var(--accent-red); }
        .btn-panic:hover { background: var(--accent-red); color: white; }
        .btn-copy-sm {
            background: #152238; border: 1px solid #233554; color: var(--accent-cyan);
            padding: 4px 8px; border-radius: 3px; font-size: 9px; cursor: pointer; font-weight: bold;
            transition: 0.2s;
        }
        .btn-copy-sm:hover { background: #1e3a5f; color: white; }

        /* ── KPI ROW ── */
        .kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
        .kpi-card {
            background: #0d1726; border: 1px solid var(--border);
            border-radius: 6px; padding: 14px;
        }
        .kpi-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .kpi-val { font-size: 26px; font-weight: bold; color: var(--text-main); margin-top: 5px; }

        /* ── RAG RISK GAUGE ── */
        .risk-gauge-wrap {
            margin-bottom: 20px; padding: 16px 18px;
            background: #0d1726; border: 1px solid var(--border); border-radius: 8px;
        }
        .risk-gauge-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .risk-gauge-title { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .risk-gauge-score { font-size: 28px; font-weight: 900; }
        .risk-bar-track { background: #1e293b; border-radius: 6px; height: 14px; overflow: hidden; position: relative; }
        .risk-bar-fill {
            height: 100%; border-radius: 6px;
            transition: width 0.8s cubic-bezier(0.34, 1.56, 0.64, 1);
            background: linear-gradient(90deg, #10b981 0%, #f59e0b 50%, #ef4444 100%);
        }
        .risk-bar-indicator {
            position: absolute; top: 0; height: 100%; width: 3px;
            background: white; border-radius: 2px; box-shadow: 0 0 8px rgba(255,255,255,0.6);
            transition: left 0.8s cubic-bezier(0.34, 1.56, 0.64, 1);
        }
        .risk-breakdown {
            display: flex; gap: 12px; margin-top: 10px; font-size: 10px; flex-wrap: wrap;
        }
        .risk-breakdown-item { color: var(--text-muted); }
        .rb-crit { color: var(--accent-red); font-weight: bold; }
        .rb-high { color: var(--accent-orange); font-weight: bold; }
        .rb-med  { color: #facc15; font-weight: bold; }

        /* ── ENTROPY SECTION ── */
        .entropy-wrap { 
            display: flex; gap: 8px; margin-bottom: 8px; padding: 10px 12px;
            background: #09101b; border: 1px solid var(--border); border-radius: 6px;
        }
        .entropy-bar-track { flex: 1; background: #1e293b; border-radius: 4px; height: 8px; position: relative; margin-top: 4px; }
        .entropy-bar-fill { height: 100%; border-radius: 4px; transition: width 0.6s ease; }
        .entropy-badge { 
            font-size: 9px; padding: 2px 7px; border-radius: 3px; font-weight: bold;
            display: inline-block; margin-top: 3px; letter-spacing: 0.3px;
        }

        /* ── MITRE MATRIX ── */
        .mitre-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; }
        .mitre-item {
            background: #0c1524; border: 1px solid var(--border); border-radius: 4px;
            padding: 10px 8px; text-align: center;
        }
        .mitre-count { font-size: 16px; font-weight: bold; color: var(--accent-cyan); }
        .mitre-name { font-size: 9px; color: var(--text-muted); text-transform: uppercase; margin-top: 3px; line-height: 1.2; }

        /* ── CHARTS ROW ── */
        .charts-row { display: grid; grid-template-columns: 270px 1fr; gap: 15px; margin-bottom: 20px; }
        .chart-box {
            background: #0c1524; border: 1px solid var(--border); border-radius: 6px;
            padding: 12px; height: 195px; position: relative;
        }

        /* ── ATTACK GRAPH ── */
        #attackGraphCanvas {
            width: 100%; height: 360px; background: #060e1c;
            border-radius: 6px; border: 1px solid var(--border); position: relative;
            overflow: hidden;
        }
        #attackGraphCanvas canvas { width: 100% !important; height: 100% !important; }
        .graph-legend { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 10px; font-size: 10px; color: var(--text-muted); }
        .graph-legend-item { display: flex; align-items: center; gap: 5px; }
        .graph-legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
        .graph-tooltip {
            position: absolute; background: #0d1726; border: 1px solid var(--accent-cyan);
            color: var(--text-main); padding: 8px 12px; border-radius: 5px; font-size: 10px;
            pointer-events: none; z-index: 50; max-width: 220px; box-shadow: 0 4px 16px rgba(0,0,0,0.7);
            display: none;
        }

        /* ── IOC FILTER BAR ── */
        .ioc-filter-bar { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
        .filter-btn {
            background: #0d1726; border: 1px solid var(--border); color: var(--text-muted);
            padding: 6px 12px; border-radius: 20px; font-size: 10px; cursor: pointer;
            transition: 0.2s; font-weight: bold;
        }
        .filter-btn:hover { border-color: var(--accent-cyan); color: var(--text-main); }
        .filter-btn.active { background: rgba(0,242,254,0.1); border-color: var(--accent-cyan); color: var(--accent-cyan); }
        .filter-btn.f-crit.active { background: rgba(255,0,85,0.15); border-color: var(--accent-red); color: var(--accent-red); }
        .filter-btn.f-high.active { background: rgba(255,153,0,0.15); border-color: var(--accent-orange); color: var(--accent-orange); }
        .filter-btn.f-med.active  { background: rgba(250,204,21,0.15); border-color: #facc15; color: #facc15; }

        /* ── SEARCH BOX ── */
        .search-box {
            width: 100%; background: #09101b; border: 1px solid var(--border);
            color: var(--text-main); padding: 10px 12px; border-radius: 4px;
            font-size: 12px; margin-bottom: 12px; outline: none; transition: 0.2s;
        }
        .search-box:focus { border-color: var(--accent-cyan); box-shadow: 0 0 12px rgba(0,242,254,0.2); }

        /* ── TABLE ── */
        .table-responsive { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; margin-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; font-size: 11px; }
        th { text-align: left; padding: 10px 8px; color: var(--text-muted); border-bottom: 1px solid var(--border); font-size: 10px; text-transform: uppercase; }
        td { padding: 9px 8px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }
        tr:hover td { background: rgba(0,242,254,0.02); }

        /* ── MOBILE IOC CARDS ── */
        .ioc-cards-container { display: none; }
        .ioc-card-item {
            background: #0d1726; border: 1px solid var(--border);
            border-left: 4px solid var(--accent-cyan); border-radius: 6px;
            padding: 12px; margin-bottom: 10px;
        }
        .ioc-card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
        .ioc-badge-sev { font-size: 10px; font-weight: 900; padding: 2px 6px; border-radius: 3px; }
        .ioc-card-title { font-size: 13px; font-weight: bold; color: var(--text-main); margin-bottom: 4px; }
        .ioc-card-desc { font-size: 11px; color: var(--text-muted); line-height: 1.4; margin-bottom: 8px; }
        .ioc-card-meta {
            font-size: 10px; color: var(--text-muted); background: #060a12; padding: 6px 8px;
            border-radius: 4px; margin-bottom: 8px; border: 1px solid #16263d;
        }

        /* ── BLOCKLIST SECTION ── */
        .blocklist-tabs { display: flex; gap: 4px; margin-bottom: 12px; flex-wrap: wrap; }
        .bl-tab {
            background: #0d1726; border: 1px solid var(--border); color: var(--text-muted);
            padding: 5px 12px; border-radius: 4px; font-size: 10px; cursor: pointer;
            transition: 0.2s; font-weight: bold;
        }
        .bl-tab.active { border-color: var(--accent-cyan); color: var(--accent-cyan); background: rgba(0,242,254,0.06); }
        .bl-code {
            background: #060a12; border: 1px solid #1e293b; border-radius: 4px;
            padding: 12px; font-size: 10px; line-height: 1.6; color: #a3e635;
            overflow-x: auto; max-height: 200px; overflow-y: auto;
            -webkit-overflow-scrolling: touch; white-space: pre;
        }

        /* ── PLAYBOOK CARD ── */
        .playbook-step-card {
            background: #09101b; border: 1px solid var(--border); border-radius: 6px;
            padding: 10px 14px; margin-bottom: 8px; border-left: 3px solid #7c3aed;
        }
        .playbook-step-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
        .pb-prio { font-size: 9px; font-weight: 900; padding: 2px 6px; border-radius: 3px; }
        .pb-crit { background: rgba(255,0,85,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .pb-high { background: rgba(255,153,0,0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
        .pb-std  { background: rgba(56,189,248,0.2); color: #38bdf8; border: 1px solid #38bdf8; }

        /* ── TIMELINE ── */
        .timeline-box { max-height: 250px; overflow-y: auto; padding-right: 5px; -webkit-overflow-scrolling: touch; }
        .timeline-item {
            padding: 10px 12px; border-left: 2px solid var(--accent-cyan);
            background: rgba(255,255,255,0.02); margin-bottom: 8px; border-radius: 0 4px 4px 0;
        }

        /* ── MODALS ── */
        .modal-overlay {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.88); backdrop-filter: blur(6px); z-index: 1000;
            justify-content: center; align-items: center; padding: 12px;
        }
        .modal-content {
            background: #0d1726; border: 1px solid var(--accent-cyan); border-radius: 8px;
            width: 840px; max-width: 95vw; max-height: 88vh; padding: 20px;
            box-shadow: 0 0 40px rgba(0,242,254,0.3); overflow-y: auto; display: flex; flex-direction: column;
        }
        .hex-dump {
            background: #05080e; color: #a3e635; padding: 12px; border-radius: 4px;
            font-family: monospace; font-size: 11px; line-height: 1.4; white-space: pre;
            overflow-x: auto; border: 1px solid #1e293b; max-height: 300px;
            -webkit-overflow-scrolling: touch;
        }

        /* ── KEYBOARD SHORTCUT BADGE ── */
        .shortcut-footer {
            margin-top: 25px; padding: 10px; background: #080d17; border: 1px solid var(--border);
            border-radius: 6px; text-align: center; font-size: 10px; color: var(--text-muted);
        }
        .kbd-key {
            background: #1e293b; color: var(--accent-cyan); padding: 2px 6px; border-radius: 3px;
            border: 1px solid #334155; font-weight: bold; margin: 0 2px;
        }

        /* ── RESPONSIVE ── */
        @media (max-width: 1024px) {
            .main-grid { grid-template-columns: 1fr; gap: 16px; }
            .charts-row { grid-template-columns: 1fr; gap: 16px; }
            .chart-box { height: 210px; }
        }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .top-hud { flex-direction: column; align-items: flex-start; gap: 12px; padding: 12px 14px; }
            .hud-actions { width: 100%; }
            .btn-nav-home { flex: 1; text-align: center; }
            .mobile-jump-bar { display: flex; }
            .kpi-row { grid-template-columns: repeat(2, 1fr); gap: 10px; }
            .kpi-val { font-size: 22px; }
            .mitre-grid { grid-template-columns: repeat(3, 1fr); gap: 6px; }
            .mitre-count { font-size: 13px; }
            .mitre-name { font-size: 8px; }
            .ioc-table-wrapper { display: none !important; }
            .ioc-cards-container { display: flex; flex-direction: column; }
            .modal-content { width: 96vw; max-height: 90vh; padding: 14px; }
            .hex-dump { font-size: 9.5px; max-height: 220px; }
            .btn { padding: 13px 14px; font-size: 12px; }
        }
    </style>
</head>
<body>
    <!-- Top HUD -->
    <div class="top-hud">
        <div class="logo-box">
            <div class="radar-pulse"></div>
            <div>
                <div class="logo-title">SPECTRA // TACTICAL COMMAND HUD</div>
                <div style="font-size:10px; color:var(--text-muted); letter-spacing:0.5px;">AIR-GAPPED TRIAGE SUITE &bull; ZERO CLOUD &bull; SESSION SECURE</div>
            </div>
        </div>
        <div class="hud-actions">
            <div id="perfBadge" class="perf-badge" style="display:none;">⚡ 0.00 ms (0.0 MB/s)</div>
            <button class="btn-nav-home" onclick="openBriefingModal()" style="cursor:pointer; border-color:#38bdf8; color:#38bdf8; font-weight:bold;">📢 WAR-ROOM BRIEFING</button>
            <button class="btn-nav-home" onclick="openDeployModal()" style="cursor:pointer; border-color:var(--accent-cyan); color:var(--accent-cyan); font-weight:bold;">⚡ QUICK DEPLOY</button>
            <a href="/" class="btn-nav-home">🏠 BERANDA</a>
            <div class="status-badge">🛡️ AIR-GAPPED READY</div>
        </div>
    </div>

    <!-- Mobile Jump Bar -->
    <div class="mobile-jump-bar" id="mobileJumpBar">
        <a href="#sec-triage"    class="jump-pill">📂 Triase</a>
        <a href="#sec-metrics"   class="jump-pill">📊 Metrik</a>
        <a href="#sec-charts"    class="jump-pill">📈 Visual</a>
        <a href="#sec-graph"     class="jump-pill">🕸️ Graf</a>
        <a href="#sec-ioc"       class="jump-pill">🎯 IOC <span id="iocPillCount" class="pill-count">0</span></a>
        <a href="#sec-playbook"  class="jump-pill">📋 Playbook</a>
        <a href="#sec-entropy"   class="jump-pill">🔬 Entropi</a>
        <a href="#sec-blocklist" class="jump-pill">🛡️ Blocklist</a>
    </div>

    <div class="main-grid">
        <!-- ════ SIDEBAR CONTROLS ════ -->
        <div>
            <div class="panel" id="sec-triage">
                <div class="panel-header">1. Artifact Injection</div>
                <div class="dropzone" id="dropzone" onclick="document.getElementById('fileInput').click()">
                    <div style="font-size:28px; margin-bottom:6px;">📂</div>
                    <div style="font-weight:bold; font-size:13px; color:var(--accent-cyan);">Pilih / Lepas Berkas PCAP</div>
                    <div style="font-size:10px; color:var(--text-muted); margin-top:4px;">📱 Ketuk untuk pilih &bull; 💻 Drag & drop di desktop</div>
                    <div style="font-size:9px; color:#475569; margin-top:2px;">Format: .pcap, .pcapng (Maks 150MB)</div>
                    <input type="file" id="fileInput" style="display:none;" accept=".pcap,.pcapng" onchange="uploadPCAP()">
                </div>
                <div id="fileInfo" style="margin-top:10px; font-size:11px; color:var(--accent-cyan); word-break:break-all; min-height:16px;"></div>
                
                <button class="btn btn-green" id="btnLoadDemo" onclick="loadSampleAttack()">🧪 Muat Contoh Serangan (1-Click Demo)</button>
                <button class="btn btn-red" id="btnLiveSniff" onclick="triggerLiveSniff()">🔴 Live Sniffing (10s)</button>

                <div class="panel-header" style="margin-top:25px;">Engine & Rules</div>
                <button class="btn btn-outline" onclick="openRuleModal()">⚙️ Custom Rule Inspector (<span id="ruleCountBadge">8 Rules</span>)</button>

                <div class="panel-header" style="margin-top:25px;">Tactical Output</div>
                <button class="btn btn-outline" onclick="openBriefingModal()" style="border-color:#38bdf8; color:#38bdf8; font-weight:bold;">📢 Executive War-Room Briefing</button>
                <button class="btn btn-cyan" onclick="window.open('/api/export/dossier','_blank')">📄 1-Click Incident Dossier (PDF)</button>
                <button class="btn btn-outline" onclick="window.location.href='/api/export/json'">💾 Export JSON Terstruktur</button>
                <button class="btn btn-purple" onclick="window.location.href='/api/export/stix'">⚙️ Export STIX 2.1 Bundle (CTI)</button>

                <div class="panel-header" style="margin-top:25px; color:var(--accent-red);">Session Cleanse</div>
                <button class="btn btn-panic" onclick="clearSession()">🧹 Bersihkan Memori & Bukti Sesi</button>
            </div>

            <!-- Forensic Integrity -->
            <div class="panel">
                <div class="panel-header">
                    <span>Forensic Integrity</span>
                    <button class="btn-copy-sm" onclick="copySHA256()">📋 Salin</button>
                </div>
                <div style="font-size:10px; color:var(--text-muted); line-height:1.6;">
                    <div><strong>SHA-256 Checksum:</strong></div>
                    <div id="sha256Display" style="color:var(--accent-cyan); word-break:break-all; font-family:monospace; background:#060a12; padding:6px; border-radius:4px; border:1px solid #16263d; margin-top:4px;">Menunggu artefak...</div>
                    <div style="margin-top:8px;"><strong>Status:</strong> <span style="color:var(--accent-green);">Memory-Only / No DB Persistence</span></div>
                </div>
            </div>

            <!-- Entropy Summary -->
            <div class="panel" id="sec-entropy">
                <div class="panel-header">🔬 Shannon Entropy Analysis</div>
                <div style="font-size:10px; color:var(--text-muted); margin-bottom:10px;">Skor Entropi Shannon (0.0–8.0). Nilai &gt;7.2 mengindikasikan payload terenkripsi, ransomware, atau C2 obfuscation.</div>
                <div style="margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="font-size:10px; color:var(--text-muted);">MAX PAYLOAD ENTROPY</span>
                        <span id="maxEntropyVal" style="font-size:12px; font-weight:bold; color:var(--accent-cyan);">–</span>
                    </div>
                    <div class="entropy-bar-track">
                        <div id="maxEntropyBar" class="entropy-bar-fill" style="width:0%; background:var(--accent-cyan);"></div>
                    </div>
                    <div id="maxEntropyLabel" style="font-size:9px; color:var(--text-muted); margin-top:4px;"></div>
                </div>
                <div>
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="font-size:10px; color:var(--text-muted);">AVG PAYLOAD ENTROPY</span>
                        <span id="avgEntropyVal" style="font-size:12px; font-weight:bold; color:var(--accent-cyan);">–</span>
                    </div>
                    <div class="entropy-bar-track">
                        <div id="avgEntropyBar" class="entropy-bar-fill" style="width:0%; background:#0284c7;"></div>
                    </div>
                </div>
            </div>

            <!-- Tactical Terminal & One-Liner Deploy Panel -->
            <div class="panel">
                <div class="panel-header" style="display:flex; justify-content:space-between; align-items:center;">
                    <span>⚡ Quick Terminal Deploy</span>
                    <button class="btn-copy-sm" onclick="openDeployModal()" title="Buka Detail Modal Quick Deploy">🔍</button>
                </div>
                <div style="background:rgba(0,255,136,0.08); border:1px solid var(--accent-green); border-radius:4px; padding:6px 8px; font-size:9px; color:var(--accent-green); margin-bottom:10px; line-height:1.4;">
                    🛡️ AIR-GAPPED &amp; OFFLINE READY: Zero Runtime, Zero C-Libs, Single Static Binary Execution.
                </div>
                <div style="font-size:10px; color:var(--text-muted); line-height:1.5;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                        <span style="color:var(--accent-green); font-weight:bold;">🐧 Linux / macOS:</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('linux')">📋</button>
                    </div>
                    <div class="mono" style="background:#060a12; padding:6px 8px; border-radius:4px; color:#a3e635; font-size:8.5px; word-break:break-all; margin-bottom:8px; border:1px solid #1e293b;" id="sb-cmd-linux">curl -sSL <span class="dyn-host">http://127.0.0.1:8888</span>/install.sh | bash</div>

                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                        <span style="color:var(--accent-cyan); font-weight:bold;">🪟 Windows PowerShell:</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('win')">📋</button>
                    </div>
                    <div class="mono" style="background:#060a12; padding:6px 8px; border-radius:4px; color:#38bdf8; font-size:8.5px; word-break:break-all; margin-bottom:8px; border:1px solid #1e293b;" id="sb-cmd-win">iwr -useb <span class="dyn-host">http://127.0.0.1:8888</span>/install.ps1 | iex</div>

                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                        <span style="color:var(--accent-orange); font-weight:bold;">📱 Termux / Android:</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('termux')">📋</button>
                    </div>
                    <div class="mono" style="background:#060a12; padding:6px 8px; border-radius:4px; color:#f59e0b; font-size:8.5px; word-break:break-all; margin-bottom:12px; border:1px solid #1e293b;" id="sb-cmd-termux">curl -sSL <span class="dyn-host">http://127.0.0.1:8888</span>/install.sh | sh</div>

                    <div style="border-top:1px solid #1e293b; padding-top:8px; margin-top:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:3px;">
                            <span style="color:var(--text-main); font-weight:bold;">Direct SSH Pipe:</span>
                            <button class="btn-copy-sm" onclick="copyTextToClipboard('ssh -p 2222 spectra@127.0.0.1 < file.pcap','Disalin!')">📋</button>
                        </div>
                        <div class="mono" style="background:#060a12; padding:6px 8px; border-radius:4px; color:#cbd5e1; font-size:8.5px; word-break:break-all; border:1px solid #1e293b;">ssh -p 2222 spectra@127.0.0.1 &lt; file.pcap</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ════ MAIN ANALYTICS ════ -->
        <div>
            <!-- KPI Row -->
            <div class="kpi-row" id="sec-metrics">
                <div class="kpi-card" style="border-left:3px solid var(--accent-green);" id="threatCard">
                    <div class="kpi-label">THREAT RISK SCORE</div>
                    <div class="kpi-val" id="threatScoreDisplay" style="color:var(--accent-green); font-size:30px;">--</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">TOTAL PACKETS</div>
                    <div class="kpi-val" id="totalPacketsDisplay">0</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">TRIAGE SPEED</div>
                    <div class="kpi-val" id="triageSpeedDisplay" style="color:var(--accent-cyan);">0.00 ms</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">IOC DETECTED</div>
                    <div class="kpi-val" id="iocCountDisplay" style="color:var(--accent-red);">0</div>
                </div>
            </div>

            <!-- RAG Risk Gauge -->
            <div class="risk-gauge-wrap">
                <div class="risk-gauge-header">
                    <span class="risk-gauge-title">Threat Risk Index (RAG Score)</span>
                    <span class="risk-gauge-score" id="ragScoreDisplay" style="color:var(--accent-green);">0 / 100</span>
                </div>
                <div class="risk-bar-track">
                    <div class="risk-bar-fill" id="ragBarFill" style="width:0%;"></div>
                    <div class="risk-bar-indicator" id="ragBarIndicator" style="left:0%;"></div>
                </div>
                <div class="risk-breakdown" id="ragBreakdown">
                    <span class="risk-breakdown-item">Load a PCAP to see risk breakdown</span>
                </div>
            </div>

            <!-- MITRE ATT&CK Matrix -->
            <div class="panel" style="padding:14px 16px; margin-bottom:20px;">
                <div class="panel-header" style="margin-bottom:10px; padding-bottom:6px;">MITRE ATT&CK Tactic Breakdown</div>
                <div class="mitre-grid">
                    <div class="mitre-item"><div class="mitre-count" id="mitreRecon">0</div><div class="mitre-name">Reconnaissance</div></div>
                    <div class="mitre-item"><div class="mitre-count" id="mitreAccess">0</div><div class="mitre-name">Initial Access</div></div>
                    <div class="mitre-item"><div class="mitre-count" id="mitreExec">0</div><div class="mitre-name">Execution</div></div>
                    <div class="mitre-item"><div class="mitre-count" id="mitreCred">0</div><div class="mitre-name">Credential Acc.</div></div>
                    <div class="mitre-item"><div class="mitre-count" id="mitreC2">0</div><div class="mitre-name">Command &amp; C2</div></div>
                    <div class="mitre-item"><div class="mitre-count" id="mitreExfil">0</div><div class="mitre-name">Exfiltration</div></div>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="charts-row" id="sec-charts">
                <div class="chart-box">
                    <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px;">Protocol Volume</div>
                    <canvas id="protoChart"></canvas>
                </div>
                <div class="chart-box">
                    <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase; margin-bottom:6px;">Top Host Flows</div>
                    <canvas id="flowsChart"></canvas>
                </div>
            </div>

            <!-- Attack Graph -->
            <div class="panel" id="sec-graph">
                <div class="panel-header">
                    <span>🕸️ Interactive Attack Relation Graph</span>
                    <span id="graphNodeCount" style="font-size:10px; color:var(--text-muted);">0 nodes</span>
                </div>
                <div style="position:relative;">
                    <div id="attackGraphCanvas" style="width:100%; height:340px; background:#060e1c; border-radius:6px; border:1px solid var(--border); overflow:hidden;">
                        <canvas id="graphCanvas" style="width:100%; height:100%;"></canvas>
                    </div>
                    <div class="graph-tooltip" id="graphTooltip"></div>
                </div>
                <div class="graph-legend">
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#ff0055;"></div><span>🔴 Attacker IP (IOC Sumber)</span></div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#ff9900;"></div><span>🟠 Victim / Target IP</span></div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#00f2fe;"></div><span>🔵 Normal Traffic</span></div>
                    <div class="graph-legend-item"><div class="graph-legend-dot" style="background:#ff005588; width:22px; height:4px; border-radius:2px;"></div><span>— IOC Edge (Merah)</span></div>
                </div>
            </div>

            <!-- IOC Findings -->
            <div class="panel" id="sec-ioc">
                <div class="panel-header">
                    <span>2. Identified Indicators of Compromise (IOC)</span>
                    <span id="iocCountBadge" style="font-size:10px; color:var(--text-muted);">0 findings</span>
                </div>

                <!-- Interactive Filter Bar -->
                <div class="ioc-filter-bar">
                    <button class="filter-btn active" onclick="filterIOCSeverity('ALL', this)">Semua (<span id="countFilterAll">0</span>)</button>
                    <button class="filter-btn f-crit" onclick="filterIOCSeverity('CRITICAL', this)">🔴 Critical (<span id="countFilterCrit">0</span>)</button>
                    <button class="filter-btn f-high" onclick="filterIOCSeverity('HIGH', this)">🟠 High (<span id="countFilterHigh">0</span>)</button>
                    <button class="filter-btn f-med"  onclick="filterIOCSeverity('MEDIUM', this)">🟡 Medium (<span id="countFilterMed">0</span>)</button>
                </div>

                <input type="text" class="search-box" id="iocSearch" placeholder="🔍 Cari IOC, IP, atau teknik MITRE..." onkeyup="filterIOC()">

                <!-- Desktop Table -->
                <div class="ioc-table-wrapper table-responsive">
                    <table>
                        <thead><tr>
                            <th>Severity</th>
                            <th>Threat Signature</th>
                            <th>Flow / Target</th>
                            <th>Entropy</th>
                            <th>MITRE ATT&CK</th>
                            <th>Action</th>
                        </tr></thead>
                        <tbody id="iocTableBody">
                            <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Belum ada artefak. Unggah PCAP atau klik Demo.</td></tr>
                        </tbody>
                    </table>
                </div>

                <!-- Mobile Cards -->
                <div class="ioc-cards-container" id="iocCardsContainer">
                    <div style="text-align:center; color:var(--text-muted); font-size:11px; padding:15px 0;">Belum ada artefak. Unggah PCAP atau klik Demo.</div>
                </div>
            </div>

            <!-- Tactical Incident Playbook Panel -->
            <div class="panel" id="sec-playbook">
                <div class="panel-header">
                    <span>📋 3. Tactical Incident Containment Playbook</span>
                    <span id="playbookStepCount" style="font-size:10px; color:var(--text-muted);">0 action steps</span>
                </div>
                <div id="playbookEmpty" style="font-size:11px; color:var(--text-muted);">Playbook mitigasi insiden otomatis akan disusun setelah artefak dianalisis.</div>
                <div id="playbookContent" style="display:none;">
                    <div id="playbookSummary" style="font-size:11px; color:var(--accent-cyan); margin-bottom:12px; font-weight:bold;"></div>
                    <div id="playbookStepsList" style="display:flex; flex-direction:column; gap:8px;"></div>
                    <div style="display:flex; gap:8px; margin-top:14px; flex-wrap:wrap;">
                        <button class="btn btn-purple" style="margin-top:0; flex:1;" onclick="copyPlaybookPlan()">📋 Copy Playbook Execution Plan</button>
                        <button class="btn btn-outline" style="margin-top:0; flex:1;" onclick="downloadPlaybook()">⬇️ Unduh Playbook (TXT)</button>
                    </div>
                </div>
            </div>

            <!-- Blocklist Generator -->
            <div class="panel" id="sec-blocklist">
                <div class="panel-header">
                    <span>🛡️ 4. Blocklist &amp; Mitigation Rules Generator</span>
                    <span id="blocklistIPCount" style="font-size:10px; color:var(--text-muted);">0 attacker IPs</span>
                </div>
                <div id="blocklistEmpty" style="font-size:11px; color:var(--text-muted);">Analisis PCAP terlebih dahulu untuk menghasilkan rules mitigasi otomatis.</div>
                <div id="blocklistContent" style="display:none;">
                    <div class="blocklist-tabs">
                        <button class="bl-tab active" onclick="switchBLTab('iptables',this)">🐧 iptables</button>
                        <button class="bl-tab" onclick="switchBLTab('windows',this)">🪟 Windows PS</button>
                        <button class="bl-tab" onclick="switchBLTab('suricata',this)">🔍 Suricata/Snort</button>
                        <button class="bl-tab" onclick="switchBLTab('plaintext',this)">📋 Plain IP List</button>
                    </div>
                    <div class="bl-code" id="blCodeDisplay"></div>
                    <div style="display:flex; gap:8px; margin-top:10px; flex-wrap:wrap;">
                        <button class="btn btn-outline" style="margin-top:0; flex:1;" onclick="copyBLRules()">📋 Salin Rules</button>
                        <button class="btn btn-outline" style="margin-top:0; flex:1;" onclick="downloadBLRules()">⬇️ Unduh Script</button>
                    </div>
                </div>
            </div>

            <!-- Attack Killchain Timeline -->
            <div class="panel" id="sec-timeline">
                <div class="panel-header">5. Automated Attack Killchain Timeline</div>
                <div class="timeline-box" id="timelineContainer">
                    <div style="font-size:11px; color:var(--text-muted);">Alur serangan akan tampil setelah analisis.</div>
                </div>
            </div>

            <!-- Keyboard Shortcut Helper Footer -->
            <div class="shortcut-footer">
                ⚡ <strong>Tactical Keyboard Shortcuts:</strong> 
                <span class="kbd-key">Ctrl+U</span> Buka Dropzone &bull; 
                <span class="kbd-key">Ctrl+D</span> 1-Click Demo &bull; 
                <span class="kbd-key">Alt+W</span> Forensic Wipe
            </div>
        </div>
    </div>

    <!-- Modal Packet Inspector -->
    <div class="modal-overlay" id="inspectorModal" onclick="handleModalBackdrop(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:10px;">
                <div style="font-weight:bold; color:var(--accent-cyan); font-size:13px;" id="modalTitle">PACKET RAW EVIDENCE INSPECTOR</div>
                <button onclick="closeModal()" style="background:#1e293b; border:1px solid #334155; color:white; width:28px; height:28px; border-radius:4px; font-size:14px; cursor:pointer; display:flex; align-items:center; justify-content:center;">✕</button>
            </div>
            <div style="font-size:11px; margin-bottom:10px; color:var(--text-muted); line-height:1.4;" id="modalSubtitle"></div>
            <div id="modalEntropyBadge" style="margin-bottom:10px;"></div>
            <div class="hex-dump" id="modalHexDump"></div>
            <div style="display:flex; gap:10px; margin-top:15px;">
                <button class="btn btn-outline" style="margin-top:0; flex:1;" onclick="copyHexDump()">📋 Salin Bukti Forensik</button>
                <button class="btn btn-outline" style="margin-top:0; width:90px;" onclick="closeModal()">✕ Tutup</button>
            </div>
        </div>
    </div>

    <!-- Modal Custom Rule Inspector -->
    <div class="modal-overlay" id="ruleModal" onclick="handleRuleModalBackdrop(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:10px;">
                <div style="font-weight:bold; color:var(--accent-cyan); font-size:13px;">⚙️ ACTIVE DETECTION RULES ENGINE (YAML/JSON)</div>
                <button onclick="closeRuleModal()" style="background:#1e293b; border:1px solid #334155; color:white; width:28px; height:28px; border-radius:4px; font-size:14px; cursor:pointer; display:flex; align-items:center; justify-content:center;">✕</button>
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:12px;">
                SPECTRA mengevaluasi signature bawaan dan aturan eksternal dari <code>rules.json</code> secara in-memory.
            </div>
            <div class="table-responsive" style="max-height:360px; overflow-y:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th>Name</th>
                            <th>Severity</th>
                            <th>Protocol</th>
                            <th>Match Type</th>
                            <th>Pattern</th>
                            <th>MITRE Ref</th>
                        </tr>
                    </thead>
                    <tbody id="rulesTableBody">
                        <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Memuat aturan deteksi...</td></tr>
                    </tbody>
                </table>
            </div>
            <div style="display:flex; justify-content:flex-end; margin-top:14px;">
                <button class="btn btn-outline" style="width:110px; margin-top:0;" onclick="closeRuleModal()">✕ Tutup</button>
            </div>
        </div>
    </div>

    <!-- Modal Tactical Terminal Quick Deploy -->
    <div class="modal-overlay" id="deployModal" onclick="handleDeployModalBackdrop(event)">
        <div class="modal-content" onclick="event.stopPropagation()" style="width:780px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; border-bottom:1px solid var(--border); padding-bottom:10px;">
                <div style="font-weight:bold; color:var(--accent-cyan); font-size:14px;">⚡ TACTICAL TERMINAL QUICK DEPLOY (ONE-LINER PIPELINE)</div>
                <button onclick="closeDeployModal()" style="background:#1e293b; border:1px solid #334155; color:white; width:28px; height:28px; border-radius:4px; font-size:14px; cursor:pointer; display:flex; align-items:center; justify-content:center;">✕</button>
            </div>
            
            <div style="background:rgba(0,255,136,0.1); border:1px solid var(--accent-green); border-radius:6px; padding:10px 14px; margin-bottom:16px; font-size:11px; color:var(--accent-green); font-weight:bold; display:flex; align-items:center; gap:8px;">
                🛡️ AIR-GAPPED &amp; OFFLINE READY: Zero Runtime, Zero C-Libs, Single Static Binary Execution.
            </div>

            <div style="font-size:12px; color:var(--text-muted); margin-bottom:16px;">
                SPECTRA adalah biner mandiri Pure Go (CGo Disabled) yang dapat langsung diunduh dan dieksekusi di terminal target tanpa perlu menginstal compiler, Python, Node, Npcap, atau dependensi C eksternal:
            </div>

            <div style="display:flex; flex-direction:column; gap:14px;">
                <!-- Linux & macOS -->
                <div style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span style="color:var(--accent-green); font-weight:bold; font-size:12px;">🐧 Linux &amp; macOS (Intel / Apple Silicon / ARM64)</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('linux')" style="padding:4px 10px; font-size:11px;">📋 Salin</button>
                    </div>
                    <div class="mono" style="background:#000; padding:10px; border-radius:4px; color:#a3e635; font-size:11px; word-break:break-all; border:1px solid #1e293b;" id="modal-cmd-linux">curl -sSL <span class="dyn-host">http://127.0.0.1:8888</span>/install.sh | bash</div>
                    <div style="font-size:10px; color:#64748b; margin-top:4px;">* Otomatis mendeteksi arsitektur OS (x86_64, aarch64, Darwin M1/M2/M3), memberi izin chmod +x, dan meluncurkan biner.</div>
                </div>

                <!-- Windows PowerShell -->
                <div style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span style="color:var(--accent-cyan); font-weight:bold; font-size:12px;">🪟 Windows PowerShell (x86_64 / AMD64)</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('win')" style="padding:4px 10px; font-size:11px;">📋 Salin</button>
                    </div>
                    <div class="mono" style="background:#000; padding:10px; border-radius:4px; color:#38bdf8; font-size:11px; word-break:break-all; border:1px solid #1e293b;" id="modal-cmd-win">iwr -useb <span class="dyn-host">http://127.0.0.1:8888</span>/install.ps1 | iex</div>
                    <div style="font-size:10px; color:#64748b; margin-top:4px;">* Mengunduh spectra.exe mandiri, unblock file security Windows, dan langsung mengeksekusi di terminal PowerShell.</div>
                </div>

                <!-- Termux Android -->
                <div style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span style="color:var(--accent-orange); font-weight:bold; font-size:12px;">📱 Termux / Android / IoT Edge Devices</span>
                        <button class="btn-copy-sm" onclick="copyDeployCmd('termux')" style="padding:4px 10px; font-size:11px;">📋 Salin</button>
                    </div>
                    <div class="mono" style="background:#000; padding:10px; border-radius:4px; color:#f59e0b; font-size:11px; word-break:break-all; border:1px solid #1e293b;" id="modal-cmd-termux">curl -sSL <span class="dyn-host">http://127.0.0.1:8888</span>/install.sh | sh</div>
                    <div style="font-size:10px; color:#64748b; margin-top:4px;">* Cocok untuk inspeksi paket darurat di lapangan langsung dari smartphone atau perangkat edge.</div>
                </div>
            </div>

            <div style="display:flex; justify-content:flex-end; margin-top:16px;">
                <button class="btn btn-outline" style="width:110px; margin-top:0;" onclick="closeDeployModal()">✕ Tutup</button>
            </div>
        </div>
    </div>

    <!-- Modal Executive War-Room Briefing (Non-Teknis) -->
    <div class="modal-overlay" id="briefingModal" onclick="handleBriefingModalBackdrop(event)">
        <div class="modal-content" onclick="event.stopPropagation()" style="width:820px; max-width:95vw; background:#0b1320; border:1px solid #38bdf8; border-radius:8px; padding:22px; max-height:90vh; overflow-y:auto;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:16px;">
                <div>
                    <div style="font-weight:bold; color:#38bdf8; font-size:15px; letter-spacing:0.5px;">📢 EXECUTIVE WAR-ROOM CRISIS BRIEFING</div>
                    <div style="font-size:11px; color:var(--text-muted);">Ringkasan situasi insiden siber dalam narasi bahasa manusia untuk pimpinan &amp; orang awam</div>
                </div>
                <button onclick="closeBriefingModal()" style="background:#1e293b; border:1px solid #334155; color:white; width:28px; height:28px; border-radius:4px; font-size:14px; cursor:pointer; display:flex; align-items:center; justify-content:center;">✕</button>
            </div>

            <!-- Banner Status Krisis -->
            <div id="brBanner" style="background:#101c30; border:1px solid #38bdf8; border-left:5px solid #38bdf8; border-radius:6px; padding:14px; margin-bottom:14px;">
                <div id="brHeadline" style="font-size:14px; font-weight:bold; color:#f8fafc; margin-bottom:4px;">Menunggu artefak dianalisis...</div>
                <div style="font-size:11px; color:#94a3b8; display:flex; gap:16px; flex-wrap:wrap; margin-top:6px;">
                    <div><strong>Tingkat Bahaya:</strong> <span id="brSeverity" style="color:var(--accent-cyan); font-weight:bold;">--</span></div>
                    <div><strong>Dampak Bisnis:</strong> <span id="brImpact" style="color:#f59e0b; font-weight:bold;">--</span></div>
                </div>
            </div>

            <!-- 2 Kolom: Sasaran & Asal Penyerang -->
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:14px;">
                <div style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:10px 12px;">
                    <div style="font-size:10px; color:#94a3b8; text-transform:uppercase;">🎯 Sasaran / Server Terdampak</div>
                    <div id="brTarget" style="font-size:12px; font-weight:bold; color:#f1f5f9; margin-top:3px;">--</div>
                </div>
                <div style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:10px 12px;">
                    <div style="font-size:10px; color:#94a3b8; text-transform:uppercase;">🦹 Asal Host Penyerang</div>
                    <div id="brAttacker" style="font-size:12px; font-weight:bold; color:#ef4444; margin-top:3px;">--</div>
                </div>
            </div>

            <!-- Cerita Kejadian (Bahasa Manusia) -->
            <div style="margin-bottom:14px;">
                <div style="font-size:12px; font-weight:bold; color:#38bdf8; margin-bottom:6px;">
                    <span>📖 Apa yang Sebenarnya Terjadi? (Penjelasan Bahasa Manusia)</span>
                </div>
                <div id="brStory" style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px; font-size:11.5px; color:#cbd5e1; line-height:1.6; white-space:pre-wrap;">Belum ada artefak jaringan yang dianalisis. Silakan upload file PCAP terlebih dahulu.</div>
            </div>

            <!-- Status Kebocoran Data -->
            <div style="margin-bottom:14px;">
                <div style="font-size:12px; font-weight:bold; color:#f59e0b; margin-bottom:6px;">
                    <span>📊 Apakah Data Perusahaan Kita Bocor atau Rusak?</span>
                </div>
                <div id="brDataIntegrity" style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px; font-size:11.5px; color:#cbd5e1; line-height:1.5;">--</div>
            </div>

            <!-- Arahan Keputusan Pimpinan -->
            <div style="margin-bottom:18px;">
                <div style="font-size:12px; font-weight:bold; color:var(--accent-green); margin-bottom:6px;">
                    <span>🎯 Arahan Keputusan yang Harus Dikeluarkan Pimpinan:</span>
                </div>
                <div id="brDecisions" style="background:#060a12; border:1px solid #1e293b; border-radius:6px; padding:12px; font-size:11px; color:#cbd5e1; line-height:1.6;">--</div>
            </div>

            <!-- Actions Bar Modal -->
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; border-top:1px solid var(--border); padding-top:14px;">
                <div style="display:flex; gap:8px;">
                    <button class="btn btn-cyan" onclick="copyWhatsAppBriefing()" style="padding:9px 16px; font-size:11.5px; font-weight:bold;">
                        📋 Salin Format WhatsApp / Email Direksi
                    </button>
                    <button class="btn btn-outline" onclick="downloadBriefingTxt()" style="padding:9px 14px; font-size:11.5px;">
                        ⬇️ Unduh Teks (TXT)
                    </button>
                </div>
                <button class="btn btn-outline" style="width:90px; margin-top:0;" onclick="closeBriefingModal()">✕ Tutup</button>
            </div>
        </div>
    </div>

    <script>
    // ═══════════════════════════════════════════════════════
    //  SPECTRA Dashboard v2.0 — Full Feature Script
    // ═══════════════════════════════════════════════════════
    let currentAnalysis = null;
    let protoChartInstance = null;
    let flowsChartInstance = null;
    let currentBLFormat = 'iptables';
    let currentIOCSeverityFilter = 'ALL';

    // ── Keyboard Shortcuts (Ctrl+U, Ctrl+D, Alt+W) ──
    window.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'u') {
            e.preventDefault();
            document.getElementById('fileInput').click();
        }
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'd') {
            e.preventDefault();
            loadSampleAttack();
        }
        if ((e.altKey && e.key.toLowerCase() === 'w') || (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'w')) {
            e.preventDefault();
            clearSession();
        }
    });

    // ── Drag & Drop ──
    const dropzone = document.getElementById('dropzone');
    if (dropzone) {
        ['dragenter','dragover'].forEach(n => dropzone.addEventListener(n, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.add('dragover'); }, false));
        ['dragleave','drop'].forEach(n => dropzone.addEventListener(n, e => { e.preventDefault(); e.stopPropagation(); dropzone.classList.remove('dragover'); }, false));
        dropzone.addEventListener('drop', e => { const f = e.dataTransfer && e.dataTransfer.files; if (f && f.length) runAnalysisWithFile(f[0]); }, false);
    }

    async function uploadPCAP() {
        const input = document.getElementById('fileInput');
        if (input.files.length) runAnalysisWithFile(input.files[0]);
    }

    async function loadSampleAttack() {
        const btn = document.getElementById('btnLoadDemo');
        document.getElementById('fileInfo').innerText = 'Mengambil skenario serangan multi-vektor...';
        if (btn) btn.innerText = '⏳ Memuat...';
        try {
            const res = await fetch('/api/sample-pcap');
            if (!res.ok) throw new Error('Gagal mengunduh sampel');
            const blob = await res.blob();
            await runAnalysisWithFile(new File([blob], 'attack_sample_multivector.pcap'));
        } catch(err) { alert(err.message); }
        finally { if (btn) btn.innerText = '🧪 Muat Contoh Serangan (1-Click Demo)'; }
    }

    // ── Live Traffic Capture Sniffing ──
    async function triggerLiveSniff() {
        const btn = document.getElementById('btnLiveSniff');
        const fileInfo = document.getElementById('fileInfo');
        if (!confirm('Jalankan Live Sniffing selama 10 detik langsung dari kartu jaringan?')) return;

        btn.disabled = true;
        let countdown = 10;
        btn.innerText = '🔴 Sniffing (' + countdown + 's)...';
        fileInfo.innerText = 'Sedang mendengarkan paket raw socket lokal...';

        const timer = setInterval(() => {
            countdown--;
            if (countdown > 0) {
                btn.innerText = '🔴 Sniffing (' + countdown + 's)...';
            } else {
                clearInterval(timer);
                btn.innerText = '⏳ Menganalisis...';
            }
        }, 1000);

        try {
            const res = await fetch('/api/live-capture?duration=10s', { method: 'POST' });
            clearInterval(timer);
            if (!res.ok) {
                const errMsg = await res.text();
                throw new Error(errMsg);
            }
            const data = await res.json();
            currentAnalysis = data;
            fileInfo.innerText = '✓ Selesai Live Capture (' + (data.total_packets || 0) + ' paket ditangkap)';
            renderResults(data);
        } catch(err) {
            clearInterval(timer);
            fileInfo.innerText = '✗ Live Capture terhenti';
            alert('Live Capture Alert:\n' + err.message);
        } finally {
            btn.disabled = false;
            btn.innerText = '🔴 Live Sniffing (10s)';
        }
    }

    async function runAnalysisWithFile(file) {
        const info = document.getElementById('fileInfo');
        info.innerText = 'Menganalisis: ' + file.name + ' (' + (file.size/1024).toFixed(1) + ' KB)...';
        const fd = new FormData();
        fd.append('pcap_file', file);
        try {
            const res = await fetch('/api/analyze', { method: 'POST', body: fd });
            if (!res.ok) throw new Error(await res.text());
            const data = await res.json();
            currentAnalysis = data;
            info.innerText = '✓ Selesai: ' + file.name + ' (' + (file.size/1024).toFixed(1) + ' KB)';
            renderResults(data);
        } catch(err) {
            info.innerText = '✗ Gagal memproses berkas';
            alert('Triage error: ' + err.message);
        }
    }

    async function clearSession() {
        if (!confirm('Hapus seluruh temuan analisis dan bersihkan memori lokal?')) return;
        await fetch('/api/clear');
        currentAnalysis = null;
        document.getElementById('fileInfo').innerText = '';
        document.getElementById('threatScoreDisplay').innerText = '--';
        document.getElementById('threatScoreDisplay').style.color = 'var(--accent-green)';
        document.getElementById('threatCard').style.borderLeftColor = 'var(--accent-green)';
        document.getElementById('totalPacketsDisplay').innerText = '0';
        document.getElementById('triageSpeedDisplay').innerText = '0.00 ms';
        document.getElementById('iocCountDisplay').innerText = '0';
        document.getElementById('iocCountBadge').innerText = '0 findings';
        document.getElementById('sha256Display').innerText = 'Menunggu artefak...';
        ['mitreRecon','mitreAccess','mitreExec','mitreCred','mitreC2','mitreExfil'].forEach(id => document.getElementById(id).innerText = '0');
        document.getElementById('iocTableBody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Belum ada artefak.</td></tr>';
        document.getElementById('iocCardsContainer').innerHTML = '<div style="text-align:center; color:var(--text-muted); font-size:11px; padding:15px 0;">Belum ada artefak.</div>';
        document.getElementById('timelineContainer').innerHTML = '<div style="font-size:11px; color:var(--text-muted);">Alur serangan akan tampil setelah analisis.</div>';
        document.getElementById('blocklistEmpty').style.display = '';
        document.getElementById('blocklistContent').style.display = 'none';
        document.getElementById('blocklistIPCount').innerText = '0 attacker IPs';
        document.getElementById('playbookEmpty').style.display = '';
        document.getElementById('playbookContent').style.display = 'none';
        document.getElementById('playbookStepCount').innerText = '0 action steps';
        document.getElementById('iocPillCount').innerText = '0';
        document.getElementById('ragScoreDisplay').innerText = '0 / 100';
        document.getElementById('ragScoreDisplay').style.color = 'var(--accent-green)';
        document.getElementById('ragBarFill').style.width = '0%';
        document.getElementById('ragBarIndicator').style.left = '0%';
        document.getElementById('ragBreakdown').innerHTML = '<span class="risk-breakdown-item">Load a PCAP to see risk breakdown</span>';
        document.getElementById('maxEntropyVal').innerText = '–';
        document.getElementById('avgEntropyVal').innerText = '–';
        document.getElementById('maxEntropyBar').style.width = '0%';
        document.getElementById('avgEntropyBar').style.width = '0%';
        document.getElementById('maxEntropyLabel').innerText = '';
        document.getElementById('graphNodeCount').innerText = '0 nodes';
        document.getElementById('perfBadge').style.display = 'none';
        updateFilterCounts([]);
        clearGraph();
        if (protoChartInstance) protoChartInstance.destroy();
        if (flowsChartInstance) flowsChartInstance.destroy();
        alert('Sesi dan cache berhasil dibersihkan secara aman.');
    }

    // ════ RENDER RESULTS ════
    function renderResults(data) {
        // Threat Score
        const scoreEl = document.getElementById('threatScoreDisplay');
        const cardEl  = document.getElementById('threatCard');
        scoreEl.innerText = data.threat_score;
        const scoreColor = data.threat_score >= 70 ? 'var(--accent-red)' : (data.threat_score >= 30 ? 'var(--accent-orange)' : 'var(--accent-green)');
        scoreEl.style.color = scoreColor;
        cardEl.style.borderLeftColor = scoreColor;

        // Stats
        document.getElementById('totalPacketsDisplay').innerText = data.total_packets.toLocaleString();
        document.getElementById('triageSpeedDisplay').innerText = data.analysis_duration;
        const cnt = data.indicators ? data.indicators.length : 0;
        document.getElementById('iocCountDisplay').innerText = cnt;
        document.getElementById('iocCountBadge').innerText = cnt + ' findings';
        document.getElementById('iocPillCount').innerText = cnt;
        document.getElementById('sha256Display').innerText = data.sha256_checksum || '–';

        // Throughput & Performance Badge
        if (data.throughput_mbps !== undefined && data.throughput_mbps > 0) {
            const pb = document.getElementById('perfBadge');
            pb.style.display = 'inline-block';
            pb.innerText = '⚡ ' + data.analysis_duration + ' (' + data.throughput_mbps.toFixed(1) + ' MB/s • ' + Math.round(data.throughput_pkts_sec).toLocaleString() + ' pkts/s)';
        }

        // Active Rules Count Badge
        if (data.active_rules_count) {
            document.getElementById('ruleCountBadge').innerText = data.active_rules_count + ' Rules';
        }

        // MITRE
        if (data.mitre_summary) {
            document.getElementById('mitreRecon').innerText   = data.mitre_summary.reconnaissance || 0;
            document.getElementById('mitreAccess').innerText  = data.mitre_summary.initial_access || 0;
            document.getElementById('mitreExec').innerText    = data.mitre_summary.execution || 0;
            document.getElementById('mitreCred').innerText    = data.mitre_summary.credential_access || 0;
            document.getElementById('mitreC2').innerText      = data.mitre_summary.command_and_control || 0;
            document.getElementById('mitreExfil').innerText   = data.mitre_summary.exfiltration || 0;
        }

        // RAG Risk Gauge
        renderRiskGauge(data);

        // Entropy
        renderEntropy(data);

        // Charts
        renderCharts(data);

        // Attack Graph
        renderAttackGraph(data.attack_graph);

        // IOC Table + Cards
        updateFilterCounts(data.indicators || []);
        renderIOC(data.indicators || []);

        // Playbook
        renderPlaybook(data.playbook);

        // Timeline
        renderTimeline(data.timeline || []);

        // Blocklist
        renderBlocklist(data.blocklist_rules);
    }

    // ════ RAG RISK GAUGE ════
    function renderRiskGauge(data) {
        const score = data.threat_score || 0;
        const color = score >= 70 ? 'var(--accent-red)' : (score >= 30 ? 'var(--accent-orange)' : 'var(--accent-green)');
        const ragEl = document.getElementById('ragScoreDisplay');
        ragEl.innerText = score + ' / 100';
        ragEl.style.color = color;
        document.getElementById('ragBarFill').style.width = score + '%';
        document.getElementById('ragBarIndicator').style.left = Math.max(0, score - 1) + '%';

        const bd = data.risk_breakdown || {};
        document.getElementById('ragBreakdown').innerHTML =
            '<span class="risk-breakdown-item">CRITICAL: <span class="rb-crit">' + (bd.critical_count||0) + '×(+' + (bd.critical_points||0) + 'p)</span></span>' +
            '<span class="risk-breakdown-item">HIGH: <span class="rb-high">' + (bd.high_count||0) + '×(+' + (bd.high_points||0) + 'p)</span></span>' +
            '<span class="risk-breakdown-item">MEDIUM: <span class="rb-med">' + (bd.medium_count||0) + '×(+' + (bd.medium_points||0) + 'p)</span></span>' +
            '<span class="risk-breakdown-item">Raw Score: <strong style="color:var(--text-main)">' + (bd.raw_score||0) + '</strong></span>';
    }

    // ════ ENTROPY ════
    function renderEntropy(data) {
        const maxE = data.max_entropy || 0;
        const avgE = data.avg_entropy || 0;

        document.getElementById('maxEntropyVal').innerText = maxE.toFixed(3) + ' / 8.0';
        document.getElementById('avgEntropyVal').innerText = avgE.toFixed(3) + ' / 8.0';

        const maxPct = Math.min(100, (maxE / 8.0) * 100);
        const avgPct = Math.min(100, (avgE / 8.0) * 100);

        const maxColor = maxE >= 7.2 ? '#ef4444' : (maxE >= 6.0 ? '#f97316' : '#10b981');
        const avgColor = avgE >= 7.2 ? '#ef4444' : (avgE >= 6.0 ? '#f97316' : '#10b981');

        const barMax = document.getElementById('maxEntropyBar');
        barMax.style.width = maxPct + '%';
        barMax.style.background = maxColor;

        const barAvg = document.getElementById('avgEntropyBar');
        barAvg.style.width = avgPct + '%';
        barAvg.style.background = avgColor;

        const lblMax = document.getElementById('maxEntropyLabel');
        if (maxE >= 7.5)      lblMax.innerText = '🔴 HIGHLY SUSPICIOUS — Encrypted/Packed Payload';
        else if (maxE >= 7.2) lblMax.innerText = '🟠 HIGH ENTROPY — Possible C2 / Obfuscation';
        else if (maxE >= 6.0) lblMax.innerText = '🟡 ELEVATED — Compressed or Encoded Data';
        else if (maxE >= 3.5) lblMax.innerText = '🟢 NORMAL — Plaintext/Structured Data';
        else                  lblMax.innerText = '⚪ LOW — Sparse or Repetitive Payload';
        lblMax.style.color = maxColor;
    }

    // ════ CHARTS ════
    function renderCharts(data) {
        const isMobile = window.innerWidth < 768;
        if (protoChartInstance) protoChartInstance.destroy();
        const stats = data.protocol_stats || {};
        protoChartInstance = new Chart(document.getElementById('protoChart').getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['TCP','UDP','DNS','HTTP','ICMP'],
                datasets: [{
                    data: [stats.tcp_count||0, stats.udp_count||0, stats.dns_count||0, stats.http_count||0, stats.icmp_count||0],
                    backgroundColor: ['#0284c7','#10b981','#f59e0b','#ec4899','#8b5cf6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: isMobile ? 'bottom' : 'right', labels: { color:'#94a3b8', font:{size:9}, boxWidth:10, padding:8 } } }
            }
        });

        if (flowsChartInstance) flowsChartInstance.destroy();
        const flows = (data.network_flows || []).slice(0, 5);
        flowsChartInstance = new Chart(document.getElementById('flowsChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: flows.map(f => f.src_ip + ' > ' + f.dst_ip),
                datasets: [{ label:'Packets', data: flows.map(f => f.packets), backgroundColor:'#00f2fe', borderRadius:3 }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { ticks:{color:'#64748b',font:{size:8}}, grid:{display:false} },
                    y: { ticks:{color:'#64748b',font:{size:8}}, grid:{color:'rgba(255,255,255,0.05)'} }
                },
                plugins: { legend: { display:false } }
            }
        });
    }
    window.addEventListener('resize', () => { if (currentAnalysis) renderCharts(currentAnalysis); });

    // ════ ATTACK GRAPH (Pure Canvas 2D) ════
    let graphNodes = [];
    let graphEdges = [];
    let graphDragging = null;
    let graphOffset = {x:0, y:0};

    function clearGraph() {
        graphNodes = []; graphEdges = [];
        const canvas = document.getElementById('graphCanvas');
        if (canvas) {
            const ctx = canvas.getContext('2d');
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
    }

    function renderAttackGraph(graphData) {
        if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
            document.getElementById('graphNodeCount').innerText = '0 nodes — load PCAP to visualize';
            return;
        }

        const container = document.getElementById('attackGraphCanvas');
        const canvas = document.getElementById('graphCanvas');
        canvas.width  = container.offsetWidth;
        canvas.height = container.offsetHeight;

        const W = canvas.width, H = canvas.height;
        const cx = W / 2, cy = H / 2;
        const n = graphData.nodes.length;
        const r = Math.min(W, H) * 0.36;

        graphNodes = graphData.nodes.map((node, i) => {
            const angle = (2 * Math.PI * i) / n - Math.PI / 2;
            return {
                id: node.id,
                label: node.label,
                role: node.role,
                color: node.color || '#00f2fe',
                tooltip: node.tooltip,
                x: cx + r * Math.cos(angle),
                y: cy + r * Math.sin(angle),
                vx: 0, vy: 0,
                r: node.role === 'attacker' ? 18 : (node.role === 'victim' ? 15 : 12)
            };
        });
        graphEdges = graphData.edges || [];

        document.getElementById('graphNodeCount').innerText = n + ' nodes, ' + graphEdges.length + ' edges';

        // Force-directed simulation (30 iterations)
        for (let iter = 0; iter < 30; iter++) {
            for (let a = 0; a < graphNodes.length; a++) {
                for (let b = a + 1; b < graphNodes.length; b++) {
                    const dx = graphNodes[b].x - graphNodes[a].x;
                    const dy = graphNodes[b].y - graphNodes[a].y;
                    const dist = Math.sqrt(dx*dx + dy*dy) || 1;
                    const force = 2200 / (dist * dist);
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    graphNodes[a].vx -= fx; graphNodes[a].vy -= fy;
                    graphNodes[b].vx += fx; graphNodes[b].vy += fy;
                }
            }
            for (const edge of graphEdges) {
                const na = graphNodes.find(n => n.id === edge.from);
                const nb = graphNodes.find(n => n.id === edge.to);
                if (!na || !nb) continue;
                const dx = nb.x - na.x;
                const dy = nb.y - na.y;
                const dist = Math.sqrt(dx*dx + dy*dy) || 1;
                const force = (dist - 120) * 0.04;
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                na.vx += fx; na.vy += fy;
                nb.vx -= fx; nb.vy -= fy;
            }
            for (const node of graphNodes) {
                node.vx += (cx - node.x) * 0.015;
                node.vy += (cy - node.y) * 0.015;
                node.x += node.vx * 0.5;
                node.y += node.vy * 0.5;
                node.vx *= 0.6; node.vy *= 0.6;
                const pad = node.r + 10;
                node.x = Math.max(pad, Math.min(W - pad, node.x));
                node.y = Math.max(pad, Math.min(H - pad, node.y));
            }
        }

        drawGraph();
        setupGraphInteraction(canvas);
    }

    function drawGraph() {
        const canvas = document.getElementById('graphCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        // Draw edges
        for (const edge of graphEdges) {
            const na = graphNodes.find(n => n.id === edge.from);
            const nb = graphNodes.find(n => n.id === edge.to);
            if (!na || !nb) continue;

            ctx.beginPath();
            ctx.moveTo(na.x, na.y);
            ctx.lineTo(nb.x, nb.y);
            ctx.strokeStyle = edge.is_ioc ? 'rgba(255,0,85,0.75)' : 'rgba(0,242,254,0.25)';
            ctx.lineWidth = edge.is_ioc ? 2.5 : 1;
            if (edge.is_ioc) {
                ctx.shadowColor = 'rgba(255,0,85,0.5)';
                ctx.shadowBlur = 6;
            }
            ctx.stroke();
            ctx.shadowBlur = 0;

            // Arrow
            const angle = Math.atan2(nb.y - na.y, nb.x - na.x);
            const arrowX = nb.x - Math.cos(angle) * (nb.r + 4);
            const arrowY = nb.y - Math.sin(angle) * (nb.r + 4);
            ctx.beginPath();
            ctx.moveTo(arrowX, arrowY);
            ctx.lineTo(arrowX - 10 * Math.cos(angle - 0.4), arrowY - 10 * Math.sin(angle - 0.4));
            ctx.lineTo(arrowX - 10 * Math.cos(angle + 0.4), arrowY - 10 * Math.sin(angle + 0.4));
            ctx.closePath();
            ctx.fillStyle = edge.is_ioc ? 'rgba(255,0,85,0.8)' : 'rgba(0,242,254,0.4)';
            ctx.fill();
        }

        // Draw nodes
        for (const node of graphNodes) {
            if (node.role === 'attacker') {
                ctx.shadowColor = '#ff0055'; ctx.shadowBlur = 18;
            } else if (node.role === 'victim') {
                ctx.shadowColor = '#ff9900'; ctx.shadowBlur = 14;
            } else {
                ctx.shadowColor = '#00f2fe'; ctx.shadowBlur = 6;
            }

            ctx.beginPath();
            ctx.arc(node.x, node.y, node.r, 0, 2 * Math.PI);
            ctx.fillStyle = node.color;
            ctx.fill();
            ctx.strokeStyle = 'rgba(255,255,255,0.2)';
            ctx.lineWidth = 1.5;
            ctx.stroke();
            ctx.shadowBlur = 0;

            ctx.font = node.r > 14 ? '14px sans-serif' : '10px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const icon = node.role === 'attacker' ? '⚠' : (node.role === 'victim' ? '🎯' : '●');
            ctx.fillStyle = '#fff';
            ctx.fillText(icon, node.x, node.y - 1);

            ctx.shadowBlur = 0;
            ctx.font = '9px Consolas, monospace';
            ctx.fillStyle = '#94a3b8';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            const shortLabel = node.label.length > 15 ? node.label.substring(0,13)+'…' : node.label;
            ctx.fillText(shortLabel, node.x, node.y + node.r + 3);
        }
    }

    function setupGraphInteraction(canvas) {
        const tooltip = document.getElementById('graphTooltip');
        const getNode = (x, y) => graphNodes.find(n => Math.hypot(n.x - x, n.y - y) <= n.r + 4);

        canvas.onmousedown = (e) => {
            const rect = canvas.getBoundingClientRect();
            const node = getNode(e.clientX - rect.left, e.clientY - rect.top);
            if (node) { graphDragging = node; graphOffset = {x: node.x - (e.clientX - rect.left), y: node.y - (e.clientY - rect.top)}; }
        };
        canvas.onmousemove = (e) => {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left, y = e.clientY - rect.top;
            if (graphDragging) {
                graphDragging.x = x + graphOffset.x;
                graphDragging.y = y + graphOffset.y;
                drawGraph();
                return;
            }
            const node = getNode(x, y);
            if (node) {
                tooltip.style.display = 'block';
                tooltip.style.left = Math.min(x + 14, canvas.width - 230) + 'px';
                tooltip.style.top = (y - 10) + 'px';
                tooltip.innerHTML = '<strong style="color:var(--accent-cyan)">' + node.id + '</strong><br>' + node.tooltip.replace(/\|/g,'<br>');
                canvas.style.cursor = 'grab';
            } else {
                tooltip.style.display = 'none';
                canvas.style.cursor = 'default';
            }
        };
        canvas.onmouseup = () => { graphDragging = null; };
        canvas.onmouseleave = () => { graphDragging = null; tooltip.style.display = 'none'; };
    }

    // ════ IOC FILTER BAR ════
    function updateFilterCounts(indicators) {
        let crit = 0, high = 0, med = 0;
        indicators.forEach(i => {
            if (i.severity === 'CRITICAL') crit++;
            else if (i.severity === 'HIGH') high++;
            else if (i.severity === 'MEDIUM') med++;
        });
        document.getElementById('countFilterAll').innerText = indicators.length;
        document.getElementById('countFilterCrit').innerText = crit;
        document.getElementById('countFilterHigh').innerText = high;
        document.getElementById('countFilterMed').innerText = med;
    }

    function filterIOCSeverity(sev, btn) {
        currentIOCSeverityFilter = sev;
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        filterIOC();
    }

    // ════ IOC TABLE + CARDS ════
    function renderIOC(indicators) {
        const iocBody = document.getElementById('iocTableBody');
        const iocCards = document.getElementById('iocCardsContainer');
        iocBody.innerHTML = ''; iocCards.innerHTML = '';

        if (!indicators || indicators.length === 0) {
            iocBody.innerHTML = '<tr><td colspan="6" style="color:var(--accent-green); text-align:center;">✅ Trafik bersih. Tidak ada anomali terdeteksi.</td></tr>';
            iocCards.innerHTML = '<div style="color:var(--accent-green); text-align:center; padding:15px; font-size:12px;">✅ Trafik bersih.</div>';
            return;
        }

        indicators.forEach((ind, idx) => {
            const sc = ind.severity === 'CRITICAL' ? 'var(--accent-red)' : (ind.severity === 'HIGH' ? 'var(--accent-orange)' : '#facc15');
            const sbg = ind.severity === 'CRITICAL' ? 'rgba(255,0,85,0.15)' : (ind.severity === 'HIGH' ? 'rgba(255,153,0,0.15)' : 'rgba(250,204,21,0.15)');

            let eBadge = '';
            if (ind.entropy > 0) {
                const ec = ind.entropy >= 7.2 ? '#ef4444' : (ind.entropy >= 6.0 ? '#f97316' : '#10b981');
                eBadge = '<span style="color:' + ec + '; font-size:9px; font-weight:bold;">H=' + ind.entropy.toFixed(2) + '</span>';
            }

            const tr = document.createElement('tr');
            tr.setAttribute('data-severity', ind.severity);
            tr.innerHTML =
                '<td><span style="color:' + sc + '; font-weight:bold;">[' + ind.severity + ']</span></td>' +
                '<td><strong>' + esc(ind.title) + '</strong><br><small style="color:var(--text-muted);">' + esc(ind.description) + '</small></td>' +
                '<td style="font-size:10px;">' + (ind.src_ip||'-') + ' &rarr; ' + (ind.dst_ip||'-') + '</td>' +
                '<td>' + (eBadge || '<span style="color:var(--text-muted); font-size:9px;">N/A</span>') + '</td>' +
                '<td style="color:var(--accent-cyan); font-size:10px;">' + esc(ind.mitre_attack) + '</td>' +
                '<td><button onclick="inspectEvidence(' + idx + ')" style="background:#1e293b; border:1px solid #334155; color:var(--accent-cyan); padding:5px 9px; border-radius:3px; cursor:pointer; font-size:10px; font-weight:bold;">🔍</button></td>';
            iocBody.appendChild(tr);

            const card = document.createElement('div');
            card.className = 'ioc-card-item';
            card.setAttribute('data-severity', ind.severity);
            card.style.borderLeftColor = sc;
            card.innerHTML =
                '<div class="ioc-card-header">' +
                '  <span class="ioc-badge-sev" style="background:' + sbg + '; color:' + sc + '; border:1px solid ' + sc + ';">' + ind.severity + '</span>' +
                '  <span style="font-size:10px; color:var(--accent-cyan); font-weight:bold;">' + esc(ind.mitre_attack) + '</span>' +
                '</div>' +
                '<div class="ioc-card-title">' + esc(ind.title) + '</div>' +
                '<div class="ioc-card-desc">' + esc(ind.description) + '</div>' +
                '<div class="ioc-card-meta">' +
                '  <strong>Flow:</strong> ' + (ind.src_ip||'-') + ' &rarr; ' + (ind.dst_ip||'-') +
                (ind.entropy > 0 ? ' &nbsp;|&nbsp; <strong>Entropy:</strong> ' + ind.entropy.toFixed(2) + '/8.0 ' + (ind.entropy_label||'') : '') +
                '</div>' +
                '<button onclick="inspectEvidence(' + idx + ')" class="btn btn-outline" style="margin-top:6px; padding:9px; font-size:11px;">🔍 Periksa Bukti Forensik</button>';
            iocCards.appendChild(card);
        });
    }

    function filterIOC() {
        const q = document.getElementById('iocSearch').value.toLowerCase();
        document.querySelectorAll('#iocTableBody tr').forEach(r => {
            const sev = r.getAttribute('data-severity') || 'ALL';
            const matchSev = (currentIOCSeverityFilter === 'ALL' || sev === currentIOCSeverityFilter);
            const matchText = r.innerText.toLowerCase().includes(q);
            r.style.display = (matchSev && matchText) ? '' : 'none';
        });
        document.querySelectorAll('#iocCardsContainer .ioc-card-item').forEach(c => {
            const sev = c.getAttribute('data-severity') || 'ALL';
            const matchSev = (currentIOCSeverityFilter === 'ALL' || sev === currentIOCSeverityFilter);
            const matchText = c.innerText.toLowerCase().includes(q);
            c.style.display = (matchSev && matchText) ? '' : 'none';
        });
    }

    // ════ TACTICAL PLAYBOOK ════
    function renderPlaybook(playbook) {
        if (!playbook || !playbook.steps || playbook.steps.length === 0) {
            document.getElementById('playbookEmpty').style.display = '';
            document.getElementById('playbookContent').style.display = 'none';
            document.getElementById('playbookStepCount').innerText = '0 action steps';
            return;
        }

        document.getElementById('playbookStepCount').innerText = playbook.steps.length + ' containment steps';
        document.getElementById('playbookEmpty').style.display = 'none';
        document.getElementById('playbookContent').style.display = '';
        document.getElementById('playbookSummary').innerText = '📋 ' + (playbook.summary || 'Tactical Incident Response Playbook');

        const list = document.getElementById('playbookStepsList');
        list.innerHTML = '';

        playbook.steps.forEach(s => {
            const card = document.createElement('div');
            card.className = 'playbook-step-card';
            const prioClass = s.priority === 'P1-CRITICAL' ? 'pb-crit' : (s.priority === 'P2-URGENT' ? 'pb-high' : 'pb-std');
            
            card.innerHTML = 
                '<div class="playbook-step-head">' +
                '  <span style="font-weight:bold; font-size:11px; color:var(--text-main);">Step ' + String(s.step_number).padStart(2, '0') + ': ' + esc(s.phase) + '</span>' +
                '  <span class="pb-prio ' + prioClass + '">' + s.priority + '</span>' +
                '</div>' +
                '<div style="font-size:11px; color:#cbd5e1; margin-bottom:6px;">' + esc(s.action) + '</div>' +
                (s.mitre_ref ? '<div style="font-size:9px; color:var(--accent-cyan); margin-bottom:4px;">Ref MITRE: ' + esc(s.mitre_ref) + '</div>' : '') +
                (s.command ? '<div style="background:#060a12; padding:6px 8px; border-radius:4px; font-size:10px; color:#a3e635; border:1px solid #16263d; word-break:break-all;"><code>' + esc(s.command) + '</code></div>' : '');
            
            list.appendChild(card);
        });
    }

    function copyPlaybookPlan() {
        if (!currentAnalysis || !currentAnalysis.playbook || !currentAnalysis.playbook.raw_plan_text) {
            alert('Belum ada playbook yang dihasilkan.');
            return;
        }
        copyTextToClipboard(currentAnalysis.playbook.raw_plan_text, 'Playbook Execution Plan disalin ke clipboard!');
    }

    function downloadPlaybook() {
        window.location.href = '/api/playbook?format=text';
    }

    // ════ CUSTOM RULE INSPECTOR ════
    async function openRuleModal() {
        const modal = document.getElementById('ruleModal');
        const tbody = document.getElementById('rulesTableBody');
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">Memuat aturan aktif...</td></tr>';
        modal.style.display = 'flex';

        try {
            const res = await fetch('/api/rules');
            if (!res.ok) throw new Error('Gagal memuat aturan');
            const rules = await res.json();
            tbody.innerHTML = '';
            document.getElementById('ruleCountBadge').innerText = rules.length + ' Rules';

            rules.forEach(r => {
                const tr = document.createElement('tr');
                const sc = r.risk_level === 'CRITICAL' ? 'var(--accent-red)' : (r.risk_level === 'HIGH' ? 'var(--accent-orange)' : '#facc15');
                tr.innerHTML = 
                    '<td style="color:var(--accent-cyan); font-weight:bold;">' + esc(r.id) + '</td>' +
                    '<td><strong>' + esc(r.name) + '</strong><br><small style="color:var(--text-muted);">' + esc(r.recommendation) + '</small></td>' +
                    '<td><span style="color:' + sc + '; font-weight:bold;">[' + r.risk_level + ']</span></td>' +
                    '<td>' + (r.target_protocol || 'ANY') + '</td>' +
                    '<td><span style="background:#1e293b; padding:2px 6px; border-radius:3px; font-size:9px;">' + r.match_type + '</span></td>' +
                    '<td style="font-family:monospace; color:#a3e635; font-size:10px; max-width:180px; overflow:hidden; text-overflow:ellipsis;">' + esc(r.pattern) + '</td>' +
                    '<td style="color:var(--text-muted); font-size:10px;">' + esc(r.mitre_id) + ' (' + esc(r.mitre_tactic) + ')</td>';
                tbody.appendChild(tr);
            });
        } catch(err) {
            tbody.innerHTML = '<tr><td colspan="7" style="color:var(--accent-red); text-align:center;">Gagal memuat aturan: ' + err.message + '</td></tr>';
        }
    }

    function closeRuleModal() {
        document.getElementById('ruleModal').style.display = 'none';
    }

    function handleRuleModalBackdrop(e) {
        if (e.target === document.getElementById('ruleModal')) closeRuleModal();
    }

    // ── QUICK DEPLOY MODAL & DYNAMIC HOST ──
    function openDeployModal() {
        document.getElementById('deployModal').style.display = 'flex';
        updateDynHosts();
    }

    function closeDeployModal() {
        document.getElementById('deployModal').style.display = 'none';
    }

    function handleDeployModalBackdrop(e) {
        if (e.target === document.getElementById('deployModal')) closeDeployModal();
    }

    function copyDeployCmd(platform) {
        var origin = window.location.origin;
        var cmd = '';
        if (platform === 'linux') {
            cmd = 'curl -sSL ' + origin + '/install.sh | bash';
        } else if (platform === 'win') {
            cmd = 'iwr -useb ' + origin + '/install.ps1 | iex';
        } else if (platform === 'termux') {
            cmd = 'curl -sSL ' + origin + '/install.sh | sh';
        }
        copyTextToClipboard(cmd, 'Perintah ' + platform.toUpperCase() + ' disalin!');
    }

    function updateDynHosts() {
        var origin = window.location.origin;
        var dynHosts = document.querySelectorAll('.dyn-host');
        for (var i = 0; i < dynHosts.length; i++) {
            dynHosts[i].textContent = origin;
        }
    }

    // ── EXECUTIVE WAR-ROOM BRIEFING MODAL ──
    function openBriefingModal() {
        var modal = document.getElementById('briefingModal');
        modal.style.display = 'flex';

        if (!currentAnalysis || !currentAnalysis.executive_briefing) {
            document.getElementById('brHeadline').innerText = 'Menunggu Analisis Artefak Jaringan...';
            document.getElementById('brSeverity').innerText = 'SIAP MENGANALISIS';
            document.getElementById('brSeverity').style.color = 'var(--accent-cyan)';
            document.getElementById('brImpact').innerText = 'Menunggu Data';
            document.getElementById('brTarget').innerText = '-';
            document.getElementById('brAttacker').innerText = '-';
            document.getElementById('brStory').innerHTML = '<div style="color:var(--text-muted);">' +
                'Belum ada data lalu lintas jaringan yang dianalisis pada sesi saat ini.<br><br>' +
                '👉 Silakan <strong>unggah berkas PCAP</strong> atau klik tombol berikut untuk memuat contoh serangan multi-vektor:' +
                '<div style="margin-top:12px;"><button class="btn btn-green" style="display:inline-block; width:auto; padding:8px 16px; font-size:12px;" onclick="closeBriefingModal(); loadSampleAttack();">⚡ Muat Contoh Serangan (1-Click Demo)</button></div>' +
                '</div>';
            document.getElementById('brDataIntegrity').innerText = 'Integritas data akan dievaluasi setelah pemeriksaan artefak selesai.';
            document.getElementById('brDecisions').innerText = 'Instruksi keputusan operasional akan disusun secara otomatis berbasis ancaman yang terdeteksi.';
            document.getElementById('brBanner').style.borderLeftColor = 'var(--accent-cyan)';
            return;
        }

        var eb = currentAnalysis.executive_briefing;
        document.getElementById('brHeadline').innerText = eb.headline || 'Ringkasan Eksekutif';
        document.getElementById('brSeverity').innerText = eb.severity_label || '--';
        document.getElementById('brImpact').innerText = eb.business_impact_level || '--';
        document.getElementById('brTarget').innerText = eb.primary_target || '--';
        document.getElementById('brAttacker').innerText = eb.attacker_identity || '--';
        document.getElementById('brStory').innerText = eb.what_happened_story || '-';
        document.getElementById('brDataIntegrity').innerText = eb.data_integrity_status || '-';

        var decEl = document.getElementById('brDecisions');
        if (eb.recommended_decisions && eb.recommended_decisions.length > 0) {
            var decHtml = '<ul style="padding-left:18px; margin:0;">';
            for (var i = 0; i < eb.recommended_decisions.length; i++) {
                decHtml += '<li style="margin-bottom:4px;">' + esc(eb.recommended_decisions[i]) + '</li>';
            }
            decHtml += '</ul>';
            decEl.innerHTML = decHtml;
        } else {
            decEl.innerText = 'Tidak ada tindakan darurat yang diperlukan.';
        }

        var banner = document.getElementById('brBanner');
        var sevText = document.getElementById('brSeverity');
        if (currentAnalysis.threat_level === 'CRITICAL') {
            banner.style.borderLeftColor = '#ef4444';
            sevText.style.color = '#ef4444';
        } else if (currentAnalysis.threat_level === 'HIGH') {
            banner.style.borderLeftColor = '#f97316';
            sevText.style.color = '#f97316';
        } else if (currentAnalysis.threat_level === 'MEDIUM') {
            banner.style.borderLeftColor = '#eab308';
            sevText.style.color = '#eab308';
        } else {
            banner.style.borderLeftColor = '#10b981';
            sevText.style.color = '#10b981';
        }

        document.getElementById('briefingModal').style.display = 'flex';
    }

    function closeBriefingModal() {
        document.getElementById('briefingModal').style.display = 'none';
    }

    function handleBriefingModalBackdrop(e) {
        if (e.target === document.getElementById('briefingModal')) closeBriefingModal();
    }

    function copyWhatsAppBriefing() {
        if (!currentAnalysis || !currentAnalysis.executive_briefing || !currentAnalysis.executive_briefing.whatsapp_format_text) {
            alert('Teks briefing belum tersedia.');
            return;
        }
        copyTextToClipboard(currentAnalysis.executive_briefing.whatsapp_format_text, 'Format WhatsApp/Email Direksi berhasil disalin ke clipboard!');
    }

    function downloadBriefingTxt() {
        window.location.href = '/api/briefing?format=text';
    }

    // ════ TIMELINE ════
    function renderTimeline(timeline) {
        const tl = document.getElementById('timelineContainer');
        tl.innerHTML = '';
        if (!timeline || timeline.length === 0) {
            tl.innerHTML = '<div style="color:var(--text-muted); font-size:11px;">Tidak ada peristiwa killchain.</div>';
            return;
        }
        timeline.forEach(t => {
            const div = document.createElement('div');
            div.className = 'timeline-item';
            div.innerHTML = '<div style="font-size:10px; color:var(--text-muted);">' + new Date(t.timestamp).toLocaleTimeString() + ' | ' + esc(t.stage) + '</div>' +
                            '<div style="font-weight:bold; margin-top:2px; font-size:11px;">' + esc(t.message) + '</div>';
            tl.appendChild(div);
        });
    }

    // ════ BLOCKLIST PANEL ════
    const blData = {};
    function renderBlocklist(rules) {
        if (!rules || !rules.attacker_ips || rules.attacker_ips.length === 0) {
            document.getElementById('blocklistEmpty').style.display = '';
            document.getElementById('blocklistContent').style.display = 'none';
            document.getElementById('blocklistIPCount').innerText = '0 attacker IPs';
            return;
        }
        document.getElementById('blocklistIPCount').innerText = rules.attacker_ips.length + ' attacker IP(s)';
        document.getElementById('blocklistEmpty').style.display = 'none';
        document.getElementById('blocklistContent').style.display = '';

        blData['iptables']  = (rules.iptables_rules || []).join('\n');
        blData['windows']   = (rules.windows_rules  || []).join('\n');
        blData['suricata']  = (rules.suricata_rules || []).join('\n');
        blData['plaintext'] = rules.plain_ip_list || '';

        updateBLDisplay();
    }

    function switchBLTab(format, btn) {
        currentBLFormat = format;
        document.querySelectorAll('.bl-tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        updateBLDisplay();
    }

    function updateBLDisplay() {
        const el = document.getElementById('blCodeDisplay');
        const code = blData[currentBLFormat] || '';
        el.textContent = code;
        el.style.color = currentBLFormat === 'windows' ? '#38bdf8' : (currentBLFormat === 'suricata' ? '#f59e0b' : '#a3e635');
    }

    function copyBLRules() {
        copyTextToClipboard(blData[currentBLFormat] || '', 'Blocklist rules disalin ke clipboard!');
    }

    function downloadBLRules() {
        const ext = currentBLFormat === 'windows' ? 'ps1' : (currentBLFormat === 'suricata' ? 'rules' : (currentBLFormat === 'plaintext' ? 'txt' : 'sh'));
        window.location.href = '/api/export/blocklist?format=' + currentBLFormat;
    }

    // ════ EVIDENCE MODAL ════
    function inspectEvidence(idx) {
        if (!currentAnalysis || !currentAnalysis.indicators || !currentAnalysis.indicators[idx]) return;
        const ioc = currentAnalysis.indicators[idx];
        document.getElementById('modalTitle').innerText = ioc.title + ' // FORENSIC EVIDENCE DUMP';
        document.getElementById('modalSubtitle').innerText = 'Flow: ' + ioc.src_ip + ' -> ' + ioc.dst_ip + ' | MITRE: ' + ioc.mitre_attack;

        const eb = document.getElementById('modalEntropyBadge');
        if (ioc.entropy > 0) {
            const ec = ioc.entropy >= 7.2 ? '#ef4444' : (ioc.entropy >= 6.0 ? '#f97316' : '#10b981');
            eb.innerHTML = '<span style="background:' + ec + '22; color:' + ec + '; border:1px solid ' + ec + '; padding:4px 12px; border-radius:4px; font-size:11px; font-weight:bold;">Shannon Entropy: ' + ioc.entropy.toFixed(4) + ' / 8.0 — ' + (ioc.entropy_label||'') + '</span>';
        } else {
            eb.innerHTML = '';
        }

        document.getElementById('modalHexDump').innerText = ioc.evidence_hex || ('Evidence: ' + ioc.evidence + '\n\nRecommendation:\n' + ioc.recommendation);
        document.getElementById('inspectorModal').style.display = 'flex';
    }

    function closeModal() { document.getElementById('inspectorModal').style.display = 'none'; }
    function handleModalBackdrop(e) { if (e.target === document.getElementById('inspectorModal')) closeModal(); }
    window.addEventListener('keydown', e => { 
        if (e.key === 'Escape') {
            closeModal();
            closeRuleModal();
            closeDeployModal();
            closeBriefingModal();
        }
    });

    document.addEventListener('DOMContentLoaded', () => {
        updateDynHosts();
    });

    function copyHexDump() {
        copyTextToClipboard(document.getElementById('modalHexDump').innerText, 'Bukti forensik disalin ke clipboard!');
    }

    // ════ CLIPBOARD ════
    function copyTextToClipboard(text, msg) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => { if (msg) alert(msg); }).catch(() => fbCopy(text, msg));
        } else { fbCopy(text, msg); }
    }
    function fbCopy(text, msg) {
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta); if (msg) alert(msg);
    }
    function copySHA256() { copyTextToClipboard(document.getElementById('sha256Display').innerText, 'SHA-256 disalin!'); }

    function esc(str) {
        if (!str) return '';
        return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    </script>
</body>
</html>`
