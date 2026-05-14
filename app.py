import os
import sys
import json
import shutil
import threading
import webbrowser
import importlib  
import subprocess
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 5000
CASES_DIR = "cases"
os.makedirs(CASES_DIR, exist_ok=True)

def create_case_folder():
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    case_id   = f"CASE_{timestamp}"
    case_path = os.path.join(CASES_DIR, case_id)
    os.makedirs(os.path.join(case_path, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(case_path, "logs"),      exist_ok=True)
    os.makedirs(os.path.join(case_path, "reports"),   exist_ok=True)
    return case_id, case_path
class ForensicHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path == "/" or self.path == "/launcher":
            self.serve_launcher()
        elif self.path == "/dashboard":
            self.serve_dashboard()
        elif self.path == "/status":
            self.serve_status()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/run/dead":
            self.run_pipeline("dead")
        elif self.path == "/run/live":
            self.run_pipeline("live")
        else:
            self.send_error(404)

    def serve_launcher(self):
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Browser Forensic Analysis Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #f4f6f9;
            min-height: 100vh;
        }
        .header {
            background: #1a2744;
            width: 100%;
            padding: 0 40px;
            height: 56px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 3px solid #2e5baf;
            position: fixed;
            top: 0;
            z-index: 100;
        }
        .header-left { display: flex; align-items: center; gap: 12px; }
        .header-logo {
            width: 28px; height: 28px;
            background: #2e5baf;
            border-radius: 4px;
            display: flex; align-items: center; justify-content: center;
        }
        .header-logo svg { width: 16px; height: 16px; }
        .header h1 { color: #ffffff; font-size: 15px; font-weight: 600; letter-spacing: 0.3px; }
        .header-meta { color: #8a9bb5; font-size: 11px; }
        .main {
            margin-top: 56px;
            padding: 48px 40px;
            max-width: 960px;
            margin-left: auto;
            margin-right: auto;
        }
        .page-title {
            margin-bottom: 32px;
            padding-bottom: 20px;
            border-bottom: 1px solid #dde2ea;
        }
        .page-title h2 {
            font-size: 22px;
            color: #1a2744;
            font-weight: 600;
            margin-bottom: 6px;
        }
        .page-title p { color: #5a6a80; font-size: 13px; }
        .cards {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 28px;
        }
        .card {
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-top: 3px solid #2e5baf;
            border-radius: 6px;
            padding: 28px 32px;
            transition: box-shadow 0.2s;
        }
        .card:hover { box-shadow: 0 4px 16px rgba(46,91,175,0.12); }
        .card-icon {
            width: 40px; height: 40px;
            background: #eef2fb;
            border-radius: 6px;
            display: flex; align-items: center; justify-content: center;
            margin-bottom: 16px;
        }
        .card-icon svg { width: 20px; height: 20px; stroke: #2e5baf; fill: none; stroke-width: 2; }
        .card h3 { font-size: 16px; color: #1a2744; font-weight: 600; margin-bottom: 8px; }
        .card p { font-size: 12px; color: #5a6a80; line-height: 1.7; margin-bottom: 20px; }
        .card-meta {
            font-size: 11px;
            color: #5a6a80;
            margin-bottom: 16px;
            padding: 8px 12px;
            background: #f4f6f9;
            border-radius: 4px;
            border-left: 3px solid #2e5baf;
        }
        .btn {
            display: inline-block;
            padding: 10px 24px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            letter-spacing: 0.2px;
            transition: background 0.2s;
        }
        .btn-primary { background: #2e5baf; color: white; }
        .btn-primary:hover { background: #1a2744; }
        .btn-secondary { background: #1a7a4a; color: white; }
        .btn-secondary:hover { background: #155c38; }
        .warning-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #fff8e6;
            border: 1px solid #e8a800;
            border-radius: 4px;
            padding: 6px 12px;
            font-size: 11px;
            color: #7a5500;
            font-weight: 500;
            margin-bottom: 14px;
        }
        .warning-badge svg { width: 13px; height: 13px; stroke: #e8a800; fill: none; stroke-width: 2.5; }
        .status-panel {
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 6px;
            padding: 24px 28px;
            display: none;
        }
        .status-panel.show { display: block; }
        .status-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .status-label { font-size: 12px; font-weight: 600; color: #1a2744; text-transform: uppercase; letter-spacing: 0.5px; }
        .status-text { font-size: 13px; color: #5a6a80; }
        .progress-track {
            width: 100%;
            height: 4px;
            background: #dde2ea;
            border-radius: 2px;
            overflow: hidden;
            margin-bottom: 16px;
        }
        .progress-fill {
            height: 100%;
            background: #2e5baf;
            border-radius: 2px;
            width: 0%;
            transition: width 0.5s;
        }
        .steps-list { font-size: 12px; color: #5a6a80; margin-bottom: 16px; }
        .step-done { color: #1a7a4a; font-weight: 500; padding: 2px 0; }
        .view-btn {
            display: none;
            padding: 10px 24px;
            background: #2e5baf;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            letter-spacing: 0.2px;
        }
        .view-btn:hover { background: #1a2744; }
        .divider { border: none; border-top: 1px solid #dde2ea; margin: 28px 0; }
        .info-row {
            display: flex;
            gap: 24px;
            font-size: 11px;
            color: #8a9bb5;
        }
        .info-item { display: flex; align-items: center; gap: 6px; }
        .info-dot { width: 6px; height: 6px; border-radius: 50%; background: #2e5baf; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-left">
            <div class="header-logo">
                <svg viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5">
                    <circle cx="6" cy="6" r="4"/><line x1="9.5" y1="9.5" x2="14" y2="14"/>
                </svg>
            </div>
            <div>
                <h1>Browser Forensic Analysis Tool</h1>
            </div>
        </div>
        <div class="header-meta">Chrome &nbsp;|&nbsp; Edge &nbsp;|&nbsp; Firefox</div>
    </div>

    <div class="main">
        <div class="page-title">
            <h2>Select Acquisition Mode</h2>
            <p>Choose the appropriate acquisition method based on the state of the target system at the time of examination.</p>
        </div>

        <div class="cards">
            <div class="card">
                <div class="card-icon">
                    <svg viewBox="0 0 24 24">
                        <rect x="3" y="3" width="18" height="18" rx="2"/>
                        <rect x="7" y="7" width="10" height="6" rx="1"/>
                        <line x1="7" y1="17" x2="9" y2="17"/>
                        <line x1="11" y1="17" x2="13" y2="17"/>
                    </svg>
                </div>
                <h3>Dead Acquisition</h3>
                <p>Collect browser artifacts from a system where browsers are not actively running. Reads directly from browser profile directories on disk. Suitable for post-incident or offline examination.</p>
                <div class="card-meta">Browsers must be closed before running this mode.</div>
                <button class="btn btn-primary" onclick="startAcquisition('dead')">Start Dead Acquisition</button>
            </div>
            <div class="card">
                <div class="card-icon">
                    <svg viewBox="0 0 24 24">
                        <circle cx="12" cy="12" r="9"/>
                        <polyline points="12,7 12,12 15,15"/>
                    </svg>
                </div>
                <h3>Live Acquisition</h3>
                <p>Collect browser artifacts from a system where browsers are actively running. Uses Volume Shadow Copy to access locked database files including cookies and session data.</p>
                <div class="warning-badge">
                    <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Requires Administrator privileges
                </div>
                <button class="btn btn-secondary" onclick="startAcquisition('live')">Start Live Acquisition</button>
            </div>
        </div>

        <div class="status-panel" id="statusBox">
            <div class="status-header">
                <span class="status-label">Acquisition Progress</span>
                <span class="status-text" id="statusText">Initializing...</span>
            </div>
            <div class="progress-track">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="steps-list" id="stepsList"></div>
            <button class="view-btn" id="viewBtn" onclick="viewDashboard()">Open Forensic Report</button>
        </div>

        <hr class="divider">
        <div class="info-row">
            <div class="info-item"><div class="info-dot"></div>Supports Chrome, Edge, Firefox</div>
            <div class="info-item"><div class="info-dot"></div>SHA-256 hash verification</div>
            <div class="info-item"><div class="info-dot"></div>Timeline analysis and anomaly detection</div>
            <div class="info-item"><div class="info-dot"></div>Cross-browser correlation</div>
        </div>
    </div>

    <script>
        function startAcquisition(type) {
            const statusBox = document.getElementById('statusBox');
            const statusText = document.getElementById('statusText');
            const progressFill = document.getElementById('progressFill');
            const stepsList = document.getElementById('stepsList');
            const viewBtn = document.getElementById('viewBtn');

            statusBox.classList.add('show');
            viewBtn.style.display = 'none';
            stepsList.innerHTML = '';

            const liveSteps = [
                "Detecting running browsers...",
                "Creating Volume Shadow Copy...",
                "Acquiring locked browser files...",
                "Parsing history databases...",
                "Building timeline...",
                "Checking artifact acquisition status...",
                "Recovering deleted records...",
                "Analyzing DNS cache...",
                "Generating report..."
            ];

            const deadSteps = [
                "Locating browser profiles...",
                "Acquiring browser artifacts...",
                "Parsing history databases...",
                "Building timeline...",
                "Checking artifact acquisition status...",
                "Recovering deleted records...",
                "Analyzing DNS cache...",
                "Generating report..."
            ];

            const steps = type === 'live' ? liveSteps : deadSteps;
            let stepIndex = 0;
            statusText.textContent = (type === 'live' ? 'Live' : 'Dead') + ' Acquisition started';

            const interval = setInterval(() => {
                if (stepIndex < steps.length) {
                    if (stepIndex > 0) {
                        stepsList.innerHTML += '<div class="step-done">&#10003; ' + steps[stepIndex - 1] + '</div>';
                    }
                    statusText.textContent = steps[stepIndex];
                    progressFill.style.width = ((stepIndex + 1) / steps.length * 85) + '%';
                    stepIndex++;
                }
            }, 2500);

            fetch('/run/' + type, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    clearInterval(interval);
                    if (data.success) {
                        progressFill.style.width = '100%';
                        stepsList.innerHTML += '<div class="step-done">&#10003; ' + steps[steps.length - 1] + '</div>';
                        let modeInfo = '';
                        if (type === 'live' && data.browsers && data.browsers.length > 0) {
                            modeInfo = '<div style="font-size:12px;color:#5a6a80;margin-top:10px;padding:8px 12px;background:#f4f6f9;border-radius:4px;">Browsers detected as running: <strong>' + data.browsers.join(', ') + '</strong></div>';
                        }
                        statusText.textContent = 'Analysis complete — ' + data.elapsed + 's';
                        if (data.warnings && data.warnings.length > 0) {
                            data.warnings.forEach(w => {
                                stepsList.innerHTML += '<div style="color:#c0392b;font-size:11px;margin-top:2px;">Warning: ' + w + '</div>';
                            });
                        }
                        stepsList.innerHTML += modeInfo;
                        viewBtn.style.display = 'inline-block';
                    } else {
                        statusText.textContent = 'Error: ' + data.error;
                        progressFill.style.background = '#c0392b';
                    }
                })
                .catch(err => {
                    clearInterval(interval);
                    statusText.textContent = 'Error: ' + err.message;
                    progressFill.style.background = '#c0392b';
                });
        }

        function viewDashboard() {
            window.location.href = '/dashboard';
        }
    </script>
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_dashboard(self):
        dashboard_path = os.path.join(
            os.environ.get("CASE_FOLDER", "output"), "dashboard.html"
        )
        if os.path.exists(dashboard_path):
            with open(dashboard_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Dashboard not generated yet. Run analysis first.")

    def run_pipeline(self, mode):
        start_time = datetime.now(timezone.utc)
        running_browsers = []
        pipeline_errors = []

        try:
            # Create timestamped case folder
            case_id = start_time.strftime('%Y%m%d_%H%M%S')
            mode_label_short = "LIVE" if mode == "live" else "DEAD"
            case_folder = os.path.join("cases", f"{mode_label_short}_{case_id}")
            os.makedirs(os.path.join(case_folder, "artifacts"), exist_ok=True)
            os.makedirs(os.path.join(case_folder, "logs"), exist_ok=True)

            os.environ["CASE_FOLDER"] = case_folder
            os.makedirs("output/artifacts", exist_ok=True)
            os.makedirs("output/logs", exist_ok=True)
            os.environ["OUTPUT_FOLDER"] = "output"

        except Exception as e:
            response = json.dumps({"success": False, "error": f"Failed to create case folder: {e}"})
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response.encode())
            return

        # Step 1 — Acquisition
        try:
            if mode == "live":
                live_mod = importlib.import_module("live_acquisition")
                importlib.reload(live_mod)
                running_browsers = [b for b in ["Chrome", "Edge", "Firefox"] if live_mod.is_browser_running(b)]
                live_mod.acquire_live()
            else:
                acq_mod = importlib.import_module("acquisition")
                importlib.reload(acq_mod)
                acq_mod.acquire_artifacts()
        except Exception as e:
            pipeline_errors.append(f"Acquisition failed: {e}")
            print(f"[ERROR] Acquisition: {e}")

        # Step 2 — Parser
        try:
            parser_mod = importlib.import_module("parser")
            importlib.reload(parser_mod)
            parser_mod.parse_history()
        except Exception as e:
            pipeline_errors.append(f"Parser failed: {e}")
            print(f"[ERROR] Parser: {e}")

        # Step 3 — Timeline
        try:
            timeline_mod = importlib.import_module("timeline")
            importlib.reload(timeline_mod)
            timeline_mod.main()
        except Exception as e:
            pipeline_errors.append(f"Timeline failed: {e}")
            print(f"[ERROR] Timeline: {e}")

        # Save running browsers to timeline.json
        if mode == "live":
            try:
                timeline_path = os.path.join(case_folder, "timeline.json")
                if os.path.exists(timeline_path):
                    with open(timeline_path, "r") as f:
                        timeline_data = json.load(f)
                    timeline_data["running_browsers"] = running_browsers
                    timeline_data["acquisition_mode"] = mode
                    timeline_data["live_acquisition_time"] = datetime.now(timezone.utc).isoformat()
                    with open(timeline_path, "w") as f:
                        json.dump(timeline_data, f, indent=4)
            except Exception as e:
                pipeline_errors.append(f"Timeline metadata save failed: {e}")
                print(f"[ERROR] Timeline metadata: {e}")

        # Step 4 — Artifact health
        try:
            health_mod = importlib.import_module("artifact_health")
            importlib.reload(health_mod)
            health_mod.generate_health_report()
        except Exception as e:
            pipeline_errors.append(f"Artifact health check failed: {e}")
            print(f"[ERROR] Artifact health: {e}")

        # Step 5 — Deleted record recovery
        try:
            recover_mod = importlib.import_module("recover_deleted")
            importlib.reload(recover_mod)
            recover_mod.recover_deleted_urls()
        except Exception as e:
            pipeline_errors.append(f"Deleted record recovery failed: {e}")
            print(f"[ERROR] Deleted recovery: {e}")

        # Step 6 — DNS analysis
        try:
            dns_mod = importlib.import_module("dns_parser")
            importlib.reload(dns_mod)
            dns_mod.analyze_dns()
        except Exception as e:
            pipeline_errors.append(f"DNS analysis failed: {e}")
            print(f"[ERROR] DNS analysis: {e}")

        # Step 7 — Dashboard
        try:
            dash_mod = importlib.import_module("dashboard")
            importlib.reload(dash_mod)
            dash_mod.generate_dashboard(mode=mode)
        except Exception as e:
            pipeline_errors.append(f"Dashboard generation failed: {e}")
            print(f"[ERROR] Dashboard: {e}")

        elapsed = round((datetime.now(timezone.utc) - start_time).total_seconds(), 1)

        # Step 8 — Chain of custody
        try:
            from chain_of_custody import generate_chain_of_custody
            logs_dir = os.path.join(case_folder, "logs")
            acq_log = {}
            if os.path.exists(logs_dir) and os.listdir(logs_dir):
                acq_log_path = os.path.join(
                    logs_dir,
                    sorted(os.listdir(logs_dir))[-1]
                )
                with open(acq_log_path, "r") as f:
                    acq_log = json.load(f)
            generate_chain_of_custody(
                case_folder      = case_folder,
                mode             = mode,
                elapsed          = elapsed,
                running_browsers = running_browsers,
                acquisition_log  = acq_log
            )
        except Exception as e:
            pipeline_errors.append(f"Chain of custody failed: {e}")
            print(f"[ERROR] Chain of custody: {e}")

        # Copy outputs to output/ so dashboard always shows latest
        try:
            for fname in ["timeline.json", "dashboard.html", "artifact_health.json",
                          "deleted_recovery.json", "dns_analysis.json"]:
                src = os.path.join(case_folder, fname)
                dst = os.path.join("output", fname)
                if os.path.exists(src):
                    shutil.copy2(src, dst)
        except Exception as e:
            print(f"[ERROR] Copying to output/: {e}")

        # Respond to frontend
        if pipeline_errors:
            print(f"\n[WARNING] Pipeline completed with {len(pipeline_errors)} error(s):")
            for err in pipeline_errors:
                print(f"  - {err}")

        response = json.dumps({
            "success":  True,
            "elapsed":  elapsed,
            "mode":     mode,
            "browsers": running_browsers,
            "warnings": pipeline_errors
        })
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode())

def start_server():
    server = HTTPServer(('localhost', PORT), ForensicHandler)
    print(f"\nBrowser Forensic Tool running at: http://localhost:{PORT}")
    print("Opening browser...")
    threading.Timer(1.0, lambda: webbrowser.open(f'http://localhost:{PORT}')).start()
    print("Press Ctrl+C to stop.\n")
    server.serve_forever()

if __name__ == "__main__":
    start_server()