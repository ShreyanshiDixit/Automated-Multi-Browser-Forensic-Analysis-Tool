import os
import json
import socket
import getpass
import platform
from datetime import datetime, timezone


def generate_chain_of_custody(case_folder, mode, elapsed, running_browsers, acquisition_log):
    """
    Generates a formal chain of custody log for the forensic examination.
    Written to the case folder as chain_of_custody.json and chain_of_custody.txt
    """

    examiner  = getpass.getuser()
    hostname  = socket.gethostname()
    os_info   = platform.platform()
    python_v  = platform.python_version()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Count what was collected
    total_acquired = 0
    total_failed   = 0
    total_missing  = 0
    artifact_summary = []

    for browser, artifacts in acquisition_log.get("browsers", {}).items():
        for a in artifacts:
            status = a.get("status", "unknown")
            if status == "acquired":
                total_acquired += 1
                artifact_summary.append({
                    "browser":   browser,
                    "artifact":  a.get("artifact"),
                    "status":    "ACQUIRED",
                    "sha256":    a.get("sha256", "N/A"),
                    "size_bytes": a.get("size_bytes", 0),
                    "source":    a.get("source", "N/A"),
                })
            elif status == "failed":
                total_failed += 1
                artifact_summary.append({
                    "browser":  browser,
                    "artifact": a.get("artifact"),
                    "status":   "FAILED",
                    "sha256":   "N/A",
                    "size_bytes": 0,
                    "source":   "N/A",
                })
            elif status == "missing":
                total_missing += 1
                artifact_summary.append({
                    "browser":  browser,
                    "artifact": a.get("artifact"),
                    "status":   "NOT FOUND",
                    "sha256":   "N/A",
                    "size_bytes": 0,
                    "source":   "N/A",
                })

    custody_data = {
        "case_folder":         case_folder,
        "examination_date":    timestamp,
        "acquisition_mode":    mode.upper(),
        "elapsed_seconds":     elapsed,
        "examiner":            examiner,
        "workstation":         hostname,
        "operating_system":    os_info,
        "python_version":      python_v,
        "browsers_targeted":   ["Chrome", "Edge", "Firefox"],
        "browsers_running":    running_browsers if mode == "live" else [],
        "artifacts_acquired":  total_acquired,
        "artifacts_failed":    total_failed,
        "artifacts_missing":   total_missing,
        "artifact_details":    artifact_summary,
        "notes": (
            "Live acquisition performed using Volume Shadow Copy (VSS). "
            "Locked files accessed via VSS where available, "
            "direct copy used as fallback."
            if mode == "live"
            else
            "Dead acquisition performed. Browsers must have been closed "
            "during collection for file integrity."
        )
    }

    # Save JSON version
    json_path = os.path.join(case_folder, "chain_of_custody.json")
    with open(json_path, "w") as f:
        json.dump(custody_data, f, indent=4)

    # Save human-readable text version
    txt_path = os.path.join(case_folder, "chain_of_custody.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("       CHAIN OF CUSTODY — BROWSER FORENSIC EXAMINATION\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Case Folder       : {case_folder}\n")
        f.write(f"Examination Date  : {timestamp}\n")
        f.write(f"Acquisition Mode  : {mode.upper()}\n")
        f.write(f"Elapsed Time      : {elapsed} seconds\n")
        f.write(f"Examiner          : {examiner}\n")
        f.write(f"Workstation       : {hostname}\n")
        f.write(f"Operating System  : {os_info}\n")
        f.write(f"Python Version    : {python_v}\n\n")

        if mode == "live" and running_browsers:
            f.write(f"Browsers Running During Acquisition:\n")
            for b in running_browsers:
                f.write(f"  - {b}\n")
            f.write("\n")

        f.write(f"Artifact Summary:\n")
        f.write(f"  Acquired : {total_acquired}\n")
        f.write(f"  Failed   : {total_failed}\n")
        f.write(f"  Missing  : {total_missing}\n\n")

        f.write("-" * 60 + "\n")
        f.write("ARTIFACT DETAILS\n")
        f.write("-" * 60 + "\n\n")

        for a in artifact_summary:
            f.write(f"Browser  : {a['browser']}\n")
            f.write(f"Artifact : {a['artifact']}\n")
            f.write(f"Status   : {a['status']}\n")
            if a['sha256'] != "N/A":
                f.write(f"SHA-256  : {a['sha256']}\n")
                f.write(f"Size     : {a['size_bytes']} bytes\n")
                f.write(f"Source   : {a['source']}\n")
            f.write("\n")

        f.write("=" * 60 + "\n")
        f.write("Notes:\n")
        f.write(custody_data["notes"] + "\n")
        f.write("=" * 60 + "\n")

    print(f"\nChain of custody saved: {txt_path}")
    return custody_data