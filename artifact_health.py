import os
import json
import sqlite3
from datetime import datetime, timezone

_case        = os.environ.get("CASE_FOLDER", "output")
ARTIFACT_DIR = os.path.join(_case, "artifacts")
OUTPUT_DIR   = _case

ARTIFACTS_TO_CHECK = [
    {
        "browser": "Chrome",
        "name": "Browsing History",
        "file": "Chrome_History",
        "table": "urls",
        "description": "URLs visited by the user"
    },
    {
        "browser": "Chrome",
        "name": "Downloads",
        "file": "Chrome_History",
        "table": "downloads",
        "description": "Files downloaded by the user"
    },
    {
        "browser": "Chrome",
        "name": "Cookies",
        "file": "Chrome_Cookies",
        "table": "cookies",
        "description": "Session and login cookies"
    },
    {
        "browser": "Edge",
        "name": "Browsing History",
        "file": "Edge_History",
        "table": "urls",
        "description": "URLs visited by the user"
    },
    {
        "browser": "Edge",
        "name": "Downloads",
        "file": "Edge_History",
        "table": "downloads",
        "description": "Files downloaded by the user"
    },
    {
        "browser": "Edge",
        "name": "Cookies",
        "file": "Edge_Cookies",
        "table": "cookies",
        "description": "Session and login cookies"
    },
    {
    "browser": "Firefox",
    "name": "Browsing History",
    "file": "Firefox_places.sqlite",
    "table": "moz_places",
    "description": "URLs visited by the user"
    },
    {
    "browser": "Firefox",
    "name": "Cookies",
    "file": "Firefox_cookies.sqlite",
    "table": "moz_cookies",
    "description": "Session and login cookies"
    },
]

def check_artifact(artifact):
    filepath = os.path.join(ARTIFACT_DIR, artifact["file"])

    if not os.path.exists(filepath):
        # Check acquisition log to see if it was locked vs genuinely missing
        note = "File not found in acquired artifacts"
        status = "MISSING"

        # Check logs for locked status
        log_dir = "output/logs"
        if os.path.exists(log_dir):
            for log_file in os.listdir(log_dir):
                try:
                    with open(os.path.join(log_dir, log_file), "r") as f:
                        log_data = json.load(f)
                    for browser_logs in log_data.get("browsers", {}).values():
                        for entry in browser_logs:
                            if entry.get("status") == "locked":
                                if artifact["browser"].lower() in log_file.lower() or True:
                                    note = "File locked by running browser — run as Administrator"
                                    status = "LOCKED"
                except:
                    pass
        return {
            "browser": artifact["browser"],
            "name": artifact["name"],
            "status": "MISSING",
            "description": artifact["description"],
            "records": 0,
            "note": "File not found in acquired artifacts"
        }

    try:
        conn = sqlite3.connect(filepath)
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {artifact['table']}")
        count = cursor.fetchone()[0]
        conn.close()

        if count == 0:
            status = "EMPTY"
            note = "Table exists but no records found - possible deletion"
        else:
            status = "RECOVERED"
            note = f"{count} records extracted successfully"

        return {
            "browser": artifact["browser"],
            "name": artifact["name"],
            "status": status,
            "description": artifact["description"],
            "records": count,
            "note": note
        }

    except Exception as e:
        return {
            "browser": artifact["browser"],
            "name": artifact["name"],
            "status": "ERROR",
            "description": artifact["description"],
            "records": 0,
            "note": str(e)
        }

def generate_health_report():
    print("Running artifact health check...")

    results = []
    for artifact in ARTIFACTS_TO_CHECK:
        result = check_artifact(artifact)
        results.append(result)

        if result["status"] in ("RECOVERED", "PRESENT"):
            icon = "OK"
        elif result["status"] == "EMPTY":
            icon = "EMPTY"
        else:
            icon = "MISSING"

        print(f"  [{result['browser']}] {result['name']} - {icon} - {result['note']}")

    recovered = sum(
        1 for r in results
        if r["status"] in ("RECOVERED", "PRESENT")
    )
    locked = sum(
        1 for r in results
        if r["status"] == "LOCKED"
    )
    total = len(results)
    score = f"{recovered}/{total}"
    lock_note = f" ({locked} locked — run as Administrator)" if locked > 0 else ""
    print(f"\nHealth Score: {score} artifacts recovered{lock_note}")

    print(f"\nHealth Score: {score} artifacts recovered")

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "browsers": ["Chrome", "Edge", "Firefox"],
        "health_score": score,
        "artifacts": results
    }

    path = os.path.join(OUTPUT_DIR, "artifact_health.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"Saved: {path}")
    return output

if __name__ == "__main__":
    generate_health_report()