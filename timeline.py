import sqlite3
import os
import json
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote_plus

_case        = os.environ.get("CASE_FOLDER", "output")
ARTIFACT_DIR = os.path.join(_case, "artifacts")
OUTPUT_DIR   = _case

BROWSERS = {
    "Chrome": os.path.join(ARTIFACT_DIR, "Chrome_History"),
    "Edge": os.path.join(ARTIFACT_DIR, "Edge_History"),
    "Firefox": os.path.join(ARTIFACT_DIR, "Firefox_places.sqlite"),
}

SESSION_GAP_MINUTES = 30

#timestamp conversion
def chrome_time_to_dt(chrome_time):
    if chrome_time == 0:
        return None
    try:
        timestamp = (chrome_time / 1000000) - 11644473600
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except:
        return None

#converts datetime object to readable string
def dt_to_str(dt):
    if dt is None:
        return "Unknown"
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

#to collect all events from all browser
def load_events():
    events = []

    for browser_name, db_path in BROWSERS.items():
        if not os.path.exists(db_path):
            print(f"{browser_name} history not found, skipping")
            continue

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if browser_name == "Firefox":
            cursor.execute("""
                SELECT url, title, last_visit_date
                FROM moz_places
                WHERE visit_count > 0
                ORDER BY last_visit_date ASC
            """)
            for row in cursor.fetchall():
                url, title, visit_time = row
                dt = firefox_time_to_dt(visit_time or 0)
                if dt:
                    events.append({
                        "datetime": dt,
                        "type": "visit",
                        "browser": browser_name,
                        "title": title or "No Title",
                        "url": url,
                        "detail": ""
                    })
        else:
            cursor.execute("""
                SELECT url, title, last_visit_time
                FROM urls
                ORDER BY last_visit_time ASC
            """)
            for row in cursor.fetchall():
                url, title, visit_time = row
                dt = chrome_time_to_dt(visit_time)
                if dt:
                    events.append({
                        "datetime": dt,
                        "type": "visit",
                        "browser": browser_name,
                        "title": title or "No Title",
                        "url": url,
                        "detail": ""
                    })
            try:
                cursor.execute("""
                    SELECT target_path, tab_url, start_time
                    FROM downloads
                    ORDER BY start_time ASC
                """)
                for row in cursor.fetchall():
                    target_path, tab_url, start_time = row
                    dt = chrome_time_to_dt(start_time)
                    if dt and tab_url:
                        events.append({
                            "datetime": dt,
                            "type": "download",
                            "browser": browser_name,
                            "title": os.path.basename(target_path) if target_path else "Unknown File",
                            "url": tab_url,
                            "detail": target_path or ""
                        })
            except:
                pass

        conn.close()

    events.sort(key=lambda x: x["datetime"])
    return events

def firefox_time_to_dt(firefox_time):
    if firefox_time == 0:
        return None
    try:
        timestamp = firefox_time / 1000000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except:
        return None

def build_sessions(events):
    sessions = []
    if not events:
        return sessions

    current_session = [events[0]]

    #calculates gap
    for i in range(1, len(events)):
        gap = (events[i]["datetime"] - events[i-1]["datetime"]).total_seconds() / 60
        if gap > SESSION_GAP_MINUTES:
            sessions.append(current_session)
            current_session = []
        current_session.append(events[i])

    sessions.append(current_session)
    return sessions

#separates event by browser
def detect_cross_browser(events):
    correlations = []
    window_minutes = 1440

    chrome_events  = [e for e in events if e["browser"] == "Chrome"]
    edge_events    = [e for e in events if e["browser"] == "Edge"]
    firefox_events = [e for e in events if e["browser"] == "Firefox"]

    pairs = [
        ("Chrome", "Edge", chrome_events, edge_events),
        ("Chrome", "Firefox", chrome_events, firefox_events),
        ("Edge", "Firefox", edge_events, firefox_events),
    ]

    seen_domains = set()

    for browser1, browser2, events1, events2 in pairs:
        for e1 in events1:
            for e2 in events2:
                diff = abs((e1["datetime"] - e2["datetime"]).total_seconds()) / 60
                try:
                    domain1 = urlparse(e1["url"]).netloc
                    domain2 = urlparse(e2["url"]).netloc
                    if (
                        domain1 and domain2 and
                        domain1 == domain2 and
                        diff <= window_minutes and
                        domain1 not in seen_domains
                    ):
                        seen_domains.add(domain1)
                        correlations.append({
                            "domain": domain1,
                            "browser1": browser1,
                            "browser2": browser2,
                            "time1": dt_to_str(e1["datetime"]),
                            "time2": dt_to_str(e2["datetime"]),
                            "gap_minutes": round(diff, 1)
                        })
                except:
                    pass

    return correlations[:10]

SUSPICIOUS_KEYWORDS = [
    "delete history", "clear history", "ccleaner", "bleachbit",
    "hide online activity", "anonymous browsing", "cover tracks",
    "delete digital footprint", "how to delete", "wipe history",
    "clear browsing", "remove traces", "hide activity",
    "tor browser", "private browsing", "incognito",
    "how to hide", "vpn hide", "anonymous"
]

def detect_anomalies(events, sessions):
    anomalies = []

    #loops through pairs of consecutive sessions
    for i in range(1, len(sessions)):
        last_event_prev = sessions[i-1][-1]
        first_event_cur = sessions[i][0]
        gap_minutes = (first_event_cur["datetime"] - last_event_prev["datetime"]).total_seconds() / 60
        gap_hours = gap_minutes / 60
        gap_start_hour = last_event_prev["datetime"].hour

        if gap_minutes > 120:
            anomaly = {
                "type": "TIMELINE_GAP",
                "message": f"Gap of {gap_hours:.1f} hours detected: {dt_to_str(last_event_prev['datetime'])} → {dt_to_str(first_event_cur['datetime'])}",
                "details": []
            }

            if gap_start_hour >= 19 and gap_hours >= 9:
                anomaly["details"].append("⚠ Large gap detected starting in evening hours")
                anomaly["details"].append("⚠ History deletion or private browsing session suspected")
                anomaly["details"].append("⚠ No records found for this period — possible anti-forensic activity")
            else:
                anomaly["details"].append("Gap consistent with normal inactivity (sleep/away)")

            anomalies.append(anomaly)

    return anomalies

def print_timeline(sessions, anomalies, correlations):
    print("\nFORENSIC TIMELINE REPORT")

    for i, session in enumerate(sessions, 1):
        start = dt_to_str(session[0]["datetime"])
        end = dt_to_str(session[-1]["datetime"])
        duration = (session[-1]["datetime"] - session[0]["datetime"]).total_seconds() / 60
        browsers_in_session = set(e["browser"] for e in session)

        print(f"\nSession {i}")
        print(f"Start: {start}")
        print(f"End: {end}")
        print(f"Duration: {duration:.1f} minutes")
        print(f"Events: {len(session)}")
        print(f"Browsers: {', '.join(browsers_in_session)}")

        for e in session:
            icon = "Download" if e["type"] == "download" else "Visit"
            print(f"  [{e['browser']}] {icon} | {dt_to_str(e['datetime'])} | {e['title'][:50]}")

    print("\nANOMALY DETECTION")
    if not anomalies:
        print("No anomalies detected.")
    else:
        for a in anomalies:
            print(f"\n[{a['type']}] {a['message']}")
            for d in a["details"]:
                print(f"  -> {d}")

    print("\nCROSS-BROWSER CORRELATION")
    if not correlations:
        print("No correlations found.")
    else:
        for c in correlations:
            print(f"\nDomain: {c['domain']}")
            print(f"  {c['browser1']}: {c['time1']}")
            print(f"  {c['browser2']}: {c['time2']}")
            print(f"  Gap: {c['gap_minutes']} minutes")

#complete dictionary of all results
def save_output(sessions, anomalies, correlations):
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_sessions": len(sessions),
        "total_events": sum(len(s) for s in sessions),
        "anomalies": anomalies,
        "correlations": [
            {
                "domain": c["domain"],
                "browser1": c.get("browser1", "Chrome"),
                "browser2": c.get("browser2", "Edge"),
                "time1": c.get("time1", ""),
                "time2": c.get("time2", ""),
                "gap_minutes": c["gap_minutes"]
            }
            for c in correlations
        ],
        "sessions": [
            {
                "session_number": i + 1,
                "start": dt_to_str(s[0]["datetime"]),
                "end": dt_to_str(s[-1]["datetime"]),
                "event_count": len(s),
                "browsers": list(set(e["browser"] for e in s)),
                "events": [
                    {
                        "time": dt_to_str(e["datetime"]),
                        "type": e["type"],
                        "browser": e["browser"],
                        "title": e["title"],
                        "url": e["url"]
                    }
                    for e in s
                ]
            }
            for i, s in enumerate(sessions)
        ]
    }

    path = os.path.join(OUTPUT_DIR, "timeline.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=4)
    print(f"\nTimeline saved: {path}")

def main():
    print("Starting timeline builder...")

    events = load_events()
    sessions = build_sessions(events)
    anomalies = detect_anomalies(events, sessions)
    correlations = detect_cross_browser(events)

    print_timeline(sessions, anomalies, correlations)
    save_output(sessions, anomalies, correlations)

    print("Done.")

if __name__ == "__main__":
    main()