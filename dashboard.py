import json
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote_plus


def generate_dashboard(mode="dead"):
    _case         = os.environ.get("CASE_FOLDER", "output")
    TIMELINE_JSON = os.path.join(_case, "timeline.json")
    HEALTH_JSON   = os.path.join(_case, "artifact_health.json")
    DELETED_JSON  = os.path.join(_case, "deleted_recovery.json")
    OUTPUT_HTML   = os.path.join(_case, "dashboard.html")

    with open(TIMELINE_JSON, "r") as f:
        data = json.load(f)
    with open(HEALTH_JSON, "r") as f:
        health_data = json.load(f)
    try:
        with open(DELETED_JSON, "r") as f:
            deleted_data = json.load(f)
    except:
        deleted_data = None
    try:
        with open(os.path.join(_case, "dns_analysis.json"), "r") as f:
            dns_data = json.load(f)
    except:
        dns_data = None

    sessions       = data["sessions"]
    anomalies      = data["anomalies"]
    correlations   = data.get("correlations", [])
    total_events   = data["total_events"]
    total_sessions = data["total_sessions"]
    generated_at   = data["generated_at"]

    session_labels = [f"S{s['session_number']}" for s in sessions]
    session_counts = [s["event_count"] for s in sessions]

    hourly = [0] * 24
    for session in sessions:
        for event in session["events"]:
            try:
                hour = int(event["time"][11:13])
                hourly[hour] += 1
            except:
                pass

    download_count = sum(1 for s in sessions for e in s["events"] if e["type"] == "download")
    chrome_count   = sum(1 for s in sessions for e in s["events"] if e.get("browser") == "Chrome")
    edge_count     = sum(1 for s in sessions for e in s["events"] if e.get("browser") == "Edge")
    firefox_count  = sum(1 for s in sessions for e in s["events"] if e.get("browser") == "Firefox")

    gap_banners = []
    for a in anomalies:
        if a["type"] == "TIMELINE_GAP":
            is_suspicious = any(
                "suspected" in d or "anti-forensic" in d
                for d in a.get("details", [])
            )
            gap_banners.append({
                "message": a["message"],
                "details": a["details"],
                "is_suspicious": is_suspicious
            })

    session_cards_html = ""
    for idx, session in enumerate(sessions):
        events_html = ""
        for e in session["events"]:
            icon       = "DL" if e["type"] == "download" else "WEB"
            type_class = "download" if e["type"] == "download" else "visit"
            browser    = e.get("browser", "")
            if browser == "Chrome":
                browser_cls = "browser-chrome"
            elif browser == "Edge":
                browser_cls = "browser-edge"
            else:
                browser_cls = "browser-firefox"
            title      = e["title"][:70] + "..." if len(e["title"]) > 70 else e["title"]
            url        = e["url"][:80] + "..." if len(e["url"]) > 80 else e["url"]
            safe_title = e["title"].lower().replace('"', '').replace("'", "")
            safe_url   = e["url"].lower().replace('"', '').replace("'", "")
            events_html += f"""
            <div class="event-row" data-type="{type_class}" data-title="{safe_title}" data-url="{safe_url}" data-browser="{browser.lower()}">
                <span class="event-icon {'dl' if e['type'] == 'download' else ''}">{icon}</span>
                <div class="event-info">
                    <span class="browser-badge {browser_cls}">{browser}</span>
                    <div class="event-title">{title}</div>
                    <div class="event-url">{url}</div>
                    <div class="event-time">{e["time"]}</div>
                </div>
            </div>"""

        gap_banner_html = ""
        if idx < len(gap_banners):
            banner     = gap_banners[idx]
            banner_cls = "gap-banner-suspicious" if banner["is_suspicious"] else "gap-banner-normal"
            icon       = "[CRITICAL]" if banner["is_suspicious"] else "[NOTICE]"
            details    = " &nbsp;|&nbsp; ".join(banner["details"])
            gap_banner_html = f"""
            <div class="gap-banner {banner_cls}">
                <div class="gap-banner-title">{icon} TIMELINE GAP DETECTED</div>
                <div class="gap-banner-msg">{banner["message"]}</div>
                <div class="gap-banner-details">{details}</div>
            </div>"""

        browsers_in_session = session.get("browsers", [])
        browser_tags = ""
        for b in browsers_in_session:
            bc = "browser-chrome" if b == "Chrome" else "browser-edge" if b == "Edge" else "browser-firefox"
            browser_tags += f'<span class="browser-badge {bc}">{b}</span>'

        session_cards_html += f"""
        {gap_banner_html}
        <div class="session-card" id="session-{idx}">
            <div class="session-header" onclick="toggleSession({idx})">
                <div class="session-left">
                    <span class="session-label">Session {session["session_number"]}</span>
                    {browser_tags}
                    <span class="session-meta">{session["event_count"]} events &nbsp;|&nbsp; {session["start"]} → {session["end"]}</span>
                </div>
                <span class="toggle-icon" id="toggle-{idx}">▼</span>
            </div>
            <div class="session-events hidden" id="events-{idx}">
                {events_html}
            </div>
        </div>"""

    anomalies_html = ""
    if not anomalies:
        anomalies_html = '<div class="no-anomaly">No anomalies detected.</div>'
    else:
        for a in anomalies:
            if a["type"] != "SUSPICIOUS_SEARCHES":
                details_html = "".join(
                    f'<div class="anomaly-detail">→ {d}</div>'
                    for d in a.get("details", [])
                )
                anomalies_html += f"""
                <div class="anomaly-card">
                    <div class="anomaly-type">{a["type"]}</div>
                    <div class="anomaly-message">{a["message"]}</div>
                    {details_html}
                </div>"""

    correlations_html = ""
    if not correlations:
        correlations_html = '<div class="no-anomaly">No cross-browser correlations found.</div>'
    else:
        for c in correlations:
            b1    = c.get("browser1", "Chrome")
            b2    = c.get("browser2", "Edge")
            t1    = c.get("time1", c.get("chrome_time", ""))
            t2    = c.get("time2", c.get("edge_time", ""))
            b1cls = "browser-chrome" if b1 == "Chrome" else "browser-edge" if b1 == "Edge" else "browser-firefox"
            b2cls = "browser-chrome" if b2 == "Chrome" else "browser-edge" if b2 == "Edge" else "browser-firefox"
            correlations_html += f"""
            <div class="correlation-card">
                <div class="correlation-domain">{c["domain"]}</div>
                <div class="correlation-row">
                    <span class="browser-badge {b1cls}">{b1}</span>
                    <span class="correlation-time">{t1}</span>
                </div>
                <div class="correlation-row">
                    <span class="browser-badge {b2cls}">{b2}</span>
                    <span class="correlation-time">{t2}</span>
                </div>
                <div class="correlation-gap">Gap: {c["gap_minutes"]} minutes apart</div>
            </div>"""

    chrome_artifacts  = [a for a in health_data["artifacts"] if a["browser"] == "Chrome"]
    edge_artifacts    = [a for a in health_data["artifacts"] if a["browser"] == "Edge"]
    firefox_artifacts = [a for a in health_data["artifacts"] if a["browser"] == "Firefox"]

    def build_health_rows(artifacts):
        html = ""
        for artifact in artifacts:
            status = artifact["status"]
            if status in ("RECOVERED", "PRESENT"):
                badge_class = "badge-green"
                icon = "✅"
            elif status == "EMPTY":
                badge_class = "badge-yellow"
                icon = "⚠️"
            elif status == "LOCKED":
                badge_class = "badge-locked"
                icon = "🔒"
            else:
                badge_class = "badge-red"
                icon = "❌"
            records_str = f"{artifact['records']} records" if artifact.get("records") is not None else "N/A"
            html += f"""
            <div class="health-row">
                <span class="health-icon">{icon}</span>
                <div class="health-info">
                    <div class="health-name">{artifact["name"]}</div>
                    <div class="health-desc">{artifact["description"]}</div>
                </div>
                <div class="health-right">
                    <span class="badge {badge_class}">{status}</span>
                    <div class="health-records">{records_str}</div>
                    <div class="health-note">{artifact["note"]}</div>
                </div>
            </div>"""
        return html

    score       = health_data["health_score"]
    score_parts = score.split("/")
    score_color = "#16a34a" if score_parts[0] == score_parts[1] else "#d97706"

    deleted_html = ""
    if deleted_data:
        deleted_count = len(deleted_data.get("potentially_deleted", []))
        active_count  = deleted_data.get("total_active_urls", 0)
        raw_count     = deleted_data.get("total_raw_urls", 0)
        deleted_items = ""
        for url in deleted_data.get("potentially_deleted", [])[:20]:
            clean_url = url[:90] + "..." if len(url) > 90 else url
            deleted_items += f"""
            <div class="deleted-row">
                <span class="deleted-icon">&#9632;</span>
                <div class="deleted-url">{clean_url}</div>
            </div>"""
        more_label = f'<div style="font-size:11px;color:#6b7280;margin-top:12px;">Showing 20 of {deleted_count} recovered fragments</div>' if deleted_count > 20 else ""
        deleted_html = f"""
        <div class="health-card">
            <div class="health-score-row">
                <span class="health-score-label">SQLite Carving — Raw Binary Analysis</span>
                <span class="health-score-value" style="color:#dc2626;">{deleted_count} fragments recovered</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">
                <div style="background:#f0fdf4;border:1px solid #16a34a;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:32px;font-weight:700;color:#16a34a;">{active_count}</div>
                    <div style="font-size:11px;color:#6b7280;margin-top:6px;">Active URLs in Database</div>
                </div>
                <div style="background:#fffbeb;border:1px solid #d97706;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:32px;font-weight:700;color:#d97706;">{raw_count}</div>
                    <div style="font-size:11px;color:#6b7280;margin-top:6px;">Raw URL Hits in Binary</div>
                </div>
                <div style="background:#fff5f5;border:1px solid #dc2626;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:32px;font-weight:700;color:#dc2626;">{deleted_count}</div>
                    <div style="font-size:11px;color:#6b7280;margin-top:6px;">Potentially Deleted</div>
                </div>
            </div>
            <div style="font-size:12px;color:#6b7280;margin-bottom:16px;line-height:1.6;">
                URLs found in raw database binary but absent from active records. These may represent deleted browsing history fragments.
            </div>
            {deleted_items}
            {more_label}
        </div>"""

    dns_html = ""
    if dns_data:
        dns_count = len(dns_data.get("suspicious_domains", []))
        dns_items = ""
        for domain in dns_data.get("suspicious_domains", []):
            dns_items += f"""
            <div class="deleted-row">
                <span class="deleted-icon">🔴</span>
                <div class="deleted-url">{domain}</div>
            </div>"""
        dns_html = f"""
        <div class="health-card">
            <div class="health-score-row">
                <span class="health-score-label">DNS Cache vs Browser History Comparison</span>
                <span class="health-score-value" style="color:#dc2626;">{dns_count} suspicious domain(s)</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
                <div style="background:#f0fdf4;border:1px solid #16a34a;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:28px;font-weight:700;color:#16a34a;">{dns_data.get("total_dns_domains", 0)}</div>
                    <div style="font-size:11px;color:#6b7280;margin-top:6px;">DNS Cache Domains</div>
                </div>
                <div style="background:#fff5f5;border:1px solid #dc2626;border-radius:8px;padding:16px;text-align:center;">
                    <div style="font-size:28px;font-weight:700;color:#dc2626;">{dns_count}</div>
                    <div style="font-size:11px;color:#6b7280;margin-top:6px;">Not in Browser History</div>
                </div>
            </div>
            <div style="font-size:12px;color:#6b7280;margin-bottom:16px;line-height:1.6;">
                Domains found in DNS cache but absent from browser history. These may have been visited during incognito mode or after history deletion.
            </div>
            {dns_items}
        </div>"""

    all_events_for_js = []
    for session in sessions:
        for e in session["events"]:
            all_events_for_js.append({
                "browser": e.get("browser", ""),
                "title":   e.get("title", ""),
                "url":     e.get("url", ""),
                "time":    e.get("time", ""),
                "type":    e.get("type", "")
            })

    mode_label = "Live Acquisition" if mode == "live" else "Dead Acquisition"
    # Build live browser status HTML
    live_browsers_html = ""
    if mode == "live":
        try:
            acq_time = data.get("live_acquisition_time", "Unknown")
            running = data.get("running_browsers", [])
            running_html = ""
            if running:
                badges = ""
                for b in running:
                    cls = "browser-chrome" if b == "Chrome" else "browser-edge" if b == "Edge" else "browser-firefox"
                    badges += f'<span class="browser-badge {cls} running-badge">{b} — ACTIVE</span> '
                running_html = f"""
                <div style="margin-bottom:16px;padding:12px 16px;background:#f0fdf4;
                            border:1px solid #16a34a;border-radius:8px;">
                    <div style="font-size:12px;color:#6b7280;margin-bottom:8px;font-weight:600;">
                        BROWSERS RUNNING DURING ACQUISITION
                    </div>
                    {badges}
                </div>"""
            live_browsers_html = f"""
            <div class="section">
                <div class="section-title">Live Acquisition — Browser Status at Time of Collection</div>
                <div class="health-card">
                    <div class="health-score-row">
                        <span class="health-score-label">Acquisition Time</span>
                        <span class="health-score-value" style="color:#16a34a;">{acq_time}</span>
                    </div>
                    {running_html}
                </div>
            </div>"""
        except Exception as e:
            live_browsers_html = ""

    report_rows = ""
    for s in sessions:
        for e in s["events"]:
            report_rows += f"<tr><td>{e['time']}</td><td>{e['browser']}</td><td>{e['title'][:60]}</td><td style='color:#1a73e8'>{e['url'][:80]}</td><td>{e['type']}</td></tr>"

    anomaly_rows = ""
    for a in anomalies:
        detail_str = " | ".join(a.get("details", []))
        anomaly_rows += f"<tr><td>{a['type']}</td><td>{a['message']}</td><td>{detail_str}</td></tr>"

    health_rows = ""
    for a in health_data["artifacts"]:
        health_rows += f"<tr><td>{a['browser']}</td><td>{a['name']}</td><td>{a['status']}</td><td>{a.get('records','N/A')}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Browser Forensic Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f4f6f9; color: #1a2744; min-height: 100vh; }}
        .header {{
            background: #1a2744;
            border-bottom: 3px solid #2e5baf;
            padding: 0 40px;
            height: 56px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .header h1 {{ font-size: 15px; font-weight: 600; color: #ffffff; letter-spacing: 0.3px; }}
        .header .meta {{ font-size: 11px; color: #8a9bb5; }}
        .download-btn {{
            background: #2e5baf;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 18px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            letter-spacing: 0.2px;
            transition: background 0.2s;
        }}
        .download-btn:hover {{ background: #1a2744; border: 1px solid #4a7fd4; }}
        .container {{ padding: 28px 40px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 24px; }}
        .stat-card {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-top: 3px solid #2e5baf;
            border-radius: 4px;
            padding: 16px;
            text-align: center;
        }}
        .stat-value {{ font-size: 28px; font-weight: 700; color: #2e5baf; }}
        .stat-label {{ font-size: 11px; color: #5a6a80; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .charts-grid {{ display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
        .chart-card {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 4px;
            padding: 20px;
        }}
        .chart-card h3 {{ font-size: 11px; color: #5a6a80; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; border-bottom: 1px solid #dde2ea; padding-bottom: 8px; }}
        .section {{ margin-bottom: 24px; }}
        .section-title {{
            font-size: 13px;
            font-weight: 600;
            color: #1a2744;
            margin-bottom: 14px;
            padding: 10px 14px;
            background: #eef2fb;
            border-left: 4px solid #2e5baf;
            border-radius: 0 4px 4px 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .browser-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 600; letter-spacing: 0.3px; margin-right: 6px; }}
        .browser-chrome  {{ background: #e8f0fe; color: #1a56a0; border: 1px solid #b8d0f5; }}
        .browser-edge    {{ background: #e6f4ea; color: #1a6e3a; border: 1px solid #b0dfc0; }}
        .browser-firefox {{ background: #f3e8fd; color: #6b22b0; border: 1px solid #d5b0f5; }}
        .running-badge {{ font-weight: 700; }}
        .anomaly-card {{
            background: #fff8f8;
            border: 1px solid #e8b4b4;
            border-left: 4px solid #c0392b;
            border-radius: 4px;
            padding: 14px 16px;
            margin-bottom: 10px;
        }}
        .anomaly-type {{ font-size: 10px; font-weight: 700; color: #c0392b; letter-spacing: 1px; margin-bottom: 5px; text-transform: uppercase; }}
        .anomaly-message {{ font-size: 13px; color: #1a2744; margin-bottom: 6px; }}
        .anomaly-detail {{ font-size: 12px; color: #7a5500; margin-top: 3px; padding-left: 10px; border-left: 2px solid #e8a800; }}
        .no-anomaly {{ color: #1a6e3a; font-size: 13px; padding: 12px 16px; background: #f0faf4; border-radius: 4px; border: 1px solid #b0dfc0; }}
        .correlations-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }}
        .correlation-card {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-left: 4px solid #2e5baf;
            border-radius: 4px;
            padding: 14px;
        }}
        .correlation-domain {{ font-size: 13px; font-weight: 600; color: #2e5baf; margin-bottom: 10px; font-family: monospace; }}
        .correlation-row {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
        .correlation-time {{ font-size: 11px; color: #5a6a80; font-family: monospace; }}
        .correlation-gap {{ font-size: 11px; color: #7a5500; margin-top: 6px; padding-top: 6px; border-top: 1px solid #dde2ea; }}
        .search-filter-row {{ display: flex; gap: 8px; margin-bottom: 14px; align-items: center; flex-wrap: wrap; }}
        .search-box {{
            flex: 1;
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 4px;
            padding: 8px 14px;
            color: #1a2744;
            font-size: 13px;
            outline: none;
            min-width: 200px;
        }}
        .search-box:focus {{ border-color: #2e5baf; box-shadow: 0 0 0 2px rgba(46,91,175,0.15); }}
        .search-box::placeholder {{ color: #8a9bb5; }}
        .filter-btn {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 4px;
            padding: 7px 14px;
            color: #5a6a80;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
            font-weight: 500;
        }}
        .filter-btn:hover {{ border-color: #2e5baf; color: #2e5baf; }}
        .filter-btn.active {{ background: #2e5baf; border-color: #2e5baf; color: #ffffff; }}
        .results-count {{ font-size: 11px; color: #5a6a80; margin-left: auto; }}
        .gap-banner {{ border-radius: 4px; padding: 12px 16px; margin: 10px 0; border-left: 4px solid; }}
        .gap-banner-suspicious {{ background: #fff8f8; border-color: #c0392b; }}
        .gap-banner-normal {{ background: #fffbf0; border-color: #e8a800; }}
        .gap-banner-title {{ font-size: 10px; font-weight: 700; letter-spacing: 1px; margin-bottom: 4px; text-transform: uppercase; }}
        .gap-banner-suspicious .gap-banner-title {{ color: #c0392b; }}
        .gap-banner-normal .gap-banner-title {{ color: #7a5500; }}
        .gap-banner-msg {{ font-size: 12px; color: #1a2744; margin-bottom: 3px; font-family: monospace; }}
        .gap-banner-details {{ font-size: 11px; color: #5a6a80; }}
        .session-card {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 4px;
            margin-bottom: 8px;
            overflow: hidden;
        }}
        .session-card:hover {{ border-color: #2e5baf; }}
        .session-header {{
            background: #f4f6f9;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            border-bottom: 1px solid #dde2ea;
        }}
        .session-left {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .session-label {{ font-weight: 700; color: #2e5baf; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .session-meta {{ font-size: 11px; color: #5a6a80; font-family: monospace; }}
        .toggle-icon {{ color: #8a9bb5; font-size: 11px; transition: transform 0.3s; }}
        .toggle-icon.collapsed {{ transform: rotate(-90deg); }}
        .session-events {{ padding: 8px 16px; max-height: 400px; overflow-y: auto; background: #ffffff; }}
        .session-events.hidden {{ display: none; }}
        .event-row {{
            display: flex;
            gap: 10px;
            padding: 7px 0;
            border-bottom: 1px solid #f0f2f5;
            align-items: flex-start;
        }}
        .event-row:hover {{ background: #f4f6f9; padding-left: 4px; }}
        .event-row:last-child {{ border-bottom: none; }}
        .event-row.hidden {{ display: none; }}
        .event-icon {{
            font-size: 9px;
            font-weight: 700;
            color: #ffffff;
            background: #2e5baf;
            padding: 2px 5px;
            border-radius: 2px;
            margin-top: 3px;
            letter-spacing: 0.3px;
            min-width: 28px;
            text-align: center;
        }}
        .event-icon.dl {{ background: #1a6e3a; }}
        .event-title {{ font-size: 12px; color: #1a2744; margin-bottom: 2px; margin-top: 1px; font-weight: 500; }}
        .event-url {{ font-size: 11px; color: #2e5baf; word-break: break-all; font-family: monospace; }}
        .event-time {{ font-size: 10px; color: #8a9bb5; margin-top: 2px; font-family: monospace; }}
        .health-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }}
        .health-card {{ background: #ffffff; border: 1px solid #dde2ea; border-radius: 4px; padding: 16px; }}
        .health-score-row {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid #dde2ea; }}
        .health-score-label {{ font-size: 12px; color: #5a6a80; font-weight: 500; }}
        .health-score-value {{ font-size: 16px; font-weight: 700; }}
        .health-browser-title {{ font-size: 12px; font-weight: 700; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #dde2ea; }}
        .health-row {{ display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid #f0f2f5; }}
        .health-row:last-child {{ border-bottom: none; }}
        .health-icon {{ font-size: 14px; }}
        .health-info {{ flex: 1; }}
        .health-name {{ font-size: 12px; font-weight: 600; color: #1a2744; }}
        .health-desc {{ font-size: 10px; color: #8a9bb5; margin-top: 2px; }}
        .health-right {{ text-align: right; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: 0.3px; }}
        .badge-green {{ background: #e8f5ee; color: #1a6e3a; border: 1px solid #b0dfc0; }}
        .badge-yellow {{ background: #fff8e6; color: #7a5500; border: 1px solid #e8cb80; }}
        .badge-red {{ background: #fff0f0; color: #c0392b; border: 1px solid #f0b0b0; }}
        .health-records {{ font-size: 10px; color: #2e5baf; margin-top: 2px; font-weight: 500; font-family: monospace; }}
        .health-note {{ font-size: 10px; color: #8a9bb5; margin-top: 2px; }}
        .deleted-row {{ display: flex; gap: 10px; padding: 7px 0; border-bottom: 1px solid #f0f2f5; align-items: flex-start; }}
        .deleted-row:last-child {{ border-bottom: none; }}
        .deleted-icon {{ font-size: 12px; margin-top: 1px; color: #c0392b; font-weight: 700; }}
        .deleted-url {{ font-size: 11px; color: #c0392b; word-break: break-all; line-height: 1.5; font-family: monospace; }}
        .search-input-row {{ display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }}
        .keyword-search-box {{
            flex: 1;
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-radius: 4px;
            padding: 8px 14px;
            color: #1a2744;
            font-size: 13px;
            outline: none;
        }}
        .keyword-search-box:focus {{ border-color: #2e5baf; box-shadow: 0 0 0 2px rgba(46,91,175,0.15); }}
        .keyword-search-box::placeholder {{ color: #8a9bb5; }}
        .keyword-search-btn {{
            background: #2e5baf;
            border: none;
            border-radius: 4px;
            padding: 8px 18px;
            color: #ffffff;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
            letter-spacing: 0.2px;
        }}
        .keyword-search-btn:hover {{ background: #1a2744; }}
        .keyword-result-item {{
            background: #ffffff;
            border: 1px solid #dde2ea;
            border-left: 3px solid #2e5baf;
            border-radius: 4px;
            padding: 10px 14px;
            margin-bottom: 6px;
        }}
        .keyword-result-title {{ font-size: 12px; font-weight: 600; color: #1a2744; margin-bottom: 3px; }}
        .keyword-result-url {{ font-size: 11px; color: #2e5baf; word-break: break-all; margin-bottom: 3px; font-family: monospace; }}
        .keyword-result-meta {{ font-size: 10px; color: #8a9bb5; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Browser Forensic Dashboard</h1>
        <div style="display:flex;align-items:center;gap:20px;">
            <div class="meta">
                Generated: {generated_at} &nbsp;|&nbsp;
                Mode: <span style="color:#f59e0b;font-weight:600;">{mode_label}</span>
                &nbsp;|&nbsp;
                <span style="color:#58a6ff">Chrome</span> +
                <span style="color:#4ade80">Edge</span> +
                <span style="color:#c084fc">Firefox</span>
            </div>
            <button class="download-btn" onclick="downloadReport()">Download Report</button>
        </div>
    </div>

    <div class="container">

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{total_events}</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_sessions}</div>
                <div class="stat-label">Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{download_count}</div>
                <div class="stat-label">Downloads</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#1a73e8">{chrome_count}</div>
                <div class="stat-label">Chrome Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#1e8e3e">{edge_count}</div>
                <div class="stat-label">Edge Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#8430ce">{firefox_count}</div>
                <div class="stat-label">Firefox Events</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Hourly Activity Heatmap</h3>
                <canvas id="hourlyChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Events per Session</h3>
                <canvas id="sessionChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>Browser Breakdown</h3>
                <canvas id="browserChart"></canvas>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Keyword Search — Analyst Investigation</div>
            <div style="background:#ffffff;border:1px solid #e0e4ea;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,0.06);">
                <div style="font-size:13px;color:#6b7280;margin-bottom:12px;">
                    Enter any keyword, domain or phrase to search across all browser history.
                </div>
                <div class="search-input-row">
                    <input type="text" class="keyword-search-box" id="analystKeyword"
                        placeholder="e.g. delete history, ccleaner, tor, vpn, incognito..."
                        onkeydown="if(event.key==='Enter') runKeywordSearch()" />
                    <button class="keyword-search-btn" onclick="runKeywordSearch()">Search</button>
                    <button class="keyword-search-btn" style="background:#6b7280;" onclick="clearKeywordSearch()">Clear</button>
                </div>
                <div id="keywordResults" style="margin-top:16px;"></div>
            </div>
        </div>

        {live_browsers_html}
        
        <div class="section">
            <div class="section-title">Anti-Forensics &amp; Anomaly Detection</div>
            {anomalies_html}
        </div>

        <div class="section">
            <div class="section-title">Cross-Browser Correlation Analysis</div>
            <div class="correlations-grid">{correlations_html}</div>
        </div>

        <div class="section">
            <div class="section-title">Artifact Acquisition Status</div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
                <span style="font-size:13px;color:#6b7280;">Overall Recovery Score</span>
                <span style="font-size:20px;font-weight:700;color:{score_color};">{score} artifacts recovered</span>
            </div>
            <div class="health-grid">
                <div class="health-card">
                    <div class="health-browser-title"><span class="browser-badge browser-chrome">Chrome</span></div>
                    {build_health_rows(chrome_artifacts)}
                </div>
                <div class="health-card">
                    <div class="health-browser-title"><span class="browser-badge browser-edge">Edge</span></div>
                    {build_health_rows(edge_artifacts)}
                </div>
                <div class="health-card">
                    <div class="health-browser-title"><span class="browser-badge browser-firefox">Firefox</span></div>
                    {build_health_rows(firefox_artifacts) if firefox_artifacts else '<div class="no-anomaly" style="font-size:12px;">No Firefox artifacts found.</div>'}
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Deleted Record Recovery — SQLite Carving</div>
            {deleted_html if deleted_html else '<div class="no-anomaly">No deleted recovery data.</div>'}
        </div>

        <div class="section">
            <div class="section-title">DNS Cache Analysis — Incognito Session Detection</div>
            {dns_html if dns_html else '<div class="no-anomaly">No DNS analysis data available.</div>'}
        </div>

        <div class="section">
            <div class="section-title">Chronological Browser Activity Timeline</div>
            <div class="search-filter-row">
                <input type="text" class="search-box" id="searchBox"
                    placeholder="Search by title or URL"
                    oninput="applyFilters()" />
                <button class="filter-btn active" id="btn-all"      onclick="setFilter('all')">All</button>
                <button class="filter-btn"         id="btn-visit"   onclick="setFilter('visit')">Visits</button>
                <button class="filter-btn"         id="btn-download" onclick="setFilter('download')">Downloads</button>
                <button class="filter-btn"         id="btn-chrome"  onclick="setBrowser('chrome')">Chrome</button>
                <button class="filter-btn"         id="btn-edge"    onclick="setBrowser('edge')">Edge</button>
                <button class="filter-btn"         id="btn-firefox" onclick="setBrowser('firefox')">Firefox</button>
                <span class="results-count" id="resultsCount"></span>
            </div>
            {session_cards_html}
        </div>

    </div>

    <script>
        new Chart(document.getElementById('hourlyChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps([f"{h:02d}:00" for h in range(24)])},
                datasets: [{{ label: 'Events', data: {json.dumps(hourly)}, backgroundColor: '#1a73e8', borderRadius: 4 }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#6b7280', maxRotation: 90 }}, grid: {{ color: '#f3f4f6' }} }},
                    y: {{ ticks: {{ color: '#6b7280' }}, grid: {{ color: '#f3f4f6' }} }}
                }}
            }}
        }});

        new Chart(document.getElementById('sessionChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(session_labels)},
                datasets: [{{ label: 'Events', data: {json.dumps(session_counts)}, backgroundColor: '#16a34a', borderRadius: 6 }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#6b7280' }}, grid: {{ color: '#f3f4f6' }} }},
                    y: {{ ticks: {{ color: '#6b7280' }}, grid: {{ color: '#f3f4f6' }} }}
                }}
            }}
        }});

        new Chart(document.getElementById('browserChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Chrome', 'Edge', 'Firefox'],
                datasets: [{{ data: [{chrome_count}, {edge_count}, {firefox_count}], backgroundColor: ['#1a73e8', '#16a34a', '#8430ce'], borderWidth: 2, borderColor: '#ffffff' }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#374151', padding: 16 }} }} }}
            }}
        }});

        function toggleSession(idx) {{
            const events = document.getElementById('events-' + idx);
            const toggle = document.getElementById('toggle-' + idx);
            if (events.classList.contains('hidden')) {{
                events.classList.remove('hidden');
                toggle.classList.remove('collapsed');
            }} else {{
                events.classList.add('hidden');
                toggle.classList.add('collapsed');
            }}
        }}

        let currentFilter  = 'all';
        let currentBrowser = 'all';

        function setFilter(type) {{
            currentFilter  = type;
            currentBrowser = 'all';
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('btn-' + type).classList.add('active');
            applyFilters();
        }}

        function setBrowser(browser) {{
            currentBrowser = browser;
            currentFilter  = 'all';
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('btn-' + browser).classList.add('active');
            applyFilters();
        }}

        function applyFilters() {{
            const query = document.getElementById('searchBox').value.toLowerCase().trim();
            let totalVisible = 0;
            const isFiltering = query || currentFilter !== 'all' || currentBrowser !== 'all';

            document.querySelectorAll('.session-card').forEach(sessionCard => {{
                let sessionVisible = 0;
                sessionCard.querySelectorAll('.event-row').forEach(row => {{
                    const title   = (row.dataset.title   || '').toLowerCase();
                    const url     = (row.dataset.url     || '').toLowerCase();
                    const type    = (row.dataset.type    || '').toLowerCase();
                    const browser = (row.dataset.browser || '').toLowerCase();
                    const matchSearch  = !query || title.includes(query) || url.includes(query);
                    const matchFilter  = currentFilter  === 'all' || type    === currentFilter;
                    const matchBrowser = currentBrowser === 'all' || browser === currentBrowser;
                    if (matchSearch && matchFilter && matchBrowser) {{
                        row.classList.remove('hidden');
                        sessionVisible++;
                        totalVisible++;
                    }} else {{
                        row.classList.add('hidden');
                    }}
                }});

                if (isFiltering) {{
                    if (sessionVisible === 0) {{
                        sessionCard.style.display = 'none';
                    }} else {{
                        sessionCard.style.display = 'block';
                        const idx = sessionCard.id.replace('session-', '');
                        const eventsDiv = document.getElementById('events-' + idx);
                        if (eventsDiv) eventsDiv.classList.remove('hidden');
                    }}
                }} else {{
                    sessionCard.style.display = 'block';
                }}
            }});

            document.querySelectorAll('.gap-banner').forEach(banner => {{
                banner.style.display = isFiltering ? 'none' : 'block';
            }});

            const countEl = document.getElementById('resultsCount');
            countEl.textContent = isFiltering ? totalVisible + ' result(s) found' : '';
        }}

        const allEvents = {json.dumps(all_events_for_js)};

        function runKeywordSearch() {{
            const keyword = document.getElementById('analystKeyword').value.toLowerCase().trim();
            const resultsDiv = document.getElementById('keywordResults');
            if (!keyword) {{ resultsDiv.innerHTML = ''; return; }}
            const matches = allEvents.filter(e =>
                e.title.toLowerCase().includes(keyword) ||
                e.url.toLowerCase().includes(keyword)
            );
            if (matches.length === 0) {{
                resultsDiv.innerHTML = '<div style="color:#6b7280;font-size:13px;padding:12px 0;">No results found for <strong>' + keyword + '</strong></div>';
                return;
            }}
            let html = '<div style="font-size:13px;color:#d97706;font-weight:600;margin-bottom:12px;">' + matches.length + ' result(s) found for "' + keyword + '"</div>';
            matches.forEach(e => {{
                let bcls = e.browser === 'Chrome' ? 'browser-chrome' : e.browser === 'Edge' ? 'browser-edge' : 'browser-firefox';
                html += `<div class="keyword-result-item">
                    <div class="keyword-result-title"><span class="browser-badge ${{bcls}}">${{e.browser}}</span>${{e.title || 'No Title'}}</div>
                    <div class="keyword-result-url">${{e.url}}</div>
                    <div class="keyword-result-meta">${{e.time}} | ${{e.type}}</div>
                </div>`;
            }});
            resultsDiv.innerHTML = html;
        }}

        function clearKeywordSearch() {{
            document.getElementById('analystKeyword').value = '';
            document.getElementById('keywordResults').innerHTML = '';
        }}

        function downloadReport() {{
            const w = window.open('', '_blank');
            w.document.write(`<!DOCTYPE html>
<html><head><title>Forensic Report</title>
<style>
body{{font-family:'Segoe UI',sans-serif;padding:40px;color:#1a2744;background:#ffffff;}}
h1{{color:#1a2744;margin-bottom:6px;font-size:22px;font-weight:700;}}
h2{{color:#1a2744;border-bottom:2px solid #2e5baf;padding-bottom:8px;margin-top:28px;margin-bottom:14px;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;font-weight:700;}}
.meta{{color:#5a6a80;font-size:12px;margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid #dde2ea;}}
table{{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:11px;}}
th{{background:#1a2744;color:white;padding:9px 10px;text-align:left;font-size:10px;letter-spacing:0.5px;text-transform:uppercase;}}
td{{padding:7px 10px;border-bottom:1px solid #dde2ea;font-family:monospace;font-size:11px;vertical-align:top;}}
tr:nth-child(even){{background:#f4f6f9;}}
.stat-row{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;}}
.stat{{background:#ffffff;border:1px solid #dde2ea;border-top:3px solid #2e5baf;border-radius:4px;padding:12px 20px;text-align:center;min-width:100px;}}
.stat-val{{font-size:22px;font-weight:700;color:#2e5baf;}}
.stat-lbl{{font-size:10px;color:#5a6a80;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px;}}
.anomaly{{background:#fff8f8;border-left:4px solid #c0392b;padding:10px 14px;margin-bottom:8px;border-radius:0 4px 4px 0;}}
.anomaly-title{{font-weight:700;color:#c0392b;font-size:10px;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;}}
.live-status{{background:#f0faf4;border:1px solid #b0dfc0;border-radius:4px;padding:14px 16px;margin-bottom:8px;}}
.live-badge{{display:inline-block;background:#e8f5ee;border:1px solid #b0dfc0;border-radius:3px;padding:3px 10px;font-size:11px;color:#1a6e3a;font-weight:600;margin-right:8px;}}
@media print{{body{{padding:20px;}} h2{{page-break-after:avoid;}} table{{page-break-inside:avoid;}}}}
</style></head><body>
<h1>Browser Forensic Analysis Report</h1>
<div class="meta">Generated: {generated_at} &nbsp;|&nbsp; Mode: {mode_label} &nbsp;|&nbsp; Chrome + Edge + Firefox</div>
<h2>Summary Statistics</h2>
<div class="stat-row">
<div class="stat"><div class="stat-val">{total_events}</div><div class="stat-lbl">Total Events</div></div>
<div class="stat"><div class="stat-val">{total_sessions}</div><div class="stat-lbl">Sessions</div></div>
<div class="stat"><div class="stat-val">{download_count}</div><div class="stat-lbl">Downloads</div></div>
<div class="stat"><div class="stat-val">{chrome_count}</div><div class="stat-lbl">Chrome</div></div>
<div class="stat"><div class="stat-val">{edge_count}</div><div class="stat-lbl">Edge</div></div>
<div class="stat"><div class="stat-val">{firefox_count}</div><div class="stat-lbl">Firefox</div></div>
</div>
{'<h2>Live Acquisition — Browser Status</h2><div class="live-status"><strong style="font-size:12px;color:#1a2744;">Browsers Active During Acquisition:</strong><br><br>' + ' '.join(f'<span class="live-badge">{b} — ACTIVE</span>' for b in data.get("running_browsers", [])) + '</div>' if mode == "live" and data.get("running_browsers") else ''}
<h2>Anti-Forensics and Anomaly Detection</h2>
{''.join([f'<div class="anomaly"><div class="anomaly-title">{a["type"]}</div><div style="font-size:13px;">{a["message"]}</div>{"".join(["<div style=color:#d97706;font-size:12px;margin-top:4px;>→ " + d + "</div>" for d in a.get("details",[])])}</div>' for a in anomalies]) or '<p style="color:#16a34a">No anomalies detected.</p>'}
<h2>Artifact Acquisition Status</h2>
<table><tr><th>Browser</th><th>Artifact</th><th>Status</th><th>Records</th><th>Note</th></tr>
{health_rows}
</table>
<h2>Chronological Browser Activity Timeline</h2>
<table><tr><th>Time</th><th>Browser</th><th>Title</th><th>URL</th><th>Type</th></tr>
{report_rows}
</table>
</body></html>`);
            w.document.close();
            setTimeout(() => w.print(), 500);
        }}
    </script>
</body>
</html>"""

    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nDashboard generated: {OUTPUT_HTML}")

if __name__ == "__main__":
    generate_dashboard()