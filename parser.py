import sqlite3
import os
from datetime import datetime, timezone

#artifacts files 
_case        = os.environ.get("CASE_FOLDER", "output")
ARTIFACT_DIR = os.path.join(_case, "artifacts")
OUTPUT_DIR   = _case

BROWSERS = {
    "Chrome": {
        "history_db": os.path.join(ARTIFACT_DIR, "Chrome_History"),
        "type": "chromium"
    },
    "Edge": {
        "history_db": os.path.join(ARTIFACT_DIR, "Edge_History"),
        "type": "chromium"
    },
    "Firefox": {
        "history_db": os.path.join(ARTIFACT_DIR, "Firefox_places.sqlite"),
        "type": "firefox"
    }
}
#timestamp conversion
def chrome_time_to_utc(chrome_time):
    if chrome_time == 0:
        return "Unknown"
    try:
        timestamp = (chrome_time / 1000000) - 11644473600
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return "Invalid"

def extract_history(cursor, browser_name):
    print(f"\n{browser_name} - Browsing History")

    #sql query
    cursor.execute("""
        SELECT url, title, visit_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time ASC
    """)

    rows = cursor.fetchall()
    history = []

    if not rows:
        print("No history found.")
        return history

    #loops through each row from database
    for row in rows:
        url, title, visit_count, last_visit_time = row
        readable_time = chrome_time_to_utc(last_visit_time)

        print(f"Time: {readable_time}")
        print(f"Title: {title}")
        print(f"URL: {url[:80]}")
        print(f"Visits: {visit_count}")
        print("-" * 50)

        history.append({
            "browser": browser_name,
            "time": readable_time,
            "title": title or "No Title",
            "url": url,
            "visit_count": visit_count,
            "type": "visit"
        })

    print(f"Total records: {len(rows)}")
    return history

#for extracting downloads
def extract_downloads(cursor, browser_name):
    print(f"\n{browser_name} - Downloads")

    cursor.execute("""
        SELECT target_path, tab_url, total_bytes, start_time, end_time, state
        FROM downloads
        ORDER BY start_time ASC
    """)

    rows = cursor.fetchall()
    downloads = []

    if not rows:
        print("No downloads found.")
        return downloads

    for row in rows:
        target_path, tab_url, total_bytes, start_time, end_time, state = row

        state_map = {
            0: "In Progress",
            1: "Complete",
            2: "Cancelled",
            3: "Interrupted"
        }
        state_str = state_map.get(state, "Unknown")

        print(f"Start: {chrome_time_to_utc(start_time)}")
        print(f"End: {chrome_time_to_utc(end_time)}")
        print(f"File: {os.path.basename(target_path)}")
        print(f"Source: {tab_url[:80]}")
        print(f"Size: {total_bytes} bytes")
        print(f"Status: {state_str}")

        downloads.append({
            "browser": browser_name,
            "time": chrome_time_to_utc(start_time),
            "file": os.path.basename(target_path),
            "url": tab_url,
            "size": total_bytes,
            "status": state_str,
            "type": "download"
        })

    print(f"Total downloads: {len(rows)}")
    return downloads

#firefox timestamp converter
def firefox_time_to_utc(firefox_time):
    if firefox_time == 0:
        return "Unknown"
    try:
        timestamp = firefox_time / 1000000
        return datetime.fromtimestamp(
            timestamp, tz=timezone.utc
        ).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return "Invalid"
    

#firefox history extractor
def extract_firefox_history(cursor, browser_name):
    print(f"\n{browser_name} - Browsing History")

    cursor.execute("""
        SELECT url, title, visit_count, last_visit_date
        FROM moz_places
        WHERE visit_count > 0
        ORDER BY last_visit_date ASC
    """)

    rows = cursor.fetchall()
    history = []

    if not rows:
        print("No history found.")
        return history

    for row in rows:
        url, title, visit_count, last_visit_date = row
        readable_time = firefox_time_to_utc(last_visit_date or 0)

        print(f"Time: {readable_time}")
        print(f"Title: {title}")
        print(f"URL: {url[:80]}")
        print(f"Visits: {visit_count}")
        print("-" * 50)

        history.append({
            "browser": browser_name,
            "time": readable_time,
            "title": title or "No Title",
            "url": url,
            "visit_count": visit_count,
            "type": "visit"
        })

    print(f"Total records: {len(rows)}")
    return history

def extract_firefox_downloads(cursor, browser_name):
    print(f"\n{browser_name} - Downloads")

    cursor.execute("""
        SELECT content, dateAdded
        FROM moz_annos
        WHERE anno_attribute_id = (
            SELECT id FROM moz_anno_attributes
            WHERE name = 'downloads/destinationFileName'
        )
        ORDER BY dateAdded ASC
    """)

    rows = cursor.fetchall()
    downloads = []

    if not rows:
        print("No downloads found.")
        return downloads

    for row in rows:
        filename, date_added = row
        readable_time = firefox_time_to_utc(date_added or 0)

        print(f"Time: {readable_time}")
        print(f"File: {filename}")
        print("-" * 50)

        downloads.append({
            "browser": browser_name,
            "time": readable_time,
            "file": filename,
            "url": "",
            "size": 0,
            "status": "Complete",
            "type": "download"
        })

    print(f"Total downloads: {len(rows)}")
    return downloads

#main
def parse_history():
    all_history = []
    all_downloads = []

    print("Starting parser...")

    for browser_name, browser in BROWSERS.items():
        db_path = browser["history_db"]
        browser_type = browser["type"]

        if not os.path.exists(db_path):
            print(f"{browser_name} History not found, skipping")
            continue

        print(f"\nParsing {browser_name}...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if browser_type == "firefox":
            history = extract_firefox_history(cursor, browser_name)
            downloads = extract_firefox_downloads(cursor, browser_name)
        else:
            history = extract_history(cursor, browser_name)
            downloads = extract_downloads(cursor, browser_name)

        all_history.extend(history)
        all_downloads.extend(downloads)

        conn.close()

    print(f"\nTotal history: {len(all_history)}")
    print(f"Total downloads: {len(all_downloads)}")
    print(f"Browsers parsed: {len(BROWSERS)}")

    return all_history, all_downloads

if __name__ == "__main__":
    parse_history()