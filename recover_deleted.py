import re
import os
import json
import sqlite3
from datetime import datetime, timezone

_case        = os.environ.get("CASE_FOLDER", "output")
ARTIFACT_DIR = os.path.join(_case, "artifacts")
OUTPUT_DIR   = _case
HISTORY_FILE = os.path.join(ARTIFACT_DIR, "Chrome_History")

def recover_deleted_urls():
    print("Starting SQLite carving...")

    if not os.path.exists(HISTORY_FILE):
        print("History file not found")
        return []

    #reads raw binary of history files
    with open(HISTORY_FILE, "rb") as f:
        raw_data = f.read()

    #compiles a regex pattern
    url_pattern = re.compile(
        rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{10,200}'
    )

    all_matches = url_pattern.findall(raw_data)

    #decode and clean
    recovered_urls = set()
    for match in all_matches:
        try:
            url = match.decode("utf-8", errors="ignore").strip()
            if len(url) > 15:
                recovered_urls.add(url)
        except:
            pass

    #now from sqlite database
    try:
        conn = sqlite3.connect(HISTORY_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM urls")
        active_urls = set(row[0] for row in cursor.fetchall())
        conn.close()
    except:
        active_urls = set()

    #Find URLs in raw file but NOT in active database,potentially deleted records
    potentially_deleted = []
    for url in recovered_urls:
        if url not in active_urls:
            if (
                "http" in url and
                "." in url and
                len(url) > 20 and
                len(url) < 150 and
                "sqlite" not in url.lower() and
                "chrome-extension" not in url.lower() and
                not any(url.endswith(c) for c in list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) and
                not url[-1].isdigit() or url.endswith(".pdf") or url.endswith(".html")
            ):
                potentially_deleted.append(url)

    potentially_deleted.sort()

    if not potentially_deleted:
        print("No deleted fragments found.")
        print("Space may have been reused or overwritten.")
    else:
        print(f"{len(potentially_deleted)} potentially deleted URLs found:")
        for url in potentially_deleted[:50]:
            print(f"  {url[:100]}")

    #output dictionary
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": "SQLite raw binary carving",
        "total_active_urls": len(active_urls),
        "total_raw_urls": len(recovered_urls),
        "potentially_deleted": potentially_deleted[:50],
        "note": "These URLs were found in raw database bytes but are absent from active records. They may represent deleted browsing history."
    }

    path = os.path.join(OUTPUT_DIR, "deleted_recovery.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\nSaved: {path}")
    print(f"Active URLs: {len(active_urls)}")
    print(f"Raw hits: {len(recovered_urls)}")
    print(f"Possibly deleted: {len(potentially_deleted)}")

    return potentially_deleted

if __name__ == "__main__":
    recover_deleted_urls()