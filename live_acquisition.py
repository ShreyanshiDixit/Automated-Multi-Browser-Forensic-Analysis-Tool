import os
import sys
import time
import shutil
import hashlib
import subprocess
import json
import getpass
from datetime import datetime, timezone

username = getpass.getuser()

LOCALAPPDATA = os.environ.get('LOCALAPPDATA', f'C:\\Users\\{username}\\AppData\\Local')
APPDATA      = os.environ.get('APPDATA',      f'C:\\Users\\{username}\\AppData\\Roaming')

CHROME_PATH  = os.path.join(LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default')
EDGE_PATH    = os.path.join(LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data', 'Default')

# Auto-detect Firefox profile
_ff_profiles = os.path.join(APPDATA, 'Mozilla', 'Firefox', 'Profiles')
FIREFOX_PATH = ""
if os.path.exists(_ff_profiles):
    for p in os.listdir(_ff_profiles):
        if 'default-release' in p:
            FIREFOX_PATH = os.path.join(_ff_profiles, p)
            break
    if not FIREFOX_PATH:
        profiles = os.listdir(_ff_profiles)
        if profiles:
            FIREFOX_PATH = os.path.join(_ff_profiles, profiles[0])

_case = os.environ.get("CASE_FOLDER", "output")
OUTPUT_DIR = os.path.join(_case, "artifacts")
LOG_DIR    = os.path.join(_case, "logs")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

BROWSERS = {
    "Chrome": {
        "path": CHROME_PATH,
        "artifacts": {
            "History": os.path.join(CHROME_PATH, "History"),
            "Cookies": os.path.join(CHROME_PATH, "Network", "Cookies"),
        }
    },
    "Edge": {
        "path": EDGE_PATH,
        "artifacts": {
            "History": os.path.join(EDGE_PATH, "History"),
            "Cookies": os.path.join(EDGE_PATH, "Network", "Cookies"),
        }
    },
    "Firefox": {
        "path": FIREFOX_PATH,
        "artifacts": {
            "History": os.path.join(FIREFOX_PATH, "places.sqlite"),
            "Cookies": os.path.join(FIREFOX_PATH, "cookies.sqlite"),
        }
    }
}

def compute_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def is_browser_running(browser_name):
    process_map = {
        "Chrome": "chrome.exe",
        "Edge": "msedge.exe",
        "Firefox": "firefox.exe"
    }
    process = process_map.get(browser_name, "")
    try:
        result = subprocess.run(
            f'tasklist /FI "IMAGENAME eq {process}"',
            shell=True,
            capture_output=True,
            text=True
        )
        return process.lower() in result.stdout.lower()
    except:
        return False

def create_vss():
    print("  Creating Volume Shadow Copy...")
    try:
        result = subprocess.run(
            'wmic shadowcopy call create Volume="C:\\"',
            shell=True,
            capture_output=True,
            text=True
        )
        time.sleep(5)  # wait for VSS to be ready
        print("  Shadow copy created successfully")
        return True
    except Exception as e:
        print(f"  Failed to create shadow copy: {e}")
        return False

def get_vss_path():
    try:
        result = subprocess.run(
            'vssadmin list shadows',
            shell=True,
            capture_output=True,
            text=True
        )
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Shadow Copy Volume' in line:
                # Line looks like:
                # Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
                shadow_path = line.strip().split('Shadow Copy Volume:')[-1].strip()
                return shadow_path
        return None
    except:
        return None

def live_acquire_file(src_path, dst_path, vss_path=None):
    import tempfile

    # Try VSS path first
    if vss_path:
        drive_removed = src_path[2:]
        vss_full = vss_path + drive_removed
        try:
            shutil.copy2(vss_full, dst_path)
            return True
        except:
            pass

    # Try copying to a temp file first then moving — bypasses some lock types
    try:
        tmp = tempfile.mktemp(suffix=".tmp")
        shutil.copy2(src_path, tmp)
        shutil.move(tmp, dst_path)
        return True
    except:
        pass

    # Final fallback — direct copy
    try:
        shutil.copy2(src_path, dst_path)
        return True
    except Exception as e:
        print(f"  Direct copy failed: {e}")
        return False

def acquire_live():
    log = {
        "acquisition_type": "live",
        "acquisition_time": datetime.now(timezone.utc).isoformat(),
        "browsers": {}
    }

    print("\nLive Acquisition Starting...")
    print("Checking which browsers are running...\n")

    # Check browser status
    for browser_name in BROWSERS:
        running = is_browser_running(browser_name)
        status = "RUNNING" if running else "NOT RUNNING"
        print(f"  {browser_name}: {status}")

    print()

    # Try to create VSS for locked file access
    vss_created = create_vss()
    vss_path = get_vss_path() if vss_created else None

    if vss_path:
        print(f"  VSS path: {vss_path}\n")
    else:
        print("  VSS not available - attempting direct copy\n")

    # Acquire each browser
    for browser_name, browser in BROWSERS.items():
        print(f"  Acquiring {browser_name}...")
        log["browsers"][browser_name] = []
        copied = set()

        for artifact_name, src_path in browser["artifacts"].items():
            if src_path in copied:
                continue
            copied.add(src_path)

            filename = browser_name + "_" + os.path.basename(src_path)
            dst_path = os.path.join(OUTPUT_DIR, filename)

            if not os.path.exists(src_path):
                print(f"    {artifact_name} - not found")
                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "missing"
                })
                continue

            success = live_acquire_file(src_path, dst_path, vss_path)

            if success:
                file_hash = compute_hash(dst_path)
                size = os.path.getsize(dst_path)
                print(f"    {artifact_name} - acquired")
                print(f"    SHA-256: {file_hash}")
                print(f"    Size: {size} bytes")
                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "acquired",
                    "source": src_path,
                    "destination": dst_path,
                    "sha256": file_hash,
                    "size_bytes": size
                })
            else:
                print(f"    {artifact_name} - failed")
                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "failed"
                })

    # Save log
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    log_path = os.path.join(LOG_DIR, f"live_acquisition_log_{timestamp}.json")
    with open(log_path, "w") as f:
        json.dump(log, f, indent=4)

    print(f"\nLog saved: {log_path}")
    print("Live acquisition complete.")

if __name__ == "__main__":
    acquire_live()