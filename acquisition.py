import os
import getpass
import shutil
import hashlib
import json
import subprocess
import time
from datetime import datetime, timezone

#folders to save output artifacts
_case = os.environ.get("CASE_FOLDER", "output")
OUTPUT_DIR = os.path.join(_case, "artifacts")
LOG_DIR    = os.path.join(_case, "logs")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

#path of evidence
username = getpass.getuser()

CHROME_PATH = os.path.join(
    os.environ.get('LOCALAPPDATA', f'C:\\Users\\{username}\\AppData\\Local'),
    'Google', 'Chrome', 'User Data', 'Default'
)
EDGE_PATH = os.path.join(
    os.environ.get('LOCALAPPDATA', f'C:\\Users\\{username}\\AppData\\Local'),
    'Microsoft', 'Edge', 'User Data', 'Default'
)

firefox_profiles_path = os.path.join(
    os.environ.get('APPDATA', f'C:\\Users\\{username}\\AppData\\Roaming'),
    'Mozilla', 'Firefox', 'Profiles'
)

FIREFOX_PATH = ""
if os.path.exists(firefox_profiles_path):
    profiles = os.listdir(firefox_profiles_path)
    for p in profiles:
        if 'default-release' in p:
            FIREFOX_PATH = os.path.join(firefox_profiles_path, p)
            break
    if not FIREFOX_PATH and profiles:
        FIREFOX_PATH = os.path.join(firefox_profiles_path, profiles[0])

#full file path
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

#creates sha-256
def compute_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def get_vss_path():
    try:
        result = subprocess.run(
            'vssadmin list shadows',
            shell=True,
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if 'Shadow Copy Volume' in line:
                shadow_path = line.strip().split('Shadow Copy Volume:')[-1].strip()
                return shadow_path
        return None
    except:
        return None

def create_vss():
    try:
        subprocess.run(
            'wmic shadowcopy call create Volume="C:\\"',
            shell=True,
            capture_output=True,
            text=True
        )
        time.sleep(5)
        return get_vss_path()
    except:
        return None

def copy_with_vss_fallback(src_path, dst_path, vss_path=None):
    # Try direct copy first
    try:
        shutil.copy2(src_path, dst_path)
        return "direct"
    except Exception:
        pass

    # Try VSS if available
    if vss_path:
        try:
            drive_letter = src_path[:2]
            path_no_drive = src_path[2:]
            vss_full = vss_path.rstrip('\\') + path_no_drive
            shutil.copy2(vss_full, dst_path)
            return "vss"
        except Exception:
            pass

    # Try creating a new VSS if we don't have one
    if not vss_path:
        print("    Attempting VSS creation for locked file...")
        new_vss = create_vss()
        if new_vss:
            try:
                drive_letter = src_path[:2]
                path_no_drive = src_path[2:]
                vss_full = new_vss.rstrip('\\') + path_no_drive
                shutil.copy2(vss_full, dst_path)
                return "vss_new"
            except Exception:
                pass

    return None

#acquire artifacts
def acquire_artifacts():
    log = {
        "acquisition_time": datetime.now(timezone.utc).isoformat(),
        "browsers": {}
    }

    print("Starting acquisition")

    # Try to get VSS path upfront
    vss_path = get_vss_path()
    if vss_path:
        print(f"  VSS available: {vss_path}")
    else:
        print("  VSS not pre-available, will attempt on locked files")

    for browser_name, browser in BROWSERS.items():
        print(f"\nBrowser: {browser_name}")
        log["browsers"][browser_name] = []
        copied = set() #to check already copied file paths

        for artifact_name, src_path in browser["artifacts"].items():
            if src_path in copied:
                continue
            copied.add(src_path)

            #creates destination filename
            filename = browser_name + "_" + os.path.basename(src_path)
            dst_path = os.path.join(OUTPUT_DIR, filename)

            #checks if source file exist
            if not os.path.exists(src_path):
                print(f"  {artifact_name} not found")
                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "missing",
                    "path": src_path
                })
                continue

            #computing SHA-256
            try:
                method = copy_with_vss_fallback(src_path, dst_path, vss_path)

                if method is None:
                    print(f"  {artifact_name} could not be copied (locked, VSS also failed)")
                    log["browsers"][browser_name].append({
                        "artifact": artifact_name,
                        "status": "error",
                        "error": "File locked and VSS fallback failed"
                    })
                    continue

                file_hash = compute_hash(dst_path)
                size = os.path.getsize(dst_path)

                print(f"  {artifact_name} copied successfully (method: {method})")
                print(f"  SHA-256: {file_hash}")
                print(f"  Size: {size} bytes")

                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "acquired",
                    "source": src_path,
                    "destination": dst_path,
                    "sha256": file_hash,
                    "size_bytes": size,
                    "copy_method": method
                })

            except Exception as e:
                print(f"  Error copying {artifact_name}: {e}")
                log["browsers"][browser_name].append({
                    "artifact": artifact_name,
                    "status": "error",
                    "error": str(e)
                })

    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    log_path = os.path.join(LOG_DIR, f"acquisition_log_{timestamp}.json")

    with open(log_path, "w") as f:
        json.dump(log, f, indent=4)

    print(f"\nLog saved: {log_path}")
    print("Acquisition done.")

if __name__ == "__main__":
    acquire_artifacts()