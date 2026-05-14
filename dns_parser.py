import os
import json
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

_case        = os.environ.get("CASE_FOLDER", "output")
ARTIFACT_DIR = os.path.join(_case, "artifacts")
OUTPUT_DIR   = _case
TIMELINE_JSON = os.path.join(_case, "timeline.json")

def get_dns_cache():
    print("Fetching DNS cache...")
    try:
        result = subprocess.run(
            'ipconfig /displaydns',
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        print(f"Failed to get DNS cache: {e}")
        return ""

def parse_dns_output(dns_output):
    domains = set()
    lines = dns_output.split('\n')
    for line in lines:
        line = line.strip()
        if 'Record Name' in line:
            parts = line.split(':')
            if len(parts) > 1:
                domain = parts[-1].strip().rstrip('.')
                if domain and '.' in domain and len(domain) > 3:
                    domains.add(domain.lower())
    return domains

def get_history_domains():
    if not os.path.exists(TIMELINE_JSON):
        print("Timeline JSON not found - run main.py first")
        return set()

    with open(TIMELINE_JSON, "r") as f:
        data = json.load(f)

    domains = set()
    for session in data.get("sessions", []):
        for event in session.get("events", []):
            url = event.get("url", "")
            try:
                domain = urlparse(url).netloc.lower()
                if domain:
                    domain = domain.replace("www.", "")
                    domains.add(domain)
            except:
                pass

    return domains

def analyze_dns():
    print("\nDNS Cache Analysis — Incognito Detection")
    print("-" * 60)

    dns_output = get_dns_cache()
    if not dns_output:
        print("No DNS cache data available.")
        return []

    dns_domains = parse_dns_output(dns_output)
    history_domains = get_history_domains()

    print(f"DNS cache domains found: {len(dns_domains)}")
    print(f"Browser history domains: {len(history_domains)}")

    # Domains in DNS but not in history
    suspicious_domains = []
    for domain in dns_domains:
        # Check if domain or its parent domain is in history
        found = False
        for hist_domain in history_domains:
            if domain in hist_domain or hist_domain in domain:
                found = True
                break
        if not found:
            suspicious_domains.append(domain)

    # Filter out Windows/system domains
    system_domains = [
        "microsoft.com", "windows.com", "windowsupdate.com",
        "msftconnecttest.com", "msftncsi.com", "live.com",
        "office.com", "bing.com", "msn.com", "local",
        "localhost", "vmware.com", "broadcasthost"
    ]

    filtered = []
    for domain in suspicious_domains:
        is_system = any(sys_d in domain for sys_d in system_domains)
        if not is_system and len(domain) > 4:
            filtered.append(domain)

    filtered.sort()

    if not filtered:
        print("\nNo suspicious DNS entries found.")
        print("All DNS domains matched browser history.")
    else:
        print(f"\n⚠ {len(filtered)} domain(s) in DNS cache but NOT in browser history:")
        print("These may have been visited during incognito or after history deletion:\n")
        for domain in filtered[:30]:
            print(f"  🔴 {domain}")

    # Save output
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_dns_domains": len(dns_domains),
        "total_history_domains": len(history_domains),
        "suspicious_domains": filtered[:30],
        "note": "Domains found in DNS cache but absent from browser history. May indicate incognito browsing or deleted history."
    }

    path = os.path.join(OUTPUT_DIR, "dns_analysis.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\nSaved: {path}")
    return filtered

if __name__ == "__main__":
    analyze_dns()