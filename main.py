import os
import sys
from datetime import datetime, timezone

def run_acquisition():
    print("\nStep 1: Evidence Acquisition + Hash Verification")
    from acquisition import acquire_artifacts
    acquire_artifacts()

def run_parser():
    print("\nStep 2: Artifact Parsing - Chrome + Edge")
    from parser import parse_history
    parse_history()

def run_timeline():
    print("\nStep 3: Timeline Construction + Anomaly Detection")
    from timeline import main as timeline_main
    timeline_main()

def run_health():
    print("\nStep 4: Artifact Health Check")
    from artifact_health import generate_health_report
    generate_health_report()

def run_deleted_recovery():
    print("\nStep 5: Deleted Record Recovery - SQLite Carving")
    from recover_deleted import recover_deleted_urls
    recover_deleted_urls()

def run_dashboard():
    print("\nStep 6: Generating Dashboard")
    from dashboard import generate_dashboard
    generate_dashboard()

def run_dns():
    print("\nStep 7: DNS Cache Analysis")
    from dns_parser import analyze_dns
    analyze_dns()

def main():
    print("Automated Browser Forensic Analysis Tool")
    print("Browsers: Chrome + Edge\n")

    #records when the analysis began
    start_time = datetime.now(timezone.utc)
    print(f"Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    try:
        run_acquisition()
        run_parser()
        run_timeline()
        run_health()
        run_deleted_recovery()
        run_dns()
        run_dashboard()

        end_time = datetime.now(timezone.utc)
        elapsed = (end_time - start_time).total_seconds()

        print(f"\nAnalysis complete in {elapsed:.1f} seconds")
        print("Output files:")
        print("  - output/dashboard.html")
        print("  - output/timeline.json")
        print("  - output/artifact_health.json")
        print("  - output/deleted_recovery.json")
        print("  - output/logs/")

    except Exception as e:
        print(f"\nError: {e}")
        print("Check your artifact files and paths.")
        sys.exit(1)

if __name__ == "__main__":
    main()