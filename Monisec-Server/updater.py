# === TODO: Integrate GitHub Updater ===
# Step 1: Import the updater module
#import updater

# Step 2: At the top of your `__main__` block, before any mode-specific logic,
#         add the following code to check for updates before running MoniSec Client:
#
#         try:
#             updater.check_for_updates()
#         except Exception as e:
#             logging.warning(f"Updater failed: {e}")
#
#         This will ensure the latest code is pulled from GitHub before continuing.

import argparse
import requests
import os

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/vapt-automation/main/"
GITHUB_VERSION_URL = GITHUB_RAW_BASE + "version.txt"
LOCAL_VERSION_FILE = "version.txt"

FILES_TO_UPDATE = [
    "monisec-server.py",
    "server_crypt.py",
    "server_siem.py",
    "updater.py",
    "version.txt"
]

def check_for_updates(force=False, dry_run=False):
    print("\n=== Checking for updates from GitHub... ===")
    updated = False
    headers = {"User-Agent": "GenericUpdater/1.0"}

    try:
        # Step 1: Read local version
        local_version = "0.0.0"
        if os.path.exists(LOCAL_VERSION_FILE):
            with open(LOCAL_VERSION_FILE, "r") as f:
                local_version = f.read().strip()

        # Step 2: Get remote version
        response = requests.get(GITHUB_VERSION_URL, headers=headers, timeout=5)
        if response.status_code != 200:
            print(f"[!] Could not retrieve remote version info (HTTP {response.status_code}).")
            print("=== Update check skipped ===\n")
            return False

        remote_version = response.text.strip()

        # Step 3: Compare versions
        local_v = parse_version(local_version)
        remote_v = parse_version(remote_version)

        if remote_v > local_v or force:
            if remote_v > local_v:
                print(f"[+] New version detected: {remote_version} (current: {local_version})")
            elif force:
                print(f"[!] Forced update triggered. Re-fetching files...")

            for filename in FILES_TO_UPDATE:
                file_url = GITHUB_RAW_BASE + filename
                file_resp = requests.get(file_url, headers=headers, timeout=10)

                if file_resp.status_code == 200:
                    if dry_run:
                        print(f"[DRY-RUN] Would update {filename}")
                        continue

                    # Backup existing file
                    if os.path.exists(filename):
                        os.rename(filename, filename + ".bak")

                    with open(filename, "wb") as f:
                        f.write(file_resp.content)
                    print(f"    -> Updated {filename}")
                else:
                    print(f"    [!] Failed to update {filename} (HTTP {file_resp.status_code})")

            if not dry_run:
                with open(LOCAL_VERSION_FILE, "w") as f:
                    f.write(remote_version)

                updated = True
                print("[?] Update complete. Please restart the tool to load latest changes.")
        else:
            print("[?] Already running the latest version.")

    except Exception as e:
        print(f"[!] Update check failed: {e}")

    print("=== Update check complete ===\n")
    return updated

def parse_version(v):
    """Convert version string like '1.2.3' into a tuple (1, 2, 3) for comparison."""
    return tuple(map(int, v.strip().split(".")))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generic GitHub Updater")
    parser.add_argument("--force", action="store_true", help="Force update even if version matches")
    parser.add_argument("--dry-run", action="store_true", help="Simulate update without writing files")
    args = parser.parse_args()

    check_for_updates(force=args.force, dry_run=args.dry_run)
