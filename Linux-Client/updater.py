# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script is part of the FIMonsec Tool, which provides enterprise-grade
#          system integrity monitoring with real-time alerting capabilities. It monitors
#          critical system and application files for unauthorized modifications,
#          supports baseline comparisons, and integrates with SIEM solutions.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================

import argparse
import requests
import os

GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/FIMoniSec/main/Linux-Client/"
GITHUB_VERSION_URL = "https://raw.githubusercontent.com/sec0ps/FIMoniSec/main/Linux-Client/version.txt"
LOCAL_VERSION_FILE = "version.txt"

FILES_TO_UPDATE = [
    "audit.py",
    "client_crypt.py",
    "fim_client.py",
    "lim.py",
    "log_detection_engine.py",
    "monisec_client.py",
    "remote.py",
    "version.txt"
]

import argparse
import requests
import os

# ✅ Correct repo path
GITHUB_RAW_BASE = "https://raw.githubusercontent.com/sec0ps/FIMoniSec/main/Linux-Client/"
GITHUB_VERSION_URL = GITHUB_RAW_BASE + "version.txt"
LOCAL_VERSION_FILE = "version.txt"

FILES_TO_UPDATE = [
    "audit.py",
    "client_crypt.py",
    "fim_client.py",
    "lim.py",
    "log_detection_engine.py",
    "monisec_client.py",
    "remote.py",
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
    return tuple(map(int, v.strip().split(".")))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generic GitHub Updater")
    parser.add_argument("--force", action="store_true", help="Force update even if version matches")
    parser.add_argument("--dry-run", action="store_true", help="Simulate update without writing files")
    args = parser.parse_args()

    check_for_updates(force=args.force, dry_run=args.dry_run)

