import os
import json
import hashlib
import pyinotify
import time
import re
from datetime import datetime

# ---- Paths and Configuration ----
CONFIG_FILE = "fim.config"
HASH_DB = "known_log_hashes.json"
DEFAULT_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/audit/audit.log"
]

ALERT_LOG = "log_integrity_alerts.log"

# ---- Load monitored files from config or append defaults ----
def load_or_update_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump({"log_files": DEFAULT_LOG_FILES}, f, indent=2)
        return DEFAULT_LOG_FILES

    with open(CONFIG_FILE, 'r+') as f:
        data = json.load(f)
        existing_files = set(data.get("log_files", []))
        new_files = set(DEFAULT_LOG_FILES)
        combined = list(existing_files.union(new_files))
        data["log_files"] = combined
        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()
        return combined

# ---- Generate SHA-256 hash of file contents ----
def sha256_file(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# ---- Load known hashes or initialize empty ----
def load_hashes():
    if os.path.exists(HASH_DB):
        with open(HASH_DB, 'r') as f:
            return json.load(f)
    return {}

# ---- Save updated hashes ----
def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        json.dump(hashes, f, indent=2)

# ---- Pattern Detection ----
SUSPICIOUS_PATTERNS = [
    r"Failed password",
    r"authentication failure",
    r"sudo:",
    r"su:",
    r"log file rotated",
    r"log cleared"
]

def scan_file_for_patterns(path):
    alerts = []
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        alerts.append((path, line.strip()))
    except Exception:
        pass
    return alerts

# ---- Alert Logging ----
def log_alert(message):
    timestamp = datetime.utcnow().isoformat()
    entry = f"[{timestamp}] {message}\n"
    with open(ALERT_LOG, "a") as f:
        f.write(entry)
    print(entry.strip())  # Optional: for local visibility

# ---- Pyinotify Event Handler ----
class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        log_alert(f"MODIFY: {event.pathname}")
        alerts = scan_file_for_patterns(event.pathname)
        for path, line in alerts:
            log_alert(f"SUSPICIOUS ENTRY in {path}: {line}")

    def process_IN_DELETE_SELF(self, event):
        log_alert(f"DELETION: {event.pathname} has been deleted!")

# ---- Main Monitoring Function ----
def monitor_logs():
    log_files = load_or_update_config()
    known_hashes = load_hashes()

    # Periodic hash check
    for path in log_files:
        current_hash = sha256_file(path)
        if not current_hash:
            log_alert(f"ERROR: Could not read {path}")
            continue

        if path in known_hashes:
            if known_hashes[path] != current_hash:
                log_alert(f"HASH MISMATCH: {path} may have been altered")
        else:
            log_alert(f"NEW FILE MONITORED: {path}")

        known_hashes[path] = current_hash

    save_hashes(known_hashes)

    # Start real-time monitoring
    wm = pyinotify.WatchManager()
    mask = pyinotify.IN_MODIFY | pyinotify.IN_DELETE_SELF
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)

    for path in log_files:
        if os.path.exists(path):
            wm.add_watch(path, mask)

    print("Log Integrity Monitor running...")
    notifier.loop()

# ---- Entry Point ----
if __name__ == "__main__":
    try:
        while True:
            monitor_logs()
            time.sleep(300)  # Run every 5 minutes for hash comparison
    except KeyboardInterrupt:
        print("Exiting log integrity monitor.")
