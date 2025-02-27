import os
import json
import time
import hashlib
import inotify.adapters
from pathlib import Path
import stat

CONFIG_FILE = "fim.config"
LOG_DIR = "./logs"
LOG_FILE = os.path.join(LOG_DIR, "file_monitor.json")

def ensure_log_file():
    """Ensure that the log directory and log file exist."""
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)


def create_default_config():
    """Create a default configuration file if it does not exist."""
    default_config = {
        "scheduled_scan": {
            "directories": ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"],
            "scan_interval": 300
        },
        "real_time_monitoring": {
            "directories": ["/var/www"]
        },
        "exclusions": {
            "directories": ["/var/log"],
            "files": []
        },
        "instructions": {
            "scheduled_scan": "Add directories to 'scheduled_scan -> directories' for periodic integrity checks. Adjust 'scan_interval' to control scan frequency (0 disables it).",
            "real_time_monitoring": "Add directories to 'real_time_monitoring -> directories' for instant event detection.",
            "exclusions": "Specify directories or files to be excluded from scanning and monitoring."
        }
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)
    print(f"[INFO] Default configuration file created at {CONFIG_FILE}. Please update it as needed.")

def load_config():
    """Load configuration settings from fim.config file."""
    if not os.path.exists(CONFIG_FILE):
        create_default_config()

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def is_excluded(path, exclusions):
    """Check if a path is in the exclusion list."""
    for excluded_dir in exclusions.get("directories", []):
        if path.startswith(excluded_dir):
            return True
    if path in exclusions.get("files", []):
        return True
    return False

def get_file_metadata(filepath):
    """Retrieve file metadata including size, permissions, owner, and timestamps."""
    try:
        stats = os.stat(filepath)
        return {
            "size": stats.st_size,
            "permissions": oct(stats.st_mode),
            "owner": stats.st_uid,
            "group": stats.st_gid,
            "last_accessed": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.st_atime)),
            "last_modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.st_mtime))
        }
    except Exception:
        return None

def get_file_hash(filepath):
    """Generate SHA-256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # File may have been deleted before reading

def log_event(event):
    """Log file change events in JSON format with verbose metadata."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event
    }
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

def monitor_changes(real_time_directories, exclusions):
    """Monitor file system changes in real-time using inotify."""
    notifier = inotify.adapters.Inotify()

    for directory in real_time_directories:
        if not is_excluded(directory, exclusions):
            notifier.add_watch(directory, mask=inotify.constants.IN_CREATE |
                                               inotify.constants.IN_MODIFY |
                                               inotify.constants.IN_DELETE)

    print("[INFO] Real-time monitoring started...")

    for event in notifier.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        full_path = os.path.join(path, filename)
        if not is_excluded(full_path, exclusions):
            metadata = get_file_metadata(full_path)
            event_info = {
                "path": full_path,
                "event_type": type_names,
                "metadata": metadata
            }
            log_event(event_info)
            print(f"[EVENT] {event_info}")

def scan_files(scheduled_directories, scan_interval, exclusions):
    """Perform periodic file integrity scans."""
    print("[INFO] Periodic scanning started...")
    last_hashes = {}

    while True:
        for directory in scheduled_directories:
            if not is_excluded(directory, exclusions):
                for filepath in Path(directory).rglob("*"):
                    if filepath.is_file() and not is_excluded(str(filepath), exclusions):
                        file_hash = get_file_hash(filepath)
                        metadata = get_file_metadata(filepath)
                        if filepath in last_hashes:
                            if last_hashes[filepath] != file_hash:
                                log_event({"path": str(filepath), "event_type": "MODIFIED", "metadata": metadata})
                        else:
                            log_event({"path": str(filepath), "event_type": "NEW FILE", "metadata": metadata})
                        last_hashes[filepath] = file_hash
        time.sleep(scan_interval)

if __name__ == "__main__":
    from threading import Thread

    ensure_log_file()
    config = load_config()
    scheduled_scan = config.get("scheduled_scan", {})
    real_time_monitoring = config.get("real_time_monitoring", {})
    exclusions = config.get("exclusions", {})

    scheduled_directories = scheduled_scan.get("directories", [])
    scan_interval = scheduled_scan.get("scan_interval", 300)
    real_time_directories = real_time_monitoring.get("directories", [])

    if not scheduled_directories and not real_time_directories:
        print("[ERROR] No directories specified for monitoring. Exiting.")
        exit(1)

    # Start real-time monitoring and periodic scanning as separate threads
    if real_time_directories:
        rt_monitor = Thread(target=monitor_changes, args=(real_time_directories, exclusions), daemon=True)
        rt_monitor.start()

    if scheduled_directories:
        periodic_scan = Thread(target=scan_files, args=(scheduled_directories, scan_interval, exclusions), daemon=True)
        periodic_scan.start()

    # Keep main thread alive
    while True:
        time.sleep(1)
