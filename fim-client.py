import os
import json
import time
import hashlib
import sys
import inotify.adapters
import argparse
import daemon
from pathlib import Path
import stat
from threading import Thread
from daemon import DaemonContext

CONFIG_FILE = os.path.abspath("fim.config")
LOG_DIR = os.path.abspath("./logs")
LOG_FILE = os.path.join(LOG_DIR, "file_monitor.json")
PID_FILE = os.path.abspath("fim.pid")
OUTPUT_DIR = os.path.abspath("./output")
HASH_FILE = os.path.join(OUTPUT_DIR, "file_hashes.txt")

def ensure_log_file():
    """Ensure that the log directory and log file exist with appropriate permissions."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)  # Ensure directory exists with correct permissions
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    os.chmod(LOG_FILE, 0o600)

def ensure_output_dir():
    """Ensure that the output directory exists with appropriate permissions."""
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)

def create_default_config():
    """Create a default configuration file if it does not exist and set permissions."""
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
    os.chmod(CONFIG_FILE, 0o600)
    print(f"[INFO] Default configuration file created at {CONFIG_FILE}. Please update it as needed.")

def load_config():
    """Load configuration settings from fim.config file."""
    if not os.path.exists(CONFIG_FILE):
        create_default_config()

    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def generate_file_hashes(scheduled_directories, real_time_directories, exclusions):
    """Generate and store SHA-256 hashes for all monitored files."""
    file_hashes = {}

    for directory in scheduled_directories + real_time_directories:
        if directory not in exclusions.get("directories", []):
            for filepath in Path(directory).rglob("*"):
                if filepath.is_file() and str(filepath) not in exclusions.get("files", []):
                    file_hash = get_file_hash(filepath)
                    if file_hash:
                        file_hashes[str(filepath)] = file_hash

    write_file_hashes(file_hashes)

def get_file_hash(filepath):
    """Generate SHA-256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # File may have been deleted before reading

def write_file_hashes(file_hashes):
    """Write file hashes to the output file."""
    with open(HASH_FILE, "w") as f:
        for file, file_hash in file_hashes.items():
            f.write(f"{file}:{file_hash}\n")

def log_event(event):
    """Log file change events in JSON format."""
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
        if directory not in exclusions.get("directories", []):
            notifier.add_watch(directory, mask=inotify.constants.IN_CREATE |
                                               inotify.constants.IN_MODIFY |
                                               inotify.constants.IN_DELETE)

    print("[INFO] Real-time monitoring started...")

    for event in notifier.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        full_path = os.path.join(path, filename)
        if full_path not in exclusions.get("files", []):
            log_event({"path": full_path, "event_type": type_names})

def scan_files(scheduled_directories, scan_interval, exclusions):
    """Perform periodic file integrity scans."""
    print("[INFO] Periodic scanning started...")
    last_hashes = {}

    while True:
        for directory in scheduled_directories:
            if directory not in exclusions.get("directories", []):
                for filepath in Path(directory).rglob("*"):
                    if filepath.is_file() and str(filepath) not in exclusions.get("files", []):
                        file_hash = get_file_hash(filepath)
                        if filepath in last_hashes:
                            if last_hashes[filepath] != file_hash:
                                log_event({"path": str(filepath), "event_type": "MODIFIED"})
                        else:
                            log_event({"path": str(filepath), "event_type": "NEW FILE"})
                        last_hashes[filepath] = file_hash
        time.sleep(scan_interval)

def stop_daemon():
    """Stop the daemon process cleanly."""
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        print(f"[INFO] Stopping daemon process (PID {pid})...")
        os.kill(pid, signal.SIGTERM)
        os.remove(PID_FILE)
    else:
        print("[ERROR] No PID file found. Is the daemon running?")

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM) Client")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run client in background")
    parser.add_argument("-s", "--stop", action="store_true", help="Stop daemon process")
    return parser.parse_args()

def run_monitor():
    """Run the file monitoring process."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    ensure_log_file()
    ensure_output_dir()
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

    generate_file_hashes(scheduled_directories, real_time_directories, exclusions)

    # Start real-time monitoring and periodic scanning as separate threads
    if real_time_directories:
        rt_monitor = Thread(target=monitor_changes, args=(real_time_directories, exclusions), daemon=True)
        rt_monitor.start()

    if scheduled_directories:
        periodic_scan = Thread(target=scan_files, args=(scheduled_directories, scan_interval, exclusions), daemon=True)
        periodic_scan.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        print("[INFO] Terminating monitor process...")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        exit(0)

if __name__ == "__main__":
    args = parse_arguments()

    if args.stop:
        stop_daemon()
    elif args.daemon:
        print("[INFO] Running in background mode...")
        with daemon.DaemonContext():
            run_monitor()
    else:
        print("[INFO] Running in foreground mode...")
        run_monitor()
