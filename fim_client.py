import os
import json
import time
import hashlib
import sys
import argparse
import daemon
from pathlib import Path
import stat
from threading import Thread
from daemon import DaemonContext
import shutil
import pyinotify
import audit

CONFIG_FILE = os.path.abspath("fim.config")
LOG_DIR = os.path.abspath("./logs")
LOG_FILE = os.path.join(LOG_DIR, "file_monitor.json")
PID_FILE = os.path.abspath("fim.pid")
OUTPUT_DIR = os.path.abspath("./output")
HASH_FILE = os.path.join(OUTPUT_DIR, "file_hashes.txt")
INTEGRITY_STATE_FILE = os.path.join(OUTPUT_DIR, "integrity_state.json")

def ensure_log_file():
    """Ensure that the log directory and log file exist with appropriate permissions."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)  # Ensure directory exists with correct permissions
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    os.chmod(LOG_FILE, 0o600)

def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None):
    """Log file change events while ignoring last accessed time in metadata."""

    def filter_metadata(metadata):
        """Helper function to remove last_accessed before logging."""
        if metadata:
            return {k: v for k, v in metadata.items() if k != "last_accessed"}
        return None

    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": filter_metadata(previous_metadata),
        "new_metadata": filter_metadata(new_metadata),
        "previous_hash": previous_hash,
        "new_hash": new_hash
    }

    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

    # Send logs to SIEM (if configured)
    audit.send_to_siem(log_entry)

def ensure_output_dir():
    """Ensure that the output directory exists with appropriate permissions."""
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)

def create_default_config():
    """Create a default configuration file if it does not exist and set permissions."""
    default_config = {
        "scheduled_scan": {
            "directories": ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/var/www"],
            "scan_interval": 300
        },
        "real_time_monitoring": {
            "directories": ["/var/www"]
        },
        "exclusions": {
            "directories": ["/var/log"],
            "files": [
                "/etc/mnttab",
                "/etc/mtab",
                "/etc/hosts.deny",
                "/etc/mail/statistics",
                "/etc/random-seed",
                "/etc/adjtime",
                "/etc/httpd/logs",
                "/etc/utmpx",
                "/etc/wtmpx",
                "/etc/cups/certs",
                "/etc/dumpdates",
                "/etc/svc/volatile"
            ]
        },
        "siem_settings": {
            "enabled": False,  # Default to disabled
            "siem_server": "",
            "siem_port": 0
        },
        "instructions": {
            "scheduled_scan": "Add directories to 'scheduled_scan -> directories' for periodic integrity checks. Adjust 'scan_interval' to control scan frequency (0 disables it).",
            "real_time_monitoring": "Add directories to 'real_time_monitoring -> directories' for instant event detection.",
            "exclusions": "Specify directories or files to be excluded from scanning and monitoring.",
            "siem_settings": "Set 'enabled' to true, and provide 'siem_server' and 'siem_port' for SIEM logging."
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
        config = json.load(f)

    return config

def generate_file_hashes(scheduled_directories, real_time_directories, exclusions):
    """Generate and store SHA-256 hashes for all monitored files, tracking changes over time."""
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()

    new_file_hashes = {}
    new_integrity_state = {}

    excluded_dirs = set(exclusions.get("directories", []))
    excluded_files = set(exclusions.get("files", []))

    for directory in scheduled_directories + real_time_directories:
        if directory in excluded_dirs:
            continue

        for filepath in Path(directory).rglob("*"):
            str_filepath = str(filepath)

            # **Ensure exclusions apply BEFORE any processing**
            if str_filepath in excluded_files:
                continue

            if any(str_filepath.startswith(excluded_dir) for excluded_dir in excluded_dirs):
                continue

            if filepath.is_file():
                file_hash = get_file_hash(filepath)
                metadata = get_file_metadata(filepath)

                if file_hash and metadata:
                    previous_hash = file_hashes.get(str_filepath)
                    previous_metadata = integrity_state.get(str_filepath)

                    # **Exclusion Check Here Again to Avoid Logging**
                    if str_filepath in excluded_files or any(str_filepath.startswith(excluded_dir) for excluded_dir in excluded_dirs):
                        continue

                    if previous_hash == file_hash and previous_metadata == metadata:
                        new_file_hashes[str_filepath] = file_hash
                        new_integrity_state[str_filepath] = metadata
                        continue

                    log_event(
                        event_type="MODIFIED" if previous_hash else "NEW FILE",
                        file_path=str_filepath,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        previous_hash=previous_hash,
                        new_hash=file_hash
                    )

                    new_file_hashes[str_filepath] = file_hash
                    new_integrity_state[str_filepath] = metadata

    if new_file_hashes != file_hashes or new_integrity_state != integrity_state:
        save_file_hashes(new_file_hashes)
        save_integrity_state(new_integrity_state)
    else:
        print("[INFO] No changes detected. File hash tracking remains unchanged.")

def compare_metadata(prev_metadata, new_metadata):
    """Compare metadata while ignoring last accessed time."""
    if not prev_metadata or not new_metadata:
        return False  # No metadata to compare

    ignored_keys = ["last_accessed"]
    filtered_prev = {k: v for k, v in prev_metadata.items() if k not in ignored_keys}
    filtered_new = {k: v for k, v in new_metadata.items() if k not in ignored_keys}

    return filtered_prev != filtered_new  # Returns True if metadata (excluding access time) changed

def get_file_hash(filepath):
    """Generate SHA-256 hash of a file."""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None  # File may have been deleted before reading

def load_file_hashes():
    """Load previously stored file hashes."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return dict(line.strip().split(":") for line in f if ":" in line)
    return {}

def save_file_hashes(file_hashes):
    """Save updated file hashes to file, keeping a backup of the old file."""
    if os.path.exists(HASH_FILE):
        shutil.move(HASH_FILE, f"{HASH_FILE}_old")  # Create a backup before overwriting

    with open(HASH_FILE, "w") as f:
        for file, file_hash in file_hashes.items():
            f.write(f"{file}:{file_hash}\n")

    # Explicitly set file permissions to prevent permission errors
    os.chmod(HASH_FILE, 0o600)

def load_integrity_state():
    """Load previous integrity state from the integrity_state.json file."""
    if os.path.exists(INTEGRITY_STATE_FILE):
        with open(INTEGRITY_STATE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_integrity_state(state):
    """Save the integrity state to the integrity_state.json file."""
    with open(INTEGRITY_STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)

def get_file_metadata(filepath):
    """Retrieve metadata of a file while tracking but ignoring last accessed time."""
    try:
        stats = os.stat(filepath)
        return {
            "size": stats.st_size,
            "permissions": oct(stats.st_mode),
            "owner": stats.st_uid,
            "group": stats.st_gid,
            "last_modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.st_mtime)),
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.st_ctime)),
            "inode": stats.st_ino,
            "hard_links": stats.st_nlink,
            "device": stats.st_dev,
            "block_size": stats.st_blksize,
            "blocks": stats.st_blocks
        }
    except Exception:
        return None

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_CREATE(self, event):
        """Handles file creation event."""
        full_path = event.pathname
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)

        log_event(
            event_type="NEW FILE",
            file_path=full_path,
            previous_metadata=None,
            new_metadata=metadata,
            previous_hash=None,
            new_hash=file_hash
        )

        update_file_tracking(full_path, file_hash, metadata)

    def process_IN_DELETE(self, event):
        """Handles file deletion event."""
        full_path = event.pathname
        previous_metadata = integrity_state.get(full_path, None)
        previous_hash = file_hashes.get(full_path, None)

        log_event(
            event_type="DELETED",
            file_path=full_path,
            previous_metadata=previous_metadata,
            new_metadata=None,
            previous_hash=previous_hash,
            new_hash=None
        )

        remove_file_tracking(full_path)

    def process_IN_MODIFY(self, event):
        """Handles file modification event."""
        full_path = event.pathname
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)
        previous_hash = file_hashes.get(full_path)
        previous_metadata = integrity_state.get(full_path)

        if file_hash != previous_hash:
            log_event(
                event_type="MODIFIED",
                file_path=full_path,
                previous_metadata=previous_metadata,
                new_metadata=metadata,
                previous_hash=previous_hash,
                new_hash=file_hash
            )
            update_file_tracking(full_path, file_hash, metadata)

    def process_IN_ATTRIB(self, event):
        """Handles metadata change event."""
        full_path = event.pathname
        metadata = get_file_metadata(full_path)
        previous_metadata = integrity_state.get(full_path)

        if metadata != previous_metadata:
            log_event(
                event_type="METADATA_CHANGED",
                file_path=full_path,
                previous_metadata=previous_metadata,
                new_metadata=metadata,
                previous_hash=None,
                new_hash=None
            )
            integrity_state[full_path] = metadata
            save_integrity_state(integrity_state)

def monitor_changes(real_time_directories, exclusions):
    """Monitors file system changes using pyinotify."""
    global file_hashes, integrity_state
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()

    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)

    # Watch all directories and subdirectories
    for directory in real_time_directories:
        if directory in exclusions.get("directories", []):
            continue
        wm.add_watch(directory, pyinotify.ALL_EVENTS, rec=True, auto_add=True)

    print("[INFO] Real-time monitoring started using pyinotify...")

    # Start monitoring
    notifier.loop()

def remove_file_tracking(file_path):
    """Remove deleted file from tracking."""
    if file_path in file_hashes:
        del file_hashes[file_path]
    if file_path in integrity_state:
        del integrity_state[file_path]
    save_file_hashes(file_hashes)
    save_integrity_state(integrity_state)

def update_file_tracking(file_path, file_hash, metadata):
    """Update file tracking information for new or modified files."""
    global file_hashes, integrity_state  # Ensure these are accessible

    file_hashes[file_path] = file_hash
    integrity_state[file_path] = metadata

    save_file_hashes(file_hashes)
    save_integrity_state(integrity_state)

def scan_files(scheduled_directories, scan_interval, exclusions):
    """Perform periodic file integrity scans."""
    print("[INFO] Periodic scanning started...")
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()

    while True:
        for directory in scheduled_directories:
            if directory not in exclusions.get("directories", []):
                for filepath in Path(directory).rglob("*"):
                    if filepath.is_file() and str(filepath) not in exclusions.get("files", []):
                        file_hash = get_file_hash(filepath)
                        metadata = get_file_metadata(filepath)

                        if file_hash and metadata:
                            previous_hash = file_hashes.get(str(filepath))
                            previous_metadata = integrity_state.get(str(filepath))

                            if previous_hash == file_hash and previous_metadata == metadata:
                                continue  # No changes, move to next file

                            if previous_hash != file_hash or previous_metadata != metadata:
                                log_event(
                                    event_type="MODIFIED" if previous_hash else "NEW FILE",
                                    file_path=str(filepath),
                                    previous_metadata=previous_metadata,
                                    new_metadata=metadata,
                                    previous_hash=previous_hash,
                                    new_hash=file_hash
                                )

                            file_hashes[str(filepath)] = file_hash
                            integrity_state[str(filepath)] = metadata

        save_file_hashes(file_hashes)
        save_integrity_state(integrity_state)
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
    parser.add_argument("-l", "--log-config", action="store_true", help="Configure SIEM logging")
    return parser.parse_args()

def run_monitor():
    """Run the file monitoring process with real-time monitoring and scheduled scans running separately."""
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

    # 🔹 Start real-time monitoring **immediately**
    if real_time_directories:
        rt_monitor = Thread(target=monitor_changes, args=(real_time_directories, exclusions), daemon=True)
        rt_monitor.start()
        print("[INFO] Real-time monitoring started.")

    # 🔹 Run the scheduled scan loop in the main thread
    if scheduled_directories:
        while True:
            generate_file_hashes(scheduled_directories, real_time_directories, exclusions)
            print(f"[INFO] Scheduled scan completed. Sleeping for {scan_interval} seconds.")
            time.sleep(scan_interval)

if __name__ == "__main__":
    args = parse_arguments()

    if args.log_config:
        audit.configure_siem()
        exit(0)  # Exit after configuring SIEM

    if args.stop:
        stop_daemon()
    elif args.daemon:
        print("[INFO] Running in background mode...")
        with daemon.DaemonContext():
            run_monitor()
    else:
        print("[INFO] Running in foreground mode...")
        run_monitor()
