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
import shutil

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
    """Log file change events in JSON format with detailed metadata."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": previous_metadata,
        "new_metadata": new_metadata,
        "previous_hash": previous_hash,
        "new_hash": new_hash
    }
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

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
            "files": ["/etc/mtab"]
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
        config = json.load(f)

    print(f"[DEBUG] Loaded Exclusions: {config.get('exclusions', {})}")  # DEBUG to confirm exclusions
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
            print(f"[DEBUG] Skipping excluded directory: {directory}")
            continue

        for filepath in Path(directory).rglob("*"):
            str_filepath = str(filepath)

            # **Ensure exclusions apply BEFORE any processing**
            if str_filepath in excluded_files:
                print(f"[DEBUG] Skipping excluded file: {str_filepath}")
                continue

            if any(str_filepath.startswith(excluded_dir) for excluded_dir in excluded_dirs):
                print(f"[DEBUG] Skipping file inside excluded directory: {str_filepath}")
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
        print(f"[INFO] File hash tracking updated. {len(new_file_hashes)} entries stored.")
    else:
        print("[INFO] No changes detected. File hash tracking remains unchanged.")

def compare_metadata(old_metadata, new_metadata):
    """Compare metadata while ignoring last_accessed."""
    if not old_metadata or not new_metadata:
        return True  # If missing, treat as a change

    ignored_keys = {"last_accessed"}  # Ignore atime
    filtered_old = {k: v for k, v in old_metadata.items() if k not in ignored_keys}
    filtered_new = {k: v for k, v in new_metadata.items() if k not in ignored_keys}

    return filtered_old != filtered_new  # Returns True if metadata differs

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
    """Retrieve metadata of a file."""
    try:
        stats = os.stat(filepath)
        return {
            "size": stats.st_size,
            "permissions": oct(stats.st_mode),
            "owner": stats.st_uid,
            "group": stats.st_gid,
            "last_accessed": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stats.st_atime)),
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

def monitor_changes(real_time_directories, exclusions):
    """Monitor file system changes in real-time using inotify."""
    notifier = inotify.adapters.Inotify()

    # Add watch for each real-time directory
    for directory in real_time_directories:
        if directory not in exclusions.get("directories", []):
            notifier.add_watch(directory, mask=inotify.constants.IN_CREATE |
                                               inotify.constants.IN_DELETE |
                                               inotify.constants.IN_MODIFY |
                                               inotify.constants.IN_ATTRIB)

    print("[INFO] Real-time monitoring started...")

    # Load tracking data
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()

    for event in notifier.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        full_path = os.path.join(path, filename)

        # Skip excluded files
        if full_path in exclusions.get("files", []):
            continue

        # 🔹 **Handle File Creation**
        if "IN_CREATE" in type_names:
            time.sleep(0.5)  # Small delay to ensure file creation completes
            if os.path.exists(full_path):  # Ensure file still exists
                file_hash = get_file_hash(full_path)
                metadata = get_file_metadata(full_path)

                if file_hash and metadata:
                    file_hashes[full_path] = file_hash
                    integrity_state[full_path] = metadata

                    save_file_hashes(file_hashes)
                    save_integrity_state(integrity_state)

                    log_event(
                        event_type="NEW FILE",
                        file_path=full_path,
                        new_metadata=metadata,
                        new_hash=file_hash
                    )

                    print(f"[INFO] New file detected: {full_path}")

        # 🔹 **Handle File Deletions**
        elif "IN_DELETE" in type_names:
            if full_path in file_hashes:
                del file_hashes[full_path]  # Remove from hash tracking
            if full_path in integrity_state:
                del integrity_state[full_path]  # Remove from metadata tracking

            save_file_hashes(file_hashes)
            save_integrity_state(integrity_state)

            log_event(
                event_type="DELETED FILE",
                file_path=full_path
            )

            print(f"[INFO] File deleted: {full_path}")

        # 🔹 **Handle File Modifications**
        elif "IN_MODIFY" in type_names or "IN_ATTRIB" in type_names:
            if os.path.exists(full_path):  # Ensure file still exists
                new_hash = get_file_hash(full_path)
                new_metadata = get_file_metadata(full_path)
                previous_hash = file_hashes.get(full_path)
                previous_metadata = integrity_state.get(full_path)

                if previous_hash != new_hash or previous_metadata != new_metadata:
                    file_hashes[full_path] = new_hash
                    integrity_state[full_path] = new_metadata

                    save_file_hashes(file_hashes)
                    save_integrity_state(integrity_state)

                    log_event(
                        event_type="MODIFIED",
                        file_path=full_path,
                        previous_metadata=previous_metadata,
                        new_metadata=new_metadata,
                        previous_hash=previous_hash,
                        new_hash=new_hash
                    )

                    print(f"[INFO] File modified: {full_path}")

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

    if args.stop:
        stop_daemon()
    elif args.daemon:
        print("[INFO] Running in background mode...")
        with daemon.DaemonContext():
            run_monitor()
    else:
        print("[INFO] Running in foreground mode...")
        run_monitor()
