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
INODE_TRACKING_FILE = os.path.join(OUTPUT_DIR, "inode_tracking.json")

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
            "scan_interval": 60
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
        print("[ERROR] Configuration file not found. Creating default config...")
        create_default_config()
        return load_config()  # Reload after creating the default config

    with open(CONFIG_FILE, "r") as f:
        try:
            config = json.load(f)
#            print(f"[DEBUG] Loaded config: {json.dumps(config, indent=4)}")  # Debugging line

            # Ensure the 'siem_settings' key exists
            if "siem_settings" not in config:
                print("[WARNING] 'siem_settings' key missing in fim.config.")
                audit.configure_siem()  # Prompt user for SIEM settings
                return load_config()  # Reload config after setting SIEM

            return config

        except json.JSONDecodeError:
            print("[ERROR] Invalid JSON format in fim.config. Creating a new default config...")
            create_default_config()  # Create default config if JSON is invalid
            return load_config()  # Reload the default config

def generate_file_hashes(scheduled_directories, real_time_directories, exclusions):
    """Generate and store SHA-256 hashes for all monitored files, tracking changes over time."""
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()
    inode_tracking = load_inode_tracking()  # ✅ NEW: Load inode tracking from file

    new_file_hashes = {}
    new_integrity_state = {}
    new_inode_tracking = {}

    excluded_dirs = set(exclusions.get("directories", []))
    excluded_files = set(exclusions.get("files", []))

    existing_files = set()

    for directory in scheduled_directories + real_time_directories:
        if directory in excluded_dirs:
            continue

        for filepath in Path(directory).rglob("*"):
            str_filepath = str(filepath)

            # ✅ **Apply exclusions before processing**
            if str_filepath in excluded_files or any(str_filepath.startswith(excluded_dir) for excluded_dir in excluded_dirs):
                continue

            if filepath.is_file():
                file_hash = get_file_hash(filepath)
                metadata = get_file_metadata(filepath)

                if file_hash and metadata:
                    inode = metadata["inode"]  # ✅ NEW: Track inode

                    # **✅ Check if this inode was seen before at a different path (File Moved)**
                    if inode in inode_tracking and inode_tracking[inode] != str_filepath:
                        log_event(
                            event_type="MOVED",
                            file_path=str_filepath,
                            previous_metadata=integrity_state.get(inode_tracking[inode], None),
                            new_metadata=metadata,
                            previous_hash=file_hashes.get(inode_tracking[inode], None),
                            new_hash=file_hash
                        )
                        print(f"[INFO] File moved: {inode_tracking[inode]} → {str_filepath}")

                        # ✅ **Remove old file tracking**
                        file_hashes.pop(inode_tracking[inode], None)
                        integrity_state.pop(inode_tracking[inode], None)

                    # ✅ **Track new file information**
                    new_file_hashes[str_filepath] = file_hash
                    new_integrity_state[str_filepath] = metadata
                    new_inode_tracking[inode] = str_filepath  # ✅ Store inode mapping
                    existing_files.add(str_filepath)

    # 🔹 **Detect Deleted Files (Not Moved)**
    deleted_files = set(file_hashes.keys()) - existing_files
    for deleted_file in deleted_files:
        log_event(
            event_type="DELETED",
            file_path=deleted_file,
            previous_metadata=integrity_state.get(deleted_file, None),
            new_metadata=None,
            previous_hash=file_hashes.get(deleted_file, None),
            new_hash=None
        )
        print(f"[INFO] Detected deleted file: {deleted_file}")

        file_hashes.pop(deleted_file, None)
        integrity_state.pop(deleted_file, None)

    # ✅ **Save Updated Hashes, Integrity State, and Inode Tracking**
    save_file_hashes(new_file_hashes)
    save_integrity_state(new_integrity_state)
    save_inode_tracking(new_inode_tracking)  # ✅ NEW: Save inode tracking persistently

    print("[INFO] File hash and integrity state tracking updated.")

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
    temp_hash_file = f"{HASH_FILE}.tmp"

    # ✅ Write new hashes to a temporary file first
    with open(temp_hash_file, "w") as f:
        for file, file_hash in file_hashes.items():
            f.write(f"{file}:{file_hash}\n")

    # ✅ Only create a backup if the current file exists and is not empty
    if os.path.exists(HASH_FILE) and os.stat(HASH_FILE).st_size > 0:
        shutil.copy(HASH_FILE, f"{HASH_FILE}_old")  # ✅ Preserve previous state instead of moving

    # ✅ Now, safely replace the existing file with the new version
    shutil.copy(temp_hash_file, HASH_FILE)

    # ✅ Explicitly set file permissions
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
    moved_files = {}  # Dictionary to track moved files (inode: old_path)

    def process_IN_CREATE(self, event):
        """Handles file creation."""
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
        """Handles file deletion. Avoid logging if the file was moved."""
        full_path = event.pathname
        previous_metadata = integrity_state.get(full_path, None)
        previous_hash = file_hashes.get(full_path, None)

        # **Check if this file was moved before considering it deleted**
        if previous_metadata and previous_metadata["inode"] in self.moved_files:
            return  # Skip delete event as it's part of a move

        log_event(
            event_type="DELETED",
            file_path=full_path,
            previous_metadata=previous_metadata,
            new_metadata=None,
            previous_hash=previous_hash,
            new_hash=None
        )

        remove_file_tracking(full_path)

    def process_IN_ATTRIB(self, event):
        """Handles metadata changes like permission and ownership updates."""
        full_path = event.pathname
        metadata = get_file_metadata(full_path)
        previous_metadata = integrity_state.get(full_path)

        if metadata and previous_metadata and compare_metadata(previous_metadata, metadata):
            log_event(
                event_type="METADATA_CHANGED",
                file_path=full_path,
                previous_metadata=previous_metadata,
                new_metadata=metadata,
                previous_hash=None,
                new_hash=None
            )
            update_file_tracking(full_path, get_file_hash(full_path), metadata)

    def process_IN_MODIFY(self, event):
        """Handles file modifications."""
        full_path = event.pathname
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)
        previous_hash = file_hashes.get(full_path)
        previous_metadata = integrity_state.get(full_path)

        if file_hash and file_hash != previous_hash:
            log_event(
                event_type="MODIFIED",
                file_path=full_path,
                previous_metadata=previous_metadata,
                new_metadata=metadata,
                previous_hash=previous_hash,
                new_hash=file_hash
            )
            update_file_tracking(full_path, file_hash, metadata)

    def process_IN_MOVED_FROM(self, event):
        """Handles a file being moved FROM a location."""
        full_path = event.pathname
        metadata = get_file_metadata(full_path)

        if metadata:
            inode = metadata["inode"]
            self.moved_files[inode] = full_path  # Store old path by inode
            print(f"[DEBUG] File moved FROM: {full_path} (inode: {inode})")

    def process_IN_MOVED_TO(self, event):
        """Handles a file being moved TO a new location."""
        full_path = event.pathname
        metadata = get_file_metadata(full_path)

        if metadata:
            inode = metadata["inode"]

            if inode in self.moved_files:
                old_path = self.moved_files.pop(inode)

                # Log MOVE event
                log_event(
                    event_type="MOVED",
                    file_path=full_path,
                    previous_metadata=get_file_metadata(old_path),
                    new_metadata=metadata,
                    previous_hash=get_file_hash(old_path),
                    new_hash=get_file_hash(full_path)
                )

                print(f"[INFO] File moved: {old_path} → {full_path}")

                # Ensure we update tracking
                remove_file_tracking(old_path)
                update_file_tracking(full_path, get_file_hash(full_path), metadata)

            else:
                # If we don't have a previous record, treat it as a new file
                file_hash = get_file_hash(full_path)
                log_event(
                    event_type="NEW FILE",
                    file_path=full_path,
                    previous_metadata=None,
                    new_metadata=metadata,
                    previous_hash=None,
                    new_hash=file_hash
                )
                update_file_tracking(full_path, file_hash, metadata)

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

def load_inode_tracking():
    """Load previous inode tracking data."""
    if os.path.exists(INODE_TRACKING_FILE):
        with open(INODE_TRACKING_FILE, "r") as f:
            return json.load(f)
    return {}

def save_inode_tracking(inode_tracking):
    """Save updated inode tracking data."""
    with open(INODE_TRACKING_FILE, "w") as f:
        json.dump(inode_tracking, f, indent=4)

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
