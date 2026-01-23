# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
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
import os
import json
import time
import hashlib
import sys
import argparse
import daemon
import signal
import re
import difflib
import subprocess
import shutil
import pyinotify
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from pathlib import Path

is_baseline_mode = False
exclusions = {}
integrity_state = {}

BASE_DIR = "/opt/FIMoniSec/Linux-Client"
CONFIG_FILE = os.path.join(BASE_DIR, "fim.config")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "file_monitor.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
PID_FILE = os.path.join(OUTPUT_DIR, "fim.pid")
INTEGRITY_STATE_FILE = os.path.join(OUTPUT_DIR, "integrity_state.json")

class EventHandler(pyinotify.ProcessEvent):
    """Event handler for file system changes."""

    def process_IN_CREATE(self, event):
        """Handles file creation with enhanced detection for moved files."""
        global is_baseline_mode, integrity_state, exclusions
        
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)
    
        if file_hash and metadata:
            # Add hash to metadata
            metadata["hash"] = file_hash
            
            # Check if this might be a moved file rather than a new file
            moved_from = detect_moved_file(file_hash, metadata, full_path)
            
            if moved_from:
                # This is likely a moved file
                if not is_baseline_mode:
                    prev_metadata = integrity_state.get(moved_from)
                    log_event(
                        event_type="MOVED",
                        file_path=full_path,
                        previous_metadata=prev_metadata,
                        new_metadata=metadata,
                        previous_hash=file_hash,
                        new_hash=file_hash,
                        old_path=moved_from
                    )
                
                # Remove the old file entry
                remove_file_tracking(moved_from)
                # Add the new file entry
                update_file_tracking(full_path, file_hash, metadata)
            else:
                # Only log events if not in baseline mode
                if not is_baseline_mode:
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
        """Handles file deletion."""
        global is_baseline_mode, integrity_state, exclusions
        
        full_path = event.pathname
        
        # Skip excluded files
        if should_exclude_file(full_path, exclusions):
            return
            
        previous_metadata = integrity_state.get(full_path, None)
        previous_hash = previous_metadata.get("hash") if previous_metadata else None

        if previous_metadata:  # Only log if we were tracking this file
            if not is_baseline_mode:
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
        """Handles metadata changes like permission, ownership, and size updates."""
        global is_baseline_mode, integrity_state, exclusions
        
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        metadata = get_file_metadata(full_path)
        previous_metadata = integrity_state.get(full_path)

        if metadata and previous_metadata:
            changes = compare_metadata(previous_metadata, metadata)

            if changes:
                # Preserve the hash in the metadata
                file_hash = previous_metadata.get("hash")
                metadata["hash"] = file_hash
                
                if not is_baseline_mode:
                    log_event(
                        event_type="METADATA_CHANGED",
                        file_path=full_path,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        changes=changes
                    )

                update_file_tracking(full_path, file_hash, metadata)

    def process_IN_MODIFY(self, event):
        """Handles file modifications."""
        global is_baseline_mode, integrity_state, exclusions
        
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)
        previous_metadata = integrity_state.get(full_path)
        previous_hash = previous_metadata.get("hash") if previous_metadata else None

        if file_hash and previous_hash and file_hash != previous_hash:
            # Add hash to metadata
            metadata["hash"] = file_hash
            
            if not is_baseline_mode:
                log_event(
                    event_type="MODIFIED",
                    file_path=full_path,
                    previous_metadata=previous_metadata,
                    new_metadata=metadata,
                    previous_hash=previous_hash,
                    new_hash=file_hash
                )

            update_file_tracking(full_path, file_hash, metadata)
    
######################################################################################

def load_config():
    """Load configuration settings from fim.config file."""
    if not os.path.exists(CONFIG_FILE):
        print("[ERROR] Configuration file not found. Creating default config...")
        create_default_config()
        return load_config()  # Reload after creating the default config

    with open(CONFIG_FILE, "r") as f:
        try:
            config = json.load(f)

            # Ensure the 'siem_settings' key exists
            if "siem_settings" not in config:
                print("[WARNING] 'siem_settings' key missing in fim.config. Adding default...")
                config["siem_settings"] = {
                    "enabled": False,
                    "siem_type": "none",
                    "host": "",
                    "port": 514,
                    "protocol": "udp"
                }
                # Save the updated config
                with open(CONFIG_FILE, "w") as fw:
                    json.dump(config, fw, indent=4)

            return config

        except json.JSONDecodeError:
            print("[ERROR] Invalid JSON format in fim.config. Creating a new default config...")
            create_default_config()
            return load_config()  # Reload the default config

def create_default_config():
    """Create a default configuration file."""
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
            ],
            "patterns": [
                "*.tmp",
                "*.log",
                "*.swp",
                "*~"
            ],
            "extensions": [
                ".bak",
                ".tmp",
                ".swp",
                ".cache"
            ],
            "max_size": 1073741824
        },
        "siem_settings": {
            "enabled": False,
            "siem_server": "",
            "siem_port": 0
        },
        "performance": {
            "worker_threads": 4,
            "chunk_size": 65536
        },
        "client_settings": {
            "BASE_DIR": "/opt/FIMoniSec/Linux-Client",
            "lim_enabled": False
        }
    }

    # Ensure directory exists
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)

    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)
    os.chmod(CONFIG_FILE, 0o600)

    print(f"[INFO] Created default configuration file: {CONFIG_FILE}")

def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None, changes=None, old_path=None):
    """Log file change events with exact details of what changed."""
    global integrity_state, is_baseline_mode

    # Skip alerts during baseline mode
    if is_baseline_mode:
        return None

    # Get MITRE ATT&CK mapping
    mitre_mapping = get_mitre_mapping(event_type, file_path, changes)

    # Create log entry
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "log_type": "FIM",
        "event_type": event_type,
        "file_path": file_path,
        "mitre_mapping": mitre_mapping
    }

    # Add original path for moved files
    if event_type == "MOVED" and old_path:
        log_entry["old_path"] = old_path

    # Add hash information if available
    if previous_hash:
        log_entry["previous_hash"] = previous_hash
    if new_hash:
        log_entry["new_hash"] = new_hash

    # Add metadata changes if available
    if changes:
        log_entry["changes"] = changes

    # Enhanced logging for config file changes
    if event_type in ["MODIFIED", "METADATA_CHANGED"] and is_config_file(file_path):
        config_diff = get_config_diff(file_path)
        if config_diff:
            log_entry["config_changes"] = {
                "diff": config_diff[:20]  # Limit to 20 lines
            }

    # Write to log file
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry, indent=4) + "\n")

    # Print alert
    mitre_id = mitre_mapping.get("technique_id", "Unknown")
    mitre_name = mitre_mapping.get("technique_name", "Unknown")
    mitre_tactic = mitre_mapping.get("tactic", "Unknown")

    # Format changes text
    changes_text = ""
    if event_type == "METADATA_CHANGED" and changes:
        change_items = list(changes.keys())
        if change_items:
            changes_text = f" ({', '.join(change_items)})"

    # Print alert based on event type
    if event_type == "NEW FILE":
        print(f"[NEW FILE] {file_path} - MITRE: {mitre_id} ({mitre_name}, {mitre_tactic})")
        if is_config_file(file_path):
            backup_config_file(file_path)
    elif event_type == "DELETED":
        print(f"[DELETED] {file_path} - MITRE: {mitre_id} ({mitre_name}, {mitre_tactic})")
    elif event_type == "MODIFIED":
        print(f"[MODIFIED] {file_path} - MITRE: {mitre_id} ({mitre_name}, {mitre_tactic})")
        if "config_changes" in log_entry and "diff" in log_entry["config_changes"]:
            print(f"[CONFIG CHANGES for {file_path}]:")
            for diff_line in log_entry["config_changes"]["diff"][:5]:
                print(f"  {diff_line}")
            if len(log_entry["config_changes"]["diff"]) > 5:
                print(f"  ... and {len(log_entry['config_changes']['diff']) - 5} more changes")
    elif event_type == "METADATA_CHANGED":
        print(f"[METADATA] {file_path}{changes_text} - MITRE: {mitre_id} ({mitre_name}, {mitre_tactic})")
    elif event_type == "MOVED":
        print(f"[MOVED] {old_path} -> {file_path} - MITRE: {mitre_id} ({mitre_name}, {mitre_tactic})")
        if is_config_file(file_path):
            backup_config_file(file_path)

    return log_entry

def process_file(filepath, integrity_state):
    """Process a single file for hashing and metadata tracking."""
    str_filepath = str(filepath)
    metadata = get_file_metadata(filepath)

    if not metadata:
        return None

    prev_metadata = integrity_state.get(str_filepath)
    file_hash = None

    # Use hash cache: Only compute a hash if the file was modified
    if not prev_metadata or metadata["last_modified"] != prev_metadata["last_modified"]:
        file_hash = get_file_hash(filepath)  # Compute new hash
    else:
        file_hash = prev_metadata.get("hash")  # Reuse existing hash

    if file_hash:
        # Include the hash in the metadata
        metadata["hash"] = file_hash
        return str_filepath, file_hash, metadata
    return None

def generate_file_hashes(scheduled_directories, real_time_directories, exclusions, config=None):
    """Generate and store SHA-256 hashes for all monitored files, tracking changes over time."""
    global is_baseline_mode  # Add global declaration here
    
    # Check if this is an initial baseline
    is_initial_baseline = not os.path.exists(INTEGRITY_STATE_FILE) or os.path.getsize(INTEGRITY_STATE_FILE) <= 2  # {} is 2 bytes
    
    if is_initial_baseline:
        print("[INFO] Performing initial baseline - alerts will be suppressed during this process")
        is_baseline_mode = True  # Set the global variable
    
    integrity_state = load_integrity_state()

    # Performance optimization: Dynamic thread pool sizing
    cpu_count = os.cpu_count() or 2
    worker_count = 4  # Default value
    
    if config and "performance" in config:
        worker_count = config.get("performance", {}).get("worker_threads", cpu_count)
    
    # Avoid excessive threads
    worker_count = min(worker_count, cpu_count * 2)
    worker_count = max(worker_count, 2)  # Ensure at least 2 threads

    print(f"[INFO] Using {worker_count} worker threads for file processing")

    new_integrity_state = integrity_state.copy()
    existing_files = set()
    all_files = []

    start_time = time.time()
    
    # Build file list with enhanced exclusion logic
    for directory in scheduled_directories + real_time_directories:
        if directory in exclusions.get("directories", []):
            continue
        for filepath in Path(directory).rglob("*"):
            if filepath.is_file() and not should_exclude_file(filepath, exclusions):
                all_files.append(filepath)

    file_count = len(all_files)
    print(f"[INFO] Found {file_count} files to process")
    
    # Create a separate function for processing each file
    def process_file_with_backup(filepath):
        result = process_file(filepath, integrity_state)
        
        # Backup config files during the scan
        str_filepath = str(filepath)
        if is_config_file(str_filepath):
            backup_config_file(str_filepath)
            
        return result
    
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = executor.map(process_file_with_backup, all_files)

    changes_detected = 0
    
    for result in results:
        if result:
            str_filepath, file_hash, metadata = result
            existing_files.add(str_filepath)

            previous_metadata = integrity_state.get(str_filepath)
            previous_hash = previous_metadata.get("hash") if previous_metadata else None

            if str_filepath in integrity_state:
                # Detect Metadata Changes Separately
                metadata_changes = compare_metadata(previous_metadata, metadata)
                if metadata_changes:
                    # Only log during non-baseline operations
                    if not is_initial_baseline:
                        log_event(
                            event_type="METADATA_CHANGED",
                            file_path=str_filepath,
                            previous_metadata=previous_metadata,
                            new_metadata=metadata,
                            changes=metadata_changes
                        )
                    changes_detected += 1

                # Detect Content Changes (Hash Differences)
                if previous_hash != file_hash:
                    # Only log during non-baseline operations
                    if not is_initial_baseline:
                        log_event(
                            event_type="MODIFIED",
                            file_path=str_filepath,
                            previous_metadata=previous_metadata,
                            new_metadata=metadata,
                            previous_hash=previous_hash,
                            new_hash=file_hash
                        )
                    changes_detected += 1

            else:
                # Only log during non-baseline operations
                if not is_initial_baseline:
                    log_event(
                        event_type="NEW FILE",
                        file_path=str_filepath,
                        previous_metadata=None,
                        new_metadata=metadata,
                        previous_hash=None,
                        new_hash=file_hash
                    )
                changes_detected += 1

            new_integrity_state[str_filepath] = metadata

    # Detect deleted files (but not during initial baseline)
    if not is_initial_baseline:
        deleted_files = set(integrity_state.keys()) - existing_files
        for deleted_file in deleted_files:
            previous_metadata = integrity_state.get(deleted_file)
            previous_hash = previous_metadata.get("hash") if previous_metadata else None
            
            log_event(
                event_type="DELETED",
                file_path=deleted_file,
                previous_metadata=integrity_state.get(deleted_file, None),
                new_metadata=None,
                previous_hash=previous_hash,
                new_hash=None
            )
            new_integrity_state.pop(deleted_file, None)
            changes_detected += 1

    save_integrity_state(new_integrity_state)

    # Add execution stats
    end_time = time.time()
    duration = end_time - start_time
    
    if is_initial_baseline:
        print(f"[INFO] Initial baseline completed in {duration:.2f} seconds. Added {changes_detected} files to integrity state.")
        print("[INFO] Config files have been backed up for future comparison.")
        is_baseline_mode = False  # Reset baseline mode after completion
    else:
        print(f"[INFO] Scan completed in {duration:.2f} seconds. Detected {changes_detected} changes.")

def compare_metadata(prev_metadata, new_metadata):
    """Compare metadata and categorize changes into specific types."""
    if not prev_metadata or not new_metadata:
        return None

    changes = {}

    # Ownership change detection
    if prev_metadata.get("owner") != new_metadata.get("owner") or prev_metadata.get("group") != new_metadata.get("group"):
        changes["Ownership changed"] = {
            "previous_owner": prev_metadata.get("owner", "Unknown"),
            "new_owner": new_metadata.get("owner", "Unknown"),
            "previous_group": prev_metadata.get("group", "Unknown"),
            "new_group": new_metadata.get("group", "Unknown")
        }

    # Permissions change detection
    if prev_metadata.get("permissions") != new_metadata.get("permissions"):
        changes["Permissions changed"] = {
            "previous_permissions": prev_metadata.get("permissions", "Unknown"),
            "new_permissions": new_metadata.get("permissions", "Unknown")
        }

    # Size change detection
    if prev_metadata.get("size") != new_metadata.get("size"):
        changes["Size changed"] = {
            "previous_size": prev_metadata.get("size", "Unknown"),
            "new_size": new_metadata.get("size", "Unknown")
        }

    # Last modified timestamp change detection
    if prev_metadata.get("last_modified") != new_metadata.get("last_modified"):
        changes["Last modified timestamp changed"] = {
            "previous_timestamp": prev_metadata.get("last_modified", "Unknown"),
            "new_timestamp": new_metadata.get("last_modified", "Unknown")
        }

    return changes if changes else None

def get_file_hash(filepath, chunk_size=65536):
    """Generate SHA-256 hash of a file efficiently using buffered reads."""
    try:
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception:
        return None  # File may have been deleted before reading

def load_integrity_state():
    """Load previous integrity state from the integrity_state.json file with error handling."""
    if os.path.exists(INTEGRITY_STATE_FILE):
        try:
            with open(INTEGRITY_STATE_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Corrupted integrity state file: {e}")
            print("[INFO] Creating backup of corrupted file and starting with empty state")
            
            # Create backup of corrupted file
            backup_file = f"{INTEGRITY_STATE_FILE}.corrupt_{int(time.time())}"
            try:
                shutil.copy(INTEGRITY_STATE_FILE, backup_file)
                print(f"[INFO] Backup created at: {backup_file}")
            except Exception as backup_error:
                print(f"[ERROR] Failed to create backup: {backup_error}")
            
            # Try to repair the JSON file if possible
            try:
                repaired = repair_json_file(INTEGRITY_STATE_FILE)
                if repaired:
                    print("[INFO] Successfully repaired integrity state file")
                    with open(INTEGRITY_STATE_FILE, "r") as f:
                        return json.load(f)
            except Exception as repair_error:
                print(f"[ERROR] Could not repair file: {repair_error}")
            
            # If repair failed or wasn't attempted, create an empty state
            return {}
    return {}

def repair_json_file(file_path):
    """Attempt to repair a corrupted JSON file by finding and fixing syntax errors."""
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        # Common JSON corruption patterns and fixes
        # 1. Truncated file - add missing closing braces
        if content.count('{') > content.count('}'):
            content += '}' * (content.count('{') - content.count('}'))
        
        # 2. Handle trailing commas in arrays/objects
        content = re.sub(r',\s*}', '}', content)
        content = re.sub(r',\s*]', ']', content)
        
        # 3. Fix unescaped quotes in strings
        # This is a simplified approach - a full repair might need more sophisticated handling
        
        # Test if the repaired content is valid JSON
        json.loads(content)
        
        # If we got here, the repair worked - write it back
        with open(file_path, "w") as f:
            f.write(content)
        
        return True
    except Exception as e:
        print(f"[ERROR] Repair attempt failed: {e}")
        
        # If repair failed, create a new empty JSON object
        try:
            with open(file_path, "w") as f:
                f.write('{}')
            return True
        except Exception as write_error:
            print(f"[ERROR] Failed to write new empty file: {write_error}")
            return False

def save_integrity_state(state):
    """Save the integrity state to the integrity_state.json file with validation."""
    if not isinstance(state, dict):
        print(f"[ERROR] Invalid integrity state type: {type(state)}. Expected dict.")
        return False
    
    # Create a temporary file first
    temp_file = f"{INTEGRITY_STATE_FILE}.tmp"
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(INTEGRITY_STATE_FILE), exist_ok=True)
        
        # Validate the state can be serialized to JSON
        json_data = json.dumps(state, indent=4)
        
        # Write to temporary file first
        with open(temp_file, "w") as f:
            f.write(json_data)
        
        # Verify the file was written correctly by reading it back
        with open(temp_file, "r") as f:
            json.load(f)
        
        # Create a backup of the current file if it exists
        if os.path.exists(INTEGRITY_STATE_FILE):
            backup_file = f"{INTEGRITY_STATE_FILE}.bak"
            try:
                shutil.copy(INTEGRITY_STATE_FILE, backup_file)
            except Exception as e:
                print(f"[WARNING] Failed to create backup: {e}")
        
        # Move the temp file to the final location
        shutil.move(temp_file, INTEGRITY_STATE_FILE)
        
        # Set permissions
        os.chmod(INTEGRITY_STATE_FILE, 0o600)
        
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save integrity state: {e}")
        
        # If anything went wrong, try to remove the temp file
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        
        return False

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

def monitor_changes(real_time_directories, exclusions):
    """Monitors file system changes using pyinotify with error handling."""
    global integrity_state, is_baseline_mode
    
    try:
        integrity_state = load_integrity_state()

        wm = pyinotify.WatchManager()
        handler = EventHandler()
        notifier = pyinotify.Notifier(wm, handler)

        # Watch all directories and subdirectories
        for directory in real_time_directories:
            if directory in exclusions.get("directories", []):
                continue
            
            try:
                mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB
                wm.add_watch(directory, mask, rec=True, auto_add=True)
                print(f"[INFO] Watching directory: {directory}")
            except Exception as e:
                print(f"[ERROR] Failed to watch directory {directory}: {e}")

        print("[INFO] Real-time monitoring started using pyinotify...")

        # Start monitoring
        notifier.loop()
    except Exception as e:
        print(f"[ERROR] Real-time monitoring thread crashed: {e}")
        print("[INFO] Attempting to restart real-time monitoring in 10 seconds...")
        time.sleep(10)
        
        # Recursive call to restart the monitoring
        monitor_changes(real_time_directories, exclusions)

def remove_file_tracking(file_path):
    """Remove deleted file from tracking."""
    global integrity_state
    if file_path in integrity_state:
        del integrity_state[file_path]
    save_integrity_state(integrity_state)

def update_file_tracking(file_path, file_hash, metadata):
    """Update file tracking information for new or modified files."""
    global integrity_state  # Ensure these are accessible

    # Add hash to metadata
    metadata["hash"] = file_hash
    integrity_state[file_path] = metadata
    
    save_integrity_state(integrity_state)

def scan_files(scheduled_directories, scan_interval, exclusions):
    """Perform periodic file integrity scans with enhanced move detection."""
    print("[INFO] Periodic scanning started...")
    integrity_state = load_integrity_state()

    while True:
        start_time = time.time()
        changes_detected = 0
        
        # First pass: collect all current files
        current_files = {}
        for directory in scheduled_directories:
            if directory not in exclusions.get("directories", []):
                for filepath in Path(directory).rglob("*"):
                    if filepath.is_file() and not should_exclude_file(filepath, exclusions):
                        str_filepath = str(filepath)
                        metadata = get_file_metadata(filepath)
                        file_hash = get_file_hash(filepath)
                        
                        if file_hash and metadata:
                            # Store metadata and hash for later processing
                            metadata["hash"] = file_hash
                            current_files[str_filepath] = (file_hash, metadata)
        
        # Second pass: process changes including moves
        for str_filepath, (file_hash, metadata) in current_files.items():
            previous_metadata = integrity_state.get(str_filepath)
            previous_hash = previous_metadata.get("hash") if previous_metadata else None

            # Skip if both hash and metadata are unchanged
            if previous_hash == file_hash and previous_metadata and \
               all(previous_metadata.get(k) == metadata.get(k) for k in metadata.keys() if k != "hash"):
                continue  # No changes, move to next file

            # Check if this is a new file
            if not previous_metadata:
                # Check if it might be a moved file
                moved_from = detect_moved_file(file_hash, metadata, str_filepath)
                
                if moved_from:
                    # This is likely a moved file
                    prev_metadata = integrity_state.get(moved_from)
                    log_event(
                        event_type="MOVED",
                        file_path=str_filepath,
                        previous_metadata=prev_metadata,
                        new_metadata=metadata,
                        previous_hash=file_hash,
                        new_hash=file_hash,
                        old_path=moved_from
                    )
                    
                    # Remove the old file entry
                    integrity_state.pop(moved_from, None)
                    changes_detected += 1
                else:
                    # Genuinely new file
                    log_event(
                        event_type="NEW FILE",
                        file_path=str_filepath,
                        previous_metadata=None,
                        new_metadata=metadata,
                        previous_hash=None,
                        new_hash=file_hash
                    )
                    changes_detected += 1
            else:
                # Check for metadata changes
                metadata_changes = compare_metadata(previous_metadata, metadata)
                if metadata_changes:
                    log_event(
                        event_type="METADATA_CHANGED",
                        file_path=str_filepath,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        changes=metadata_changes
                    )
                    changes_detected += 1
                
                # Check for content changes (if metadata changes weren't detected)
                elif previous_hash != file_hash:
                    log_event(
                        event_type="MODIFIED",
                        file_path=str_filepath,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        previous_hash=previous_hash,
                        new_hash=file_hash
                    )
                    changes_detected += 1

            # Update integrity state with current info
            integrity_state[str_filepath] = metadata

        # Check for deleted files
        existing_files = set(current_files.keys())
        deleted_files = set(integrity_state.keys()) - existing_files
        
        for deleted_file in deleted_files:
            previous_metadata = integrity_state.get(deleted_file)
            previous_hash = previous_metadata.get("hash") if previous_metadata else None
            
            # Check if this file was part of a move operation
            # If it was, it would have been removed from integrity_state already
            if deleted_file in integrity_state:
                log_event(
                    event_type="DELETED",
                    file_path=deleted_file,
                    previous_metadata=integrity_state.get(deleted_file, None),
                    new_metadata=None,
                    previous_hash=previous_hash,
                    new_hash=None
                )
                integrity_state.pop(deleted_file, None)
                changes_detected += 1

        # Save the updated integrity state
        save_integrity_state(integrity_state)

        # Report scan results
        end_time = time.time()
        duration = end_time - start_time
        if changes_detected > 0:
            print(f"[INFO] Scheduled scan completed in {duration:.2f} seconds. Detected {changes_detected} changes.")
        else:
            print(f"[INFO] Scheduled scan completed in {duration:.2f} seconds. No changes detected.")
        
        # Wait for next scan interval
        time.sleep(scan_interval)

def should_exclude_file(file_path, exclusions):
    """Determine if a file should be excluded based on various criteria."""
    str_path = str(file_path)
    
    # Basic path exclusion
    if str_path in exclusions.get("files", []):
        return True
        
    # Directory exclusion
    for excluded_dir in exclusions.get("directories", []):
        if str_path.startswith(excluded_dir):
            return True
    
    # Pattern exclusion (glob patterns)
    for pattern in exclusions.get("patterns", []):
        if Path(str_path).match(pattern):
            return True
    
    # Extension exclusion
    if Path(str_path).suffix.lower() in exclusions.get("extensions", []):
        return True
    
    # Size exclusion
    if "max_size" in exclusions:
        try:
            if os.path.exists(str_path) and os.path.isfile(str_path) and os.path.getsize(str_path) > exclusions["max_size"]:
                return True
        except (OSError, IOError):
            pass  # If we can't check size, don't exclude
    
    return False

def detect_moved_file(file_hash, metadata, new_path):
    """Detect if a file was moved by comparing hash and inode with existing tracked files."""
    global integrity_state
    
    # Files with the same hash and inode are likely the same file that was moved
    current_inode = metadata.get("inode")
    
    for path, file_data in integrity_state.items():
        # Skip the current file
        if path == new_path:
            continue
            
        # Check if hash matches
        if file_data.get("hash") == file_hash:
            # If the inode also matches, this is very likely a moved file
            if file_data.get("inode") == current_inode:
                return path
            
            # If only hash matches but file size is the same, it might be a copy
            # This is a weaker indication but still useful
            if file_data.get("size") == metadata.get("size"):
                # Check if the original file still exists
                if not os.path.exists(path):
                    return path
    
    # No match found
    return None

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
    """Run the file monitoring process with real-time monitoring and scheduled scans."""
    global is_baseline_mode, integrity_state, exclusions

    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    config = load_config()
    scheduled_scan = config.get("scheduled_scan", {})
    real_time_monitoring = config.get("real_time_monitoring", {})
    exclusions = config.get("exclusions", {})

    scheduled_directories = scheduled_scan.get("directories", [])
    scan_interval = scheduled_scan.get("scan_interval", 300)
    real_time_directories = real_time_monitoring.get("directories", [])

    if not scheduled_directories and not real_time_directories:
        print("[ERROR] No directories specified for monitoring. Exiting.")
        handle_shutdown()

    # Check if this is an initial baseline run
    is_baseline_mode = not os.path.exists(INTEGRITY_STATE_FILE) or os.path.getsize(INTEGRITY_STATE_FILE) <= 2

    if is_baseline_mode:
        print("\n[INFO] INITIAL BASELINE MODE - Creating baseline integrity state...")
        print("[INFO] No alerts will be generated until baseline is complete\n")

    # Load initial integrity state
    integrity_state = load_integrity_state()

    # Start real-time monitoring in a background thread
    if real_time_directories:
        rt_monitor = Thread(target=monitor_changes, args=(real_time_directories, exclusions), daemon=True)
        rt_monitor.start()
        print("[INFO] Real-time monitoring started.")

    # Run the scheduled scan
    if scheduled_directories:
        try:
            print("[INFO] Starting scheduled file scanning")
            # Run an initial scan
            generate_file_hashes(scheduled_directories, real_time_directories, exclusions, config)

            # Then perform periodic scans
            scan_thread = Thread(target=scan_files, args=(scheduled_directories, scan_interval, exclusions), daemon=True)
            scan_thread.start()

            # Keep main thread alive
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            handle_shutdown()
    else:
        # If no scheduled directories, just keep the main thread alive
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            handle_shutdown()

############################################################################################################

def is_binary_file(file_path):
    """Check if a file is likely binary based on extension."""
    if not file_path or file_path == "N/A":
        return False

    binary_extensions = [
        '.exe', '.bin', '.o', '.so', '.dll', '.pyc', '.pyd',
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico',
        '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.deb', '.rpm', '.iso', '.img'
    ]

    return any(file_path.lower().endswith(ext) for ext in binary_extensions)

def is_config_file(file_path):
    """Check if a file is a configuration file."""
    if not file_path or file_path == "N/A":
        return False

    # Skip binary files
    if is_binary_file(file_path):
        return False

    # Config file extensions
    config_extensions = ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml', '.xml', '.properties']
    file_path_lower = file_path.lower()

    # Check by extension
    if any(file_path_lower.endswith(ext) for ext in config_extensions):
        return True

    # Files in /etc are typically configs
    if file_path.startswith('/etc/'):
        # Exclude non-config patterns
        non_config_patterns = ['.cache', '.lock', '.socket', '.pid', '.placeholder']
        if not any(pattern in file_path_lower for pattern in non_config_patterns):
            return True

    # Check for common config naming patterns
    file_name = os.path.basename(file_path_lower)
    if file_name.endswith('_config') or file_name == 'config':
        return True

    return False

def get_config_diff(file_path):
    """Get diff between current config file and its backup using sudo if necessary."""
    if not is_config_file(file_path):
        return None
        
    try:
        # Get the backup path
        config_backup_dir = os.path.join(OUTPUT_DIR, "config_backups")
        safe_filename = file_path.replace("/", "_").replace("\\", "_")
        backup_path = os.path.join(config_backup_dir, f"{safe_filename}.bak")
        
        # If we don't have a backup yet, create one and return None (no diff available)
        if not os.path.exists(backup_path):
            backup_config_file(file_path)
            return None
        
        # Read backup content
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                old_content = f.read()
        except UnicodeDecodeError:
            with open(backup_path, 'rb') as f:
                old_content = f.read().decode('latin1')  # Use latin1 as fallback
                
        # Read current content - first try normal access
        new_content = None
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                new_content = f.read()
        except (IOError, PermissionError, UnicodeDecodeError):
            try:
                # Try using sudo cat
                result = subprocess.run(['sudo', '/bin/cat', file_path], 
                                     capture_output=True, 
                                     text=True, 
                                     check=True)
                new_content = result.stdout
            except subprocess.SubprocessError as se:
                print(f"[WARNING] Failed to read config file {file_path} even with sudo: {str(se)}")
                return None
        
        if not new_content:
            return None
            
        # Calculate diff
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        diff = list(difflib.unified_diff(old_lines, new_lines, n=2))
        
        # Process the diff to make it more readable
        readable_diff = []
        for line in diff[3:] if len(diff) > 3 else []:  # Skip the header lines
            if line.startswith('+'):
                readable_diff.append(f"Added: {line[1:]}")
            elif line.startswith('-'):
                readable_diff.append(f"Removed: {line[1:]}")
        
        # After getting diff, update the backup
        backup_config_file(file_path)
        
        return readable_diff if readable_diff else None
        
    except Exception as e:
        print(f"[WARNING] Failed to generate config diff for {file_path}: {str(e)}")
        return None

def backup_config_file(file_path):
    """Create or update a backup of a config file using sudo if necessary."""
    try:
        # Create config backup directory if it doesn't exist
        config_backup_dir = os.path.join(OUTPUT_DIR, "config_backups")
        
        # Create directory if it doesn't exist
        if not os.path.exists(config_backup_dir):
            os.makedirs(config_backup_dir, exist_ok=True)
            # Set secure permissions (0700) on the directory
            os.chmod(config_backup_dir, 0o700)
            print(f"[INFO] Created config backup directory with secure permissions (0700)")
        else:
            # Ensure the directory has the correct permissions
            current_mode = os.stat(config_backup_dir).st_mode & 0o777
            if current_mode != 0o700:
                os.chmod(config_backup_dir, 0o700)
                print(f"[INFO] Updated config backup directory permissions from {oct(current_mode)} to 0700")
        
        # Create a safe filename for the backup
        safe_filename = file_path.replace("/", "_").replace("\\", "_")
        backup_path = os.path.join(config_backup_dir, f"{safe_filename}.bak")
        
        # Only create backup if file exists
        if os.path.exists(file_path) and os.path.isfile(file_path):
            # First try binary mode to be safe
            try:
                # Try using sudo cat with binary output
                result = subprocess.run(['sudo', '/bin/cat', file_path], 
                                     capture_output=True, 
                                     check=True)
                
                # Write the output to our backup file in binary mode
                with open(backup_path, 'wb') as dst:
                    dst.write(result.stdout)
                    
                print(f"[INFO] Successfully backed up config file: {file_path}")
                    
            except subprocess.SubprocessError as se:
                print(f"[WARNING] Failed to backup config file {file_path} with sudo: {str(se)}")
                
                # Try normal file access if sudo fails
                try:
                    with open(file_path, 'rb') as src:
                        content = src.read()
                        
                    with open(backup_path, 'wb') as dst:
                        dst.write(content)
                except (IOError, PermissionError) as e:
                    print(f"[WARNING] Failed to backup config file {file_path}: {str(e)}")
                    return None
                    
            # Set secure permissions on backup
            os.chmod(backup_path, 0o600)
            return backup_path
    except Exception as e:
        print(f"[WARNING] Failed to backup config file {file_path}: {str(e)}")
    
    return None

def is_system_directory(file_path):
    """Check if a file is in a system directory."""
    if not file_path or file_path == "N/A":
        return False
        
    system_dirs = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/usr/lib/', '/etc/']
    
    return any(file_path.startswith(d) for d in system_dirs)

def get_mitre_mapping(event_type, file_path, changes=None):
    """Map file events to MITRE ATT&CK techniques."""
    mitre_mapping = {
        "NEW FILE": {
            "technique_id": "T1222",
            "technique_name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion",
            "description": "Adversary created new file that could be used for persistence or execution"
        },
        "DELETED": {
            "technique_id": "T1485",
            "technique_name": "Data Destruction",
            "tactic": "Impact",
            "description": "Adversary deleted file that may be critical for system operation or evidence removal"
        },
        "MODIFIED": {
            "technique_id": "T1565",
            "technique_name": "Data Manipulation",
            "tactic": "Impact",
            "description": "Adversary modified existing file content"
        },
        "METADATA_CHANGED": {
            "technique_id": "T1222",
            "technique_name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion",
            "description": "Adversary modified file attributes which could indicate permission changes"
        },
        "MOVED": {
            "technique_id": "T1036",
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion",
            "description": "Adversary moved file to a different location, potentially to hide malicious activity or evade detection"
        }
    }
    
    # Context-aware mappings
    if event_type == "MODIFIED":
        if is_config_file(file_path):
            return {
                "technique_id": "T1562.001",
                "technique_name": "Disable or Modify Tools",
                "tactic": "Defense Evasion",
                "description": "Adversary may modify configuration files to disable security tools"
            }
        if "/etc/passwd" in file_path or "/etc/shadow" in file_path:
            return {
                "technique_id": "T1136",
                "technique_name": "Create Account",
                "tactic": "Persistence",
                "description": "Adversary may create accounts by modifying account databases"
            }
        if "/etc/crontab" in file_path or "/etc/cron.d" in file_path:
            return {
                "technique_id": "T1053.003",
                "technique_name": "Scheduled Task/Job: Cron",
                "tactic": "Persistence",
                "description": "Adversary may create scheduled tasks for persistence"
            }
        if ".ssh" in file_path:
            return {
                "technique_id": "T1098",
                "technique_name": "Account Manipulation",
                "tactic": "Persistence",
                "description": "Adversary may modify SSH keys for persistence"
            }
        if "/etc/hosts" in file_path:
            return {
                "technique_id": "T1565.002",
                "technique_name": "Data Manipulation: Transmitted Data Manipulation",
                "tactic": "Impact",
                "description": "Adversary may redirect network traffic by modifying hosts file"
            }
        if ".bashrc" in file_path or ".bash_profile" in file_path or ".profile" in file_path:
            return {
                "technique_id": "T1546.004",
                "technique_name": "Event Triggered Execution: Unix Shell Configuration Modification",
                "tactic": "Persistence",
                "description": "Adversary modified shell configuration for automatic execution"
            }
    
    # Handle metadata changes more specifically
    if event_type == "METADATA_CHANGED" and changes:
        if isinstance(changes, dict):
            if "Permissions changed" in changes:
                return {
                    "technique_id": "T1222.002",
                    "technique_name": "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
                    "tactic": "Defense Evasion",
                    "description": "Adversary modified permissions to allow execution or hide activity"
                }
            if "Ownership changed" in changes:
                return {
                    "technique_id": "T1222.002",
                    "technique_name": "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
                    "tactic": "Defense Evasion",
                    "description": "Adversary changed file ownership to execute with different privileges"
                }
    
    # For new files in specific locations
    if event_type == "NEW FILE":
        if "/etc/init.d/" in file_path or "/lib/systemd/" in file_path:
            return {
                "technique_id": "T1543.002",
                "technique_name": "Create or Modify System Process: Systemd Service",
                "tactic": "Persistence",
                "description": "Adversary created service file for persistence and privilege execution"
            }
        if "/var/www/" in file_path and any(ext in file_path.lower() for ext in ['.php', '.jsp', '.asp', '.aspx']):
            return {
                "technique_id": "T1505.003",
                "technique_name": "Server Software Component: Web Shell",
                "tactic": "Persistence",
                "description": "Adversary may have placed web shell for remote access"
            }
        if "/tmp/" in file_path and is_binary_file(file_path):
            return {
                "technique_id": "T1574.005",
                "technique_name": "Hijack Execution Flow: Dynamic Linker Hijacking",
                "tactic": "Persistence",
                "description": "Adversary placed binary in temporary directory for execution hijacking"
            }
    
    # Context-specific mappings for moved files
    if event_type == "MOVED":
        # Moving files to/from sensitive locations
        if "/etc/" in file_path:
            return {
                "technique_id": "T1036.005",
                "technique_name": "Masquerading: Match Legitimate Name or Location",
                "tactic": "Defense Evasion",
                "description": "Adversary moved file to a system configuration directory to appear legitimate"
            }
        if "/bin/" in file_path or "/sbin/" in file_path or "/usr/bin/" in file_path:
            return {
                "technique_id": "T1036.003",
                "technique_name": "Masquerading: Rename System Utilities",
                "tactic": "Defense Evasion",
                "description": "Adversary moved file to a system binary location, potentially masquerading as legitimate tool"
            }
        if "/tmp/" in file_path or "/var/tmp/" in file_path:
            return {
                "technique_id": "T1074.001",
                "technique_name": "Data Staged: Local Data Staging",
                "tactic": "Collection",
                "description": "Adversary moved file to a temporary location, potentially staging for exfiltration"
            }
        if "/.ssh/" in file_path:
            return {
                "technique_id": "T1098",
                "technique_name": "Account Manipulation",
                "tactic": "Persistence",
                "description": "Adversary moved file to SSH directory, potentially for persistence via SSH keys"
            }

    # Provide generic mapping if no specific context match
    return mitre_mapping.get(event_type, {
        "technique_id": "T1565",
        "technique_name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Generic file manipulation"
    })

############################################################

def handle_shutdown(signum=None, frame=None):
    """Cleanly handle shutdown signals."""
    print("[INFO] Caught termination signal. Cleaning up...")

    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
        print(f"[INFO] Removed PID file: {PID_FILE}")

    sys.exit(0)

def print_help():
    print("""
File Integrity Monitor (FIM) Client

Usage:
  python fim.py [option]

Options:
  help               Show this help message and exit
  -d or daemon       Run FIM in background (daemon) mode
  -s or stop         Stop FIM daemon process
""")

if __name__ == "__main__":
    args = sys.argv[1:]  # Get command-line arguments

    print("FIM Security Tool")

    if not args:
        print("[INFO] Running in foreground mode...")
        run_monitor()
        sys.exit(0)

    arg = args[0].lower()

    if arg in ("help", "-h", "--help"):
        print_help()
        sys.exit(0)

    elif arg in ("-s", "stop"):
        stop_daemon()
        sys.exit(0)

    elif arg in ("-d", "daemon"):
        print("[INFO] Running in background mode...")
        with daemon.DaemonContext():
            run_monitor()
        sys.exit(0)

    else:
        print(f"[ERROR] Unknown option: {arg}")
        print_help()
        sys.exit(1)
