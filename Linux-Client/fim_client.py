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
import os
import json
import time
import hashlib
import sys
import argparse
import daemon
import signal
from pathlib import Path
import stat
from threading import Thread
from daemon import DaemonContext
import shutil
import pyinotify
import audit
from concurrent.futures import ThreadPoolExecutor
#from monisec_client import BASE_DIR

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries (numpy, pandas, sklearn) not available.")
    print("[WARNING] ML-based anomaly detection will be disabled.")
    print("[INFO] Install with: pip install numpy pandas scikit-learn")
    ML_LIBRARIES_AVAILABLE = False

# Global variable for ML model
ml_model_info = None

# Global variable for exclusions config
exclusions = {}

def get_base_dir():
    """Get the base directory for the application based on script location"""
    return os.path.dirname(os.path.abspath(__file__))

# Set BASE_DIR
BASE_DIR = get_base_dir()

# Define all paths relative to BASE_DIR
CONFIG_FILE = os.path.join(BASE_DIR, "fim.config")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "file_monitor.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
PID_FILE = os.path.join(OUTPUT_DIR, "fim.pid")
HASH_FILE = os.path.join(OUTPUT_DIR, "file_hashes.txt")
INTEGRITY_STATE_FILE = os.path.join(OUTPUT_DIR, "integrity_state.json")

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
            
def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None, changes=None):
    """Log file change events with exact details of what changed."""
    global ml_model_info
    
    # Correlate with process information if available
    process_correlation = correlate_with_processes(file_path, event_type)
    
    # Get MITRE ATT&CK mapping
    mitre_mapping = get_mitre_mapping(event_type, file_path, changes)
    
    # Create base log entry
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": previous_metadata if previous_metadata else "N/A",
        "new_metadata": new_metadata if new_metadata else "N/A",
        "changes": changes if changes else "N/A",
        "previous_hash": previous_hash if previous_hash else "N/A",
        "new_hash": new_hash if new_hash else "N/A",
        "process_correlation": process_correlation if process_correlation else "N/A",
        "mitre_mapping": mitre_mapping
    }

    # Check for anomalies if ML model is available
    if ml_model_info:
        anomaly_result = detect_file_anomalies(log_entry, ml_model_info)
        if anomaly_result:
            log_entry["anomaly_detection"] = anomaly_result
            print(f"[ALERT] Anomalous file activity detected: {file_path} (Score: {anomaly_result['anomaly_score']:.4f})")
            
            # Print MITRE info for context
            if mitre_mapping and "technique_id" in mitre_mapping:
                print(f"[MITRE ATT&CK] {mitre_mapping['technique_id']} ({mitre_mapping['technique_name']}): {mitre_mapping['description']}")
                
            # Print process correlation for context
            if process_correlation:
                proc = process_correlation.get("related_process", {})
                print(f"[PROCESS CORRELATION] Likely modified by PID {proc.get('pid')} ({proc.get('process_name')}): {proc.get('cmdline')}")

    # Write to log file
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry, indent=4) + "\n")

    # Send logs to SIEM (if configured)
    audit.send_to_siem(log_entry)
    
    return log_entry

def process_file(filepath, file_hashes, integrity_state):
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
        file_hash = file_hashes.get(str_filepath)  # Reuse existing hash

    if file_hash:
        return str_filepath, file_hash, metadata
    return None

def generate_file_hashes(scheduled_directories, real_time_directories, exclusions, config=None):
    """Generate and store SHA-256 hashes for all monitored files, tracking changes over time."""
    file_hashes = load_file_hashes()
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

    new_file_hashes = file_hashes.copy()
    new_integrity_state = integrity_state.copy()

    excluded_dirs = set(exclusions.get("directories", []))
    excluded_files = set(exclusions.get("files", []))

    existing_files = set()
    all_files = []

    start_time = time.time()
    
    # Build file list with enhanced exclusion logic
    for directory in scheduled_directories + real_time_directories:
        if directory in excluded_dirs:
            continue
        for filepath in Path(directory).rglob("*"):
            if filepath.is_file() and not should_exclude_file(filepath, exclusions):
                all_files.append(filepath)

    file_count = len(all_files)
    print(f"[INFO] Found {file_count} files to process")
    
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = executor.map(lambda fp: process_file(fp, file_hashes, integrity_state), all_files)

    for result in results:
        if result:
            str_filepath, file_hash, metadata = result
            existing_files.add(str_filepath)

            previous_hash = file_hashes.get(str_filepath)
            previous_metadata = integrity_state.get(str_filepath)

            if str_filepath in file_hashes:
                # Detect Metadata Changes Separately
                metadata_changes = compare_metadata(previous_metadata, metadata)
                if metadata_changes:
                    log_event(
                        event_type="METADATA_CHANGED",
                        file_path=str_filepath,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        changes=metadata_changes
                    )

                # Detect Content Changes (Hash Differences)
                if previous_hash != file_hash:
                    log_event(
                        event_type="MODIFIED",
                        file_path=str_filepath,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        previous_hash=previous_hash,
                        new_hash=file_hash
                    )

            else:
                log_event(
                    event_type="NEW FILE",
                    file_path=str_filepath,
                    previous_metadata=None,
                    new_metadata=metadata,
                    previous_hash=None,
                    new_hash=file_hash
                )

            new_file_hashes[str_filepath] = file_hash
            new_integrity_state[str_filepath] = metadata

    # Detect deleted files
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
        new_file_hashes.pop(deleted_file, None)
        new_integrity_state.pop(deleted_file, None)

    save_file_hashes(new_file_hashes)
    save_integrity_state(new_integrity_state)

    # Add execution stats
    end_time = time.time()
    duration = end_time - start_time

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

class EventHandler(pyinotify.ProcessEvent):
    """Enhanced event handler that includes process correlation, MITRE mapping, and anomaly detection."""

    def process_IN_CREATE(self, event):
        """Handles file creation."""
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)

        if file_hash and metadata:
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
        
        # Skip excluded files
        if should_exclude_file(full_path, exclusions):
            return
            
        previous_metadata = integrity_state.get(full_path, None)
        previous_hash = file_hashes.get(full_path, None)

        if previous_hash or previous_metadata:  # Only log if we were tracking this file
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
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        metadata = get_file_metadata(full_path)
        previous_metadata = integrity_state.get(full_path)

        if metadata and previous_metadata:
            changes = compare_metadata(previous_metadata, metadata)

            if changes:
                log_event(
                    event_type="METADATA_CHANGED",
                    file_path=full_path,
                    previous_metadata=previous_metadata,
                    new_metadata=metadata,
                    changes=changes
                )

                update_file_tracking(full_path, get_file_hash(full_path), metadata)

    def process_IN_MODIFY(self, event):
        """Handles file modifications and ensures metadata is logged correctly."""
        full_path = event.pathname
        
        # Skip directories and excluded files
        if os.path.isdir(full_path) or should_exclude_file(full_path, exclusions):
            return
            
        file_hash = get_file_hash(full_path)
        metadata = get_file_metadata(full_path)
        previous_hash = file_hashes.get(full_path)
        previous_metadata = integrity_state.get(full_path)

        if file_hash and previous_hash and file_hash != previous_hash:
            log_event(
                event_type="MODIFIED",
                file_path=full_path,
                previous_metadata=previous_metadata,
                new_metadata=metadata,
                previous_hash=previous_hash,
                new_hash=file_hash
            )

            update_file_tracking(full_path, file_hash, metadata)

def monitor_changes(real_time_directories, exclusions):
    """Monitors file system changes using pyinotify with enhanced detection and error handling."""
    global file_hashes, integrity_state
    
    try:
        file_hashes = load_file_hashes()
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

def correlate_with_processes(file_path, event_type):
    """Correlate file changes with process activity from PIM."""
    pim_data_file = os.path.join(OUTPUT_DIR, "integrity_processes.json")
    correlation = {}
    
    if not os.path.exists(pim_data_file):
        return None
    
    try:
        with open(pim_data_file, "r") as f:
            processes = json.load(f)
            
        # Find processes that might be responsible for the file change
        for pid, process_info in processes.items():
            # Check if the process has accessed this file or its directory
            cmdline = process_info.get("cmdline", "").lower()
            exe_path = process_info.get("exe_path", "").lower()
            file_path_lower = file_path.lower()
            file_dir_lower = os.path.dirname(file_path).lower()
            
            is_related = False
            
            # Check if file path appears in command line
            if file_path_lower in cmdline or file_dir_lower in cmdline:
                is_related = True
                
            # Check common write patterns
            if any(pattern in cmdline for pattern in ["> " + file_path_lower, ">> " + file_path_lower, 
                                                    "tee " + file_path_lower, "echo", "cat"]):
                is_related = True
            
            # Special handling for common tools that modify files
            common_tools = ["vi", "vim", "nano", "emacs", "gedit", "sed", "awk", "perl", "python", "bash"]
            if process_info.get("process_name", "").lower() in common_tools and file_path_lower in cmdline:
                is_related = True
                
            if is_related:
                correlation["related_process"] = {
                    "pid": pid,
                    "process_name": process_info.get("process_name", "unknown"),
                    "cmdline": process_info.get("cmdline", ""),
                    "user": process_info.get("user", "unknown"),
                    "start_time": process_info.get("start_time", "unknown")
                }
                break
                
        return correlation if correlation else None
    except Exception as e:
        print(f"[ERROR] Failed to correlate with processes: {e}")
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
    """Run the file monitoring process with real-time monitoring and scheduled scans running separately."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_shutdown)   # Ctrl+C
    signal.signal(signal.SIGTERM, handle_shutdown)  # kill <pid>

#    ensure_log_file()
#    ensure_output_dir()
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

    # Initialize ML model for anomaly detection
    try:
        global ml_model_info
        ml_model_info = implement_file_activity_baselining()
        if ml_model_info:
            print("[INFO] ML-based anomaly detection initialized.")
        else:
            print("[INFO] ML-based anomaly detection not available - insufficient data or missing libraries.")
    except Exception as e:
        print(f"[WARNING] Failed to initialize ML component: {e}")
        ml_model_info = None

    # Start real-time monitoring in a background thread
    if real_time_directories:
        rt_monitor = Thread(target=monitor_changes, args=(real_time_directories, exclusions), daemon=True)
        rt_monitor.start()
        print("[INFO] Real-time monitoring started.")

    # Periodically retrain ML model
    try:
        ml_retraining_thread = Thread(target=periodic_ml_retraining, daemon=True)
        ml_retraining_thread.start()
        print("[INFO] ML model periodic retraining scheduled.")
    except Exception as e:
        print(f"[WARNING] ML retraining setup failed: {e}")

    # Run the scheduled scan loop in the main thread
    if scheduled_directories:
        try:
            while True:
                generate_file_hashes(scheduled_directories, real_time_directories, exclusions, config)
                print(f"[INFO] Scheduled scan completed. Sleeping for {scan_interval} seconds.")
                time.sleep(scan_interval)
        except KeyboardInterrupt:
            handle_shutdown()

def is_binary_file(file_path):
    """Check if a file is likely binary based on extension or sampling the content."""
    if not file_path or file_path == "N/A":
        return False
        
    binary_extensions = ['.exe', '.bin', '.o', '.so', '.dll', '.pyc', '.pyd', 
                         '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', 
                         '.tar', '.gz', '.bz2', '.xz', '.pdf']
    
    # Check extension first (faster)
    if any(file_path.lower().endswith(ext) for ext in binary_extensions):
        return True
    
    # If file exists, try reading first few bytes
    try:
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, 'rb') as f:
                sample = f.read(1024)
                # Heuristic: If more than 30% non-printable/control chars, likely binary
                non_printable = sum(1 for b in sample if b < 32 and b != 9 and b != 10 and b != 13)
                if non_printable > len(sample) * 0.3:
                    return True
    except:
        pass
            
    return False

def is_config_file(file_path):
    """Check if a file is likely a configuration file."""
    if not file_path or file_path == "N/A":
        return False
        
    config_extensions = ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml', '.xml', '.properties']
    config_patterns = ['config', 'conf', 'settings', '.rc']
    
    file_path_lower = file_path.lower()
    
    has_config_ext = any(file_path_lower.endswith(ext) for ext in config_extensions)
    has_config_pattern = any(pattern in file_path_lower for pattern in config_patterns)
    
    return has_config_ext or has_config_pattern

def is_system_directory(file_path):
    """Check if a file is in a system directory."""
    if not file_path or file_path == "N/A":
        return False
        
    system_dirs = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/lib/', '/usr/lib/', '/etc/']
    
    return any(file_path.startswith(d) for d in system_dirs)

def implement_file_activity_baselining():
    """Implement ML-based behavioral baselining for file activity."""
    try:
        # Import required libraries
        from sklearn.ensemble import IsolationForest
        import numpy as np
        import pandas as pd
        
        print("[INFO] Initializing ML-based anomaly detection for file activity...")
        
        # Read historical file events
        events = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if isinstance(event, dict) and "event_type" in event and "file_path" in event:
                            events.append(event)
                    except json.JSONDecodeError:
                        continue
        
        if len(events) < 10:  # Need minimum data
            print("[WARNING] Not enough historical data for ML model training. Need at least 10 events.")
            return None
        
        # Extract features from events
        features = []
        for event in events:
            timestamp = event.get("timestamp", "")
            try:
                dt_parts = timestamp.split(" ")
                if len(dt_parts) >= 2:
                    time_parts = dt_parts[1].split(":")
                    if len(time_parts) >= 1:
                        event_hour = int(time_parts[0])
                    else:
                        event_hour = 12
                else:
                    event_hour = 12
            except:
                event_hour = 12  # Default if parsing fails
                
            event_type_mapping = {
                "NEW FILE": 1,
                "MODIFIED": 2,
                "DELETED": 3,
                "METADATA_CHANGED": 4
            }
            
            file_path = event.get("file_path", "")
            
            event_feature = {
                "event_hour": event_hour,
                "event_type": event_type_mapping.get(event.get("event_type"), 0),
                "is_binary": 1 if is_binary_file(file_path) else 0,
                "is_config": 1 if is_config_file(file_path) else 0,
                "is_system_dir": 1 if is_system_directory(file_path) else 0,
            }
            
            # Add metadata features if available
            new_metadata = event.get("new_metadata", None)
            if isinstance(new_metadata, dict):
                if "size" in new_metadata and new_metadata["size"] != "N/A":
                    try:
                        event_feature["file_size"] = float(new_metadata["size"])
                    except:
                        pass
            
            features.append(event_feature)
            
        # Create dataframe and train model
        df = pd.DataFrame(features)
        
        # Ensure we have enough data and features
        if len(df) < 10:
            print("[WARNING] Not enough valid events for ML model training.")
            return None
            
        # Select only numeric columns
        numeric_cols = [col for col in df.columns if df[col].dtype.kind in 'ifc']
        if len(numeric_cols) < 2:
            print("[WARNING] Not enough numeric features for ML model training.")
            return None
            
        # Train isolation forest
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(df[numeric_cols])
        
        print(f"[INFO] ML model trained successfully with {len(df)} events and {len(numeric_cols)} features.")
        
        return {
            "model": model,
            "features": numeric_cols,
            "event_type_mapping": event_type_mapping
        }
    except ImportError:
        print("[WARNING] scikit-learn, numpy, or pandas not available. ML-based anomaly detection disabled.")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to initialize ML model: {e}")
        return None

def detect_file_anomalies(event, ml_model_info):
    """Detect anomalies in file events using the ML model."""
    if not ml_model_info or not ml_model_info.get("model"):
        return None
        
    try:
        import pandas as pd
        
        model = ml_model_info["model"]
        feature_names = ml_model_info["features"]
        event_type_mapping = ml_model_info["event_type_mapping"]
        
        # Extract features from the event
        timestamp = event.get("timestamp", "")
        try:
            dt_parts = timestamp.split(" ")
            if len(dt_parts) >= 2:
                time_parts = dt_parts[1].split(":")
                if len(time_parts) >= 1:
                    event_hour = int(time_parts[0])
                else:
                    event_hour = 12
            else:
                event_hour = 12
        except:
            event_hour = 12
            
        event_type = event_type_mapping.get(event.get("event_type"), 0)
        file_path = event.get("file_path", "")
        
        # Prepare features similar to training data
        features = {
            "event_hour": event_hour,
            "event_type": event_type,
            "is_binary": 1 if is_binary_file(file_path) else 0,
            "is_config": 1 if is_config_file(file_path) else 0,
            "is_system_dir": 1 if is_system_directory(file_path) else 0,
        }
        
        # Add metadata features if available
        new_metadata = event.get("new_metadata", None)
        if isinstance(new_metadata, dict) and new_metadata != "N/A":
            if "size" in new_metadata and new_metadata["size"] != "N/A":
                try:
                    features["file_size"] = float(new_metadata["size"])
                except:
                    pass
        
        # Create a dataframe with only the features used during training
        df_features = {}
        for feature in feature_names:
            df_features[feature] = [features.get(feature, 0)]
            
        df = pd.DataFrame(df_features)
        
        # Predict anomaly
        prediction = model.predict(df)[0]
        anomaly_score = model.decision_function(df)[0]
        
        if prediction == -1:  # Anomaly
            return {
                "is_anomaly": True,
                "anomaly_score": float(anomaly_score),
                "anomaly_features": features
            }
        return None
        
    except Exception as e:
        print(f"[ERROR] Failed to detect anomalies: {e}")
        return None

def periodic_ml_retraining():
    """Periodically retrain the ML model for improved anomaly detection."""
    global ml_model_info
    
    while True:
        time.sleep(3600)  # Retrain every hour
        print("[INFO] Retraining ML model for anomaly detection...")
        ml_model_info = implement_file_activity_baselining()
        if ml_model_info:
            print("[INFO] ML model retraining completed successfully.")
        else:
            print("[WARNING] ML model retraining failed or insufficient data.")

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

    # Provide generic mapping if no specific context match
    return mitre_mapping.get(event_type, {
        "technique_id": "T1565",
        "technique_name": "Data Manipulation",
        "tactic": "Impact",
        "description": "Generic file manipulation"
    })

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
  python fim_client.py [option]

Options:
  help               Show this help message and exit
  -d or daemon       Run FIM in background (daemon) mode
  -s or stop         Stop FIM daemon process
  -l or log-config   Configure SIEM logging (interactive)
""")

if __name__ == "__main__":
    args = sys.argv[1:]  # Get command-line arguments

    # Check ML libraries
    if not ML_LIBRARIES_AVAILABLE:
        print("[WARNING] Running without machine learning capability - some advanced detection features will be unavailable")
        
    # Show version info
    print("File Integrity Monitor v2.0")
    print("Enhanced with machine learning, MITRE ATT&CK mapping, and process correlation")

    if not args:
        print("[INFO] Running in foreground mode...")
        run_monitor()
        sys.exit(0)

    arg = args[0].lower()

    if arg in ("help", "-h", "--help"):
        print_help()
        sys.exit(0)

    elif arg in ("-l", "log-config"):
        audit.configure_siem()
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
