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
import math
import re
import difflib
import subprocess
import stat
import shutil
import pyinotify
import audit
import psutil
import time
import joblib
from collections import defaultdict, Counter, deque
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from daemon import DaemonContext
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

ML_LIBRARIES_AVAILABLE = True
try:
    # Try a simple operation to verify ML libraries work
    test_array = np.array([1, 2, 3])
    test_model = IsolationForest(n_estimators=10)
except Exception:
    ML_LIBRARIES_AVAILABLE = False

ml_model_info = None
context_detection = None
adv_content_analysis = None
exclusions = {}

def get_base_dir():
    """Get the base directory for the application based on script location"""
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = "/opt/FIMoniSec/Linux-Client"
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
    global ml_model_info, context_detection, adv_content_analysis
    
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
    
    # Perform advanced content analysis for file modifications and new files
    if adv_content_analysis and os.path.exists(file_path) and event_type in ["MODIFIED", "NEW FILE"]:
        try:
            # Analyze file content changes
            content_analysis = adv_content_analysis.analyze_file_changes(file_path, previous_hash, new_hash)
            if content_analysis and "error" not in content_analysis:
                log_entry["content_analysis"] = content_analysis
                
                # Check for malware indicators in high-risk changes
                if (content_analysis.get("diff", {}).get("significant_change", False) or 
                    content_analysis.get("type_specific", {}).get("criticality", "low") in ["medium", "high"]):
                    
                    malware_check = adv_content_analysis.check_malware_indicators(file_path, new_hash)
                    if malware_check and "error" not in malware_check:
                        log_entry["malware_indicators"] = malware_check
                        
                        # Alert on high entropy or suspicious strings
                        if malware_check.get("high_entropy", False) or malware_check.get("strings_analysis"):
                            print(f"[ALERT] Potential malicious content detected in: {file_path}")
                            if malware_check.get("high_entropy", False):
                                print(f"[ALERT] High entropy detected (Score: {malware_check.get('entropy', 0):.2f})")
                            
                            if malware_check.get("strings_analysis"):
                                print("[ALERT] Suspicious strings detected:")
                                for category, items in malware_check.get("strings_analysis", {}).items():
                                    if items:
                                        print(f"  - {category}: {items[0]}" + (f" and {len(items)-1} more" if len(items) > 1 else ""))
                
                # Alert on critical changes based on file type
                if content_analysis.get("type_specific", {}).get("criticality") == "high":
                    print(f"[ALERT] Critical changes detected in: {file_path}")
                    file_type = content_analysis.get("file_type", "unknown")
                    
                    if file_type == "config":
                        changes = content_analysis.get("type_specific", {}).get("changes", {})
                        print(f"[ALERT] Critical configuration changes: {len(changes.get('added', {}))} added, {len(changes.get('removed', {}))} removed, {len(changes.get('modified', {}))} modified")
                    
                    elif file_type == "script":
                        suspicious = content_analysis.get("type_specific", {}).get("suspicious_patterns", {})
                        if suspicious:
                            print("[ALERT] Suspicious script patterns detected:")
                            for category, items in suspicious.items():
                                if items:
                                    print(f"  - {category}: {items[0]}" + (f" and {len(items)-1} more" if len(items) > 1 else ""))
                    
                    # Print associated MITRE technique for context
                    if mitre_mapping:
                        print(f"[MITRE ATT&CK] {mitre_mapping.get('technique_id', 'N/A')} ({mitre_mapping.get('technique_name', 'N/A')}): {mitre_mapping.get('description', 'N/A')}")
        
        except Exception as e:
            print(f"[WARNING] Advanced content analysis failed: {e}")

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
    
    # Add context-aware detection analysis
    if context_detection:
        try:
            # Calculate risk score
            risk_analysis = context_detection.calculate_risk_score(log_entry)
            log_entry["risk_analysis"] = risk_analysis
            
            # Look for attack chains
            attack_patterns = context_detection.correlate_attack_chain(log_entry)
            if attack_patterns:
                log_entry["attack_patterns"] = attack_patterns
                
                # Alert on high-severity attack patterns
                for pattern in attack_patterns:
                    print(f"[ATTACK CHAIN DETECTED] {pattern['pattern']} (Severity: {pattern['severity']})")
                    print(f"[ATTACK CHAIN DETECTED] Matched techniques: {', '.join(pattern['matched_techniques'])}")
            
            # Alert on high-risk events
            if risk_analysis.get("is_alert", False):
                print(f"[HIGH RISK EVENT] Risk score: {risk_analysis['score']:.2f} - {file_path}")
                for component, value in risk_analysis.get("components", {}).items():
                    print(f"  - {component}: {value}")
        except Exception as e:
            print(f"[WARNING] Context-aware detection failed: {e}")

    # Write to log file
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry, indent=4) + "\n")

    # Send logs to SIEM (if configured)
    audit.send_to_siem(log_entry)
    
    if should_alert(log_entry):
        trigger_alert(log_entry)
    
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
    """Run the file monitoring process with real-time monitoring and adaptive scheduled scans."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, handle_shutdown)   # Ctrl+C
    signal.signal(signal.SIGTERM, handle_shutdown)  # kill <pid>

    config = load_config()
    scheduled_scan = config.get("scheduled_scan", {})
    real_time_monitoring = config.get("real_time_monitoring", {})
    exclusions = config.get("exclusions", {})

    scheduled_directories = scheduled_scan.get("directories", [])
    scan_interval = scheduled_scan.get("scan_interval", 300)  # Still used as fallback
    real_time_directories = real_time_monitoring.get("directories", [])

    if not scheduled_directories and not real_time_directories:
        print("[ERROR] No directories specified for monitoring. Exiting.")
        handle_shutdown()

    # Ensure enhanced_fim configuration exists
    config = ensure_enhanced_config()
    
    # Load initial file hashes and integrity states
    global file_hashes, integrity_state
    file_hashes = load_file_hashes()
    integrity_state = load_integrity_state()
    
    # Initialize context-aware detection
    global context_detection
    context_detection = ContextAwareDetection(config.get('enhanced_fim', {}))
    print("[INFO] Context-aware detection initialized")
    
    # Initialize advanced content analysis
    global adv_content_analysis
    adv_content_analysis = AdvancedFileContentAnalysis(config.get('enhanced_fim', {}).get('content_analysis', {}))
    print("[INFO] Advanced content analysis initialized")
    
    # Initialize adaptive scanner
    adaptive_scanner = AdaptiveScanner(config.get('enhanced_fim', {}).get('performance', {}))
    print("[INFO] Adaptive scanner initialized")

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

    # Define callback function for adaptive scanner
    def process_files_callback(file_list, scan_type):
        """Callback for adaptive scanner to process files and return changes."""
        changes = []
        
        for file_path in file_list:
            # Skip excluded files
            if should_exclude_file(file_path, exclusions):
                continue
                
            # Get file hash and metadata
            file_hash = get_file_hash(file_path)
            metadata = get_file_metadata(file_path)
            
            if not file_hash or not metadata:
                continue
                
            str_file_path = str(file_path)
            previous_hash = file_hashes.get(str_file_path)
            previous_metadata = integrity_state.get(str_file_path)
            
            # Detect changes
            if previous_hash and previous_metadata:
                # Check for metadata changes
                metadata_changes = compare_metadata(previous_metadata, metadata)
                if metadata_changes:
                    log_event(
                        event_type="METADATA_CHANGED",
                        file_path=str_file_path,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        changes=metadata_changes
                    )
                    changes.append(str_file_path)
                
                # Check for content changes
                if previous_hash != file_hash:
                    log_event(
                        event_type="MODIFIED",
                        file_path=str_file_path,
                        previous_metadata=previous_metadata,
                        new_metadata=metadata,
                        previous_hash=previous_hash,
                        new_hash=file_hash
                    )
                    changes.append(str_file_path)
            else:
                # New file
                log_event(
                    event_type="NEW FILE",
                    file_path=str_file_path,
                    previous_metadata=None,
                    new_metadata=metadata,
                    previous_hash=None,
                    new_hash=file_hash
                )
                changes.append(str_file_path)
            
            # Update tracking data
            file_hashes[str_file_path] = file_hash
            integrity_state[str_file_path] = metadata
        
        # If changes were detected, save updated tracking data
        if changes:
            save_file_hashes(file_hashes)
            save_integrity_state(integrity_state)
            
            # Log summary based on scan type
            scan_type_desc = {
                "critical": "Critical system files",
                "standard": "Standard monitoring",
                "minimal": "Low-priority files"
            }
            print(f"[INFO] {scan_type_desc.get(scan_type, 'File scan')} detected {len(changes)} changes")
            
        return changes

    # Run the scheduled scan with adaptive scanning
    if scheduled_directories:
        try:
            print("[INFO] Starting adaptive file scanning")
            # Use adaptive scheduling instead of fixed interval
            adaptive_scanner.adaptive_scan_scheduler(scheduled_directories, process_files_callback)
        except KeyboardInterrupt:
            handle_shutdown()
    else:
        # If no scheduled directories, just keep the main thread alive
        try:
            while True:
                time.sleep(60)
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

def ensure_enhanced_config():
    """Ensure the enhanced_fim section exists in the configuration file."""
    config = load_config()
    
    # Check if enhanced_fim section exists
    if 'enhanced_fim' not in config:
        print("[INFO] Adding enhanced_fim configuration section...")
        
        # Add default enhanced_fim section
        config['enhanced_fim'] = {
            "enabled": True,
            "environment": "production",
            "performance": {
                "system_load_threshold": 75,
                "io_threshold": 80,
                "worker_threads": 4
            },
            "behavioral": {
                "training_samples": 100,
                "retraining_interval": 86400,
                "max_baseline_samples": 10000
            },
            "content_analysis": {
                "diff_threshold": 0.3,
                "max_file_size": 10485760
            },
            "detection": {
                "risk_multiplier": 1.5,
                "alert_threshold": 70
            }
        }
        
        # Also update instructions if they exist
        if 'instructions' in config:
            config['instructions']['enhanced_fim'] = "Configure enhanced file integrity monitoring capabilities including performance optimization, behavioral analysis, content analysis, and detection."
        
        # Save updated config
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        
        print("[INFO] Enhanced FIM configuration added to config file.")
        
    return config

#################### FIM PERFORMANCE #######################
class AdaptiveScanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.system_load_threshold = self.config.get('system_load_threshold', 75)  # Default 75% CPU load
        self.io_threshold = self.config.get('io_threshold', 80)  # Default 80% I/O utilization
        self.scan_history = defaultdict(lambda: {'last_scan': 0, 'change_frequency': 0})
        self.critical_paths = self.config.get('critical_paths', ['/etc', '/bin', '/sbin', '/usr/bin'])
        self.is_paused = False
        self.backoff_multiplier = 1.0

    def get_system_load(self):
        """Get current system load metrics"""
        cpu_percent = psutil.cpu_percent(interval=0.5)
        io_counters = psutil.disk_io_counters()
        memory_percent = psutil.virtual_memory().percent
        
        return {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'io': io_counters
        }
    
    def should_throttle(self):
        """Determine if scanning should be throttled based on system load"""
        system_load = self.get_system_load()
        
        # Check if system is under heavy load
        if system_load['cpu'] > self.system_load_threshold:
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 10.0)
            return True
        else:
            self.backoff_multiplier = max(self.backoff_multiplier * 0.8, 1.0)
            return False
    
    def prioritize_scan_targets(self, directories):
        """Prioritize directories to scan based on criticality and change history"""
        prioritized = []
        
        # First tier: Critical system paths
        critical = [d for d in directories if any(d.startswith(cp) for cp in self.critical_paths)]
        
        # Second tier: Frequently changing directories
        current_time = time.time()
        change_frequency = {d: self.scan_history[d]['change_frequency'] for d in directories}
        sorted_by_frequency = sorted(
            [d for d in directories if d not in critical],
            key=lambda d: change_frequency.get(d, 0),
            reverse=True
        )
        
        # Third tier: Directories not scanned recently
        time_since_scan = {d: current_time - self.scan_history[d]['last_scan'] for d in directories}
        sorted_by_time = sorted(
            [d for d in directories if d not in critical and d not in sorted_by_frequency[:10]],
            key=lambda d: time_since_scan.get(d, float('inf')),
            reverse=True
        )
        
        # Combine tiers with appropriate scanning intensity
        return {
            'high_intensity': critical,
            'medium_intensity': sorted_by_frequency[:10],  # Top 10 frequently changing dirs
            'low_intensity': sorted_by_time  # Remaining dirs sorted by scan age
        }
    
    def differential_scan(self, directory, file_index):
        """Focus scanning on recently modified files"""
        # Get all files in directory with modification times
        current_files = {}
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    mtime = os.path.getmtime(full_path)
                    current_files[full_path] = mtime
                except (OSError, IOError):
                    continue
        
        # Identify new and modified files since last scan
        if directory not in file_index:
            # First scan of this directory - all files are "new"
            file_index[directory] = current_files
            return list(current_files.keys()), []
        
        previous_files = file_index[directory]
        
        # Find new and modified files
        new_files = []
        modified_files = []
        
        for path, mtime in current_files.items():
            if path not in previous_files:
                new_files.append(path)
            elif mtime > previous_files[path]:
                modified_files.append(path)
        
        # Update the file index
        file_index[directory] = current_files
        
        return new_files, modified_files
    
    def update_scan_history(self, directory, changes_detected):
        """Update scan history and change frequency metrics"""
        current_time = time.time()
        
        # Get previous values
        previous = self.scan_history[directory]
        last_scan_time = previous['last_scan']
        change_frequency = previous['change_frequency']
        
        # Calculate time since last scan
        time_delta = current_time - last_scan_time if last_scan_time > 0 else 86400  # Default to 1 day
        
        # Exponential moving average for change frequency
        if changes_detected:
            # If changes were detected, increase the frequency score
            new_frequency = change_frequency * 0.7 + 0.3 * (1 / max(time_delta, 1))
        else:
            # If no changes, decay the frequency score
            new_frequency = change_frequency * 0.9
        
        # Update history
        self.scan_history[directory] = {
            'last_scan': current_time,
            'change_frequency': new_frequency
        }
    
    def adaptive_scan_scheduler(self, scheduled_directories, scan_callback):
        """Run scanning with adaptive scheduling based on system load and directory priority"""
        file_index = {}  # Track files and their modification times
        
        while True:
            # Check if scanning should be throttled
            if self.should_throttle():
                print(f"[INFO] System under load, throttling scans (backoff: {self.backoff_multiplier:.2f}x)")
                time.sleep(5 * self.backoff_multiplier)  # Adaptive backoff
                continue
            
            # Prioritize directories
            prioritized = self.prioritize_scan_targets(scheduled_directories)
            
            # Process high-priority directories first, with full scanning
            for directory in prioritized['high_intensity']:
                if self.should_throttle():
                    break  # Recheck system load between directories
                
                print(f"[INFO] High-intensity scanning of critical directory: {directory}")
                # For critical directories, do a full scan
                all_files = []
                for root, _, files in os.walk(directory):
                    for file in files:
                        all_files.append(os.path.join(root, file))
                
                changes = scan_callback(all_files, "critical")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Medium priority directories - scan frequently changed files
            for directory in prioritized['medium_intensity']:
                if self.should_throttle():
                    break
                
                print(f"[INFO] Medium-intensity scanning of frequently changing directory: {directory}")
                # Use differential scanning for these directories
                new_files, modified_files = self.differential_scan(directory, file_index)
                changes = scan_callback(new_files + modified_files, "standard")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Low priority directories - scan minimally
            for directory in prioritized['low_intensity']:
                if self.should_throttle():
                    break
                
                print(f"[INFO] Low-intensity scanning of infrequently changing directory: {directory}")
                # For low priority, only scan new files
                new_files, _ = self.differential_scan(directory, file_index)
                changes = scan_callback(new_files, "minimal")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Sleep between full scan cycles, with adaptive timing
            sleep_time = 60 * self.backoff_multiplier  # Base: 1 minute, scales with load
            print(f"[INFO] Completed scan cycle, sleeping for {sleep_time:.1f} seconds")
            time.sleep(sleep_time)

############################################################

##################### Machine Leanrning Code ###############
class EnhancedBehavioralBaselining:
    def __init__(self, config=None):
        self.config = config or {}
        self.models = {}
        self.feature_scalers = {}
        self.baseline_data = defaultdict(list)
        self.model_dir = self.config.get('model_dir', os.path.join(os.getcwd(), 'ml_models'))
        self.training_samples_required = self.config.get('training_samples', 100)
        self.retraining_interval = self.config.get('retraining_interval', 86400)  # 24 hours
        self.last_training_time = 0
        self.feature_importance = {}
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load existing models if available
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models if available"""
        model_types = ['temporal', 'contextual', 'content']
        
        for model_type in model_types:
            model_path = os.path.join(self.model_dir, f"{model_type}_model.joblib")
            scaler_path = os.path.join(self.model_dir, f"{model_type}_scaler.joblib")
            
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                try:
                    self.models[model_type] = joblib.load(model_path)
                    self.feature_scalers[model_type] = joblib.load(scaler_path)
                    print(f"[INFO] Loaded {model_type} model and scaler")
                except Exception as e:
                    print(f"[ERROR] Failed to load {model_type} model: {e}")
    
    def extract_temporal_features(self, event):
        """Extract time-based features from event data"""
        # Parse timestamp
        timestamp = event.get('timestamp', '')
        try:
            if timestamp:
                dt = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                hour = dt.tm_hour
                minute = dt.tm_min
                weekday = dt.tm_wday  # 0-6, Monday is 0
                is_weekend = 1 if weekday >= 5 else 0
                is_business_hours = 1 if (8 <= hour <= 18 and weekday < 5) else 0
                is_night = 1 if (hour < 6 or hour >= 22) else 0
            else:
                # Default values if timestamp is missing
                hour, minute, weekday = 12, 0, 0
                is_weekend, is_business_hours, is_night = 0, 1, 0
        except ValueError:
            # Default values if timestamp format is invalid
            hour, minute, weekday = 12, 0, 0
            is_weekend, is_business_hours, is_night = 0, 1, 0
        
        # Event type encoding
        event_type_map = {
            'NEW FILE': 1,
            'MODIFIED': 2,
            'DELETED': 3,
            'METADATA_CHANGED': 4
        }
        event_type_code = event_type_map.get(event.get('event_type', ''), 0)
        
        # Extract features
        features = {
            'hour': hour,
            'minute': minute,
            'weekday': weekday,
            'is_weekend': is_weekend,
            'is_business_hours': is_business_hours,
            'is_night': is_night,
            'event_type_code': event_type_code
        }
        
        return features
    
    def extract_contextual_features(self, event):
        """Extract context-related features from event data"""
        # File path features
        file_path = event.get('file_path', '')
        is_system_file = 1 if any(file_path.startswith(d) for d in ['/bin', '/sbin', '/lib', '/etc', '/usr/bin', '/usr/sbin', '/usr/lib']) else 0
        is_home_file = 1 if '/home/' in file_path else 0
        is_temp_file = 1 if any(t in file_path for t in ['/tmp/', '/var/tmp/', '/dev/shm/']) else 0
        is_config_file = 1 if any(file_path.endswith(ext) for ext in ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml']) else 0
        is_executable = 1 if any(file_path.endswith(ext) for ext in ['', '.sh', '.py', '.rb', '.pl']) and (is_system_file or '/bin/' in file_path) else 0
        
        # Process correlation features
        process_correlation = event.get('process_correlation', {})
        has_process_correlation = 1 if process_correlation and process_correlation != 'N/A' else 0
        
        process_info = {}
        if has_process_correlation:
            related_process = process_correlation.get('related_process', {})
            process_info = {
                'pid': related_process.get('pid', 0),
                'process_name': related_process.get('process_name', ''),
                'user': related_process.get('user', '')
            }
        
        is_root_process = 1 if process_info.get('user') == 'root' else 0
        is_system_process = 1 if process_info.get('process_name') in ['systemd', 'init', 'cron', 'sshd'] else 0
        
        # File metadata features
        new_metadata = event.get('new_metadata', {})
        if isinstance(new_metadata, str):
            new_metadata = {}
        
        file_size = 0
        try:
            file_size = int(new_metadata.get('size', 0))
        except (ValueError, TypeError):
            pass
        
        features = {
            'is_system_file': is_system_file,
            'is_home_file': is_home_file,
            'is_temp_file': is_temp_file,
            'is_config_file': is_config_file,
            'is_executable': is_executable,
            'has_process_correlation': has_process_correlation,
            'is_root_process': is_root_process,
            'is_system_process': is_system_process,
            'file_size': file_size
        }
        
        return features
    
    def extract_content_features(self, event):
        """Extract content-related features from file changes"""
        # Check for hash changes
        previous_hash = event.get('previous_hash', '')
        new_hash = event.get('new_hash', '')
        hash_changed = 1 if previous_hash and new_hash and previous_hash != new_hash else 0
        
        # Check for metadata changes
        changes = event.get('changes', {})
        if isinstance(changes, str):
            changes = {}
        
        permission_changed = 1 if 'Permissions changed' in changes else 0
        ownership_changed = 1 if 'Ownership changed' in changes else 0
        size_changed = 1 if 'Size changed' in changes else 0
        timestamp_changed = 1 if 'Last modified timestamp changed' in changes else 0
        
        # Metadata details
        new_metadata = event.get('new_metadata', {})
        if isinstance(new_metadata, str):
            new_metadata = {}
            
        previous_metadata = event.get('previous_metadata', {})
        if isinstance(previous_metadata, str):
            previous_metadata = {}
        
        size_delta = 0
        try:
            new_size = int(new_metadata.get('size', 0))
            prev_size = int(previous_metadata.get('size', 0))
            size_delta = new_size - prev_size
        except (ValueError, TypeError):
            pass
        
        features = {
            'hash_changed': hash_changed,
            'permission_changed': permission_changed,
            'ownership_changed': ownership_changed,
            'size_changed': size_changed,
            'timestamp_changed': timestamp_changed,
            'size_delta': size_delta
        }
        
        return features
    
    def combine_features(self, event):
        """Combine all feature types for comprehensive analysis"""
        temporal = self.extract_temporal_features(event)
        contextual = self.extract_contextual_features(event)
        content = self.extract_content_features(event)
        
        # Combine all features
        features = {}
        features.update(temporal)
        features.update(contextual)
        features.update(content)
        
        return features
    
    def train_models(self, events):
        """Train or update anomaly detection models based on collected events"""
        if len(events) < self.training_samples_required:
            print(f"[INFO] Not enough samples for training. Have {len(events)}, need {self.training_samples_required}")
            return False
        
        print(f"[INFO] Training anomaly detection models with {len(events)} events")
        
        # Extract all feature types
        all_features = []
        for event in events:
            features = self.combine_features(event)
            all_features.append(features)
        
        # Convert to DataFrame
        df = pd.DataFrame(all_features)
        
        # Replace NaN values with 0
        df.fillna(0, inplace=True)
        
        # Train different models for different feature types
        model_configs = {
            'temporal': {
                'features': [col for col in df.columns if col in self.extract_temporal_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            },
            'contextual': {
                'features': [col for col in df.columns if col in self.extract_contextual_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            },
            'content': {
                'features': [col for col in df.columns if col in self.extract_content_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            }
        }
        
        # Train each model
        for model_name, config in model_configs.items():
            feature_cols = config['features']
            if not feature_cols:
                continue  # Skip if no features available
            
            # Get feature subset
            X = df[feature_cols]
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Train model
            model = config['model']
            model.fit(X_scaled)
            
            # Save model and scaler
            self.models[model_name] = model
            self.feature_scalers[model_name] = scaler
            
            # Save to disk
# Save feature scaler
            joblib.dump(scaler, os.path.join(self.model_dir, f"{model_name}_scaler.joblib"))
            
            # Calculate feature importance for interpretability (for RandomForest only)
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                self.feature_importance[model_name] = dict(zip(feature_cols, importances))
        
        self.last_training_time = time.time()
        return True
    
    def detect_anomalies(self, event):
        """Detect anomalies using all trained models"""
        if not self.models:
            return None  # No trained models available
        
        # Extract and combine features
        features = self.combine_features(event)
        
        # Run detection for each model
        anomaly_results = {}
        for model_name, model in self.models.items():
            # Get relevant features for this model
            if model_name == 'temporal':
                model_features = self.extract_temporal_features(event)
            elif model_name == 'contextual':
                model_features = self.extract_contextual_features(event)
            elif model_name == 'content':
                model_features = self.extract_content_features(event)
            else:
                continue
            
            # Create feature vector
            feature_names = list(model_features.keys())
            feature_values = list(model_features.values())
            
            # Skip if no features available
            if not feature_names:
                continue
            
            # Scale features
            scaler = self.feature_scalers.get(model_name)
            if not scaler:
                continue
                
            X = np.array(feature_values).reshape(1, -1)
            X_scaled = scaler.transform(X)
            
            # Predict anomaly
            prediction = model.predict(X_scaled)[0]
            anomaly_score = model.decision_function(X_scaled)[0]
            
            # Score interpretation:
            # Isolation Forest: negative = anomaly, positive = normal
            # Convert to standard range [-1, 1] where -1 is most anomalous
            norm_score = anomaly_score
            
            anomaly_results[model_name] = {
                'is_anomaly': prediction == -1,
                'score': norm_score,
                'contributing_features': self.get_contributing_features(model_name, X_scaled[0], feature_names)
            }
        
        # Combine results for final decision
        if anomaly_results:
            combined_score = np.mean([r['score'] for r in anomaly_results.values()])
            is_anomaly = any(r['is_anomaly'] for r in anomaly_results.values())
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': combined_score,
                'model_scores': anomaly_results,
                'summary': f"Anomaly detected with score {combined_score:.4f}" if is_anomaly else "Normal activity"
            }
        
        return None
    
    def get_contributing_features(self, model_name, features_scaled, feature_names):
        """Identify which features contributed most to the anomaly score"""
        if model_name not in self.feature_importance or not self.feature_importance[model_name]:
            return []
            
        # Get feature importance
        importance = self.feature_importance[model_name]
        
        # Find features with highest deviation from norm, weighted by importance
        contributors = []
        for i, feature in enumerate(feature_names):
            if feature in importance:
                # Calculate contribution: absolute scaled value * feature importance
                contrib = abs(features_scaled[i]) * importance[feature]
                contributors.append((feature, contrib))
        
        # Sort by contribution and return top 3
        return [f for f, _ in sorted(contributors, key=lambda x: x[1], reverse=True)[:3]]
    
    def update_baseline(self, event):
        """Update baseline with new event data"""
        # Add to baseline data
        self.baseline_data['events'].append(event)
        
        # Limit size of baseline data
        max_samples = self.config.get('max_baseline_samples', 10000)
        if len(self.baseline_data['events']) > max_samples:
            self.baseline_data['events'] = self.baseline_data['events'][-max_samples:]
        
        # Check if retraining is needed
        current_time = time.time()
        if current_time - self.last_training_time > self.retraining_interval:
            # Retrain models with updated data
            print("[INFO] Retraining anomaly detection models with updated baseline data")
            self.train_models(self.baseline_data['events'])
    
    def analyze_time_series(self, events, window_size=60):
        """Analyze time series patterns in events"""
        if not events:
            return None
            
        # Group events by time window
        time_windows = defaultdict(list)
        
        for event in events:
            timestamp = event.get('timestamp', '')
            if not timestamp:
                continue
                
            try:
                dt = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                # Round to the nearest window
                window_key = time.strftime("%Y-%m-%d %H:00:00", dt)  # Hourly windows
                time_windows[window_key].append(event)
            except ValueError:
                continue
        
        # Analyze frequency patterns
        window_counts = {window: len(events) for window, events in time_windows.items()}
        
        if len(window_counts) < 3:
            return None  # Not enough data for meaningful analysis
            
        # Detect frequency anomalies
        values = list(window_counts.values())
        mean_count = np.mean(values)
        std_count = np.std(values)
        
        # Detect windows with unusual activity
        z_scores = {window: (count - mean_count) / max(std_count, 0.001) for window, count in window_counts.items()}
        anomalous_windows = {window: z for window, z in z_scores.items() if abs(z) > 2.0}
        
        if anomalous_windows:
            return {
                'anomalous_windows': anomalous_windows,
                'window_counts': window_counts,
                'mean_count': mean_count,
                'std_count': std_count
            }
        
        return None

############################################################

################## ADV ANALYSIS CODE #######################
class AdvancedFileContentAnalysis:
    def __init__(self, config=None):
        self.config = config or {}
        self.file_cache = {}  # Cache for file content
        self.diff_threshold = self.config.get('diff_threshold', 0.3)  # Threshold for significant diffs
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB max for content analysis
        self.content_signatures = {}  # Store file content signatures
        
    def analyze_file_changes(self, file_path, previous_hash, new_hash):
        """Analyze changes between file versions using diff and semantic analysis"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
            
        # Check file size before processing
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return {
                    'analysis_type': 'size_only',
                    'file_size': file_size,
                    'too_large': True,
                    'message': f"File too large for content analysis ({file_size} bytes)"
                }
        except OSError:
            return {'error': 'Cannot access file'}
        
        # Determine file type
        file_type = self.determine_file_type(file_path)
        
        # Select appropriate analysis method based on file type
        if file_type == 'binary':
            return self.analyze_binary_changes(file_path, previous_hash, new_hash)
        elif file_type in ['config', 'script', 'text']:
            return self.analyze_text_changes(file_path, previous_hash, new_hash, file_type)
        else:
            return {'analysis_type': 'hash_only', 'file_type': 'unknown'}
    
    def determine_file_type(self, file_path):
        """Determine file type based on extension and content sampling"""
        # Check by extension first
        _, ext = os.path.splitext(file_path.lower())
        
        # Binary file extensions
        binary_extensions = ['.exe', '.bin', '.o', '.so', '.dll', '.pyc', '.pyd', 
                             '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', 
                             '.tar', '.gz', '.bz2', '.xz', '.pdf']
        
        # Config file extensions
        config_extensions = ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml', '.xml', '.properties']
        
        # Script file extensions
        script_extensions = ['.sh', '.py', '.rb', '.pl', '.js', '.php', '.ps1', '.bat', '.cmd']
        
        # Text file extensions
        text_extensions = ['.txt', '.md', '.log', '.csv', '.html', '.htm', '.css']
        
        if ext in binary_extensions:
            return 'binary'
        elif ext in config_extensions:
            return 'config'
        elif ext in script_extensions:
            return 'script'
        elif ext in text_extensions:
            return 'text'
        
        # If extension doesn't give a clear answer, check content
        try:
            # Read first few KB to determine content type
            with open(file_path, 'rb') as f:
                content = f.read(4096)
                
            # Check for binary content
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            binary_chars = bytearray(set(range(256)) - set(text_chars))
            
            # If >30% non-text chars, likely binary
            if float(len([b for b in content if b in binary_chars])) / len(content) > 0.3:
                return 'binary'
                
            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
                
                # Check for config patterns
                if any(pattern in text_content for pattern in ['<config', '<?xml', '{', '[', 'config', 'setting']):
                    return 'config'
                
                # Check for script patterns
                if any(pattern in text_content for pattern in ['#!/', 'import ', 'function ', 'def ', 'class ']):
                    return 'script'
                    
                # Default to text
                return 'text'
            except UnicodeDecodeError:
                return 'binary'
                
        except (IOError, OSError):
            # If we can't read the file, default to binary
            return 'binary'
    
    def analyze_binary_changes(self, file_path, previous_hash, new_hash):
        """Analyze changes in binary files using entropy and partial hashing"""
        # For binary files, we focus on entropy analysis and segment hashing
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Calculate entropy
            entropy = self.calculate_entropy(content)
            
            # Calculate segment hashes (divide file into segments and hash each)
            segment_size = min(4096, len(content) // 10) if len(content) > 0 else 0
            segments = []
            
            if segment_size > 0:
                for i in range(0, len(content), segment_size):
                    segment = content[i:i + segment_size]
                    segment_hash = hashlib.md5(segment).hexdigest()
                    segments.append({
                        'offset': i,
                        'size': len(segment),
                        'hash': segment_hash
                    })
            
            # Check if we have a previous signature to compare against
            diff_analysis = None
            if previous_hash in self.content_signatures:
                prev_sig = self.content_signatures[previous_hash]
                diff_analysis = self.compare_binary_signatures(prev_sig, {
                    'entropy': entropy,
                    'segments': segments,
                    'file_size': len(content)
                })
            
            # Store current signature
            self.content_signatures[new_hash] = {
                'entropy': entropy,
                'segments': segments,
                'file_size': len(content)
            }
            
            return {
                'analysis_type': 'binary',
                'file_size': len(content),
                'entropy': entropy,
                'segment_count': len(segments),
                'diff_analysis': diff_analysis
            }
            
        except (IOError, OSError):
            return {'error': 'Cannot access file for binary analysis'}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0
            
        entropy = 0
        data_len = len(data)
        if data_len == 0:  # Additional check to prevent division by zero
            return 0
            
        # Count byte frequencies
        counter = Counter(data)
        
        # Calculate entropy
        for count in counter.values():
            probability = count / data_len
            if probability > 0:  # Prevent log(0) which is undefined
                entropy -= probability * math.log2(probability)
            
        return entropy
    
    def compare_binary_signatures(self, old_sig, new_sig):
        """Compare binary file signatures to identify changes"""
        # Compare file sizes
        old_size = old_sig.get('file_size', 0)
        new_size = new_sig.get('file_size', 0)
        size_delta = new_size - old_size
        size_change_pct = (size_delta / old_size * 100) if old_size > 0 else float('inf')
        
        # Compare entropy
        old_entropy = old_sig.get('entropy', 0)
        new_entropy = new_sig.get('entropy', 0)
        entropy_delta = new_entropy - old_entropy
        
        # Compare segments
        old_segments = old_sig.get('segments', [])
        new_segments = new_sig.get('segments', [])
        
        # Find matching segments
        matching_segments = 0
        modified_segments = 0
        
        # Map of segment offset to hash
        old_segment_map = {seg['offset']: seg['hash'] for seg in old_segments}
        new_segment_map = {seg['offset']: seg['hash'] for seg in new_segments}
        
        # Find common offsets
        common_offsets = set(old_segment_map.keys()) & set(new_segment_map.keys())
        
        for offset in common_offsets:
            if old_segment_map[offset] == new_segment_map[offset]:
                matching_segments += 1
            else:
                modified_segments += 1
        
        # Calculate similarity
        total_segments = len(old_segments)
        similarity = matching_segments / total_segments if total_segments > 0 else 0
        
        # Analyze entropy change
        is_encrypted = entropy_delta > 1.0 and new_entropy > 7.0
        is_compressed = entropy_delta > 0.5 and size_delta < 0
        is_decompressed = entropy_delta < -0.5 and size_delta > 0
        
        return {
            'size_delta': size_delta,
            'size_change_pct': size_change_pct,
            'entropy_delta': entropy_delta,
            'matching_segments': matching_segments,
            'modified_segments': modified_segments,
            'similarity': similarity,
            'is_encrypted': is_encrypted,
            'is_compressed': is_compressed,
            'is_decompressed': is_decompressed,
            'significant_change': similarity < 0.7
        }
    
    def analyze_text_changes(self, file_path, previous_hash, new_hash, file_type):
        """Analyze changes in text files using diff and semantic analysis"""
        try:
            # Read current file content
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                new_content = f.read()
                
            # Get old content if available
            old_content = None
            if previous_hash in self.file_cache:
                old_content = self.file_cache[previous_hash]
            
            # Store new content in cache
            self.file_cache[new_hash] = new_content
            
            # If we don't have the old content, we can only analyze current state
            if old_content is None:
                return self.analyze_text_content(new_content, file_type)
            
            # Get diff between versions
            diff_result = self.compute_text_diff(old_content, new_content)
            
            # Combine with content analysis
            content_analysis = self.analyze_text_content(new_content, file_type)
            
            # Special handling for different file types
            type_specific = {}
            
            if file_type == 'config':
                type_specific = self.analyze_config_changes(old_content, new_content)
            elif file_type == 'script':
                type_specific = self.analyze_script_changes(old_content, new_content)
            
            # Combine all analyses
            result = {
                'analysis_type': 'text',
                'file_type': file_type,
                'diff': diff_result,
                'content': content_analysis
            }
            
            if type_specific:
                result['type_specific'] = type_specific
                
            return result
            
        except (IOError, OSError, UnicodeDecodeError) as e:
            return {'error': f'Text analysis failed: {str(e)}'}
    
    def compute_text_diff(self, old_content, new_content):
        """Compute diff between old and new content"""
        # Split into lines
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        
        # Get unified diff
        diff = list(difflib.unified_diff(old_lines, new_lines, n=2))
        
        # Count additions and deletions
        additions = len([line for line in diff if line.startswith('+')])
        deletions = len([line for line in diff if line.startswith('-')])
        
        # Calculate similarity using difflib's SequenceMatcher
        similarity = difflib.SequenceMatcher(None, old_content, new_content).ratio()
        
        # Get changed sections for more detailed analysis
        changed_sections = []
        diff_iter = iter(diff)
        
        # Skip the header lines
        for _ in range(3):
            next(diff_iter, None)
        
        current_section = {'context': [], 'additions': [], 'deletions': []}
        
        for line in diff_iter:
            if line.startswith(' '):  # Context line
                if current_section['additions'] or current_section['deletions']:
                    changed_sections.append(current_section)
                    current_section = {'context': [], 'additions': [], 'deletions': []}
                current_section['context'].append(line[1:])
            elif line.startswith('+'):  # Addition
                current_section['additions'].append(line[1:])
            elif line.startswith('-'):  # Deletion
                current_section['deletions'].append(line[1:])
        
        # Add the last section if non-empty
        if current_section['additions'] or current_section['deletions']:
            changed_sections.append(current_section)
        
        return {
            'additions': additions,
            'deletions': deletions,
            'similarity': similarity,
            'changed_sections': changed_sections[:5],  # Limit to first 5 sections
            'significant_change': similarity < self.diff_threshold
        }
    
    def analyze_text_content(self, content, file_type):
        """Analyze text content for patterns of interest"""
        # Basic text statistics
        line_count = content.count('\n') + 1
        word_count = len(content.split())
        char_count = len(content)
        
        # Look for patterns based on file type
        patterns = {}
        
        if file_type == 'config':
            patterns['ip_addresses'] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
            patterns['urls'] = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
            patterns['uncommon_ports'] = re.findall(r'port\s*[=:]\s*(\d+)', content)
        elif file_type == 'script':
            patterns['functions'] = re.findall(r'function\s+(\w+)|def\s+(\w+)', content)
            patterns['imports'] = re.findall(r'import\s+(\w+)|from\s+(\w+)', content)
            patterns['suspicious_commands'] = re.findall(r'system\(|exec\(|eval\(|shell_exec|subprocess', content)
        
        return {
            'line_count': line_count,
            'word_count': word_count,
            'char_count': char_count,
            'patterns': patterns
        }
    
    def analyze_config_changes(self, old_content, new_content):
        """Special analysis for configuration files"""
        # Try to detect config format
        config_format = self.detect_config_format(new_content)
        
        if config_format == 'json':
            return self.analyze_json_config(old_content, new_content)
        elif config_format == 'ini':
            return self.analyze_ini_config(old_content, new_content)
        elif config_format == 'xml':
            return self.analyze_xml_config(old_content, new_content)
        else:
            # Generic key-value extraction for unknown formats
            old_settings = self.extract_generic_settings(old_content)
            new_settings = self.extract_generic_settings(new_content)
            return self.compare_settings(old_settings, new_settings)
    
    def detect_config_format(self, content):
        """Detect configuration file format"""
        # Check for JSON format
        if content.strip().startswith('{') and content.strip().endswith('}'):
            try:
                json.loads(content)
                return 'json'
            except json.JSONDecodeError:
                pass
        
        # Check for XML format
        if content.strip().startswith('<') and content.strip().endswith('>'):
            if '<?xml' in content or '<config' in content:
                return 'xml'
        
        # Check for INI format
        if '[' in content and ']' in content and '=' in content:
            if re.search(r'^\s*\[[^\]]+\]', content, re.MULTILINE):
                return 'ini'
        
        # Default to generic
        return 'generic'
    
    def analyze_json_config(self, old_content, new_content):
        """Analyze changes in JSON configuration files"""
        try:
            old_json = json.loads(old_content)
            new_json = json.loads(new_content)
            
            # Flatten nested JSON for comparison
            old_flat = self.flatten_json(old_json)
            new_flat = self.flatten_json(new_json)
            
            return self.compare_settings(old_flat, new_flat)
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON format'}
    
    def flatten_json(self, json_obj, prefix=''):
        """Flatten nested JSON object into key-value pairs"""
        flattened = {}
        
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    flattened.update(self.flatten_json(v, key))
                else:
                    flattened[key] = str(v)
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    flattened.update(self.flatten_json(item, key))
                else:
                    flattened[key] = str(item)
        else:
            flattened[prefix] = str(json_obj)
            
        return flattened
    
    def analyze_ini_config(self, old_content, new_content):
        """Analyze changes in INI configuration files"""
        # Parse INI-style settings
        old_settings = self.parse_ini_content(old_content)
        new_settings = self.parse_ini_content(new_content)
        
        return self.compare_settings(old_settings, new_settings)
    
    def parse_ini_content(self, content):
        """Parse INI-style configuration"""
        settings = {}
        current_section = 'DEFAULT'
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith(('#', ';')):
                continue
            
            # Parse section headers
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                continue
            
            # Parse key-value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                settings[f"{current_section}.{key.strip()}"] = value.strip()
        
        return settings
    
    def analyze_xml_config(self, old_content, new_content):
        """Analyze changes in XML configuration files"""
        # Simple XML parsing
        old_settings = self.extract_xml_settings(old_content)
        new_settings = self.extract_xml_settings(new_content)
        
        return self.compare_settings(old_settings, new_settings)
    
    def extract_xml_settings(self, content):
        """Extract settings from XML content using regex"""
        settings = {}
        
        # Find all XML tags with values
        tag_pattern = re.compile(r'<([^>/\s]+)[^>]*>(.*?)</\1>', re.DOTALL)
        attribute_pattern = re.compile(r'(\w+)=["\'](.*?)["\']')
        
        for match in tag_pattern.finditer(content):
            tag_name = match.group(1)
            tag_value = match.group(2).strip()
            
            if tag_value:
                settings[tag_name] = tag_value
            
            # Also extract attributes
            tag_start = match.group(0)[:match.group(0).find('>')] # This line had an extra bracket
            for attr_match in attribute_pattern.finditer(tag_start):
                attr_name = attr_match.group(1)
                attr_value = attr_match.group(2)
                settings[f"{tag_name}.{attr_name}"] = attr_value
        
        return settings
    
    def extract_generic_settings(self, content):
        """Extract key-value pairs from generic config content"""
        settings = {}
        
        # Look for key-value patterns
        patterns = [
            r'(\w+)\s*[=:]\s*([^;#\n]+)',  # key=value or key: value
            r'(-{1,2}\w+)\s+([^-][^;#\n]*)'  # --key value
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                key = match.group(1).strip()
                value = match.group(2).strip()
                settings[key] = value
        
        return settings
    
    def compare_settings(self, old_settings, new_settings):
        """Compare settings between versions"""
        # Find added, removed, and modified settings
        old_keys = set(old_settings.keys())
        new_keys = set(new_settings.keys())
        
        added_keys = new_keys - old_keys
        removed_keys = old_keys - new_keys
        common_keys = old_keys & new_keys
        
        modified_keys = {key for key in common_keys if old_settings[key] != new_settings[key]}
        
        # Collect changes
        changes = {
            'added': {key: new_settings[key] for key in added_keys},
            'removed': {key: old_settings[key] for key in removed_keys},
            'modified': {key: {'old': old_settings[key], 'new': new_settings[key]} for key in modified_keys}
        }
        
        # Count changes
        total_changes = len(added_keys) + len(removed_keys) + len(modified_keys)
        
        # Calculate criticality based on changes
        criticality = 'low'
        if total_changes > 10:
            criticality = 'high'
        elif total_changes > 5:
            criticality = 'medium'
        
        return {
            'format': 'config',
            'changes': changes,
            'total_changes': total_changes,
            'criticality': criticality
        }
    
    def analyze_script_changes(self, old_content, new_content):
        """Analyze changes in script files for security implications"""
        # Extract functions and imports from both versions
        old_functions = set(re.findall(r'function\s+(\w+)|def\s+(\w+)', old_content))
        new_functions = set(re.findall(r'function\s+(\w+)|def\s+(\w+)', new_content))
        
        old_imports = set(re.findall(r'import\s+(\w+)|from\s+(\w+)', old_content))
        new_imports = set(re.findall(r'import\s+(\w+)|from\s+(\w+)', new_content))
        
        # Look for suspicious patterns
        suspicious_patterns = {
            'system_commands': r'system\s*\(|exec\s*\(|shell_exec|subprocess\..*call|os\.system',
            'network_access': r'socket\.|urllib|requests\.|http\.|connect\s*\(',
            'file_operations': r'open\s*\(|file\s*\(|read\s*\(|write\s*\(|unlink\s*\(',
            'eval_code': r'eval\s*\(|exec\s*\(|execfile|compile\s*\(|__import__',
            'privilege_escalation': r'sudo|su\s+|setuid|setgid|chmod\s+777|chown\s+root',
            'data_exfiltration': r'base64\.|encode\s*\(|encrypt\s*\(|\.send\s*\('
        }
        
        # Check for these patterns in new content
        suspicious_matches = {}
        for category, pattern in suspicious_patterns.items():
            matches = re.findall(pattern, new_content)
            if matches:
                suspicious_matches[category] = matches
        
        # Compare functions and imports
        added_functions = [f[0] or f[1] for f in new_functions - old_functions if any(f)]
        removed_functions = [f[0] or f[1] for f in old_functions - new_functions if any(f)]
        
        added_imports = [i[0] or i[1] for i in new_imports - old_imports if any(i)]
        removed_imports = [i[0] or i[1] for i in old_imports - new_imports if any(i)]
        
        # Analyze criticality based on findings
        criticality = 'low'
        
        # Elevate criticality based on suspicious patterns
        if any(category in suspicious_matches for category in ['eval_code', 'privilege_escalation']):
            criticality = 'high'
        elif any(category in suspicious_matches for category in ['system_commands', 'network_access']):
            criticality = 'medium'
        elif suspicious_matches:
            criticality = 'low'
            
        return {
            'format': 'script',
            'added_functions': added_functions,
            'removed_functions': removed_functions,
            'added_imports': added_imports,
            'removed_imports': removed_imports,
            'suspicious_patterns': suspicious_matches,
            'criticality': criticality
        }
    
    def check_malware_indicators(self, file_path, file_hash):
        """Check file against known malware indicators"""
        entropy = None
        strings_analysis = None
        
        try:
            # Calculate entropy for all files
            with open(file_path, 'rb') as f:
                content = f.read()
                entropy = self.calculate_entropy(content)
                
            # For non-binary files, extract suspicious strings
            if not self.determine_file_type(file_path) == 'binary':
                strings_analysis = self.extract_suspicious_strings(file_path)
                
            return {
                'file_hash': file_hash,
                'entropy': entropy,
                'high_entropy': entropy > 7.0 if entropy is not None else False,
                'strings_analysis': strings_analysis
            }
        except (IOError, OSError):
            return {'error': 'Cannot access file for malware analysis'}
    
    def extract_suspicious_strings(self, file_path):
        """Extract suspicious strings from a file using external 'strings' tool"""
        suspicious_categories = {
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'urls': r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'encoded_commands': r'base64 -d|base64 --decode|base64\.decode',
            'shell_commands': r'sh -c|bash -c|cmd\.exe|powershell',
            'common_exfil': r'curl|wget|nc \-|netcat|ssh|sftp'
        }
        
        try:
            # Use strings command if available (more efficient for binary files)
            if os.path.exists('/usr/bin/strings'):
                output = subprocess.check_output(['strings', file_path], stderr=subprocess.DEVNULL)
                strings_content = output.decode('utf-8', errors='replace')
            else:
                # Fallback to reading the file directly
                with open(file_path, 'rb') as f:
                    content = f.read()
                    strings_content = ''.join(chr(c) if c >= 32 and c < 127 else ' ' for c in content)
            
            # Look for suspicious patterns
            findings = {}
            for category, pattern in suspicious_categories.items():
                matches = set(re.findall(pattern, strings_content))
                if matches:
                    findings[category] = list(matches)[:10]  # Limit to first 10 matches
            
            return findings if findings else None
            
        except (IOError, OSError, subprocess.SubprocessError):
            return None
    
    def analyze_partial_file_changes(self, file_path, old_content, new_content):
        """Analyze changes in specific parts of files"""
        # Get diff
        diff_result = self.compute_text_diff(old_content, new_content)
        
        # Detect if changes are localized to specific sections
        changed_sections = diff_result.get('changed_sections', [])
        
        # Identify specific types of changes
        change_types = []
        for section in changed_sections:
            context = '\n'.join(section.get('context', []))
            additions = '\n'.join(section.get('additions', []))
            deletions = '\n'.join(section.get('deletions', []))
            
            # Look for specific patterns in changes
            if re.search(r'password|passwd|secret|key|token|auth', context, re.IGNORECASE):
                change_types.append('credential_change')
            
            if re.search(r'127\.0\.0\.1|localhost', deletions, re.IGNORECASE) and not re.search(r'127\.0\.0\.1|localhost', additions, re.IGNORECASE):
                change_types.append('localhost_removal')
            
            if re.search(r'deny|block|restrict', deletions, re.IGNORECASE) and not re.search(r'deny|block|restrict', additions, re.IGNORECASE):
                change_types.append('security_restriction_removal')
            
            # Check for added URLs or IPs
            new_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', additions)
            new_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', additions)
            
            if new_urls:
                change_types.append('new_url_added')
            
            if new_ips:
                change_types.append('new_ip_added')
        
        # Determine criticality based on change types
        criticality = 'low'
        if 'security_restriction_removal' in change_types or 'credential_change' in change_types:
            criticality = 'high'
        elif 'localhost_removal' in change_types or 'new_url_added' in change_types or 'new_ip_added' in change_types:
            criticality = 'medium'
        
        return {
            'localized_changes': len(changed_sections) <= 3,
            'change_types': change_types,
            'criticality': criticality
        }

############################################################

################## CONTEXT ANALYSIS CODE ###################
class ContextAwareDetection:
    def __init__(self, config=None):
        self.config = config or {}
        self.event_history = deque(maxlen=1000)  # Keep last 1000 events
        self.attack_chains = defaultdict(list)
        self.environment = self.config.get('environment', 'production')
        self.ip_blocklist = set()
        self.suspicious_processes = set()
        self.mitre_techniques = self.load_mitre_techniques()
        
        # Environment-specific settings
        self.thresholds = {
            'production': {'risk_multiplier': 1.5, 'alert_threshold': 70},
            'staging': {'risk_multiplier': 1.2, 'alert_threshold': 75},
            'development': {'risk_multiplier': 1.0, 'alert_threshold': 80}
        }
        
        # Load critical file mappings
        self.file_criticality = self.load_file_criticality()
    
    def load_mitre_techniques(self):
        """Load detailed MITRE ATT&CK technique information"""
        # This would typically load from a JSON file containing full technique details
        # Simplified example included here
        techniques = {
            "T1222": {
                "name": "File and Directory Permissions Modification",
                "tactic": "Defense Evasion",
                "severity": 70,
                "detection_difficulty": "Medium",
                "related_techniques": ["T1222.001", "T1222.002", "T1574"],
                "common_tools": ["chmod", "chown", "icacls", "attrib"]
            },
            "T1565": {
                "name": "Data Manipulation",
                "tactic": "Impact",
                "severity": 75,
                "detection_difficulty": "High",
                "related_techniques": ["T1565.001", "T1565.002", "T1565.003"],
                "common_tools": ["hex editor", "sed", "awk", "vim"]
            },
            # Add more techniques as needed
        }
        return techniques
    
    def load_file_criticality(self):
        """Load file criticality mappings based on environment"""
        # This would typically load from a configuration file
        # Simplified example included here
        base_criticality = {
            "/etc/passwd": 95,
            "/etc/shadow": 95,
            "/etc/sudoers": 90,
            "/etc/ssh/sshd_config": 85,
            "/etc/hosts": 80,
            "/var/www/html": 75,
            "/bin": 70,
            "/sbin": 70,
            "/usr/bin": 70,
            "/usr/sbin": 70,
            "/boot": 90,
            "/lib": 70,
            "/etc/crontab": 85,
            "/etc/cron.d": 85,
            "/.ssh/authorized_keys": 90
        }
        
        # Adjust criticality based on environment
        if self.environment == 'development':
            return {k: max(v * 0.7, 50) for k, v in base_criticality.items()}
        elif self.environment == 'staging':
            return {k: max(v * 0.9, 60) for k, v in base_criticality.items()}
        else:  # production
            return base_criticality
    
    def calculate_file_criticality(self, file_path):
        """Calculate criticality score for a file based on path and content"""
        # Direct match for known critical files
        for critical_path, score in self.file_criticality.items():
            if file_path.startswith(critical_path):
                return score
        
        # Criticality based on file type and location
        if file_path.startswith('/etc/'):
            return 70
        elif file_path.startswith(('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/')):
            return 65
        elif '/www/' in file_path:
            if any(ext in file_path.lower() for ext in ['.php', '.asp', '.jsp']):
                return 75  # Web executable content
            return 60
        elif '.ssh/' in file_path:
            return 85
        elif any(file_path.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb']):
            return 60  # Scripts
        elif any(file_path.endswith(ext) for ext in ['.conf', '.cfg', '.ini', '.json']):
            return 65  # Config files
        
        # Default criticality
        return 50
    
    def correlate_attack_chain(self, event):
        """Identify potential attack chains by correlating multiple events"""
        # Extract key information
        event_type = event.get('event_type')
        file_path = event.get('file_path')
        timestamp = event.get('timestamp')
        technique_id = event.get('mitre_mapping', {}).get('technique_id', 'unknown')
        process_info = event.get('process_correlation', {}).get('related_process', {})
        
        # Create event identifier for grouping
        host_id = event.get('host_id', 'localhost')
        user_id = process_info.get('user', 'unknown')
        process_name = process_info.get('process_name', 'unknown')
        
        # Group identifier to track related events
        group_key = f"{host_id}_{user_id}_{process_name}"
        
        # Add to event history
        self.event_history.append(event)
        
        # Add to potential attack chain
        self.attack_chains[group_key].append({
            'timestamp': timestamp,
            'event_type': event_type,
            'file_path': file_path,
            'technique_id': technique_id,
            'process_pid': process_info.get('pid', 'unknown')
        })
        
        # Prune old events from attack chains (events older than 30 minutes)
        if timestamp:
            try:
                event_time = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                event_time = time.mktime(event_time)
                
                # Remove events older than 30 minutes
                cutoff_time = event_time - (30 * 60)
                self.attack_chains[group_key] = [
                    e for e in self.attack_chains[group_key] 
                    if time.mktime(time.strptime(e['timestamp'], "%Y-%m-%d %H:%M:%S")) >= cutoff_time
                ]
                
                # Remove empty chains
                if not self.attack_chains[group_key]:
                    del self.attack_chains[group_key]
            except (ValueError, TypeError):
                pass  # Skip time-based pruning if timestamp format is invalid
        
        # Check for attack patterns in this chain
        return self.detect_attack_patterns(group_key)
    
    def detect_attack_patterns(self, group_key):
        """Detect known attack patterns in event chains"""
        if group_key not in self.attack_chains:
            return None
        
        chain = self.attack_chains[group_key]
        if len(chain) < 2:
            return None  # Need at least 2 events for a chain
        
        # Common attack patterns to check for
        patterns = [
            {
                'name': 'Reconnaissance and Data Theft',
                'severity': 85,
                'techniques': ['T1083', 'T1005', 'T1039', 'T1020'],
                'min_match': 2
            },
            {
                'name': 'Credential Access',
                'severity': 90,
                'techniques': ['T1003', 'T1552', 'T1555', 'T1212'],
                'min_match': 1
            },
            {
                'name': 'Defense Evasion',
                'severity': 85,
                'techniques': ['T1222', 'T1562', 'T1070', 'T1036', 'T1027'],
                'min_match': 2
            },
            {
                'name': 'Persistence',
                'severity': 80,
                'techniques': ['T1053', 'T1543', 'T1546', 'T1098', 'T1136'],
                'min_match': 1
            }
        ]
        
        # Check each pattern against our chain
        chain_techniques = [event['technique_id'] for event in chain]
        detected_patterns = []
        
        for pattern in patterns:
            matches = [tech for tech in chain_techniques if any(tech.startswith(pt) for pt in pattern['techniques'])]
            if len(matches) >= pattern['min_match']:
                detected_patterns.append({
                    'pattern': pattern['name'],
                    'severity': pattern['severity'],
                    'matched_techniques': matches,
                    'events': chain
                })
        
        return detected_patterns if detected_patterns else None
    
    def calculate_risk_score(self, event):
        """Calculate risk score based on multiple factors including file criticality"""
        # Base score starts from file criticality
        file_path = event.get('file_path', '')
        base_score = self.calculate_file_criticality(file_path)
        
        # Adjust for MITRE technique severity
        mitre_mapping = event.get('mitre_mapping', {})
        # Check if mitre_mapping is a dictionary
        if not isinstance(mitre_mapping, dict):
            mitre_mapping = {}
        technique_id = mitre_mapping.get('technique_id', '')
        
        technique_severity = 50  # Default value
        if technique_id in self.mitre_techniques:
            technique_severity = self.mitre_techniques[technique_id].get('severity', 50)
        
        # Adjust for anomaly detection results
        anomaly_data = event.get('anomaly_detection', {})
        # Check if anomaly_data is a dictionary
        if not isinstance(anomaly_data, dict):
            anomaly_data = {}
        anomaly_score = anomaly_data.get('anomaly_score', 0)
        
        # Consider process correlation
        process_correlation = event.get('process_correlation', {})
        # Check if process_correlation is a dictionary
        if not isinstance(process_correlation, dict):
            process_correlation = {}
        process_factor = 1.0  # Default neutral factor
        
        if process_correlation and process_correlation != "N/A":
            process = process_correlation.get('related_process', {})
            if not isinstance(process, dict):
                process = {}
            
            # Check for suspicious processes
            process_name = process.get('process_name', '').lower()
            if process_name in self.suspicious_processes:
                process_factor = 1.5
            
            # Check for unusual execution paths
            cmd_line = process.get('cmdline', '').lower()
            if cmd_line and ('/tmp/' in cmd_line or '/dev/shm/' in cmd_line):
                process_factor = 1.4
        
        # Calculate final risk score
        risk_multiplier = self.thresholds[self.environment]['risk_multiplier']
        
        # Combine all factors: base criticality, technique severity, anomaly score, and process factor
        risk_score = (
            (base_score * 0.3) +                      # 30% from file criticality
            (technique_severity * 0.3) +              # 30% from MITRE technique severity
            (anomaly_score * 50 * 0.2) +              # 20% from anomaly score (scaled from [-1,1] to [0,100])
            (base_score * process_factor * 0.2)       # 20% from process context
        ) * risk_multiplier
        
        # Cap at 100
        risk_score = min(max(risk_score, 0), 100)
        
        return {
            'score': risk_score,
            'components': {
                'file_criticality': base_score,
                'technique_severity': technique_severity,
                'anomaly_factor': anomaly_score * 50,
                'process_factor': process_factor,
                'environment_multiplier': risk_multiplier
            },
            'is_alert': risk_score >= self.thresholds[self.environment]['alert_threshold']
        }

    def calculate_risk_score(self, event):
        """Calculate risk score based on multiple factors including file criticality"""
        # Base score starts from file criticality
        file_path = event.get('file_path', '')
        base_score = self.calculate_file_criticality(file_path)
        
        # Adjust for MITRE technique severity
        mitre_mapping = event.get('mitre_mapping', {})
        # Check if mitre_mapping is a dictionary
        if not isinstance(mitre_mapping, dict):
            mitre_mapping = {}
        technique_id = mitre_mapping.get('technique_id', '')
        
        technique_severity = 50  # Default value
        if technique_id in self.mitre_techniques:
            technique_severity = self.mitre_techniques[technique_id].get('severity', 50)
        
        # Adjust for anomaly detection results
        anomaly_data = event.get('anomaly_detection', {})
        # Check if anomaly_data is a dictionary
        if not isinstance(anomaly_data, dict):
            anomaly_data = {}
        anomaly_score = anomaly_data.get('anomaly_score', 0)
        
        # Consider process correlation
        process_correlation = event.get('process_correlation', {})
        # Check if process_correlation is a dictionary
        if not isinstance(process_correlation, dict):
            process_correlation = {}
        process_factor = 1.0  # Default neutral factor
        
        if process_correlation and process_correlation != "N/A":
            process = process_correlation.get('related_process', {})
            if not isinstance(process, dict):
                process = {}
            
            # Check for suspicious processes
            process_name = process.get('process_name', '').lower()
            if process_name in self.suspicious_processes:
                process_factor = 1.5
            
            # Check for unusual execution paths
            cmd_line = process.get('cmdline', '').lower()
            if cmd_line and ('/tmp/' in cmd_line or '/dev/shm/' in cmd_line):
                process_factor = 1.4
        
        # Calculate final risk score
        risk_multiplier = self.thresholds[self.environment]['risk_multiplier']
        
        # Combine all factors: base criticality, technique severity, anomaly score, and process factor
        risk_score = (
            (base_score * 0.3) +                      # 30% from file criticality
            (technique_severity * 0.3) +              # 30% from MITRE technique severity
            (anomaly_score * 50 * 0.2) +              # 20% from anomaly score (scaled from [-1,1] to [0,100])
            (base_score * process_factor * 0.2)       # 20% from process context
        ) * risk_multiplier
        
        # Cap at 100
        risk_score = min(max(risk_score, 0), 100)
        
        return {
            'score': risk_score,
            'components': {
                'file_criticality': base_score,
                'technique_severity': technique_severity,
                'anomaly_factor': anomaly_score * 50,
                'process_factor': process_factor,
                'environment_multiplier': risk_multiplier
            },
            'is_alert': risk_score >= self.thresholds[self.environment]['alert_threshold']
        }

############################################################

################## FIM CONTROLLER CODE ENHANCEMENT #########

def should_alert(event):
    """Determine if an event should trigger an alert"""
    # Check risk score
    risk_assessment = event.get('risk_analysis', {})
    if not isinstance(risk_assessment, dict):
        risk_assessment = {}
    if risk_assessment.get('is_alert', False):
        return True
    
    # Check anomaly detection
    anomaly = event.get('anomaly_detection', {})
    if not isinstance(anomaly, dict):
        anomaly = {}
    if anomaly and anomaly.get('is_anomaly', False) and anomaly.get('anomaly_score', 0) < -0.7:
        return True
        
    # Check attack chains
    attack_patterns = event.get('attack_patterns', [])
    if attack_patterns:
        return True
        
    # Check malware indicators
    indicators = event.get('malware_indicators', {})
    if not isinstance(indicators, dict):
        indicators = {}
    if indicators and indicators.get('high_entropy', False):
        return True
        
    # Check content analysis criticality
    content = event.get('content_analysis', {})
    if not isinstance(content, dict):
        content = {}
    type_specific = content.get('type_specific', {})
    if not isinstance(type_specific, dict):
        type_specific = {}
    if content and type_specific.get('criticality', 'low') == 'high':
        return True
        
    return False

def get_alert_reasons(event):
    """Get human-readable reasons for an alert"""
    reasons = []
    
    # Risk score reason
    risk = event.get('risk_analysis', {})
    if risk.get('is_alert', False):
        reasons.append(f"High risk score ({risk.get('score', 0):.2f})")
        
        # Add risk components
        components = risk.get('components', {})
        if components.get('file_criticality', 0) > 80:
            reasons.append("Critical file modified")
        if components.get('technique_severity', 0) > 80:
            reasons.append("Severe MITRE technique detected")
        if components.get('process_factor', 1.0) > 1.2:
            reasons.append("Suspicious process involvement")
    
    # Anomaly reasons
    anomaly = event.get('anomaly_detection', {})
    if anomaly and anomaly.get('is_anomaly', False):
        reasons.append(f"Behavioral anomaly ({anomaly.get('anomaly_score', 0):.2f})")
        
        # Add model-specific reasons
        if 'model_scores' in anomaly:
            for model, result in anomaly.get('model_scores', {}).items():
                if result.get('is_anomaly', False):
                    features = result.get('contributing_features', [])
                    if features:
                        reasons.append(f"Unusual {model} pattern: {', '.join(features)}")
    
    # Attack chain reasons
    attack_patterns = event.get('attack_patterns', [])
    if attack_patterns:
        for pattern in attack_patterns:
            reasons.append(f"Part of attack pattern: {pattern.get('pattern', 'Unknown')}")
    
    # Content analysis reasons
    content = event.get('content_analysis', {})
    if content:
        if content.get('type_specific', {}).get('criticality', 'low') == 'high':
            reasons.append("Critical content changes detected")
            
        # Add specific content reasons
        if content.get('type_specific', {}).get('suspicious_patterns', {}):
            patterns = content.get('type_specific', {}).get('suspicious_patterns', {})
            for category in patterns:
                reasons.append(f"Suspicious {category} found in content")
    
    # Malware indicators
    indicators = event.get('malware_indicators', {})
    if indicators and indicators.get('high_entropy', False):
        reasons.append(f"High entropy content ({indicators.get('entropy', 0):.2f})")
        
    return reasons

def get_suggested_actions(event):
    """Get suggested actions based on the event"""
    actions = []
    risk_score = event.get('risk_analysis', {}).get('score', 0)
    event_type = event.get('event_type', '')
    file_path = event.get('file_path', '')
    
    # Basic actions based on risk
    if risk_score > 90:
        actions.append("Isolate host immediately")
        actions.append("Initiate incident response procedure")
    elif risk_score > 80:
        actions.append("Terminate suspicious processes")
        actions.append("Take file backup for forensic analysis")
    elif risk_score > 70:
        actions.append("Increase monitoring on this host")
        
    # Content-specific actions
    content = event.get('content_analysis', {})
    if content:
        if content.get('type_specific', {}).get('format', '') == 'config':
            actions.append("Review configuration changes")
            
        if content.get('type_specific', {}).get('format', '') == 'script':
            suspicious = content.get('type_specific', {}).get('suspicious_patterns', {})
            if suspicious:
                actions.append("Review script for malicious code")
    
    # File-specific actions
    if event_type == 'NEW FILE' and 'bin' in file_path:
        actions.append("Verify executable authenticity")
    
    if event_type == 'MODIFIED' and any(ext in file_path for ext in ['.conf', '.cfg', '.ini']):
        actions.append("Verify configuration changes with admin")
        
    # Malware indicators
    indicators = event.get('malware_indicators', {})
    if indicators and indicators.get('high_entropy', False):
        actions.append("Scan file with anti-virus")
        
    # Minimal default action
    if not actions:
        actions.append("Investigate file changes")
        
    return actions

def trigger_alert(event):
    """Trigger an alert for a high-risk event"""
    alert_file = os.path.join(OUTPUT_DIR, "fim_alerts.json")
    
    # Create alert object
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": event.get("uuid", str(time.time())),
        "file_path": event.get("file_path", ""),
        "event_type": event.get("event_type", ""),
        "risk_score": event.get("risk_analysis", {}).get("score", 0),
        "anomaly_score": event.get("anomaly_detection", {}).get("anomaly_score", 0),
        "alert_reasons": get_alert_reasons(event),
        "suggested_actions": get_suggested_actions(event),
        "raw_event": event
    }
    
    # Write alert to file
    try:
        with open(alert_file, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write alert: {e}")
        
    # Print alert to console
    print(f"\n[ALERT] High-risk file integrity event detected!")
    print(f"[ALERT] File: {alert['file_path']}")
    print(f"[ALERT] Event: {alert['event_type']}")
    print(f"[ALERT] Risk Score: {alert['risk_score']:.2f}")
    print(f"[ALERT] Reasons: {', '.join(alert['alert_reasons'])}")
    print(f"[ALERT] Suggested Actions: {', '.join(alert['suggested_actions'])}")
    
############################################################

def handle_shutdown(signum=None, frame=None):
    """Cleanly handle shutdown signals."""
    print("[INFO] Caught termination signal. Cleaning up...")
    
    # Clean up context detection resources if needed
    global context_detection, adv_content_analysis
    if context_detection:
        print("[INFO] Context-aware detection shut down.")
    
    if adv_content_analysis:
        print("[INFO] Advanced content analysis shut down.")

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
