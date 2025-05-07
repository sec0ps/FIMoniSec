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
import time
import json
import sys
import subprocess
import hashlib
import signal
import argparse
import daemon
import daemon.pidfile
import threading
import traceback
import atexit
import re

# New imports for ML and analysis
import numpy as np  # For numerical operations
import pandas as pd  # For data manipulation
from sklearn.ensemble import IsolationForest  # For anomaly detection

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries (numpy, pandas, scikit-learn) not found. ML-based detection will be disabled.")
    ML_LIBRARIES_AVAILABLE = False

BASE_DIR = "/opt/FIMoniSec/Linux-Client"
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOG_DIR = os.path.join(BASE_DIR, "logs")

LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
PIM_LOGGING_JSON = os.path.join(LOG_DIR, "pim_monitor.json")

# Preserve environment variables for sudo and command execution
daemon_env = os.environ.copy()
daemon_env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"

def ensure_output_dir():
    """Ensure that the output directory and necessary files exist."""
    # Make sure the output and log directories exist
    try:
        os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        
        # Ensure directories are fully created before continuing
        if not os.path.exists(OUTPUT_DIR) or not os.path.exists(LOG_DIR):
            print("[ERROR] Failed to create required directories")
            sys.exit(1)
            
        print(f"[INFO] Ensuring output directories exist: {OUTPUT_DIR}, {LOG_DIR}")
        
        # Ensure integrity process file exists with valid JSON
        if not os.path.exists(INTEGRITY_PROCESS_FILE):
            with open(INTEGRITY_PROCESS_FILE, "w") as f:
                f.write("{}\n")  # Initialize with empty JSON object
            os.chmod(INTEGRITY_PROCESS_FILE, 0o600)
            print(f"[INFO] Created integrity file: {INTEGRITY_PROCESS_FILE}")
        
        # Ensure PIM logging file exists
        if not os.path.exists(PIM_LOGGING_JSON):
            with open(PIM_LOGGING_JSON, "w") as f:
                f.write("")  # Empty file is fine for append-only logging
            os.chmod(PIM_LOGGING_JSON, 0o600)
            print(f"[INFO] Created PIM logging file: {PIM_LOGGING_JSON}")
        
        # Create PID file directory if it doesn't exist
        pid_dir = os.path.dirname(PID_FILE)
        if not os.path.exists(pid_dir):
            os.makedirs(pid_dir, mode=0o700, exist_ok=True)
            
        return True
    except Exception as e:
        print(f"[ERROR] Failed to ensure output directories: {e}")
        traceback.print_exc()
        sys.exit(1)

def start_daemon():
    with daemon.DaemonContext(
        working_directory='.',
        umask=0o022,
        pidfile=daemon.pidfile.TimeoutPIDLockFile(PID_FILE),
        stdout=open(LOG_FILE, 'a+'),
        stderr=open(LOG_FILE, 'a+'),
        stdin=open(os.devnull, 'r'),
    ):
        run_monitor()

def load_process_metadata():
    """
    Load stored process metadata from integrity_processes.json.
    This file will now store all process information previously stored in separate files.
    """
    if os.path.exists(INTEGRITY_PROCESS_FILE):
        try:
            with open(INTEGRITY_PROCESS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse integrity_processes.json: {e}")
            # Create backup of corrupted file
            backup_file = f"{INTEGRITY_PROCESS_FILE}.corrupted.{int(time.time())}"
            try:
                import shutil
                shutil.copy(INTEGRITY_PROCESS_FILE, backup_file)
                print(f"[INFO] Created backup of corrupted file: {backup_file}")
            except Exception as backup_error:
                print(f"[ERROR] Failed to create backup: {backup_error}")
            return {}
    return {}

def save_process_metadata(processes):
    """
    Save full process metadata to integrity_processes.json safely.
    This now includes all process tracking information previously stored in separate files.
    """
    temp_file = f"{INTEGRITY_PROCESS_FILE}.tmp"
    try:
        with open(temp_file, "w") as f:
            json.dump(processes, f, indent=4)

        os.replace(temp_file, INTEGRITY_PROCESS_FILE)
        os.chmod(INTEGRITY_PROCESS_FILE, 0o600)
        print(f"[INFO] Successfully wrote integrity metadata with {len(processes)} processes")

    except Exception as e:
        print(f"[ERROR] Failed to write to {INTEGRITY_PROCESS_FILE}: {e}", file=sys.stderr)

def get_all_processes():
    """
    Retrieve all running processes and their metadata with improved parsing.
    Filter out transient user commands and focus on actual system processes.
    """
    all_processes = {}

    try:
        # Use ps with explicit format specifiers to avoid parsing issues
        ps_command = "sudo -n /bin/ps -eo pid,user,start_time,ppid,comm,state --no-headers"
        output = subprocess.getoutput(ps_command)

        if not output:
            print("[ERROR] ps command returned no output. Check sudo permissions.")
            return all_processes

        for line in output.splitlines():
            parts = line.strip().split(None, 5)
            if len(parts) < 6:
                continue

            try:
                pid = parts[0].strip()
                if not pid.isdigit():
                    continue
                
                pid_int = int(pid)
                user = parts[1].strip()
                start_time = parts[2].strip()
                ppid = parts[3].strip()
                ppid_int = int(ppid) if ppid.isdigit() else 0
                process_name = parts[4].strip()  # Clean up the process name
                
                # State column: R (running), S (sleeping), D (disk sleep), etc.
                process_state = parts[5].strip()[0]  # Get first character of state
                
                # Filter out likely transient user commands
                # Skip processes that are in a "T" (stopped) state
                if process_state == 'T':
                    continue
                    
                # Get command line separately for accuracy
                cmdline_raw = subprocess.getoutput(f"sudo -n /bin/cat /proc/{pid}/cmdline 2>/dev/null").strip()
                cmdline = cmdline_raw.replace("\x00", " ").strip()
                
                # Skip typical interactive commands
                interactive_commands = ['more', 'less', 'vi', 'vim', 'nano', 'cat', 'tail', 'grep', 'awk', 'sed']
                if any(cmd == process_name for cmd in interactive_commands) and user not in ['root', 'system']:
                    continue
                
                # Get executable path
                exe_path = f"/proc/{pid}/exe"
                try:
                    # First, try using 'which' for common commands
                    if os.path.exists(f"/usr/bin/{process_name}"):
                        exe_real_path = f"/usr/bin/{process_name}"
                    elif os.path.exists(f"/usr/sbin/{process_name}"):
                        exe_real_path = f"/usr/sbin/{process_name}"
                    elif os.path.exists(f"/bin/{process_name}"):
                        exe_real_path = f"/bin/{process_name}"
                    elif os.path.exists(f"/sbin/{process_name}"):
                        exe_real_path = f"/sbin/{process_name}"
                    else:
                        # Fall back to readlink if not in standard locations
                        exe_real_path = subprocess.getoutput(f"sudo -n /usr/bin/readlink -f {exe_path}").strip()
                        
                    if not exe_real_path or "Permission denied" in exe_real_path:
                        exe_real_path = f"/usr/bin/{process_name}"  # Make a reasonable assumption
                        process_hash = "UNKNOWN_" + get_process_hash(process_name, cmdline)
                    else:
                        process_hash = get_process_hash(exe_real_path, cmdline)
                except Exception:
                    exe_real_path = f"/usr/bin/{process_name}"  # Make a reasonable assumption
                    process_hash = "UNKNOWN_" + get_process_hash(process_name, cmdline)
                
                # Resolve lineage
                lineage = resolve_lineage(pid_int)
                
                # Check for short-lived interactive processes
                is_interactive = False
                terminal_processes = ['bash', 'zsh', 'sh', 'csh', 'ksh', 'dash', 'tcsh', 'fish']
                session_indicators = ['sshd', 'login', 'gdm-session', 'lightdm']
                
                if (any(term in lineage for term in terminal_processes) and 
                    any(session in lineage for session in session_indicators) and
                    process_name not in ['sshd', 'cron', 'systemd', 'init']):
                    # Check process runtime
                    try:
                        proc_start_time = None
                        with open(f"/proc/{pid}/stat", "r") as f:
                            stats = f.read().split()
                            proc_start_time = int(stats[21]) / os.sysconf(os.sysconf_names['SC_CLK_TCK'])
                        
                        uptime = None
                        with open("/proc/uptime", "r") as f:
                            uptime = float(f.read().split()[0])
                        
                        # Calculate how many seconds the process has been running
                        runtime_seconds = uptime - proc_start_time
                        
                        # Skip processes running for less than 5 minutes
                        if runtime_seconds < 300:
                            is_interactive = True
                    except:
                        # If we can't determine runtime, continue with the process
                        pass
                
                # Skip interactive processes
                if is_interactive:
                    continue
                
                # Determine if this is a listening process (port will be set later)
                port = "NOT_LISTENING"
                
                # Build process metadata
                all_processes[process_hash] = {
                    "pid": pid_int,
                    "exe_path": exe_real_path,
                    "process_name": process_name,  # Now correctly parsed
                    "port": port,
                    "user": user,
                    "start_time": start_time,
                    "cmdline": cmdline,
                    "hash": process_hash,
                    "ppid": ppid_int,
                    "lineage": lineage,
                    "is_listening": False,
                    "state": process_state
                }
                
            except Exception as e:
                print(f"[ERROR] Failed to process PID {pid}: {e}")
                continue

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] subprocess error in get_all_processes: {e}")

    return all_processes

def get_process_hash(exe_path, cmdline=None):
    """
    Generate SHA-256 hash of the process executable only.
    This will be used as a unique identifier for process tracking.
    """
    try:
        hash_obj = hashlib.sha256()

        # Hash the executable file if it exists and is accessible
        try:
            if os.path.exists(exe_path) and os.access(exe_path, os.R_OK):
                with open(exe_path, "rb") as f:
                    hash_obj.update(f.read())
            else:
                # If executable can't be accessed, use its path as a fallback
                hash_obj.update(exe_path.encode("utf-8"))
        except (PermissionError, FileNotFoundError):
            # Handle permission issues gracefully
            hash_obj.update(exe_path.encode("utf-8"))

        # No longer include command-line arguments in hashing
        return hash_obj.hexdigest()

    except Exception as e:
        print(f"[ERROR] Failed to hash process {exe_path}: {e}")
        return f"ERROR_HASHING_{exe_path}"

def get_listening_processes():
    """
    Retrieve all listening processes and their metadata.
    This now returns processes identified by hash rather than PID.
    """
    listening_processes = {}
    
    try:
        # Try multiple commands to ensure we catch all listening processes
        commands = [
            "sudo -n /usr/bin/lsof -i -P -n",  # No grep to catch everything
            "sudo -n netstat -tulpn"           # Backup command
        ]
        
        output = ""
        for cmd in commands:
            cmd_output = subprocess.getoutput(cmd)
            if cmd_output:
                output += cmd_output + "\n"
        
        # Track processed PIDs to avoid duplicates
        processed_pids = set()
        
        for line in output.splitlines():
            # Skip header lines and empty lines
            if not line.strip() or "COMMAND" in line or "Proto" in line:
                continue
                
            # Parse based on if this is likely a lsof or netstat line
            pid = None
            process_name = None
            port = None
            
            if "LISTEN" in line or "UDP" in line:
                # This looks like a lsof line
                parts = line.split()
                if len(parts) < 2:
                    continue
                
                # Extract process info from lsof
                if parts[0] and parts[1] and parts[1].isdigit():
                    process_name = parts[0]
                    pid = parts[1]
                
                # Extract port from lsof format
                for part in parts:
                    if ':' in part:
                        port_str = part.split(':')[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            break
            else:
                # This is likely a netstat line
                parts = line.split()
                if len(parts) < 7:
                    continue
                
                # Extract process info from netstat format (PID/Program)
                for part in parts:
                    if '/' in part:
                        pid_parts = part.split('/')
                        if pid_parts[0].isdigit():
                            pid = pid_parts[0]
                            process_name = '/'.join(pid_parts[1:]) if len(pid_parts) > 1 else "UNKNOWN"
                            break
                
                # Extract port from netstat format (Local Address)
                for part in parts:
                    if ':' in part:
                        port_str = part.split(':')[-1]
                        if port_str.isdigit():
                            port = int(port_str)
                            break
            
            # Skip if we couldn't extract the needed info
            if not pid or not pid.isdigit():
                continue
                
            pid_int = int(pid)
            
            # Skip if we've already processed this PID
            if pid_int in processed_pids:
                continue
            
            processed_pids.add(pid_int)
            
            if port is None or not str(port).isdigit():
                port = "UNKNOWN"
            
            # Get executable path and command line
            try:
                exe_path = f"/proc/{pid}/exe"
                exe_real_path = subprocess.getoutput(f"sudo -n /usr/bin/readlink -f {exe_path}").strip()
                
                if "Permission denied" in exe_real_path or not exe_real_path:
                    exe_real_path = "PERMISSION_DENIED"
                    if not process_name:
                        process_name = subprocess.getoutput(f"sudo -n /bin/ps -p {pid} -o comm=").strip()
                
                cmdline_raw = subprocess.getoutput(f"sudo -n /bin/cat /proc/{pid}/cmdline 2>/dev/null").strip()
                cmdline = cmdline_raw.replace("\x00", " ")
                
                if not process_name or process_name == "UNKNOWN":
                    process_name = subprocess.getoutput(f"sudo -n /bin/ps -p {pid} -o comm=").strip()
                
                # Generate hash from executable and command line
                if exe_real_path != "PERMISSION_DENIED":
                    process_hash = get_process_hash(exe_real_path, cmdline)
                else:
                    process_hash = "UNKNOWN_" + get_process_hash(process_name, "")
                
                # Get user, start time, and parent PID
                user = subprocess.getoutput(f"sudo -n /bin/ps -o user= -p {pid}").strip()
                start_time = subprocess.getoutput(f"sudo -n /bin/ps -o lstart= -p {pid}").strip()
                ppid = subprocess.getoutput(f"sudo -n /bin/ps -o ppid= -p {pid}").strip()
                ppid = int(ppid) if ppid.isdigit() else 0
                
                if not user:
                    user = "UNKNOWN"
                
                # Get process lineage
                lineage = resolve_lineage(pid_int)
                
                # Add to listening processes dictionary
                listening_processes[process_hash] = {
                    "pid": pid_int,
                    "exe_path": exe_real_path,
                    "process_name": process_name,
                    "port": port,
                    "user": user,
                    "start_time": start_time,
                    "cmdline": cmdline,
                    "hash": process_hash,
                    "ppid": ppid,
                    "lineage": lineage,
                    "is_listening": True
                }
                
                print(f"[DEBUG] Found listening process: {process_name} (PID: {pid_int}) on port {port}")
                
            except Exception as e:
                print(f"[ERROR] Failed to process listening PID {pid}: {e}")
                continue
    
    except Exception as e:
        print(f"[ERROR] Exception in get_listening_processes: {e}")
        traceback.print_exc()
    
    return listening_processes

def log_pim_event(event_type, process_hash, previous_metadata=None, new_metadata=None):
    """
    Log process monitoring events to the dedicated PIM logging file with enhanced context.
    Includes detailed explanations and MITRE ATT&CK mappings when applicable.
    """
    # Create the basic log entry
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "process_hash": process_hash,
        "previous_metadata": previous_metadata,
        "new_metadata": new_metadata
    }
    
    # Extract details for better logging
    process_name = (new_metadata or previous_metadata or {}).get("process_name", "UNKNOWN")
    pid = (new_metadata or previous_metadata or {}).get("pid", "UNKNOWN")
    exe_path = (new_metadata or previous_metadata or {}).get("exe_path", "UNKNOWN")
    
    # Add context about what changed
    changes_description = ""
    if event_type == "PROCESS_MODIFIED" and previous_metadata and new_metadata:
        # Only include significant fields in the changes description
        significant_fields = ["exe_path", "process_name", "port", "user", "cmdline", "is_listening"]
        
        changed_fields = []
        for field in significant_fields:
            prev_value = previous_metadata.get(field)
            curr_value = new_metadata.get(field)
            if prev_value != curr_value:
                changed_fields.append(f"{field}: {prev_value} → {curr_value}")
        
        if changed_fields:
            changes_description = f"Significant changes detected: {', '.join(changed_fields)}"
            log_entry["changes_description"] = changes_description
    
    # Add MITRE ATT&CK mapping if applicable
    process_info = new_metadata or previous_metadata or {}
    
    # Only get MITRE mapping for significant events, not PID changes
    if event_type != "PROCESS_MODIFIED" or (event_type == "PROCESS_MODIFIED" and changes_description):
        mitre_mapping = classify_by_mitre_attck(event_type, process_info)
        if mitre_mapping:
            log_entry["mitre_mapping"] = mitre_mapping
    
    # Add process lineage information for context
    if new_metadata and "lineage" in new_metadata:
        log_entry["lineage"] = new_metadata.get("lineage", [])
    elif previous_metadata and "lineage" in previous_metadata:
        log_entry["lineage"] = previous_metadata.get("lineage", [])
    
    # Write to the PIM logging file
    try:
        with open(PIM_LOGGING_JSON, "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write to PIM log file: {e}")
    
    # Only print alerts for significant events
    significant_event = (
        event_type in ["NEW_PROCESS", "PROCESS_TERMINATED", "SUSPICIOUS_MEMORY_REGION", "ML_DETECTED_ANOMALY"] or
        (event_type == "PROCESS_MODIFIED" and changes_description)
    )
    
    if significant_event:
        alert_message = f"[ALERT] {event_type}: {process_name} (PID: {pid}, Path: {exe_path})"
        
        # Add changes description if available
        if changes_description:
            alert_message += f"\n  {changes_description}"
        
        # Add MITRE ATT&CK context if available
        if log_entry.get("mitre_mapping") and "techniques" in log_entry["mitre_mapping"]:
            techniques = log_entry["mitre_mapping"]["techniques"]
            if techniques:
                technique_info = techniques[0]  # Get the first technique
                alert_message += f"\n  [MITRE ATT&CK] {technique_info.get('technique_id')}: {technique_info.get('technique_name')} ({technique_info.get('tactic')})"
        
        print(alert_message)

def monitor_processes(interval=2, first_run=False, use_initial_baseline=False):
    """Enhanced monitoring loop that tracks both listening and all other processes."""
    # Load initial baseline if provided
    all_known_processes = INITIAL_BASELINE.copy() if use_initial_baseline and 'INITIAL_BASELINE' in globals() else {}
    
    detection_history = {}
    alerted_processes = set()
    
    # ML baseline establishment phase - separate from core PIM functionality
    ml_model_info = None
    ml_baseline_counter = 0
    ml_baseline_cycles = 300  # 10 minutes (at 2 second intervals)
    establishing_ml_baseline = True
    
    # CRITICAL FIX: If baseline exists, we should NOT be in first_run mode
    # This ensures alerts start immediately when a baseline already exists
    if use_initial_baseline and all_known_processes:
        first_run = False
        print("[INFO] Using existing baseline - immediate alerting enabled")
    
    # Initialize first_iteration based on first_run parameter
    first_iteration = first_run
    
    if establishing_ml_baseline:
        print("[INFO] Starting immediate process monitoring")
        print("[INFO] ML behavioral analysis will begin after 10 minutes of data collection")
    else:
        print("[INFO] Starting process monitoring with ML-based detection...")
    
    # Track the PIDs we've seen as listening
    seen_listening_pids = set()
    
    while True:
        try:
            # Get both listening and all processes
            listening_processes = get_listening_processes()
            
            # Get current listening PIDs
            current_listening_pids = set(info.get("pid") for info in listening_processes.values())
            
            # Find new listening PIDs
            new_listening_pids = current_listening_pids - seen_listening_pids
            if new_listening_pids:
                print(f"[DEBUG] Detected new listening PIDs: {new_listening_pids}")
            
            non_listening_processes = get_all_processes()
            
            # Start with a clean current processes list
            current_all_processes = {}
            
            # Add non-listening processes first
            for process_hash, info in non_listening_processes.items():
                current_all_processes[process_hash] = info
            
            # Then add ALL listening processes, overriding any duplicates
            # This ensures listening processes are properly tracked
            for process_hash, info in listening_processes.items():
                current_all_processes[process_hash] = info
            
            # Identify new processes
            new_processes = {h: info for h, info in current_all_processes.items() 
                            if h not in all_known_processes}
            
            # Identify terminated processes
            terminated_processes = {h: info for h, info in all_known_processes.items() 
                                  if h not in current_all_processes}
            
            # Process events - only log if not in first run mode
            
            # 1. Handle new processes
            for process_hash, info in new_processes.items():
                # Always update tracking
                update_process_tracking(process_hash, info)
                
                # Only log if not in first run mode
                if not first_iteration:
                    # First log it as a new process
                    log_pim_event(
                        event_type="NEW_PROCESS",
                        process_hash=process_hash,
                        previous_metadata=None,
                        new_metadata=info
                    )
                    
                    # If it's a listening process, log that specifically too
                    if info.get("is_listening", False):
                        print(f"[ALERT] NEW LISTENING PROCESS: {info.get('process_name')} (PID: {info.get('pid')}) on port {info.get('port')}")
                        log_pim_event(
                            event_type="NEW_LISTENING_PROCESS",
                            process_hash=process_hash,
                            previous_metadata=None,
                            new_metadata=info
                        )
            
            # 2. Handle terminated processes
            for process_hash, info in terminated_processes.items():
                remove_process_tracking(process_hash)
                
                if not first_iteration:
                    log_pim_event(
                        event_type="PROCESS_TERMINATED",
                        process_hash=process_hash,
                        previous_metadata=info,
                        new_metadata=None
                    )
            
            # 3. Handle modified processes - specifically check for new listening status
            for process_hash, current_info in current_all_processes.items():
                if process_hash in all_known_processes and process_hash not in new_processes:
                    # Skip during first iteration
                    if first_iteration:
                        continue
                    
                    previous_info = all_known_processes[process_hash]
                    
                    # Check if a process started listening
                    was_listening = previous_info.get("is_listening", False)
                    is_listening_now = current_info.get("is_listening", False)
                    
                    if not was_listening and is_listening_now:
                        # Process has started listening on a port
                        print(f"[ALERT] PROCESS STARTED LISTENING: {current_info.get('process_name')} (PID: {current_info.get('pid')}) on port {current_info.get('port')}")
                        log_pim_event(
                            event_type="NEW_LISTENING_PROCESS",
                            process_hash=process_hash,
                            previous_metadata=previous_info,
                            new_metadata=current_info
                        )
                    
                    # Check for other significant changes
                    changes = {}
                    significant_fields = ["exe_path", "process_name", "port", "user", "cmdline"]
                    
                    for field in significant_fields:
                        prev_value = previous_info.get(field)
                        curr_value = current_info.get(field)
                        if prev_value != curr_value:
                            changes[field] = {
                                "previous": prev_value,
                                "current": curr_value
                            }
                    
                    if changes:
                        log_pim_event(
                            event_type="PROCESS_MODIFIED",
                            process_hash=process_hash,
                            previous_metadata=previous_info,
                            new_metadata=current_info
                        )
                        update_process_tracking(process_hash, current_info)
            
            # ML Model Training - Separate from core PIM functionality
            if establishing_ml_baseline:
                # During ML baseline phase, just increment counter while still allowing PIM to operate
                ml_baseline_counter += 1
                
                # Check if we've reached the end of the baseline phase
                if ml_baseline_counter >= ml_baseline_cycles:
                    establishing_ml_baseline = False
                    print("[INFO] ML baseline collection complete (10 minutes). Training model...")
                    
                    # Train ML model only after baseline collection is complete
                    if ML_LIBRARIES_AVAILABLE:
                        ml_model_info = implement_behavioral_baselining()
                        if ml_model_info and ml_model_info.get('model'):
                            print("[INFO] ML model trained successfully. Enabling ML-based anomaly detection.")
                        else:
                            print("[WARNING] Failed to train ML model")
                    else:
                        print("[WARNING] ML libraries not available - anomaly detection disabled")
            
            # ML-based security checks - Only performed after ML baseline established
            # Core PIM functionality continues regardless of ML model status
            if not establishing_ml_baseline and ML_LIBRARIES_AVAILABLE and ml_model_info and ml_model_info.get('model'):
                # Enhanced security checks for active processes
                for process_hash, info in current_all_processes.items():
                    # Skip processes we've already alerted on recently
                    if process_hash in alerted_processes:
                        continue
                    
                    pid = info.get("pid")
                    
                    # Check for security issues
                    detection_events = []
                    
                    # 1. Memory analysis for code injection (prioritize listening processes)
                    if info.get("is_listening", False):
                        suspicious_memory = scan_process_memory(pid)
                        if suspicious_memory:
                            detection_events.append({
                                "event_type": "SUSPICIOUS_MEMORY_REGION",
                                "details": suspicious_memory
                            })
                    
                    # 2. Behavioral pattern detection
                    behavioral_patterns = analyze_process_for_anomalies(pid, info)
                    if behavioral_patterns:
                        detection_events.append({
                            "event_type": "SUSPICIOUS_BEHAVIOR",
                            "details": behavioral_patterns
                        })
                    
                    # 3. ML-based anomaly detection
                    if ml_model_info and ml_model_info.get('model'):
                        # Prepare features
                        process_features = {
                            'port': int(info.get('port', 0)) if isinstance(info.get('port', 0), (int, str)) and str(info.get('port', 0)).isdigit() else 0,
                            'lineage_length': len(info.get('lineage', [])),
                            'cmdline_length': len(info.get('cmdline', '')),
                            'user_is_root': 1 if info.get('user') == 'root' else 0,
                            'child_processes': get_child_process_count(pid),
                            'fd_count': get_open_fd_count(pid)
                        }
                        
                        # Add memory usage
                        mem_usage = get_process_memory_usage(pid)
                        if mem_usage:
                            process_features['memory_usage'] = mem_usage
                        
                        # Create prediction features
                        feature_names = ml_model_info['features']
                        features_for_prediction = {}
                        for feature in feature_names:
                            features_for_prediction[feature] = process_features.get(feature, 0)
                        
                        # Make prediction
                        import pandas as pd
                        prediction = ml_model_info['model'].predict(pd.DataFrame([features_for_prediction]))[0]
                        if prediction == -1:  # Anomaly
                            # Calculate anomaly score
                            anomaly_score = ml_model_info['model'].decision_function(pd.DataFrame([features_for_prediction]))[0]
                            
                            # Only alert on more significant anomalies
                            if anomaly_score < -0.1:  # Threshold to reduce noise
                                detection_events.append({
                                    "event_type": "ML_DETECTED_ANOMALY",
                                    "details": {
                                        "anomaly_score": anomaly_score,
                                        "features": process_features
                                    }
                                })
                    
                    # If we have detection events, log them and analyze
                    if detection_events:
                        # Calculate threat score
                        threat_assessment = calculate_threat_score(info, detection_events)
                        
                        # Add MITRE ATT&CK classification
                        for event in detection_events:
                            mitre_info = classify_by_mitre_attck(event["event_type"], info, event.get("details"))
                            if mitre_info:
                                event["mitre"] = mitre_info
                            
                            # Log the event
                            log_pim_event(
                                event_type=event["event_type"],
                                process_hash=process_hash,
                                previous_metadata=None,
                                new_metadata={
                                    "process_info": info,
                                    "detection_details": event.get("details", {}),
                                    "mitre_mapping": event.get("mitre", {}),
                                    "threat_assessment": threat_assessment
                                }
                            )
                        
                        # Add to detection history and mark as alerted
                        if process_hash not in detection_history:
                            detection_history[process_hash] = []
                        detection_history[process_hash].extend(detection_events)
                        alerted_processes.add(process_hash)
                
                # Periodically clear the alerted_processes set
                if ml_baseline_counter % 60 == 0:
                    print("[INFO] Resetting alert suppression...")
                    alerted_processes.clear()  # Allow processes to trigger alerts again
            
            # CRITICAL FIX: Always set first_iteration to False after first cycle
            # This ensures we don't miss any events after the first run
            first_iteration = False
            
            # Update for next iteration
            all_known_processes = current_all_processes.copy()
            seen_listening_pids.update(current_listening_pids)
            
            # Increment counter regardless of phase
            ml_baseline_counter += 1
            
            time.sleep(interval)
            
        except Exception as e:
            print(f"[ERROR] Exception in enhanced monitoring loop: {e}")
            traceback.print_exc()
            time.sleep(interval)  # Sleep to avoid spinning on errors
            
def create_baseline():
    """Create an initial baseline of all processes without generating alerts or logs."""
    try:
        print("[INFO] Creating initial process baseline...")
        
        # Get current processes
        listening_processes = get_listening_processes()
        all_processes = get_all_processes()
        
        # Merge processes, with listening processes taking precedence
        merged_processes = all_processes.copy()
        for process_hash, info in listening_processes.items():
            merged_processes[process_hash] = info
        
        # Log statistics but not events
        print(f"[INFO] Initial baseline: {len(merged_processes)} total processes, {len(listening_processes)} listening processes")
        
        # Write directly to integrity file without using the functions that log events
        with open(INTEGRITY_PROCESS_FILE, "w") as f:
            json.dump(merged_processes, f, indent=4)
        os.chmod(INTEGRITY_PROCESS_FILE, 0o600)
        
        print(f"[INFO] Successfully wrote baseline to {INTEGRITY_PROCESS_FILE}")
        return True
        
    except Exception as e:
        print(f"[ERROR] Failed to create baseline: {e}")
        traceback.print_exc()
        return False

def resolve_lineage(pid):
    """
    Walks the PPID chain to build the process lineage as a list of process names.
    Enhanced to handle more edge cases and improve reliability.
    """
    lineage = []
    max_depth = 20  # Prevent infinite loops in case of circular references

    try:
        seen_pids = set()
        current_pid = pid
        depth = 0

        while current_pid not in seen_pids and current_pid > 0 and depth < max_depth:
            seen_pids.add(current_pid)
            depth += 1
            
            # Check if the process still exists
            status_path = f"/proc/{current_pid}/status"
            if not os.path.exists(status_path):
                # Try to get info from ps as a fallback
                try:
                    cmd = f"sudo -n /bin/ps -p {current_pid} -o comm= -o ppid="
                    ps_output = subprocess.getoutput(cmd).strip()
                    if ps_output and len(ps_output.split()) >= 2:
                        proc_name, ppid = ps_output.split(None, 1)
                        lineage.insert(0, proc_name)
                        current_pid = int(ppid) if ppid.strip().isdigit() else 0
                        continue
                except Exception:
                    break  # If we can't get info, just end the chain
                break

            # Read from /proc status file
            try:
                with open(status_path, "r") as f:
                    status_content = f.read()
                
                # Extract process name
                name_match = re.search(r"Name:\s+(\S+)", status_content)
                if name_match:
                    name = name_match.group(1)
                    lineage.insert(0, name)
                
                # Extract parent PID
                ppid_match = re.search(r"PPid:\s+(\d+)", status_content)
                if ppid_match:
                    ppid = int(ppid_match.group(1))
                    if ppid == current_pid:  # Self-reference check
                        break
                    current_pid = ppid
                else:
                    break  # No parent found, end of chain
            except Exception as e:
                print(f"[ERROR] Failed to read status for PID {current_pid}: {e}")
                break

    except Exception as e:
        print(f"[ERROR] Failed to resolve lineage for PID {pid}: {e}")
    
    # Add more context to lineage
    if lineage:
        # Mark system init processes specifically
        if lineage[0] in ["systemd", "init"]:
            lineage[0] = f"{lineage[0]}:system"
    
    return lineage

def implement_behavioral_baselining():
    """Implement ML-based behavioral baselining for process activity."""
    from sklearn.ensemble import IsolationForest
    import numpy as np
    import pandas as pd
    
    # Define system processes that should have special treatment
    system_processes = ["systemd", "init", "sshd", "cron", "rsyslogd"]
    
    # Collect historical process behavior data
    processes_data = []
    integrity_state = load_process_metadata()
    
    for process_hash, process in integrity_state.items():
        process_name = process.get("process_name", "")
        pid = process.get("pid", 0)
        
        # Skip system processes in the training data (to prevent them from affecting the model)
        if process_name in system_processes and process_name == "systemd" and pid == 1:
            continue
            
        # Extract features
        try:
            features = {
                'pid': pid,
                'port': int(process.get('port', 0)) if isinstance(process.get('port', 0), (int, str)) and str(process.get('port', 0)).isdigit() else 0,
                'lineage_length': len(process.get('lineage', [])),
                'cmdline_length': len(process.get('cmdline', '')),
                'user_is_root': 1 if process.get('user') == 'root' else 0,
                'child_processes': get_child_process_count(pid) if pid > 0 else 0
            }
            
            # Add memory usage as a feature
            mem_usage = get_process_memory_usage(pid) if pid > 0 else None
            if mem_usage:
                features['memory_usage'] = mem_usage
                
            # Add open file descriptor count
            fd_count = get_open_fd_count(pid) if pid > 0 else None
            if fd_count:
                features['fd_count'] = fd_count
                
            processes_data.append(features)
        except Exception as e:
            print(f"[ERROR] Error extracting features for process {process_name} (Hash: {process_hash}): {e}")
    
    # Return empty model info if not enough data
    if len(processes_data) < 5:
        return {
            'model': None,
            'features': [],
            'system_processes': system_processes
        }
    
    # Create dataframe and train model
    df = pd.DataFrame(processes_data)
    numerical_features = [col for col in df.columns if col != 'pid' and df[col].dtype in [np.int64, np.float64]]
    
    # Train isolation forest
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(df[numerical_features])
    
    # Store model info
    model_info = {
        'model': model,
        'features': numerical_features,
        'system_processes': system_processes
    }
    
    return model_info

def analyze_process_for_anomalies(pid, info):
    """Analyze a process for anomalies using ML techniques."""
    # Skip certain system processes
    if info.get('process_name') == 'systemd' and pid == 1:
        return None
        
    try:
        # Extract features for anomaly detection
        features = {
            'port': int(info.get('port', 0)) if isinstance(info.get('port', 0), (int, str)) and str(info.get('port', 0)).isdigit() else 0,
            'lineage_length': len(info.get('lineage', [])),
            'cmdline_length': len(info.get('cmdline', '')),
            'user_is_root': 1 if info.get('user') == 'root' else 0,
            'child_processes': get_child_process_count(pid),
            'fd_count': get_open_fd_count(pid) 
        }
        
        mem_usage = get_process_memory_usage(pid)
        if mem_usage:
            features['memory_usage'] = mem_usage
            
        # Check for suspicious patterns through lineage
        lineage = info.get('lineage', [])
        shell_in_lineage = any(shell in lineage for shell in ['bash', 'sh', 'dash', 'zsh'])
        unexpected_execution = shell_in_lineage and any(x in info.get('process_name', '').lower() for x in ['apache', 'nginx', 'httpd'])
        
        suspicious_patterns = []
        
        # Check if running from unusual directory
        exe_path = info.get('exe_path', '')
        non_standard_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/", "/dev/", "/mnt/"]
        for unusual_dir in non_standard_dirs:
            if unusual_dir in exe_path:
                suspicious_patterns.append(f"Running from unusual directory: {unusual_dir}")
                break
        
        # REMOVED: Static port check
        # We no longer check for unusual ports based on static values
        
        # Check for unexpected shell in lineage for server process
        if unexpected_execution:
            suspicious_patterns.append(f"Unusual process ancestry for {info.get('process_name')}: includes shell")
        
        # Return results if any suspicious patterns found
        if suspicious_patterns:
            return {
                "suspicious_patterns": suspicious_patterns,
                "features": features
            }
        
        return None
    except Exception as e:
        print(f"[ERROR] Error analyzing process {pid} for anomalies: {e}")
        return None
        
def get_process_memory_usage(pid):
    """Get memory usage of a process in KB."""
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return None

def get_child_process_count(pid):
    """Count child processes of the given PID."""
    try:
        output = subprocess.getoutput(f"ps --ppid {pid} | wc -l")
        return int(output) - 1  # Subtract header line
    except Exception:
        return 0

def get_open_fd_count(pid):
    """Count open file descriptors for a process."""
    try:
        output = subprocess.getoutput(f"ls -l /proc/{pid}/fd 2>/dev/null | wc -l")
        return int(output) - 1  # Subtract total line
    except Exception:
        return 0

def scan_process_memory(pid):
    """Scan process memory for potential code injection using heuristic analysis."""
    suspicious_regions = []
    exe_path = ""
    
    try:
        # Get process executable path for context using sudo
        exe_path = subprocess.getoutput(f"sudo -n readlink -f /proc/{pid}/exe").strip()
        process_name = os.path.basename(exe_path)
        
        # Generate a process hash for logging
        cmdline = subprocess.getoutput(f"sudo -n /bin/cat /proc/{pid}/cmdline 2>/dev/null").strip().replace("\x00", " ")
        process_hash = get_process_hash(exe_path, cmdline)
        
        # Read memory maps using sudo
        maps_content = subprocess.getoutput(f"sudo -n cat /proc/{pid}/maps")
        memory_regions = []
        
        for line in maps_content.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) >= 5:
                addr_range, perms, offset, dev, inode = parts[:5]
                pathname = " ".join(parts[5:]) if len(parts) > 5 else ""
                
                memory_regions.append({
                    'addr_range': addr_range,
                    'perms': perms,
                    'offset': offset,
                    'pathname': pathname,
                    'size_kb': calculate_region_size(addr_range)
                })
        
        # Apply heuristics to detect suspicious memory regions
        for region in memory_regions:
            # Executable anonymous memory is suspicious (common in shellcode injection)
            if 'x' in region['perms'] and ('[heap]' in region['pathname'] or '[stack]' in region['pathname'] or '[anon' in region['pathname'] or region['pathname'] == ''):
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Executable anonymous memory',
                    'severity': 'high'
                })
            
            # RWX memory is highly suspicious and rare in legitimate applications
            elif 'rwx' in region['perms']:
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Memory region with rwx permissions',
                    'severity': 'high'
                })
            
            # Detect large executable allocations that aren't mapped to files
            elif 'x' in region['perms'] and region['pathname'] == '' and region['size_kb'] > 1024:
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Large executable memory allocation',
                    'severity': 'medium'
                })
            
            # Executable memory in typically non-executable regions
            elif 'x' in region['perms'] and any(suspect in region['pathname'] for suspect in ['/tmp/', '/dev/shm/']):
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Executable memory in suspicious location',
                    'severity': 'high'
                })
        
        if suspicious_regions:
            # Log using our hash-based PIM event logging
            log_pim_event(
                event_type="SUSPICIOUS_MEMORY_REGION",
                process_hash=process_hash,
                previous_metadata=None,
                new_metadata={
                    "pid": pid,
                    "process_name": process_name,
                    "exe_path": exe_path,
                    "suspicious_regions": [f"{r['region']['addr_range']} ({r['region']['perms']}) - {r['reason']}" for r in suspicious_regions]
                }
            )
    except Exception as e:
        print(f"[ERROR] Failed to scan memory for PID {pid}: {e}")
    
    return suspicious_regions

def calculate_region_size(addr_range):
    """Calculate size of memory region in KB."""
    try:
        start, end = addr_range.split('-')
        start_addr = int(start, 16)
        end_addr = int(end, 16)
        return (end_addr - start_addr) // 1024
    except Exception:
        return 0

def classify_by_mitre_attck(event_type, process_info, detection_details=None):
    """
    Map detected activities to MITRE ATT&CK techniques with enhanced impersonation detection
    by comparing process attributes to known good processes in the integrity database.
    """
    # Comprehensive built-in MITRE ATT&CK mappings
    mitre_mapping = {
        "NEW_PROCESS": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution"
            }
        ],
        "NEW_LISTENING_PROCESS": [
            {
                "technique_id": "T1571",
                "technique_name": "Non-Standard Port",
                "tactic": "Command and Control"
            },
            {
                "technique_id": "T1543",
                "technique_name": "Create or Modify System Process",
                "tactic": "Persistence"
            }
        ],
        "PROCESS_TERMINATED": [
            {
                "technique_id": "T1562.001",
                "technique_name": "Impair Defenses: Disable or Modify Tools",
                "tactic": "Defense Evasion"
            }
        ],
        "PROCESS_MODIFIED": [
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1112",
                "technique_name": "Modify Registry",
                "tactic": "Defense Evasion"
            }
        ],
        "SUSPICIOUS_MEMORY_REGION": [
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1055.001",
                "technique_name": "Process Injection: Dynamic-link Library Injection",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1055.002",
                "technique_name": "Process Injection: Portable Executable Injection",
                "tactic": "Defense Evasion"
            }
        ],
        "LINEAGE_DEVIATION": [
            {
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1036.005",
                "technique_name": "Masquerading: Match Legitimate Name or Location",
                "tactic": "Defense Evasion"
            }
        ],
        "ML_DETECTED_ANOMALY": [
            {
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution"
            },
            {
                "technique_id": "T1562",
                "technique_name": "Impair Defenses",
                "tactic": "Defense Evasion"
            }
        ],
        "SUSPICIOUS_BEHAVIOR": [
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution"
            },
            {
                "technique_id": "T1053",
                "technique_name": "Scheduled Task/Job",
                "tactic": "Persistence"
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Defense Evasion"
            }
        ],
        "UNUSUAL_PORT_USE": [
            {
                "technique_id": "T1571",
                "technique_name": "Non-Standard Port",
                "tactic": "Command and Control"
            },
            {
                "technique_id": "T1090",
                "technique_name": "Proxy",
                "tactic": "Command and Control"
            }
        ],
        "EXECUTABLE_PATH_MISMATCH": [
            {
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1036.005",
                "technique_name": "Masquerading: Match Legitimate Name or Location",
                "tactic": "Defense Evasion"
            }
        ],
        "HASH_MISMATCH": [
            {
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion"
            }
        ],
        "USER_MISMATCH": [
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "Defense Evasion"
            },
            {
                "technique_id": "T1548",
                "technique_name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation"
            }
        ]
    }
    
    # Context-based classification enhancements
    if not process_info:
        return None
        
    process_name = process_info.get("process_name", "").lower()
    exe_path = process_info.get("exe_path", "").lower()
    cmdline = process_info.get("cmdline", "").lower()
    user = process_info.get("user", "").lower()
    lineage = process_info.get("lineage", [])
    process_hash = process_info.get("hash", "")
    
    # Build contextual insights based on heuristics and patterns
    context_insights = []
    
    # CRITICAL: Check for process impersonation by comparing with known good processes
    # Load the integrity database to check for known good processes
    integrity_database = load_process_metadata()
    
    # 1. Check for process name impersonation (same name but different attributes)
    impersonation_detected = False
    impersonation_details = []
    
    # Get all processes with the same name from the integrity database
    known_good_processes = []
    for hash_key, proc_data in integrity_database.items():
        if proc_data.get("process_name", "").lower() == process_name:
            # Skip if this is the same process (same hash)
            if hash_key == process_hash:
                continue
            known_good_processes.append(proc_data)
    
    # If we found known good processes with the same name, check for impersonation
    if known_good_processes and event_type in ["NEW_PROCESS", "NEW_LISTENING_PROCESS"]:
        # Check each known good process for attribute mismatches
        for good_proc in known_good_processes:
            mismatches = []
            
            # Check executable path
            good_exe_path = good_proc.get("exe_path", "").lower()
            if good_exe_path and exe_path and good_exe_path != exe_path:
                mismatches.append(f"Executable path mismatch: {good_exe_path} vs {exe_path}")
            
            # Check user
            good_user = good_proc.get("user", "").lower()
            if good_user and user and good_user != user:
                mismatches.append(f"User mismatch: {good_user} vs {user}")
            
            # Check lineage pattern (might not be exact match but should follow similar pattern)
            good_lineage = good_proc.get("lineage", [])
            if good_lineage and lineage and len(good_lineage) > 0 and len(lineage) > 0:
                # Simple check - does it follow a different ancestry pattern?
                if (good_lineage[0] != lineage[0] or 
                    ("bash" in lineage and "bash" not in good_lineage) or
                    (len(good_lineage) > 1 and len(lineage) > 1 and good_lineage[1] != lineage[1])):
                    mismatches.append(f"Lineage mismatch: {good_lineage} vs {lineage}")
            
            # If we found mismatches, we have impersonation
            if mismatches:
                impersonation_detected = True
                impersonation_details.extend(mismatches)
    
    # 2. If impersonation detected, add specific MITRE ATT&CK techniques
    if impersonation_detected:
        context_insights.append({
            "technique_id": "T1036",
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion",
            "severity": "high",
            "evidence": f"Process impersonation detected: {process_name} with {'; '.join(impersonation_details)}"
        })
        
        context_insights.append({
            "technique_id": "T1036.005",
            "technique_name": "Masquerading: Match Legitimate Name or Location",
            "tactic": "Defense Evasion",
            "severity": "high",
            "evidence": f"Process masquerading as {process_name} but with different attributes"
        })
        
        # Add specific alert for server process impersonation
        server_processes = ["apache", "apache2", "httpd", "nginx", "sshd", "ftpd", "smbd", "nmbd", "named", "mysqld", "postgres"]
        if any(server in process_name for server in server_processes):
            context_insights.append({
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "severity": "critical",
                "evidence": f"Server process {process_name} being impersonated, possible web shell or backdoor"
            })
    
    # 3. Check for defense evasion - running from temp or unusual directories
    suspicious_dirs = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/home/"]
    if any(susp_dir in exe_path for susp_dir in suspicious_dirs):
        context_insights.append({
            "technique_id": "T1564.001",
            "technique_name": "Hide Artifacts: Hidden Files and Directories",
            "tactic": "Defense Evasion",
            "severity": "medium",
            "evidence": f"Process running from suspicious location: {exe_path}"
        })
    
    # 4. Check for privilege escalation - non-root user binding to privileged port
    port = process_info.get("port", 0)
    if isinstance(port, int) and port < 1024 and user != "root":
        context_insights.append({
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "severity": "high",
            "evidence": f"Non-root user '{user}' binding to privileged port {port}"
        })
    
    # 5. Check for suspicious command line patterns
    suspicious_cmd_patterns = [
        "base64", "-encode", "--decode", "powershell", "eval", "exec", 
        "system(", "shell_exec", "wget", "curl", "nc ", "netcat", "perl -e", "python -c"
    ]
    if any(pattern in cmdline for pattern in suspicious_cmd_patterns):
        context_insights.append({
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "severity": "medium",
            "evidence": f"Suspicious command line pattern detected: {cmdline}"
        })
    
    # 6. Check for server processes spawned by shell (suspicious lineage)
    server_processes = ["apache", "apache2", "httpd", "nginx", "sshd", "ftpd", "smbd", "nmbd", "named", "mysqld", "postgres"]
    if any(server in process_name for server in server_processes) and any(shell in lineage for shell in ["bash", "sh", "zsh", "dash"]):
        context_insights.append({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "severity": "high",
            "evidence": f"Server process '{process_name}' spawned by shell in lineage: {lineage}"
        })
    
    # 7. Check for reverse shells
    if "shell" in cmdline.lower() and any(net_tool in cmdline.lower() for net_tool in ["nc", "netcat", "socat"]):
        context_insights.append({
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "severity": "critical",
            "evidence": f"Potential reverse shell detected: {cmdline}"
        })
    
    # 8. Check for credential access
    if "shadow" in cmdline or "passwd" in cmdline or "/etc/passwd" in cmdline:
        context_insights.append({
            "technique_id": "T1003.008",
            "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "tactic": "Credential Access",
            "severity": "high",
            "evidence": f"Potential credential access attempt: {cmdline}"
        })
    
    # 9. Check for web exploitation tools
    web_exploit_tools = ["sqlmap", "nikto", "burpsuite", "metasploit", "msfconsole", "hydra", "john"]
    if any(tool in process_name.lower() or tool in cmdline.lower() for tool in web_exploit_tools):
        context_insights.append({
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "severity": "high",
            "evidence": f"Web exploitation tool detected: {process_name}"
        })
    
    # 10. Check for specific detection events
    if event_type == "SUSPICIOUS_BEHAVIOR" and detection_details:
        if "suspicious_patterns" in detection_details:
            for pattern in detection_details.get("suspicious_patterns", []):
                pattern_lower = pattern.lower() if isinstance(pattern, str) else ""
                
                if "unusual directory" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1564.001", 
                        "technique_name": "Hide Artifacts: Hidden Files and Directories",
                        "tactic": "Defense Evasion",
                        "severity": "medium",
                        "evidence": pattern
                    })
                
                elif "webshell" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1505.003", 
                        "technique_name": "Server Software Component: Web Shell",
                        "tactic": "Persistence",
                        "severity": "high",
                        "evidence": pattern
                    })
                
                elif "encoded command" in pattern_lower or "base64" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1027", 
                        "technique_name": "Obfuscated Files or Information",
                        "tactic": "Defense Evasion",
                        "severity": "medium",
                        "evidence": pattern
                    })
    
    # Merge base techniques with context-specific insights
    techniques = []
    if event_type in mitre_mapping:
        techniques.extend(mitre_mapping[event_type])
    techniques.extend(context_insights)
    
    # Deduplicate techniques
    unique_techniques = []
    seen_ids = set()
    for technique in techniques:
        if technique["technique_id"] not in seen_ids:
            unique_techniques.append(technique)
            seen_ids.add(technique["technique_id"])
    
    if unique_techniques:
        return {
            "techniques": unique_techniques,
            "evidence": {
                "process_name": process_info.get("process_name", ""),
                "pid": process_info.get("pid", ""),
                "path": process_info.get("exe_path", ""),
                "detection_type": event_type
            }
        }
    
    return None
    
def calculate_threat_score(process_info, detection_events):
    """Calculate a threat score for a process based on its behavior and detections."""
    base_score = 0
    reasons = []
    
    # Process metadata factors
    process_name = process_info.get("process_name", "").lower()
    user = process_info.get("user", "").lower()
    exe_path = process_info.get("exe_path", "").lower()
    port = process_info.get("port", 0)
    lineage = process_info.get("lineage", [])
    
    # 1. Score based on user (root processes get higher baseline)
    if user == "root":
        base_score += 10
        reasons.append("Running as root")
    
    # 2. Score based on process lineage
    suspicious_lineage = False
    for proc in lineage:
        proc_lower = proc.lower()
        if proc_lower in ["bash", "sh", "nc", "netcat", "ncat", "python", "perl", "ruby"]:
            suspicious_lineage = True
            base_score += 15
            reasons.append(f"Suspicious process in lineage: {proc}")
            break
    
    # 3. Score based on execution path
    suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/"]
    for path in suspicious_paths:
        if path in exe_path:
            base_score += 25
            reasons.append(f"Executing from suspicious location: {path}")
            break
    
    # 4. Score based on port
    if isinstance(port, int):
        # Known malicious ports
        malicious_ports = [4444, 1337, 31337, 6667, 6697, 6660, 6665, 6666, 6668, 6669]
        if port in malicious_ports:
            base_score += 30
            reasons.append(f"Listening on known malicious port: {port}")
        # Non-standard high ports (possibly suspicious)
        elif port > 10000 and port not in [27017, 28017, 50070, 50075, 50030, 50060]:
            base_score += 15
            reasons.append(f"Listening on high non-standard port: {port}")
    
    # 5. Score based on detection events
    for event in detection_events:
        event_type = event.get("event_type")
        
        if event_type == "SUSPICIOUS_MEMORY_REGION":
            base_score += 40
            regions = event.get("details", [])
            for region in regions:
                if isinstance(region, dict) and region.get("severity") == "high":
                    base_score += 15  # Extra points for high severity memory issues
            reasons.append("Suspicious memory regions detected")
            
        elif event_type == "ML_DETECTED_ANOMALY":
            # Score based on anomaly score
            details = event.get("details", {})
            anomaly_score = details.get("anomaly_score", 0)
            
            # More severe anomalies get higher scores
            if anomaly_score < -0.5:
                base_score += 35
                reasons.append(f"Severe behavioral anomaly detected (score: {anomaly_score:.2f})")
            elif anomaly_score < -0.2:
                base_score += 20
                reasons.append(f"Moderate behavioral anomaly detected (score: {anomaly_score:.2f})")
            else:
                base_score += 10
                reasons.append(f"Mild behavioral anomaly detected (score: {anomaly_score:.2f})")
                
        elif event_type == "SUSPICIOUS_BEHAVIOR":
            patterns = event.get("details", {}).get("patterns", [])
            if patterns:
                for pattern in patterns:
                    pattern_lower = pattern.lower()
                    
                    if "webshell" in pattern_lower:
                        base_score += 40
                        reasons.append("Potential web shell detected")
                    elif "malicious port" in pattern_lower:
                        base_score += 30
                        reasons.append("Known malicious port detected")
                    elif "encoded command" in pattern_lower:
                        base_score += 35
                        reasons.append("Obfuscated command execution detected")
                    elif "network utility" in pattern_lower:
                        base_score += 25
                        reasons.append("Network utility in unusual context")
                    else:
                        base_score += 15
                        reasons.append(f"Suspicious behavior: {pattern}")
            else:
                # Handle old format or simple pattern
                base_score += 20
                reasons.append("Suspicious behavior detected")
        
        elif event_type == "UNUSUAL_PORT_USE":
            base_score += 20
            reasons.append("Process using unusual port")
            
        elif event_type == "EXECUTABLE_PATH_MISMATCH":
            base_score += 25
            reasons.append("Executable path mismatch")
            
        elif event_type == "HASH_MISMATCH":
            base_score += 30
            reasons.append("Binary hash mismatch")
            
        elif event_type == "USER_MISMATCH":
            base_score += 25
            reasons.append("User mismatch")
            
        elif event_type == "LINEAGE_DEVIATION":
            base_score += 20
            reasons.append("Process lineage deviation")
    
    # 6. Cap and categorize score
    final_score = min(base_score, 100)
    
    # Determine severity category
    if final_score >= 80:
        severity = "critical"
    elif final_score >= 60:
        severity = "high"
    elif final_score >= 40:
        severity = "medium"
    elif final_score >= 20:
        severity = "low"
    else:
        severity = "informational"
    
    return {
        "score": final_score,
        "severity": severity,
        "reasons": reasons
    }
    
def remove_process_tracking(process_hash):
    """
    Remove process metadata from integrity_processes.json using process hash as the key.
    This replaces the previous PID-based approach.
    """
    integrity_state = load_process_metadata()

    if process_hash in integrity_state:
        process_info = integrity_state[process_hash]
        pid = process_info.get("pid", "UNKNOWN")
        process_name = process_info.get("process_name", "UNKNOWN")

        # Remove the process metadata
        del integrity_state[process_hash]
        save_process_metadata(integrity_state)

        print(f"[INFO] Process {process_name} (PID: {pid}, Hash: {process_hash}) removed from tracking.")
        
        # Log the removal event
        log_pim_event(
            event_type="PROCESS_TERMINATED",
            process_hash=process_hash,
            previous_metadata=process_info,
            new_metadata=None
        )
        
        return True
    else:
        print(f"[WARNING] No matching process found for hash: {process_hash}. It may have already been removed.")
        return False

def update_process_tracking(process_hash, metadata):
    """
    Update process tracking with new or modified processes.
    This now uses hash as the primary key instead of PID.
    """
    integrity_state = load_process_metadata()

    # Update the process metadata in our tracking structure using hash as key
    integrity_state[process_hash] = metadata
    
    # Log the event as new or modified based on whether it existed before
    is_new = process_hash not in integrity_state
    event_type = "NEW_PROCESS" if is_new else "PROCESS_UPDATED"
    
    # If this process has a new PID but we've seen this hash before, that's interesting
    old_metadata = integrity_state.get(process_hash)
    if not is_new and old_metadata and old_metadata.get("pid") != metadata.get("pid"):
        print(f"[INFO] Process hash {process_hash} now has PID {metadata.get('pid')}, was previously {old_metadata.get('pid')}")
        
    # Save the updated process metadata
    save_process_metadata(integrity_state)
    
    # Return information about the update for potential logging or alerting
    return {
        "event_type": event_type,
        "process_hash": process_hash,
        "is_new": is_new,
        "metadata": metadata
    }

def stop_daemon():
    """Stop the daemon process cleanly."""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            print(f"[INFO] Stopping daemon process (PID {pid})...")
            
            # Try to send SIGTERM first for graceful shutdown
            os.kill(pid, signal.SIGTERM)
            
            # Wait briefly to let the process clean up
            timeout = 5
            while timeout > 0 and os.path.exists(f"/proc/{pid}"):
                time.sleep(0.5)
                timeout -= 0.5
            
            # If process still exists, force kill
            if os.path.exists(f"/proc/{pid}"):
                print(f"[WARNING] Process did not terminate gracefully, sending SIGKILL...")
                os.kill(pid, signal.SIGKILL)
            
            # Clean up PID file if it still exists
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
                
            print("[INFO] PIM daemon successfully stopped")
        except (ValueError, ProcessLookupError) as e:
            print(f"[WARNING] Process not running or already terminated: {e}")
            # Clean up stale PID file
            os.remove(PID_FILE)
        except Exception as e:
            print(f"[ERROR] Failed to stop daemon: {e}")
    else:
        print("[ERROR] No PID file found. Is the daemon running?")

def run_monitor():
    """Run the process monitoring loop with comprehensive tracking of all processes."""
    try:
        # First, ensure all directories and files exist
        ensure_output_dir()
        
        # Write PID file
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        
        # Register cleanup on normal and signal-based exits
        atexit.register(cleanup_and_exit)
        signal.signal(signal.SIGINT, cleanup_and_exit)
        signal.signal(signal.SIGTERM, cleanup_and_exit)
        
        # Set up logging if in daemon mode
        if "--daemon" in sys.argv:
            sys.stdout = open(LOG_FILE, "a", buffering=1)
            sys.stderr = sys.stdout
        
        # Check if this is the first run (integrity file doesn't exist or is empty)
        if not os.path.exists(INTEGRITY_PROCESS_FILE) or os.path.getsize(INTEGRITY_PROCESS_FILE) <= 3:
            print("[INFO] First run detected - establishing baseline without generating alerts")
            
            # Create baseline directly here
            print("[INFO] Creating initial process baseline...")
            
            # Get current processes
            listening_processes = get_listening_processes()
            all_processes = get_all_processes()
            
            # Merge processes, with listening processes taking precedence
            merged_processes = all_processes.copy()
            for process_hash, info in listening_processes.items():
                merged_processes[process_hash] = info
            
            # Log statistics but not events
            print(f"[INFO] Initial baseline: {len(merged_processes)} total processes, {len(listening_processes)} listening processes")
            
            # Write directly to integrity file without using the functions that log events
            with open(INTEGRITY_PROCESS_FILE, "w") as f:
                json.dump(merged_processes, f, indent=4)
            os.chmod(INTEGRITY_PROCESS_FILE, 0o600)
            
            print("[INFO] Baseline established. Starting monitoring mode...")
            # Wait briefly to ensure file is fully written
            time.sleep(1)
        else:
            print("[INFO] Baseline already exists. Starting in monitoring mode.")
        
        # Store initial baseline for reference
        global INITIAL_BASELINE
        INITIAL_BASELINE = load_process_metadata()
        
        # Set flag to use initial baseline
        use_initial_baseline = True
        
        # Start periodic integrity scan in a separate thread with a delay
        print("[INFO] Waiting for monitoring to initialize before starting integrity scan...")
        integrity_thread = threading.Thread(target=rescan_all_processes, args=(120, use_initial_baseline), daemon=True)
        integrity_thread.start()
        print("[INFO] Started integrity scan thread")
        
        # Run the main monitoring loop with ML baseline establishment phase
        monitor_processes(first_run=False, use_initial_baseline=use_initial_baseline)
        
    except Exception as e:
        print(f"[ERROR] PIM encountered an error: {e}")
        traceback.print_exc()

def rescan_all_processes(interval=120, use_initial_baseline=False):
    """
    Periodically scans all processes (both listening and non-listening) and performs integrity checks.
    This replaces the previous rescan_listening_processes function.
    """
    # Set first_iteration flag based on use_initial_baseline parameter
    first_iteration = use_initial_baseline
    
    if use_initial_baseline:
        print("[INFO] Integrity scan using initial baseline - suppressing alerts for first scan")
        # Wait a longer interval before first scan to ensure monitoring is established
        time.sleep(interval * 2)
    
    while True:
        try:
            if first_iteration:
                print("[PERIODIC SCAN] First run - establishing baseline without generating alerts")
            else:
                print("[PERIODIC SCAN] Running integrity check on all processes...")

            # Load current tracking state
            integrity_state = load_process_metadata()
            
            # Get current processes
            listening_processes = get_listening_processes()
            all_processes = get_all_processes()
            
            # Merge processes, with listening processes taking precedence
            current_processes = all_processes.copy()
            for process_hash, info in listening_processes.items():
                current_processes[process_hash] = info
            
            # Only check for dead processes if not in first run mode
            if not first_iteration:
                # Check for processes in our tracking that no longer exist
                terminated_processes = {}
                for process_hash, stored_info in integrity_state.items():
                    if process_hash not in current_processes:
                        terminated_processes[process_hash] = stored_info
                        log_pim_event(
                            event_type="PROCESS_TERMINATED",
                            process_hash=process_hash,
                            previous_metadata=stored_info,
                            new_metadata=None
                        )
                        remove_process_tracking(process_hash)
            
                # Check for modifications in existing processes
                for process_hash, current_info in current_processes.items():
                    if process_hash in integrity_state:
                        stored_info = integrity_state[process_hash]
                        
                        # Check for significant metadata changes (ignore pid/ppid changes)
                        changes = {}
                        
                        # Fields to check for significant changes
                        significant_fields = ["exe_path", "process_name", "port", "user", "cmdline", "is_listening"]
                        
                        for field in significant_fields:
                            stored_value = stored_info.get(field)
                            current_value = current_info.get(field)
                            if stored_value != current_value:
                                changes[field] = {
                                    "previous": stored_value,
                                    "current": current_value
                                }
                        
                        # Log changes if any were found
                        if changes:
                            log_pim_event(
                                event_type="PROCESS_MODIFIED",
                                process_hash=process_hash,
                                previous_metadata=stored_info,
                                new_metadata=current_info
                            )
                            
                            # Update the stored metadata
                            update_process_tracking(process_hash, current_info)
                    
                    else:
                        # New process found during scan that wasn't in our tracking
                        log_pim_event(
                            event_type="NEW_UNTRACKED_PROCESS",
                            process_hash=process_hash,
                            previous_metadata=None,
                            new_metadata=current_info
                        )
                        
                        # Add to tracking
                        update_process_tracking(process_hash, current_info)
            else:
                # During first run, just update all processes without alerts
                for process_hash, info in current_processes.items():
                    update_process_tracking(process_hash, info)
            
            # Clear first_iteration flag after the first run
            first_iteration = False
            
            time.sleep(interval)
            
        except Exception as e:
            print(f"[ERROR] Exception in periodic scan: {e}")
            traceback.print_exc()
            time.sleep(interval)  # Still sleep to avoid spinning on errors

def cleanup_and_exit(signum=None, frame=None):
    """Cleanup tasks before exiting. Updated to reflect our revised approach."""
    try:
        # Save any pending changes to process integrity state
        integrity_state = load_process_metadata()
        if integrity_state:
            print(f"[INFO] Saving integrity state for {len(integrity_state)} processes")
            save_process_metadata(integrity_state)
        
        # Remove PID file
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            print(f"[INFO] Cleaned up PID file: {PID_FILE}")
        
        print("[INFO] PIM shutdown complete")
    except Exception as e:
        print(f"[ERROR] Failed during cleanup: {e}")

    # Only call sys.exit if triggered by a signal (i.e., not atexit)
    if signum is not None:
        sys.exit(0)

def print_help():
    help_text = """
Process Integrity Monitor (PIM) - Help Menu

Usage:
  python pim               Start the PIM monitoring service in foreground mode
  python pim -s or stop    Stop the PIM service if running in background (daemon) mode
  python pim restart       Restart the PIM monitoring service
  python pim -d or daemon  Run PIM in background (daemon) mode
  python pim help          Show this help message

Description:
  The Process Integrity Monitor continuously monitors ALL system processes for:
    - New or terminated processes
    - Process modifications (user, command line, etc.)
    - Suspicious memory regions (e.g., shellcode injection)
    - Anomalous behavior using machine learning
    - Classification of suspicious activity using MITRE ATT&CK framework

Note:
  Use the `-d` option to run PIM in background mode (daemon).
  This is recommended for long-term monitoring.
"""
    print(help_text.strip())

if __name__ == "__main__":
    ensure_output_dir()
    
    parser = argparse.ArgumentParser(description="Process Integrity Monitor (PIM)", add_help=False)
    parser.add_argument("-d", "--daemon", action="store_true", help="Run PIM in daemon mode")
    parser.add_argument("-s", "--stop", action="store_true", help="Stop PIM daemon")
    parser.add_argument("command", nargs="?", default=None)

    args = parser.parse_args()
    cmd = args.command

    if cmd == "help":
        print_help()
        sys.exit(0)

    elif args.stop or cmd == "stop":
        stop_daemon()

    elif args.daemon or cmd == "daemon":
        print("[INFO] Running PIM in daemon mode with comprehensive process monitoring...")
        try:
            with daemon.DaemonContext(
                working_directory=os.getcwd(),
                stdout=open(LOG_FILE, "a+", buffering=1),
                stderr=open(LOG_FILE, "a+", buffering=1),
                detach_process=True,
                umask=0o027
            ):
                run_monitor()
        except Exception as e:
            print(f"[ERROR] Failed to start in daemon mode: {e}")
            traceback.print_exc()

    elif cmd == "restart":
        stop_daemon()
        time.sleep(1)
        print("[INFO] Restarting PIM in daemon mode with comprehensive process monitoring...")
        try:
            with daemon.DaemonContext(
                working_directory=os.getcwd(),
                stdout=open(LOG_FILE, "a+", buffering=1),
                stderr=open(LOG_FILE, "a+", buffering=1),
                detach_process=True,
                umask=0o027
            ):
                run_monitor()
        except Exception as e:
            print(f"[ERROR] Failed to restart in daemon mode: {e}")
            traceback.print_exc()

    else:
        print("[INFO] Running PIM in foreground mode with comprehensive process monitoring...")
        run_monitor()
