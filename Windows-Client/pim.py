# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution (Windows Version)
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
import threading
import traceback
import logging
import ctypes
import re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Windows-specific imports
import win32api
import win32con
import win32service
import win32serviceutil
import win32security
import win32file
import win32event
import win32process
import win32pdh
import wmi
import psutil
import signal

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries not found. ML-based detection disabled.")
    ML_LIBRARIES_AVAILABLE = False

BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
FILE_MONITOR_JSON = os.path.join(LOG_DIR, "file_monitor.json")

SERVICE_RUNNING = True
MEMORY_SCAN_ENABLED = True
MEMORY_SCAN_FAILURES = 0
MAX_MEMORY_SCAN_FAILURES = 10
PROCESS_DLL_BASELINE = {}

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logging.error(f"Error checking admin status: {e}")
        return False

def ensure_directories():
    """Create all necessary directories for the application."""
    directories = [BASE_DIR, OUTPUT_DIR, LOG_DIR]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            logging.debug(f"Ensured directory exists: {directory}")
        except Exception as e:
            logging.error(f"Failed to create directory {directory}: {e}")
            
def set_secure_permissions(file_path):
    """Apply secure permissions to a file (admin and system only)."""
    try:
        sd = win32security.GetFileSecurity(
            file_path, 
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()
        
        # Get SIDs for Administrators and SYSTEM
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        # Use proper access rights constants
        # GENERIC_ALL gives full control
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, system_sid)
        
        # Apply the ACL
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            file_path, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
        logging.debug(f"Secured file: {file_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to set secure permissions on {file_path}: {e}")
        return False

def ensure_file_exists(file_path, default_content="", is_json=False):
    """Ensure a file exists with proper permissions, creating it if necessary."""
    directory = os.path.dirname(file_path)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            if is_json:
                if isinstance(default_content, str):
                    json.dump({}, f, indent=4)
                else:
                    json.dump(default_content, f, indent=4)
                
        set_secure_permissions(file_path)
        logging.debug(f"Created and secured file: {file_path}")
    return True

def get_process_hash(exe_path, cmdline=None, include_cmdline=False):
    """Generate SHA-256 hash of the process executable and optionally include cmdline."""
    try:
        # Check if the file exists first
        if not os.path.exists(exe_path):
            logging.error(f"File not found: {exe_path}")
            return "ERROR_FILE_NOT_FOUND"
            
        hash_obj = hashlib.sha256()

        # First try standard file opening
        try:
            with open(exe_path, "rb") as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
        except PermissionError:
            # Try with Windows API for system files with sharing enabled
            try:
                handle = win32file.CreateFile(
                    exe_path,
                    win32file.GENERIC_READ,
                    win32file.FILE_SHARE_READ,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                
                try:
                    # Read the file in chunks
                    file_size = win32file.GetFileSize(handle)
                    chunks_read = 0
                    buffer_size = 1024 * 1024  # 1MB buffer
                    
                    while chunks_read < file_size:
                        bytes_to_read = min(buffer_size, file_size - chunks_read)
                        hr, data = win32file.ReadFile(handle, bytes_to_read)
                        hash_obj.update(data)
                        chunks_read += len(data)
                        
                finally:
                    win32file.CloseHandle(handle)
            except Exception as e:
                logging.error(f"Windows API file access failed for {exe_path}: {e}")
                return "ERROR_HASHING_PERMISSION"

        # Only include command-line arguments in hashing if explicitly requested
        # This should typically be False for process identity tracking!
        if include_cmdline and cmdline and isinstance(cmdline, str):
            # Instead of using raw cmdline which can contain variable data,
            # use the simplified pattern that strips out dynamic elements
            cmdline_pattern = simplify_command_line(cmdline)
            hash_obj.update(cmdline_pattern.encode("utf-8"))

        return hash_obj.hexdigest()

    except FileNotFoundError:
        logging.error(f"File not found: {exe_path}")
        return "ERROR_FILE_NOT_FOUND"
    except Exception as e:
        logging.error(f"Failed to hash {exe_path}: {e}")
        return "ERROR_HASHING_UNKNOWN"

def load_process_metadata():
    """Load stored process metadata from integrity_processes.json."""
    if os.path.exists(INTEGRITY_PROCESS_FILE):
        try:
            with open(INTEGRITY_PROCESS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error in integrity_processes.json: {e}")
            return {}
        except Exception as e:
            logging.error(f"Error loading process metadata: {e}")
            return {}
    return {}

def update_process_tracking(exe_path, process_hash, process_info):
    """Update process tracking files with new or modified processes, using hash as primary key."""
    # Load existing data
    integrity_state = load_process_metadata()

    # Use hash as the primary key instead of PID
    if process_hash != "ERROR_HASHING_PERMISSION" and process_hash != "ERROR_FILE_NOT_FOUND":
        # Store metadata by hash
        integrity_state[process_hash] = process_info

    # --- Begin Process Group Tracking Enhancement ---
    process_name = process_info.get("process_name", "")
    cmdline = process_info.get("cmdline", "")
    lineage = process_info.get("lineage", [])
    
    # Skip invalid processes
    if process_hash in ["ERROR_HASHING_PERMISSION", "ERROR_FILE_NOT_FOUND"] or not process_name:
        # Save updates for the individual process
        success = save_process_metadata(integrity_state)
        return success
    
    # Create a unique identifier for the process group based on path & name
    process_group_id = f"{exe_path}|{process_name}".lower()
    
    # Check if we have a groups section
    if "process_groups" not in integrity_state:
        integrity_state["process_groups"] = {}
    
    # Initialize the group if it's new
    if process_group_id not in integrity_state["process_groups"]:
        integrity_state["process_groups"][process_group_id] = {
            "exe_path": exe_path,
            "process_name": process_name,
            "known_hashes": {},
            "common_lineage_patterns": [],
            "command_line_patterns": []
        }
    
    # Get the group
    process_group = integrity_state["process_groups"][process_group_id]
    
    # Add this hash to the known hashes with timestamp
    hash_entry = {
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "detection_count": 1
    }
    
    # Update hash record if it already exists
    if process_hash in process_group["known_hashes"]:
        hash_entry = process_group["known_hashes"][process_hash]
        hash_entry["last_seen"] = datetime.now().isoformat()
        hash_entry["detection_count"] += 1
    
    process_group["known_hashes"][process_hash] = hash_entry
    
    # Extract command line pattern
    if cmdline:
        cmd_pattern = simplify_command_line(cmdline)
        if cmd_pattern and cmd_pattern not in process_group["command_line_patterns"]:
            # Special handling for Chrome and other browsers to avoid pattern explosion
            browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"]
            is_browser = process_name.lower() in [b.lower() for b in browser_processes]
            
            if is_browser:
                # For browsers, limit the number of command line patterns
                # to avoid excessive patterns from different tabs/extensions
                if len(process_group["command_line_patterns"]) < 30:
                    process_group["command_line_patterns"].append(cmd_pattern)
                else:
                    # For browsers, only replace patterns if this is significantly different
                    # Find the most similar pattern to potentially replace
                    most_similar_idx = -1
                    most_similar_score = 0
                    
                    for i, pattern in enumerate(process_group["command_line_patterns"]):
                        # Simple similarity score - count of common words
                        common_words = len(set(pattern.split()).intersection(set(cmd_pattern.split())))
                        if common_words > most_similar_score:
                            most_similar_score = common_words
                            most_similar_idx = i
                    
                    # Replace if significantly different from all existing patterns
                    if most_similar_score < 5 and most_similar_idx >= 0:
                        process_group["command_line_patterns"][most_similar_idx] = cmd_pattern
            else:
                # For non-browser processes, just add the pattern
                process_group["command_line_patterns"].append(cmd_pattern)
    
    # Update lineage patterns - use existing check_lineage_baseline for comparison
    if lineage:
        # Create temporary process info and state for checking
        lineage_matched = False
        
        for pattern in process_group["common_lineage_patterns"]:
            temp_proc_info = {"process_name": process_name, "lineage": lineage}
            temp_state = {"temp_key": {"process_name": process_name, "lineage": pattern}}
            
            if check_lineage_baseline(temp_proc_info, temp_state, allow_flexible_match=True):
                lineage_matched = True
                break
                
        if not lineage_matched:
            # Special handling for browser processes to avoid pattern explosion
            browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"]
            is_browser = process_name.lower() in [b.lower() for b in browser_processes]
            
            if is_browser:
                # For browsers, limit the number of lineage patterns
                if len(process_group["common_lineage_patterns"]) < 10:
                    process_group["common_lineage_patterns"].append(lineage)
            else:
                # For non-browser processes, just add the pattern
                process_group["common_lineage_patterns"].append(lineage)
    # --- End Process Group Tracking Enhancement ---

    # Save updates
    success = save_process_metadata(integrity_state)
    return success

def simplify_command_line(cmdline):
    """
    Convert a command line to a simplified pattern by removing variable parts
    like process IDs, timestamps, and UUIDs, but keeping the structure.
    """
    if not cmdline:
        return ""
    
    # Extract the basic command structure
    parts = cmdline.split()
    if not parts:
        return ""
    
    # Keep the executable and option flags, replace variable values with placeholders
    pattern_parts = []
    for part in parts:
        # If it's a flag, keep it exactly
        if part.startswith("--") or part.startswith("-"):
            pattern_parts.append(part)
        # If it has an equals sign, keep the parameter name but replace the value
        elif "=" in part:
            param_name, param_value = part.split("=", 1)
            pattern_parts.append(f"{param_name}=*")
        # If it looks like a number, UUID, or timestamp, replace with placeholder
        elif re.match(r'^[0-9]+$', part) or re.match(r'^[0-9a-f-]{36}$', part):
            continue  # Skip numeric IDs and UUIDs
        # If it's a file path, keep just the extension
        elif part.endswith(".exe") or part.endswith(".dll"):
            pattern_parts.append("*" + os.path.splitext(part)[1])
        else:
            pattern_parts.append(part)
    
    return " ".join(pattern_parts)

def check_process_group_legitimacy(process_info, integrity_state):
    """
    Check if a process is legitimate based on process group tracking.
    This specifically looks at:
    1. If the hash is known for this process group
    2. If the command line pattern matches known patterns
    
    Returns a list of alerts, empty if no issues found.
    """
    alerts = []
    
    # Skip if process_groups tracking not enabled
    if "process_groups" not in integrity_state:
        return alerts
    
    # Get process information
    exe_path = process_info.get("exe_path", "")
    process_name = process_info.get("process_name", "")
    process_hash = process_info.get("hash", "")
    cmdline = process_info.get("cmdline", "")
    
    # Skip invalid processes
    if not exe_path or not process_name or not process_hash:
        return alerts
    
    # Create process group ID
    process_group_id = f"{exe_path}|{process_name}".lower()
    
    # If we haven't seen this process group before, it's new but not necessarily illegitimate
    if process_group_id not in integrity_state["process_groups"]:
        return alerts  # No alerts for new process groups
    
    # Get the process group
    process_group = integrity_state["process_groups"][process_group_id]
    
    # Check if hash is known
    if process_hash not in process_group["known_hashes"]:
        # New hash for a known process - could be an update or tampering
        if os.path.exists(exe_path):
            # The file exists - likely an update
            alerts.append({
                "type": "NEW_PROCESS_HASH",
                "details": {
                    "process": process_name,
                    "exe_path": exe_path,
                    "hash": process_hash,
                    "severity": "medium",
                    "description": f"New hash detected for known process {process_name}"
                }
            })
        else:
            # The file doesn't exist but claims to be from this path - highly suspicious
            alerts.append({
                "type": "HASH_MISMATCH_MISSING_FILE",
                "details": {
                    "process": process_name,
                    "exe_path": exe_path,
                    "hash": process_hash,
                    "severity": "high",
                    "description": f"Process {process_name} claims to be from {exe_path} but file doesn't exist"
                }
            })
    
    # Check command line pattern
    if "command_line_patterns" in process_group and cmdline:
        cmd_pattern = simplify_command_line(cmdline)
        if cmd_pattern and cmd_pattern not in process_group["command_line_patterns"]:
            alerts.append({
                "type": "UNUSUAL_COMMAND_LINE",
                "details": {
                    "process": process_name,
                    "exe_path": exe_path,
                    "command_pattern": cmd_pattern,
                    "severity": "medium",
                    "description": f"Process {process_name} launched with unusual command line pattern"
                }
            })
    
    return alerts

def remove_process_tracking(pid, process_hash=None):
    """Remove process metadata from integrity_processes.json."""
    integrity_state = load_process_metadata()

    # Find the hash if not provided
    if not process_hash:
        # Search through integrity state to find entry with matching PID
        process_hash = None
        for hash_key, proc_data in integrity_state.items():
            if proc_data.get("pid") == pid:
                process_hash = hash_key
                break
        
        if not process_hash:
            logging.warning(f"No matching process found for PID: {pid}")
            return False

    if process_hash in integrity_state:
        process_info = integrity_state[process_hash]
        proc_name = process_info.get("process_name", "UNKNOWN")

        # Remove the process metadata
        del integrity_state[process_hash]
        success = save_process_metadata(integrity_state)

        logging.info(f"Process with hash {process_hash} removed from tracking")
        return success
    else:
        logging.warning(f"No matching process found for hash: {process_hash}")
        return False

def resolve_lineage(pid):
    """Walk the parent process chain to build the process lineage."""
    lineage = []
    
    try:
        seen_pids = set()
        current_pid = pid
        
        while current_pid and current_pid not in seen_pids and current_pid > 0:
            seen_pids.add(current_pid)
            
            try:
                process = psutil.Process(current_pid)
                process_name = process.name()
                
                # Insert at beginning to maintain ancestry order (root ? leaf)
                lineage.insert(0, process_name)
                
                # Get parent PID
                parent_pid = process.ppid()
                
                # Break if we've reached the System process or a loop
                if parent_pid == 0 or parent_pid == 4 or parent_pid == current_pid:
                    break
                
                current_pid = parent_pid
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.debug(f"Could not access process {current_pid}: {e}")
                break
    
    except Exception as e:
        logging.error(f"Failed to resolve lineage for PID {pid}: {e}")
    
    return lineage

def check_lineage_baseline(process_info, integrity_state, allow_flexible_match=True):
    """
    Check if a process's lineage matches the baseline, using integrity_state.
    Enhanced to support flexible matching for multi-process applications.
    
    Args:
        process_info: Dictionary containing process metadata including lineage
        integrity_state: The loaded integrity state with process tracking data
        allow_flexible_match: Whether to allow partial matches for improved accuracy
        
    Returns:
        True if lineage is valid, False if significant deviation detected
    """
    proc_name = process_info["process_name"]
    lineage = process_info.get("lineage", [])

    if not lineage:
        return False

    # Find baseline lineage from existing processes
    baseline = None
    for hash_key, existing_proc in integrity_state.items():
        # Skip process_groups entry if it exists
        if hash_key == "process_groups":
            continue
            
        if existing_proc.get("process_name") == proc_name and existing_proc.get("lineage"):
            # Found a matching process name with established lineage
            baseline = existing_proc.get("lineage")
            break

    if not baseline:
        # First time seeing this process - return true (no deviation)
        logging.info(f"Baseline lineage established for {proc_name}: {lineage}")
        return True
    
    # Original exact matching behavior
    if lineage == baseline:
        return True
        
    # Enhanced flexible matching if enabled
    if allow_flexible_match:
        # Only check if we have enough data
        if not lineage or not baseline:
            return False
        
        # Allow similar length
        if abs(len(lineage) - len(baseline)) > 1:  # Off-by-one difference
            # Length too different - likely significant deviation
            logging.warning(f"Lineage length mismatch for {proc_name}:")
            logging.warning(f"  Expected: {baseline}")
            logging.warning(f"  Found:    {lineage}")
            return False
        
        # Get the minimum length to compare
        min_length = min(len(lineage), len(baseline))
        
        # Check key processes (first processes in lineage are most important)
        # Check for process similarity considering service hosting variances
        for i in range(min_length):
            if lineage[i].lower() != baseline[i].lower():
                # Special case for service host processes
                if "svchost.exe" in lineage[i].lower() and "svchost.exe" in baseline[i].lower():
                    continue
                elif "services.exe" in lineage[i].lower() and "services.exe" in baseline[i].lower():
                    continue
                elif "explorer.exe" in lineage[i].lower() and "explorer.exe" in baseline[i].lower():
                    continue
                # Special case for browser sub-processes
                elif any(b in lineage[i].lower() and b in baseline[i].lower() 
                       for b in ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"]):
                    continue
                # Special case for System vs Windows processes
                elif lineage[i].lower() in ["system", "smss.exe", "wininit.exe"] and baseline[i].lower() in ["system", "smss.exe", "wininit.exe"]:
                    continue
                
                # Different process in important position - significant mismatch
                logging.warning(f"Lineage deviation for {proc_name}:")
                logging.warning(f"  Expected: {baseline}")
                logging.warning(f"  Found:    {lineage}")
                return False
        
        # If we got here, core lineage matches
        return True
    
    # If flexible matching is disabled and exact match failed, report deviation
    logging.warning(f"Lineage deviation for {proc_name}:")
    logging.warning(f"  Expected: {baseline}")
    logging.warning(f"  Found:    {lineage}")
    return False

def check_for_unusual_port_use(process_info, integrity_state):
    """Check if a process is listening on a non-standard port using integrity_state."""
    alerts = []
    if not integrity_state:
        return alerts  # Return empty list if no baseline
        
    proc_name = process_info.get("process_name", "UNKNOWN")
    proc_port = process_info.get("port")
    
    # Skip if port is invalid
    if proc_port is None:
        return alerts
    
    # Convert port to integer safely
    try:
        proc_port = int(proc_port) if isinstance(proc_port, (int, str)) else 0
    except (ValueError, TypeError):
        return alerts  # Invalid port, return empty alerts
    
    # Skip if port is 0
    if proc_port <= 0:
        return alerts
    
    # Find existing ports for this process name
    expected_ports = []
    baseline_metadata = None
    
    for hash_key, existing_proc in integrity_state.items():
        # Skip process_groups entry or non-dict items
        if hash_key == "process_groups" or not isinstance(existing_proc, dict):
            continue
            
        if existing_proc.get("process_name") == proc_name:
            # Get port safely
            port = existing_proc.get("port")
            if port:
                try:
                    port_int = int(port) if isinstance(port, (int, str)) else 0
                    if port_int > 0 and port_int not in expected_ports:
                        expected_ports.append(port_int)
                except (ValueError, TypeError):
                    continue  # Skip invalid port values
            
            # Use the first match as baseline metadata
            if baseline_metadata is None:
                baseline_metadata = existing_proc
    
    # Add port mismatch alert if applicable
    if expected_ports and proc_port not in expected_ports:
        alerts.append({
            "type": "UNUSUAL_PORT_USE",
            "details": {
                "process": proc_name,
                "expected_ports": expected_ports,
                "port": proc_port  # Use 'port' instead of 'actual_port'
            }
        })
    
    # Check for other metadata mismatches if we have a baseline
    if baseline_metadata:
        if baseline_metadata.get("exe_path") != process_info.get("exe_path"):
            alerts.append({
                "type": "EXECUTABLE_PATH_MISMATCH",
                "details": {
                    "process": proc_name,
                    "expected_path": baseline_metadata.get("exe_path"),
                    "actual_path": process_info.get("exe_path")
                }
            })
        
        if (baseline_metadata.get("hash") != process_info.get("hash") and 
            not baseline_metadata.get("hash", "").startswith("ERROR") and
            not process_info.get("hash", "").startswith("ERROR")):
            alerts.append({
                "type": "HASH_MISMATCH",
                "details": {
                    "process": proc_name,
                    "expected_hash": baseline_metadata.get("hash"),
                    "actual_hash": process_info.get("hash")
                }
            })
        
        if baseline_metadata.get("user") != process_info.get("user"):
            alerts.append({
                "type": "USER_MISMATCH",
                "details": {
                    "process": proc_name,
                    "expected_user": baseline_metadata.get("user"),
                    "actual_user": process_info.get("user")
                }
            })
            
    return alerts

def get_listening_processes():
    """Get detailed information about all listening processes, excluding outbound connections."""
    listening_processes = {}

    try:
        # Use netstat to get processes listening on TCP ports
        # The -a option shows all connections and listening ports
        # The -n option shows addresses and port numbers in numerical form
        # The -o option shows the owning process ID
        # The -p TCP filters to only show TCP connections
        netstat_output = subprocess.check_output("netstat -ano -p TCP", shell=True, text=True)
        
        # Build a map of PID to port
        pid_to_ports = {}
        
        for line in netstat_output.splitlines():
            # Only include lines with LISTENING state
            if "LISTENING" not in line:
                continue
                
            parts = line.strip().split()
            if len(parts) < 5:
                continue
                
            # Extract local address and PID
            local_address = parts[1]
            try:
                pid = int(parts[4])
            except ValueError:
                continue
            
            # Extract port number
            try:
                port = int(local_address.split(":")[-1])
                if pid not in pid_to_ports:
                    pid_to_ports[pid] = []
                pid_to_ports[pid].append(port)
            except (IndexError, ValueError):
                continue
        
        # Get process details for each listening PID
        for pid, ports in pid_to_ports.items():
            try:
                proc = psutil.Process(pid)
                
                # Get basic process info
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, FileNotFoundError):
                    exe_path = "ACCESS_DENIED"
                
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = "ACCESS_DENIED"
                
                try:
                    start_time = time.strftime('%Y-%m-%d %H:%M:%S', 
                                             time.localtime(proc.create_time()))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    start_time = "UNKNOWN"
                
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "UNKNOWN"
                
                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = "UNKNOWN"
                
                # Get process hash
                if exe_path != "ACCESS_DENIED" and os.path.exists(exe_path):
                    process_hash = get_process_hash(exe_path, cmdline)
                else:
                    process_hash = "ACCESS_DENIED"
                
                # Get process lineage
                lineage = resolve_lineage(pid)
                
                # Store info for each port - only for listening ports
                for port in ports:
                    process_key = f"{pid}:{port}"
                    listening_processes[process_key] = {
                        "pid": pid,
                        "exe_path": exe_path,
                        "process_name": os.path.basename(exe_path) if exe_path != "ACCESS_DENIED" else "UNKNOWN",
                        "port": port,
                        "user": username,
                        "start_time": start_time,
                        "cmdline": cmdline,
                        "hash": process_hash,
                        "ppid": ppid,
                        "lineage": lineage
                    }
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.error(f"Failed to get information for PID {pid}: {e}")
    
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute netstat command: {e}")
    
    return listening_processes

def get_process_memory_info(pid):
    """Get detailed memory information for a process."""
    memory_info = {
        "total_memory_kb": 0,
        "working_set_kb": 0,
        "private_bytes_kb": 0,
        "regions": []
    }
    
    try:
        process = psutil.Process(pid)
        mem = process.memory_info()
        memory_info["working_set_kb"] = mem.rss // 1024
        memory_info["private_bytes_kb"] = mem.private // 1024
        memory_info["total_memory_kb"] = memory_info["working_set_kb"]
        
        # For getting detailed memory regions, we need admin rights and WinAPI
        if is_admin():
            memory_regions = enumerate_process_memory_regions(pid)
            memory_info["regions"] = memory_regions
            
    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        logging.error(f"Failed to get memory info for PID {pid}: {e}")
    
    return memory_info

def enumerate_process_memory_regions(pid):
    """Enumerate memory regions for a process to detect potential code injection."""
    regions = []
    
    if not is_admin():
        logging.warning("Administrator privileges required for memory region enumeration")
        return regions
        
    try:
        # Get handle to process with memory read rights
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        
        # Try opening the process
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )
        
        if not handle:
            error_code = ctypes.windll.kernel32.GetLastError()
            logging.error(f"Failed to open process {pid}: {error_code}")
            return regions
            
        try:
            # Define memory region structure
            class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_ulonglong),
                    ("AllocationBase", ctypes.c_ulonglong),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("__alignment1", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_ulonglong),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong),
                    ("__alignment2", ctypes.c_ulong)
                ]
            
            # Memory constants
            PAGE_NOACCESS = 0x01
            PAGE_READONLY = 0x02
            PAGE_READWRITE = 0x04
            PAGE_WRITECOPY = 0x08
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40
            PAGE_EXECUTE_WRITECOPY = 0x80
            
            # Memory state constants
            MEM_COMMIT = 0x1000
            MEM_FREE = 0x10000
            MEM_RESERVE = 0x2000
            
            # Memory type constants
            MEM_IMAGE = 0x1000000
            MEM_MAPPED = 0x40000
            MEM_PRIVATE = 0x20000
            
            # Process memory from start to end
            address = ctypes.c_ulonglong(0)
            mbi = MEMORY_BASIC_INFORMATION64()
            
            # Set up query parameters
            max_regions = 100  # Limit the number of regions to check
            region_count = 0
            
            # Safely handle potential overflow
            try:
                while region_count < max_regions:
                    result = ctypes.windll.kernel32.VirtualQueryEx(
                        handle,
                        ctypes.c_ulonglong(address.value).value,
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )
                    
                    # Break if we reached the end or encountered an error
                    if result == 0:
                        break
                    
                    region_count += 1
                    
                    # Only look at committed memory
                    if mbi.State == MEM_COMMIT:
                        # Determine permissions
                        is_executable = bool(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                        is_writable = bool(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | 
                                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                        is_readable = bool(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | 
                                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                        
                        # Determine type
                        region_type = "Unknown"
                        if mbi.Type == MEM_IMAGE:
                            region_type = "Image"
                        elif mbi.Type == MEM_MAPPED:
                            region_type = "Mapped"
                        elif mbi.Type == MEM_PRIVATE:
                            region_type = "Private"
                        
                        # Store region info using hex strings for addresses
                        try:
                            regions.append({
                                "address": f"0x{mbi.BaseAddress:X}",
                                "size_kb": mbi.RegionSize // 1024,
                                "protection": {
                                    "executable": is_executable,
                                    "writable": is_writable,
                                    "readable": is_readable
                                },
                                "type": region_type,
                                "allocation_base": f"0x{mbi.AllocationBase:X}" if mbi.AllocationBase else "0x0"
                            })
                        except Exception as e:
                            logging.debug(f"Error handling memory region data: {e}")
                            continue
                    
                    # Move to next region safely
                    try:
                        if mbi.RegionSize > 0:
                            new_address = address.value + mbi.RegionSize
                            if new_address <= address.value:  # Overflow detection
                                break
                            address.value = new_address
                        else:
                            # If region size is 0, we might be stuck in a loop
                            break
                    except OverflowError:
                        logging.debug(f"Address overflow in memory enumeration at 0x{address.value:X}")
                        break
                    except Exception as e:
                        logging.debug(f"Error advancing memory address: {e}")
                        break
            
            except OverflowError as e:
                logging.debug(f"Overflow in memory enumeration: {e}")
            except Exception as e:
                logging.error(f"Error in memory region enumeration loop: {e}")
        
        finally:
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
    
    except Exception as e:
        logging.error(f"Error setting up memory enumeration for PID {pid}: {e}")
    
    return regions

def scan_process_memory(pid, process_info=None):
    """Scan process memory for potential code injection or malicious behaviors."""
    # Skip memory scanning for system processes and known problematic applications
    if process_info:
        process_name = process_info.get("process_name", "").lower()
        user = process_info.get("user", "").lower()
        exe_path = process_info.get("exe_path", "").lower()
        
        # Skip scanning for system critical processes to reduce errors
        system_critical = ["svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", 
                           "wininit.exe", "services.exe", "winlogon.exe"]
                         
        # Skip system services and processes with known scanning issues
        if ((process_name in system_critical and "authority" in user.lower()) or
            "gamemanager" in process_name or
            "razer" in exe_path or
            process_name == "services.exe" or
            "\\razer\\" in exe_path.lower()):
            logging.debug(f"Skipping memory scan for protected or problematic process: {process_name} (PID: {pid})")
            return []
    
    if not is_admin():
        logging.debug("Administrator privileges required for memory scanning")
        return []
        
    suspicious_regions = []
    
    try:
        memory_regions = enumerate_process_memory_regions(pid)
        
        # Cap the number of suspicious regions to avoid overwhelming the logs
        if memory_regions and len(memory_regions) > 100:
            logging.debug(f"Large number of memory regions ({len(memory_regions)}) found for PID {pid}, limiting analysis")
            memory_regions = memory_regions[:100]  # Analyze only the first 100 regions
        
        process_name = process_info.get("process_name", "unknown") if process_info else "unknown"
        
        # Look for suspicious memory patterns
        for region in memory_regions:
            # Executable private memory (often used for shellcode)
            if region["protection"]["executable"] and region["type"] == "Private" and region["size_kb"] > 4:
                suspicious_regions.append({
                    "region": region,
                    "reason": "Executable private memory",
                    "severity": "medium"
                })
            
            # RWX memory is highly suspicious
            if region["protection"]["executable"] and region["protection"]["writable"] and region["type"] == "Private":
                suspicious_regions.append({
                    "region": region,
                    "reason": "Memory with RWX permissions",
                    "severity": "high"
                })
            
            # Large executable allocations that aren't mapped to a DLL
            if region["protection"]["executable"] and region["type"] == "Private" and region["size_kb"] > 1024:
                suspicious_regions.append({
                    "region": region, 
                    "reason": "Large executable memory allocation",
                    "severity": "medium"
                })
                
        # Additional advanced threat detection
        if process_info:
            # 1. Process Hollowing Detection
            hollowing_indicators = detect_process_hollowing(pid, process_info)
            if hollowing_indicators:
                for indicator in hollowing_indicators:
                    suspicious_regions.append({
                        "region": indicator.get("region", {}),
                        "reason": f"Process Hollowing: {indicator.get('indicator')}",
                        "details": indicator.get("description", ""),
                        "severity": indicator.get("severity", "high"),
                        "technique": "PROCESS_HOLLOWING"
                    })
                    
            # 2. Reflective DLL Injection Detection
            reflective_dll_indicators = detect_reflective_dll_injection(pid, process_info)
            if reflective_dll_indicators:
                for indicator in reflective_dll_indicators:
                    suspicious_regions.append({
                        "region": indicator.get("region", {}),
                        "reason": f"Reflective DLL Injection: {indicator.get('indicator')}",
                        "details": indicator.get("description", ""),
                        "severity": indicator.get("severity", "high"),
                        "technique": "REFLECTIVE_DLL_INJECTION"
                    })
                    
            # 3. Thread Execution Hijacking Detection
            thread_hijacking_indicators = detect_thread_hijacking(pid, process_info)
            if thread_hijacking_indicators:
                for indicator in thread_hijacking_indicators:
                    suspicious_regions.append({
                        "region": indicator.get("region", {}),
                        "reason": f"Thread Hijacking: {indicator.get('indicator')}",
                        "details": indicator.get("description", ""),
                        "severity": indicator.get("severity", "medium"),
                        "technique": "THREAD_HIJACKING"
                    })
                    
            # 4. DLL Search Order Hijacking Detection
            dll_hijacking_indicators = detect_dll_search_order_hijacking(pid, process_info)
            if dll_hijacking_indicators:
                for indicator in dll_hijacking_indicators:
                    suspicious_regions.append({
                        "region": {"dll_path": indicator.get("dll_path", "")},
                        "reason": f"DLL Search Order Hijacking: {indicator.get('indicator')}",
                        "details": indicator.get("description", ""),
                        "severity": indicator.get("severity", "high"),
                        "technique": "DLL_SEARCH_ORDER_HIJACKING"
                    })
        
        if suspicious_regions:
            # Cap the number of reported suspicious regions
            if len(suspicious_regions) > 10:
                logging.warning(f"Found {len(suspicious_regions)} suspicious memory regions in PID {pid} ({process_name}), reporting first 10")
                suspicious_regions = suspicious_regions[:10]
            else:
                logging.warning(f"Found {len(suspicious_regions)} suspicious memory regions in PID {pid} ({process_name})")
            
            # Log MITRE ATT&CK information for each detection
            for region in suspicious_regions:
                if "technique" in region:
                    mitre_info = classify_by_mitre_attck(region["technique"], process_info)
                    if mitre_info:
                        techniques = mitre_info.get("techniques", [])
                        if techniques:
                            technique_ids = [t.get("technique_id") for t in techniques]
                            region["mitre_techniques"] = technique_ids
                    
                    # Log to FIM system
                    log_event_to_pim(
                        event_type=region["technique"],
                        file_path=process_info.get("exe_path", ""),
                        previous_metadata=None,
                        new_metadata={
                            "pid": pid,
                            "process_name": process_name,
                            "detection": region.get("reason"),
                            "details": region.get("details"),
                            "severity": region.get("severity"),
                            "mitre_techniques": region.get("mitre_techniques", [])
                        },
                        previous_hash=None,
                        new_hash=process_info.get("hash", "")
                    )
            
    except Exception as e:
        logging.error(f"Error scanning memory for PID {pid}: {e}")
        
    return suspicious_regions

def get_process_stats(pid):
    """Get detailed statistics about a process for enhanced behavioral analysis."""
    stats = {
        "memory_usage_kb": 0,
        "cpu_percent": 0,
        "handle_count": 0,
        "thread_count": 0,
        "child_process_count": 0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
        "connection_count": 0,
        "working_set_size_kb": 0,
        "virtual_memory_kb": 0,
        "page_faults": 0,
        "peak_memory_kb": 0,
        "thread_details": [],
        "cpu_times": {"user": 0, "system": 0, "idle": 0},
        "active_window_count": 0,
        "uptime_seconds": 0,
        "memory_percent": 0
    }
    
    try:
        process = psutil.Process(pid)
        
        # CPU and memory stats with retries for better reliability
        for _ in range(2):  # Try twice to get a better CPU sample
            try:
                stats["cpu_percent"] = process.cpu_percent(interval=0.1)
                if stats["cpu_percent"] > 0:  # If we got a valid reading, stop
                    break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                break
            
        # Get detailed memory info
        try:
            mem_info = process.memory_info()
            stats["memory_usage_kb"] = mem_info.rss // 1024
            stats["working_set_size_kb"] = mem_info.rss // 1024
            stats["virtual_memory_kb"] = mem_info.vms // 1024
            # Use memory_full_info if available for more details
            try:
                mem_full = process.memory_full_info()
                stats["peak_memory_kb"] = getattr(mem_full, 'peak', 0) // 1024
                stats["page_faults"] = getattr(mem_full, 'num_page_faults', 0)
            except (psutil.AccessDenied, AttributeError):
                pass
            # Calculate percentage of system memory
            stats["memory_percent"] = process.memory_percent()
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            pass
        
        # Resource usage
        try:
            stats["handle_count"] = process.num_handles() if hasattr(process, 'num_handles') else 0
        except (psutil.AccessDenied, AttributeError):
            pass
            
        # Thread details with error handling
        try:
            threads = process.threads()
            stats["thread_count"] = len(threads)
            
            # Collect thread creation times and CPU usage for anomaly detection
            thread_details = []
            for thread in threads[:10]:  # Limit to first 10 threads to avoid overhead
                thread_details.append({
                    "id": thread.id,
                    "user_time": thread.user_time,
                    "system_time": thread.system_time
                })
            stats["thread_details"] = thread_details
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            # Fallback thread count method
            try:
                stats["thread_count"] = process.num_threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        
        # Child processes
        try:
            stats["child_process_count"] = len(process.children())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # IO stats with error handling
        try:
            io_counters = process.io_counters()
            stats["io_read_bytes"] = io_counters.read_bytes
            stats["io_write_bytes"] = io_counters.write_bytes
        except (psutil.AccessDenied, AttributeError):
            pass
        
        # Network connections with better error handling
        try:
            # Use net_connections() with proper timeout
            connections = []
            try:
                connections = process.net_connections(kind='all')
            except psutil.AccessDenied:
                # Try with just inet connections if all fails
                try:
                    connections = process.net_connections(kind='inet')
                except:
                    pass
            
            stats["connection_count"] = len(connections)
            
            # Enhanced network stats: count by connection status
            status_counts = {"ESTABLISHED": 0, "LISTEN": 0, "CLOSE_WAIT": 0, "TIME_WAIT": 0, "NONE": 0}
            
            for conn in connections:
                status = conn.status if hasattr(conn, 'status') else "NONE"
                if status in status_counts:
                    status_counts[status] += 1
                else:
                    status_counts["NONE"] += 1
            
            stats["connection_statuses"] = status_counts
            
        except (psutil.AccessDenied, AttributeError, psutil.NoSuchProcess) as e:
            logging.debug(f"Could not get network connections for PID {pid}: {e}")
        
        # CPU times (user/system/idle)
        try:
            cpu_times = process.cpu_times()
            stats["cpu_times"] = {
                "user": cpu_times.user,
                "system": cpu_times.system,
                "idle": 0  # Not directly available per process
            }
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # Calculate process uptime
        try:
            stats["uptime_seconds"] = time.time() - process.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
            
        # Windows-specific: try to get UI window count for GUI processes
        try:
            import ctypes
            EnumWindows = ctypes.windll.user32.EnumWindows
            EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_int))
            GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
            
            windows = []
            
            def enum_windows_callback(hwnd, lParam):
                window_pid = ctypes.c_int()
                GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
                if window_pid.value == pid:
                    windows.append(hwnd)
                return True
                
            EnumWindows(EnumWindowsProc(enum_windows_callback), 0)
            stats["active_window_count"] = len(windows)
        except:
            # Silently fail for non-Windows platforms or if the import fails
            pass
            
    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        logging.debug(f"Could not get complete stats for PID {pid}: {e}")
        
    return stats

def load_config():
    """Load configuration from fim.config file."""
    config_path = os.path.join(BASE_DIR, "fim.config")
    default_config = {
        "exclusions": {
            "directories": [],
            "files": [],
            "processes": []
        }
    }
    
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
                
                # Ensure exclusions section exists
                if "exclusions" not in config:
                    config["exclusions"] = default_config["exclusions"]
                
                return config
        else:
            # Create default config if it doesn't exist
            safe_write_json(config_path, default_config)
            return default_config
    except Exception as e:
        logging.error(f"Failed to load config file: {e}")
        return default_config

def is_process_whitelisted(process_name, process_path):
    """Check if a process is in the whitelist or exclusions based on configuration."""
    # Check config file exclusions
    try:
        config = load_config()
        excluded_processes = config.get("exclusions", {}).get("processes", [])
        
        # Check for direct process name match
        if process_name.lower() in [p.lower() for p in excluded_processes]:
            logging.debug(f"Process {process_name} found in process exclusions list")
            return True
        
        # Check if the process path is in excluded directories
        excluded_dirs = config.get("exclusions", {}).get("directories", [])
        for dir_path in excluded_dirs:
            if process_path.lower().startswith(dir_path.lower()):
                logging.debug(f"Process {process_name} found in excluded directory: {dir_path}")
                return True
        
        # Check if the process executable is in excluded files
        excluded_files = config.get("exclusions", {}).get("files", [])
        if process_path.lower() in [f.lower() for f in excluded_files]:
            logging.debug(f"Process {process_name} found in excluded files list")
            return True
            
    except Exception as e:
        logging.error(f"Error checking process exclusions: {e}")
    
    return False

def analyze_process_behavior(pid, process_info):
    """
    Analyze a process for suspicious behavior patterns using enhanced detection methods.
    Returns a list of detected suspicious behaviors with confidence levels and MITRE ATT&CK mappings.
    """
    suspicious_patterns = []
    
    try:
        # Get process metadata
        process_name = process_info.get("process_name", "").lower()
        exe_path = process_info.get("exe_path", "").lower()
        
        # Define special system processes that should be excluded from analysis
        special_system_processes = [
            "registry", "memcompression", "vmmem", "secure system", 
            "system", "idle", "memory compression"
        ]
        
        # Skip system processes and special Windows processes
        if process_name in special_system_processes or pid <= 4 or process_info.get("is_system_process", False):
            return []
            
        # Skip whitelisted processes
        if is_process_whitelisted(process_name, exe_path):
            logging.debug(f"Skipping whitelisted process: {process_name} ({exe_path})")
            return []
            
        # Get process lineage and other metadata
        lineage = process_info.get("lineage", [])
        cmdline = process_info.get("cmdline", "").lower()
        port = process_info.get("port", 0)
        user = process_info.get("user", "").lower()
        
        # Get enhanced process stats
        process_stats = get_process_stats(pid)
        
        # Create a behavior detection context to track confidence levels
        detection_context = {
            "process_name": process_name,
            "exe_path": exe_path,
            "pid": pid,
            "detections": {},
            "total_score": 0
        }
        
        # 1. Command shell in lineage of server processes - now with confidence levels
        shell_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe']
        server_processes = ['w3wp', 'httpd', 'tomcat', 'nginx', 'iis', 'apache', 'mysql', 'sqlservr']
        
        shell_in_lineage = any(shell.lower() in [p.lower() for p in lineage] for shell in shell_processes)
        server_process = any(server in process_name for server in server_processes)
        
        if shell_in_lineage and server_process:
            # Calculate a confidence score based on position in lineage
            shell_positions = []
            for i, proc in enumerate(lineage):
                if any(shell.lower() in proc.lower() for shell in shell_processes):
                    shell_positions.append(i)
            
            # Shells closer to the process are more suspicious
            if shell_positions:
                pos_score = 1.0 - (min(shell_positions) / max(1, len(lineage)))
                confidence = 0.7 + (pos_score * 0.3)  # 70-100% confidence
                
                detection = {
                    "type": "unusual_process_ancestry",
                    "description": f"Unusual process ancestry: command shell in lineage of web server",
                    "evidence": lineage,
                    "confidence": confidence,
                    "severity": "high",
                    "mitre_techniques": ["T1059", "T1059.003"]
                }
                
                suspicious_patterns.append(f"Unusual process ancestry: command shell in lineage of web server (confidence: {confidence:.1%})")
                detection_context["detections"]["unusual_process_ancestry"] = detection
                detection_context["total_score"] += confidence
        
        # 2. Executing from suspicious locations - enhanced with risk weighting
        suspicious_dirs = {
            "\\temp\\": 0.8,
            "\\windows\\temp\\": 0.85,
            "\\appdata\\local\\temp\\": 0.75,
            "\\programdata\\temp\\": 0.8,
            "\\users\\public\\": 0.7,
            "\\downloads\\": 0.6,
            "\\recycle": 0.9
        }
        
        # Check each suspicious directory with weighted confidence
        for suspect_dir, base_confidence in suspicious_dirs.items():
            if suspect_dir in exe_path:
                # Adjust confidence based on process type
                adjusted_confidence = base_confidence
                
                # Certain processes legitimately run from temp (installers, etc.)
                if "install" in process_name or "setup" in process_name:
                    adjusted_confidence *= 0.5  # Reduce confidence for installers
                
                # System processes in temp are more suspicious
                if "svchost" in process_name or "lsass" in process_name or "winlogon" in process_name:
                    adjusted_confidence = min(0.95, adjusted_confidence * 1.5)  # Increase confidence, max 95%
                
                detection = {
                    "type": "suspicious_location",
                    "description": f"Executing from suspicious location: {suspect_dir}",
                    "evidence": exe_path,
                    "confidence": adjusted_confidence,
                    "severity": "medium" if adjusted_confidence < 0.8 else "high",
                    "mitre_techniques": ["T1036", "T1574"]
                }
                
                suspicious_patterns.append(f"Executing from suspicious location: {suspect_dir} (confidence: {adjusted_confidence:.1%})")
                detection_context["detections"]["suspicious_location"] = detection
                detection_context["total_score"] += adjusted_confidence
                break  # Only report the most suspicious directory match
        
        # 3. Advanced port analysis using statistical risk assessment
        common_high_ports = [8080, 8443, 3000, 3001, 5000, 5001, 8000, 8008, 8888, 27017]
        
        known_malicious_ports = {
            4444: 0.9,    # Metasploit default
            1337: 0.8,    # Common hacker port
            6666: 0.85,   # Common backdoor
            6667: 0.7,    # IRC (often used in botnets)
            31337: 0.85,  # Elite speak, historical backdoor port
            12345: 0.75,  # NetBus backdoor
            54321: 0.75   # Reverse NetBus
        }
        
        # Port risk bands based on statistical analysis
        ephemeral_ports = range(49152, 65536)  # Official IANA ephemeral port range
        
        if isinstance(port, int) and port > 0:
            # Check known malicious port first
            if port in known_malicious_ports:
                confidence = known_malicious_ports[port]
                detection = {
                    "type": "known_malicious_port",
                    "description": f"Listening on known malicious port: {port}",
                    "evidence": f"Port {port}",
                    "confidence": confidence,
                    "severity": "high",
                    "mitre_techniques": ["T1571"]
                }
                
                suspicious_patterns.append(f"Listening on known malicious port: {port} (confidence: {confidence:.1%})")
                detection_context["detections"]["known_malicious_port"] = detection
                detection_context["total_score"] += confidence
            
            # Check for unusual high port (if not already flagged as malicious)
            elif port > 1024 and port not in common_high_ports and port not in ephemeral_ports:
                # Calculate confidence based on port range
                port_confidence = 0.0
                
                if port < 10000:
                    port_confidence = 0.6  # Ports 1025-9999, medium confidence
                elif port >= 10000 and port < 20000:
                    port_confidence = 0.4  # Ports 10000-19999, lower confidence
                else:
                    port_confidence = 0.3  # Ports 20000+, lowest confidence
                
                # Adjust for process type - some processes commonly use custom ports
                if any(p in process_name for p in ["java", "tomcat", "node", "mongodb", "elastic"]):
                    port_confidence *= 0.5  # Reduce confidence
                
                if port_confidence > 0.2:  # Only report if confidence is high enough
                    detection = {
                        "type": "unusual_port",
                        "description": f"Listening on unusual port: {port}",
                        "evidence": f"Port {port}",
                        "confidence": port_confidence,
                        "severity": "medium" if port_confidence < 0.5 else "high",
                        "mitre_techniques": ["T1571"]
                    }
                    
                    suspicious_patterns.append(f"Listening on unusual port: {port} (confidence: {port_confidence:.1%})")
                    detection_context["detections"]["unusual_port"] = detection
                    detection_context["total_score"] += port_confidence
        
        # 4. Enhanced process relationship analysis
        # Windows-specific process relationship checks
        if "services.exe" not in lineage and process_name == "svchost.exe":
            confidence = 0.85  # Very suspicious
            
            detection = {
                "type": "service_ancestry_violation",
                "description": "svchost.exe running without services.exe as ancestor",
                "evidence": lineage,
                "confidence": confidence,
                "severity": "critical",
                "mitre_techniques": ["T1036"]
            }
            
            suspicious_patterns.append(f"svchost.exe running without services.exe as ancestor (confidence: {confidence:.1%})")
            detection_context["detections"]["service_ancestry_violation"] = detection
            detection_context["total_score"] += confidence
        
        # 5. Advanced PowerShell encoded command analysis
        if "powershell" in process_name or "powershell" in cmdline:
            encoded_cmd_confidence = 0.0
            encoded_indicators = {
                "-encodedcommand": 0.8,
                "-enc ": 0.75,
                "-e ": 0.6,  # Lower confidence due to ambiguity
                "frombase64string": 0.85,
                "convert::frombase64": 0.85,
                "iex(new-object": 0.9  # PowerShell download cradle pattern
            }
            
            # Look for the most suspicious encoded command pattern
            for indicator, conf in encoded_indicators.items():
                if indicator in cmdline:
                    if conf > encoded_cmd_confidence:
                        encoded_cmd_confidence = conf
            
            if encoded_cmd_confidence > 0:
                # Calculate encoded command length to adjust confidence
                # Longer encoded commands are more suspicious
                enc_pattern = re.compile(r'(?:-e|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)')
                matches = enc_pattern.findall(cmdline)
                
                if matches:
                    longest_enc = max(matches, key=len)
                    # Adjust confidence based on encoded length
                    if len(longest_enc) > 500:
                        encoded_cmd_confidence = min(0.95, encoded_cmd_confidence * 1.2)
                
                detection = {
                    "type": "powershell_encoded_command",
                    "description": "PowerShell with encoded command detected",
                    "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                    "confidence": encoded_cmd_confidence,
                    "severity": "high",
                    "mitre_techniques": ["T1059.001", "T1027"]
                }
                
                suspicious_patterns.append(f"PowerShell with encoded command detected (confidence: {encoded_cmd_confidence:.1%})")
                detection_context["detections"]["powershell_encoded_command"] = detection
                detection_context["total_score"] += encoded_cmd_confidence
        
        # 6. Advanced Living Off The Land Binaries (LOLBins) detection
        lolbins = {
            "certutil.exe": {
                "patterns": ["/urlcache", "/verifyctl", "/decode"],
                "base_confidence": 0.7,
                "context_boost": {"http": 0.2, "https": 0.2, "decode": 0.15}
            },
            "regsvr32.exe": {
                "patterns": ["scrobj.dll", "/i:", "/u", "/s"],
                "base_confidence": 0.75,
                "context_boost": {"http": 0.2, "scrobj.dll": 0.15}
            },
            "mshta.exe": {
                "patterns": ["javascript:", "vbscript:", ".hta"],
                "base_confidence": 0.8,
                "context_boost": {"http": 0.2, "temp": 0.1}
            },
            "rundll32.exe": {
                "patterns": ["advpack.dll", "setupapi.dll", "shdocvw.dll", "javascript:"],
                "base_confidence": 0.7,
                "context_boost": {"http": 0.2, "javascript": 0.2}
            },
            "msiexec.exe": {
                "patterns": ["/y", "/z"],
                "base_confidence": 0.5,
                "context_boost": {"http": 0.3, "https": 0.3}
            },
            "installutil.exe": {
                "patterns": ["/logfile=", "/u"],
                "base_confidence": 0.7,
                "context_boost": {"/u": 0.2}
            },
            "regasm.exe": {
                "patterns": ["/quiet"],
                "base_confidence": 0.7,
                "context_boost": {}
            },
            "regedt32.exe": {
                "patterns": ["/i"],
                "base_confidence": 0.65,
                "context_boost": {}
            },
            "wmic.exe": {
                "patterns": ["process call create", "shadowcopy"],
                "base_confidence": 0.7,
                "context_boost": {"process": 0.1, "call": 0.1, "create": 0.1}
            },
            "bitsadmin.exe": {
                "patterns": ["/transfer", "/addfile", "/download"],
                "base_confidence": 0.8,
                "context_boost": {"http": 0.1, "https": 0.1}
            }
        }
        
        for lolbin, config in lolbins.items():
            if lolbin.lower() == process_name.lower():
                # Check for suspicious flags with enhanced pattern recognition
                for flag in config["patterns"]:
                    if flag.lower() in cmdline.lower():
                        # Start with base confidence
                        lolbin_confidence = config["base_confidence"]
                        
                        # Check for context boosters that make this more suspicious
                        for context, boost in config["context_boost"].items():
                            if context.lower() in cmdline.lower():
                                lolbin_confidence += boost
                        
                        # Cap at 95% confidence
                        lolbin_confidence = min(0.95, lolbin_confidence)
                        
                        detection = {
                            "type": "lolbin_abuse",
                            "description": f"Potential LOLBin abuse: {lolbin} with {flag}",
                            "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                            "confidence": lolbin_confidence,
                            "severity": "high",
                            "mitre_techniques": ["T1218"]
                        }
                        
                        suspicious_patterns.append(f"Potential LOLBin abuse: {lolbin} with {flag} (confidence: {lolbin_confidence:.1%})")
                        detection_context["detections"]["lolbin_abuse"] = detection
                        detection_context["total_score"] += lolbin_confidence
                        break  # Only report the first matching flag
                    
        # 7. Enhanced parent-child relationship analysis using statistical approach
        unusual_parents = {
            "lsass.exe": {
                "suspicious_parents": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
                "base_confidence": 0.85
            },
            "svchost.exe": {
                "suspicious_parents": ["cmd.exe", "powershell.exe", "rundll32.exe"],
                "base_confidence": 0.8
            },
            "csrss.exe": {
                "suspicious_parents": ["cmd.exe", "powershell.exe", "explorer.exe"],
                "base_confidence": 0.9
            },
            "winlogon.exe": {
                "suspicious_parents": ["cmd.exe", "powershell.exe", "rundll32.exe"],
                "base_confidence": 0.9
            }
        }
        
        for child, parent_config in unusual_parents.items():
            if process_name.lower() == child.lower() and lineage:
                suspicious_parents = parent_config["suspicious_parents"]
                if any(parent.lower() in lineage[0].lower() for parent in suspicious_parents):
                    # Base confidence from configuration
                    parent_confidence = parent_config["base_confidence"]
                    
                    # Additional detection for unusual parent PID
                    try:
                        ppid = int(process_info.get("ppid", 0))
                        # If PPID is suspiciously low or a user-mode PID for a system process
                        if ppid > 0 and ppid < 10 and child.lower() in ["lsass.exe", "csrss.exe", "winlogon.exe"]:
                            parent_confidence = min(0.95, parent_confidence + 0.1)
                    except (ValueError, TypeError):
                        pass
                    
                    detection = {
                        "type": "unusual_parent_process",
                        "description": f"Unusual parent process {lineage[0]} for {child}",
                        "evidence": f"Process lineage: {' -> '.join(lineage)}",
                        "confidence": parent_confidence,
                        "severity": "high",
                        "mitre_techniques": ["T1036", "T1055"]
                    }
                    
                    suspicious_patterns.append(f"Unusual parent process {lineage[0]} for {child} (confidence: {parent_confidence:.1%})")
                    detection_context["detections"]["unusual_parent_process"] = detection
                    detection_context["total_score"] += parent_confidence
        
        # 8. Enhanced resource usage analysis with process type context
        if process_stats["cpu_percent"] > 80:
            # High CPU usage might be normal for some processes but suspicious for others
            cpu_confidence = 0.0
            
            # System processes with high CPU are suspicious
            if process_name in ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe"]:
                cpu_confidence = 0.7
            # Background services with high CPU might be suspicious
            elif "service" in cmdline.lower() or process_name.endswith("d.exe") or process_name.endswith("srv.exe"):
                cpu_confidence = 0.5
            # Known CPU-intensive apps
            elif any(app in process_name.lower() for app in ["chrome", "firefox", "video", "game", "compiler", "build"]):
                cpu_confidence = 0.1  # Low confidence - likely legitimate
            # Default case - medium suspicion
            else:
                cpu_confidence = 0.3
            
            # Only report if confidence is high enough
            if cpu_confidence >= 0.5:
                detection = {
                    "type": "high_cpu_usage",
                    "description": f"Unusually high CPU usage ({process_stats['cpu_percent']}%) for {process_name}",
                    "evidence": f"CPU: {process_stats['cpu_percent']}%",
                    "confidence": cpu_confidence,
                    "severity": "medium",
                    "mitre_techniques": ["T1496"]
                }
                
                suspicious_patterns.append(f"Unusually high CPU usage ({process_stats['cpu_percent']}%) for {process_name} (confidence: {cpu_confidence:.1%})")
                detection_context["detections"]["high_cpu_usage"] = detection
                detection_context["total_score"] += cpu_confidence
        
        # 9. Advanced connection count analysis with process classification
        if process_stats["connection_count"] > 20:
            conn_confidence = 0.0
            
            # Check if this is expected to be a network-heavy process
            network_intensive = any(net in process_name.lower() for net in 
                                 ["iis", "apache", "nginx", "w3wp", "httpd", "tomcat", 
                                  "browser", "chrome", "firefox", "edge", "opera", "safari"])
            
            if process_stats["connection_count"] > 50:
                if network_intensive:
                    # High connections for network processes might be normal
                    if process_stats["connection_count"] > 200:
                        conn_confidence = 0.4  # Even for network processes, extremely high counts are suspicious
                    else:
                        conn_confidence = 0.2  # Lower confidence for network-intensive processes
                else:
                    # High connection count for non-network process is very suspicious
                    conn_confidence = 0.7
                    
                    # Even more suspicious if a system process
                    if process_name in ["svchost.exe", "lsass.exe", "csrss.exe"]:
                        conn_confidence = 0.85
            elif process_stats["connection_count"] > 20:
                # Medium connection count
                if not network_intensive:
                    conn_confidence = 0.5
            
            # Extra check for connection status distribution
            connection_statuses = process_stats.get("connection_statuses", {})
            established = connection_statuses.get("ESTABLISHED", 0)
            listen = connection_statuses.get("LISTEN", 0)
            
            # Many established connections for a non-server process is suspicious
            if established > 10 and not network_intensive:
                conn_confidence = max(conn_confidence, 0.6)
            
            # Only report if confidence is high enough
            if conn_confidence >= 0.5:
                detection = {
                    "type": "high_connection_count",
                    "description": f"High connection count ({process_stats['connection_count']}) for non-server process",
                    "evidence": f"Connections: {process_stats['connection_count']} (ESTABLISHED: {established}, LISTEN: {listen})",
                    "confidence": conn_confidence,
                    "severity": "medium" if conn_confidence < 0.7 else "high",
                    "mitre_techniques": ["T1071"]
                }
                
                suspicious_patterns.append(f"High connection count ({process_stats['connection_count']}) for non-server process (confidence: {conn_confidence:.1%})")
                detection_context["detections"]["high_connection_count"] = detection
                detection_context["total_score"] += conn_confidence
                
        # 10. Game processes and other high-resource apps - contextual analysis
        if "game" in process_name.lower() or "game" in exe_path.lower():
            # Filter out common game-related behaviors that might trigger alerts
            suspicious_patterns = [pattern for pattern in suspicious_patterns 
                                 if not ("high port" in pattern.lower() or 
                                        "connection count" in pattern.lower() or
                                        "cpu usage" in pattern.lower())]
            
            # Also remove from detection context
            if "high_connection_count" in detection_context["detections"]:
                del detection_context["detections"]["high_connection_count"]
                
            if "high_cpu_usage" in detection_context["detections"]:
                del detection_context["detections"]["high_cpu_usage"]
                
            if "unusual_port" in detection_context["detections"]:
                del detection_context["detections"]["unusual_port"]
        
        # 11. Fileless Detection (added in original code)
                # Detect file not found but process exists (potential fileless process)
                if not os.path.exists(exe_path) and exe_path != "ACCESS_DENIED":
                    fileless_confidence = 0.8  # High confidence
                    detection = {
                        "type": "fileless_process",
                        "description": "Fileless process detected: executable path doesn't exist",
                        "evidence": exe_path,
                        "confidence": fileless_confidence,
                        "severity": "high",
                        "mitre_techniques": ["T1059.001", "T1036"]
                    }
                    
                    suspicious_patterns.append(f"Fileless process detected: executable path doesn't exist (confidence: {fileless_confidence:.1%})")
                    detection_context["detections"]["fileless_process"] = detection
                    detection_context["total_score"] += fileless_confidence
                
                # 11.2 Windows Script Host execution with remote content
                if process_name in ["wscript.exe", "cscript.exe"]:
                    if "http:" in cmdline or "https:" in cmdline:
                        wsh_confidence = 0.85
                        detection = {
                            "type": "remote_script_execution",
                            "description": "Windows Script Host executing remote script content",
                            "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                            "confidence": wsh_confidence,
                            "severity": "high",
                            "mitre_techniques": ["T1059.005", "T1105"]
                        }
                        
                        suspicious_patterns.append(f"Windows Script Host executing remote script content (confidence: {wsh_confidence:.1%})")
                        detection_context["detections"]["remote_script_execution"] = detection
                        detection_context["total_score"] += wsh_confidence
                
                # 11.3 Enhanced detection of reflective loading in .NET
                reflection_patterns = {
                    "reflection.assembly": 0.8,
                    "assembly.load": 0.75,
                    "loadfrom": 0.7,
                    "loadfile": 0.7,
                    "iex": 0.7,
                    "invoke-expression": 0.8,
                    "gettypes": 0.6,
                    "getmethods": 0.6
                }
                
                if process_name in ["powershell.exe", "powershell_ise.exe"] or ".exe" not in process_name:
                    max_reflection_confidence = 0.0
                    detected_pattern = ""
                    
                    for pattern, confidence in reflection_patterns.items():
                        if pattern in cmdline.lower():
                            if confidence > max_reflection_confidence:
                                max_reflection_confidence = confidence
                                detected_pattern = pattern
                    
                    if max_reflection_confidence > 0.0:
                        # Boost confidence if multiple patterns found
                        pattern_count = sum(1 for p in reflection_patterns if p in cmdline.lower())
                        if pattern_count > 1:
                            max_reflection_confidence = min(0.95, max_reflection_confidence + (0.05 * (pattern_count - 1)))
                        
                        detection = {
                            "type": "reflection_loading",
                            "description": f".NET reflection loading detected: {detected_pattern}",
                            "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                            "confidence": max_reflection_confidence,
                            "severity": "high",
                            "mitre_techniques": ["T1127", "T1059.001"]
                        }
                        
                        suspicious_patterns.append(f".NET reflection loading detected: {detected_pattern} (confidence: {max_reflection_confidence:.1%})")
                        detection_context["detections"]["reflection_loading"] = detection
                        detection_context["total_score"] += max_reflection_confidence
                
                # 11.4 Enhanced memory analysis for fileless indicators with progressive depth
                if is_admin():
                    try:
                        # Only perform memory scanning if already found suspicious indicators
                        # or for processes with missing executable (optimize resource usage)
                        if suspicious_patterns or not os.path.exists(exe_path):
                            memory_regions = enumerate_process_memory_regions(pid)
                            
                            # Count suspicious memory regions with better classification
                            rwx_regions = 0
                            rx_regions = 0
                            executable_private_regions = 0
                            large_exec_allocs = 0
                            
                            for region in memory_regions:
                                if region["protection"]["executable"] and region["type"] == "Private":
                                    executable_private_regions += 1
                                    
                                    # Check for RWX permissions (highly suspicious)
                                    if region["protection"]["writable"]:
                                        rwx_regions += 1
                                    else:
                                        rx_regions += 1
                                    
                                    # Check for large executable allocations
                                    if region["size_kb"] > 1024:  # >1MB
                                        large_exec_allocs += 1
                            
                            # Alert on excessive RWX memory regions with severity based on count
                            if rwx_regions > 0:
                                rwx_confidence = min(0.95, 0.7 + (rwx_regions * 0.05))  # More regions = higher confidence
                                
                                detection = {
                                    "type": "rwx_memory",
                                    "description": f"Excessive RWX memory regions: {rwx_regions} - potential shellcode",
                                    "evidence": f"{rwx_regions} RWX memory regions",
                                    "confidence": rwx_confidence,
                                    "severity": "high",
                                    "mitre_techniques": ["T1055"]
                                }
                                
                                suspicious_patterns.append(f"Excessive RWX memory regions: {rwx_regions} - potential shellcode (confidence: {rwx_confidence:.1%})")
                                detection_context["detections"]["rwx_memory"] = detection
                                detection_context["total_score"] += rwx_confidence
                            
                            # Alert on excessive executable private memory
                            if executable_private_regions > 5:
                                exe_confidence = min(0.9, 0.6 + (executable_private_regions * 0.03))
                                
                                detection = {
                                    "type": "excessive_executable_memory",
                                    "description": f"Excessive executable allocations: {executable_private_regions} - potential code injection",
                                    "evidence": f"{executable_private_regions} executable private memory regions",
                                    "confidence": exe_confidence,
                                    "severity": "medium",
                                    "mitre_techniques": ["T1055"]
                                }
                                
                                suspicious_patterns.append(f"Excessive executable allocations: {executable_private_regions} - potential code injection (confidence: {exe_confidence:.1%})")
                                detection_context["detections"]["excessive_executable_memory"] = detection
                                detection_context["total_score"] += exe_confidence
                            
                            # Alert on large executable allocations (often used for unpacked code)
                            if large_exec_allocs > 0:
                                large_confidence = min(0.85, 0.7 + (large_exec_allocs * 0.05))
                                
                                detection = {
                                    "type": "large_executable_allocations",
                                    "description": f"Large executable memory allocations: {large_exec_allocs} - potential unpacked code",
                                    "evidence": f"{large_exec_allocs} large (>1MB) executable allocations",
                                    "confidence": large_confidence,
                                    "severity": "medium",
                                    "mitre_techniques": ["T1055", "T1027.002"]
                                }
                                
                                suspicious_patterns.append(f"Large executable memory allocations: {large_exec_allocs} - potential unpacked code (confidence: {large_confidence:.1%})")
                                detection_context["detections"]["large_executable_allocations"] = detection
                                detection_context["total_score"] += large_confidence
                    except Exception as e:
                        logging.debug(f"Error scanning memory for fileless indicators: {e}")
                
                # 11.5 Enhanced detection of memory-only execution tricks in command line
                memory_exec_indicators = {
                    "virtualalloc": 0.8, 
                    "heapalloc": 0.7, 
                    "memoryapi": 0.75, 
                    "writeprocessmemory": 0.85,
                    "createremotethread": 0.9, 
                    "ntwritevirtualmemory": 0.9, 
                    "shellcode": 0.9,
                    "winapi": 0.5,
                    "allocatememory": 0.6,
                    "memcpy": 0.6,
                    "marshal": 0.6,
                    "function ptr": 0.7,
                    "memset": 0.5,
                    "runtime.interopservices": 0.7
                }
                
                # Check for memory API indicators with progressive confidence
                max_memory_confidence = 0.0
                detected_indicators = []
                
                for indicator, confidence in memory_exec_indicators.items():
                    if indicator in cmdline.lower():
                        if confidence >= 0.7:  # Only collect significant indicators
                            detected_indicators.append(indicator)
                            
                        if confidence > max_memory_confidence:
                            max_memory_confidence = confidence
                
                # Adjust confidence based on number of indicators found
                if len(detected_indicators) > 1:
                    # Multiple indicators found - increase confidence
                    max_memory_confidence = min(0.95, max_memory_confidence + (0.05 * (len(detected_indicators) - 1)))
                
                if max_memory_confidence >= 0.7:  # Only report if confidence is high enough
                    indicators_str = ", ".join(detected_indicators)
                    
                    detection = {
                        "type": "memory_manipulation_apis",
                        "description": f"Memory manipulation API in command line: {indicators_str}",
                        "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                        "confidence": max_memory_confidence,
                        "severity": "high",
                        "mitre_techniques": ["T1055", "T1106"]
                    }
                    
                    suspicious_patterns.append(f"Memory manipulation API in command line: {indicators_str} (confidence: {max_memory_confidence:.1%})")
                    detection_context["detections"]["memory_manipulation_apis"] = detection
                    detection_context["total_score"] += max_memory_confidence
                
                # 11.6 Enhanced WMI process execution detection
                if "wmic" in cmdline and "process call create" in cmdline:
                    wmi_confidence = 0.8
                    
                    # Check for additional suspicious elements to adjust confidence
                    if "cmd" in cmdline or "powershell" in cmdline:
                        wmi_confidence = min(0.95, wmi_confidence + 0.1)
                    
                    if "http" in cmdline or "ftp" in cmdline:
                        wmi_confidence = min(0.95, wmi_confidence + 0.1)
                    
                    detection = {
                        "type": "wmi_process_creation",
                        "description": "WMI used to create process - potential living off the land technique",
                        "evidence": cmdline[:200] + "..." if len(cmdline) > 200 else cmdline,
                        "confidence": wmi_confidence,
                        "severity": "high",
                        "mitre_techniques": ["T1047", "T1059"]
                    }
                    
                    suspicious_patterns.append(f"WMI used to create process - potential living off the land technique (confidence: {wmi_confidence:.1%})")
                    detection_context["detections"]["wmi_process_creation"] = detection
                    detection_context["total_score"] += wmi_confidence
                
                # 11.7 Enhanced DLL hijacking detection
                if pid > 0:
                    try:
                        dll_indicators = detect_dll_search_order_hijacking(pid, process_info)
                        if dll_indicators:
                            # Use the most severe indicator
                            max_severity_indicator = max(
                                dll_indicators, 
                                key=lambda x: 0 if 'severity' not in x else 
                                              (2 if x['severity'] == 'high' else 
                                               1 if x['severity'] == 'medium' else 0)
                            )
                            
                            dll_confidence = 0.7  # Base confidence
                            
                            # Adjust based on severity
                            if max_severity_indicator.get('severity') == 'high':
                                dll_confidence = 0.85
                            elif max_severity_indicator.get('severity') == 'critical':
                                dll_confidence = 0.95
                                
                            detection = {
                                "type": "dll_hijacking",
                                "description": max_severity_indicator.get('description', 'DLL hijacking detected'),
                                "evidence": max_severity_indicator.get('dll_path', 'Unknown DLL path'),
                                "confidence": dll_confidence,
                                "severity": max_severity_indicator.get('severity', 'medium'),
                                "mitre_techniques": ["T1574.001", "T1574.002"]
                            }
                            
                            suspicious_patterns.append(f"{max_severity_indicator.get('description', 'DLL hijacking detected')} (confidence: {dll_confidence:.1%})")
                            detection_context["detections"]["dll_hijacking"] = detection
                            detection_context["total_score"] += dll_confidence
                    except Exception as e:
                        logging.debug(f"Error checking for DLL hijacking: {e}")
                        
                # 12. NEW: Context-aware behavioral analysis
                # Check behavioral patterns specific to process type
                
                # 12.1 Classification-based detection (different process types have different baselines)
                process_category = "unknown"
                
                # Classify the process
                if "svchost" in process_name or "services" in process_name or "lsass" in process_name:
                    process_category = "system"
                elif "chrome" in process_name or "firefox" in process_name or "edge" in process_name:
                    process_category = "browser"
                elif "w3wp" in process_name or "httpd" in process_name or "nginx" in process_name:
                    process_category = "webserver"
                elif "sqlservr" in process_name or "oracle" in process_name or "mysql" in process_name:
                    process_category = "database"
                elif "cmd" in process_name or "powershell" in process_name or "wscript" in process_name:
                    process_category = "shell"
                elif "devenv" in process_name or "visual studio" in exe_path or "intellij" in exe_path:
                    process_category = "development"
                elif "explorer" in process_name or "desktop" in process_name:
                    process_category = "user_interface"
                    
                # Apply category-specific detection rules
                if process_category == "system":
                    # System processes shouldn't have many open network connections
                    if process_stats["connection_count"] > 5:
                        sys_net_confidence = 0.8
                        
                        detection = {
                            "type": "system_process_network_activity",
                            "description": f"System process with unusual network activity: {process_stats['connection_count']} connections",
                            "evidence": f"{process_stats['connection_count']} network connections",
                            "confidence": sys_net_confidence,
                            "severity": "high",
                            "mitre_techniques": ["T1071"]
                        }
                        
                        suspicious_patterns.append(f"System process with unusual network activity: {process_stats['connection_count']} connections (confidence: {sys_net_confidence:.1%})")
                        detection_context["detections"]["system_process_network_activity"] = detection
                        detection_context["total_score"] += sys_net_confidence
                
                elif process_category == "browser":
                    # Browser shouldn't host many child processes unless it's the main process
                    if process_stats["child_process_count"] > 20 and "svchost" not in lineage:
                        browser_child_confidence = 0.7
                        
                        detection = {
                            "type": "browser_excessive_child_processes",
                            "description": f"Browser process with excessive child processes: {process_stats['child_process_count']}",
                            "evidence": f"{process_stats['child_process_count']} child processes",
                            "confidence": browser_child_confidence,
                            "severity": "medium",
                            "mitre_techniques": ["T1203"]
                        }
                        
                        suspicious_patterns.append(f"Browser process with excessive child processes: {process_stats['child_process_count']} (confidence: {browser_child_confidence:.1%})")
                        detection_context["detections"]["browser_excessive_child_processes"] = detection
                        detection_context["total_score"] += browser_child_confidence
                
                # 12.2 Derived metrics - analyze ratios and rates for more accurate detection
                # Handles-per-thread ratio (high values might indicate resource leaks or handle table injection)
                if process_stats["thread_count"] > 0:
                    handles_per_thread = process_stats["handle_count"] / process_stats["thread_count"]
                    
                    # Different thresholds for different process types
                    handles_threshold = 200  # Default
                    if process_category == "system":
                        handles_threshold = 100
                    elif process_category == "database":
                        handles_threshold = 300
                    elif process_category == "development":
                        handles_threshold = 400
                        
                    if handles_per_thread > handles_threshold:
                        handle_ratio_confidence = min(0.8, 0.5 + ((handles_per_thread - handles_threshold) / handles_threshold) * 0.3)
                        
                        if handle_ratio_confidence >= 0.6:  # Only report if significant
                            detection = {
                                "type": "excessive_handle_ratio",
                                "description": f"Excessive handles per thread: {handles_per_thread:.1f} (threshold: {handles_threshold})",
                                "evidence": f"Handles: {process_stats['handle_count']}, Threads: {process_stats['thread_count']}",
                                "confidence": handle_ratio_confidence,
                                "severity": "medium",
                                "mitre_techniques": ["T1134"]
                            }
                            
                            suspicious_patterns.append(f"Excessive handles per thread: {handles_per_thread:.1f} (threshold: {handles_threshold}) (confidence: {handle_ratio_confidence:.1%})")
                            detection_context["detections"]["excessive_handle_ratio"] = detection
                            detection_context["total_score"] += handle_ratio_confidence
                
                # 12.3 Calculate final threat score based on all detections
        total_weighted_score = 0
        detection_count = len(detection_context["detections"])
        
        # Apply severity multipliers
        severity_weights = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.7
        }
        
        for detection_type, detection in detection_context["detections"].items():
            severity = detection.get("severity", "medium")
            confidence = detection.get("confidence", 0.5)
            
            # Calculate weighted score
            weight = severity_weights.get(severity, 1.0)
            weighted_score = confidence * weight
            
            # Add to total
            total_weighted_score += weighted_score
        
        # Normalize final score to 0-1 range with diminishing returns for many detections
        if detection_count > 0:
            # Base score from weighted average
            avg_weighted_score = total_weighted_score / detection_count
            
            # Add bonus for multiple detections (with diminishing returns)
            multiple_detection_bonus = 1.0 + (min(5, detection_count - 1) * 0.1)
            
            # Calculate final score
            detection_context["normalized_score"] = min(1.0, avg_weighted_score * multiple_detection_bonus)
            
            # Add MITRE ATT&CK mapping to detection context
            mitre_techniques = set()
            for detection in detection_context["detections"].values():
                if "mitre_techniques" in detection:
                    for technique in detection["mitre_techniques"]:
                        mitre_techniques.add(technique)
            
            detection_context["mitre_techniques"] = list(mitre_techniques)
            
            # Add to logging
            if detection_context["normalized_score"] >= 0.7:
                logging.warning(f"High threat score {detection_context['normalized_score']:.2f} for process {process_name} (PID: {pid})")
            elif detection_context["normalized_score"] >= 0.4:
                logging.info(f"Medium threat score {detection_context['normalized_score']:.2f} for process {process_name} (PID: {pid})")
    
    except Exception as e:
        logging.error(f"Error analyzing process behavior for PID {pid}: {e}")
        import traceback
        logging.error(traceback.format_exc())
    
    return suspicious_patterns

def implement_behavioral_baselining():
    """Train more advanced ML models for process behavior anomaly detection with ensemble approach."""
    if not ML_LIBRARIES_AVAILABLE:
        logging.warning("ML libraries not available - skipping behavioral baselining")
        return None
        
    try:
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler
        from sklearn.decomposition import PCA
        import numpy as np
        import pandas as pd
        
        # Define system processes that should have special treatment
        system_processes = ["system", "smss.exe", "csrss.exe", "wininit.exe", 
                          "services.exe", "lsass.exe", "svchost.exe"]
        
        # Collect historical process behavior data
        processes_data = []
        integrity_state = load_process_metadata()
        
        for hash_key, process in integrity_state.items():
            # Skip process_groups metadata
            if hash_key == "process_groups":
                continue
                
            # Get PID as int, with error handling for when it's stored as a string
            try:
                pid = int(process.get("pid", 0))
            except (ValueError, TypeError):
                # If pid cannot be converted to int, use 0 as a default
                pid = 0
                
            process_name = process.get("process_name", "").lower()
            
            # Skip system processes in the training data
            if process_name in system_processes and pid <= 4:
                continue
                
            # Extract features
            try:
                # Get additional stats if process is still running
                try:
                    current_stats = get_process_stats(pid) if pid > 0 else {
                        "memory_usage_kb": 0,
                        "cpu_percent": 0,
                        "handle_count": 0, 
                        "thread_count": 0,
                        "child_process_count": 0,
                        "connection_count": 0,
                        "io_read_bytes": 0,
                        "io_write_bytes": 0
                    }
                except:
                    current_stats = {
                        "memory_usage_kb": 0,
                        "cpu_percent": 0,
                        "handle_count": 0, 
                        "thread_count": 0,
                        "child_process_count": 0,
                        "connection_count": 0,
                        "io_read_bytes": 0,
                        "io_write_bytes": 0
                    }
                
                # Get port with proper error handling
                try:
                    port = int(process.get('port', 0)) if process.get('port') and str(process.get('port')).isdigit() else 0
                except (ValueError, TypeError):
                    port = 0
                
                # Enhanced feature set for better behavioral profiling
                features = {
                    'pid': pid,
                    'port': port,
                    'lineage_length': len(process.get('lineage', [])),
                    'cmdline_length': len(process.get('cmdline', '')),
                    'is_admin': 1 if 'admin' in process.get('user', '').lower() else 0,
                    'is_system': 1 if 'system' in process.get('user', '').lower() else 0,
                    'child_processes': current_stats.get('child_process_count', 0),
                    'handle_count': current_stats.get('handle_count', 0),
                    'thread_count': current_stats.get('thread_count', 0),
                    'memory_usage_mb': current_stats.get('memory_usage_kb', 0) / 1024,
                    'connection_count': current_stats.get('connection_count', 0),
                    'cpu_percent': current_stats.get('cpu_percent', 0),
                    'io_read_mb': current_stats.get('io_read_bytes', 0) / (1024 * 1024),
                    'io_write_mb': current_stats.get('io_write_bytes', 0) / (1024 * 1024),
                    # Derived features - ratios often better capture anomalies
                    'memory_per_thread': (current_stats.get('memory_usage_kb', 0) / 1024) / 
                                         max(current_stats.get('thread_count', 1), 1),
                    'handles_per_thread': current_stats.get('handle_count', 0) / 
                                         max(current_stats.get('thread_count', 1), 1),
                    'connections_per_thread': current_stats.get('connection_count', 0) / 
                                             max(current_stats.get('thread_count', 1), 1)
                }
                
                # Add process category for clustering algorithms
                category = "system"
                if process_name.endswith(".exe"):
                    if any(browser in process_name for browser in ["chrome", "firefox", "edge", "opera"]):
                        category = "browser"
                    elif any(server in process_name for server in ["httpd", "nginx", "apache", "iis", "w3wp"]):
                        category = "webserver"
                    elif any(db in process_name for db in ["sql", "oracle", "mysql", "postgres"]):
                        category = "database"
                    elif any(utility in process_name for utility in ["cmd", "powershell", "explorer"]):
                        category = "utility"
                
                features['category'] = category
                
                processes_data.append(features)
            except Exception as e:
                logging.error(f"Error extracting ML features for process info: {e}")
        
        # Return empty model info if not enough data
        if len(processes_data) < 5:
            logging.warning("Not enough process data for ML model training")
            return {
                'models': None,
                'features': [],
                'system_processes': system_processes
            }
        
        # Create dataframe and preprocess data
        df = pd.DataFrame(processes_data)
        
        # Extract categorical features before numerical processing
        categorical_features = ['category']
        categorical_data = df[categorical_features].copy() if 'category' in df.columns else None
        
        # Handle numerical features
        numerical_features = [col for col in df.columns if col != 'pid' and col not in categorical_features and 
                            df[col].dtype in [np.int64, np.float64, np.bool_]]
        
        # Perform scaling for better model performance
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(df[numerical_features])
        scaled_df = pd.DataFrame(scaled_data, columns=numerical_features)
        
        # Apply dimension reduction for clustering algorithms
        # Only use PCA if we have enough features and samples
        use_pca = len(numerical_features) > 5 and len(df) > 10
        pca = None
        pca_components = None
        
        if use_pca:
            n_components = min(5, len(numerical_features))
            pca = PCA(n_components=n_components)
            # Convert to numpy array without feature names to avoid the warning
            scaled_data_for_pca = scaled_df[numerical_features].values
            pca_components = pca.fit_transform(scaled_data_for_pca)
            pca_df = pd.DataFrame(
                pca_components, 
                columns=[f'pc{i+1}' for i in range(n_components)]
            )
            logging.info(f"PCA reduced dimensions from {len(numerical_features)} to {n_components} "
                        f"explaining {sum(pca.explained_variance_ratio_) * 100:.2f}% of variance")
        
        # Train multiple models for ensemble approach
        models = {}
        
        # 1. Isolation Forest with auto contamination
        contamination = min(0.1, 1/len(df))  # At most 10% anomalies, or 1 if few samples
        iforest = IsolationForest(
            contamination=contamination, 
            random_state=42,
            n_estimators=100,  # More trees for better performance
            max_samples='auto'
        )
        iforest.fit(scaled_df[numerical_features])
        models['iforest'] = iforest
        
        # 2. DBSCAN for density-based clustering
        # Automatically estimate eps parameter based on data
        from sklearn.neighbors import NearestNeighbors
        nn_data = pca_components if use_pca else scaled_data
        n_neighbors = min(5, len(nn_data) - 1) if len(nn_data) > 5 else 2
        
        if len(nn_data) > n_neighbors:
            try:
                nn = NearestNeighbors(n_neighbors=n_neighbors)
                nn.fit(nn_data)
                distances, _ = nn.kneighbors(nn_data)
                distances = np.sort(distances[:, n_neighbors-1])
                knee_locator = KneeLocator(
                    range(len(distances)), 
                    distances, 
                    curve='convex', 
                    direction='increasing'
                )
                eps = distances[knee_locator.knee] if knee_locator.knee else np.percentile(distances, 90)
                
                # Train DBSCAN
                dbscan = DBSCAN(eps=eps, min_samples=n_neighbors)
                if use_pca:
                    dbscan.fit(pca_df)
                else:
                    dbscan.fit(scaled_df[numerical_features])
                models['dbscan'] = dbscan
                logging.info(f"DBSCAN clustering with eps={eps:.4f}, min_samples={n_neighbors}")
            except Exception as e:
                logging.warning(f"Could not train DBSCAN model: {e}")
        
        # 3. Initialize per-category models for more precise detection
        if categorical_data is not None and 'category' in categorical_data.columns:
            category_models = {}
            categories = categorical_data['category'].unique()
            
            for category in categories:
                try:
                    # Get indices for this category
                    category_indices = categorical_data.index[categorical_data['category'] == category].tolist()
                    if len(category_indices) >= 5:  # Need enough samples
                        category_data = scaled_df.iloc[category_indices]
                        
                        # Train category-specific Isolation Forest
                        cat_iforest = IsolationForest(
                            contamination=min(0.1, 1/len(category_data)),
                            random_state=42,
                            n_estimators=100
                        )
                        cat_iforest.fit(category_data[numerical_features])
                        category_models[category] = cat_iforest
                        logging.info(f"Trained category-specific model for '{category}' with {len(category_data)} samples")
                except Exception as e:
                    logging.warning(f"Error training category model for '{category}': {e}")
            
            models['category_models'] = category_models
        
        # Create stats for baseline model
        baseline_stats = {}
        for feature in numerical_features:
            baseline_stats[feature] = {
                'mean': df[feature].mean(),
                'std': df[feature].std(),
                'min': df[feature].min(),
                'max': df[feature].max(),
                'p25': df[feature].quantile(0.25),
                'median': df[feature].quantile(0.5),
                'p75': df[feature].quantile(0.75),
                'p95': df[feature].quantile(0.95)
            }
        
        # Store model info
        model_info = {
            'models': models,
            'features': numerical_features,
            'categorical_features': categorical_features if categorical_data is not None else [],
            'system_processes': system_processes,
            'scaler': scaler,
            'pca': pca if use_pca else None,
            'pca_components': pca_components if use_pca else None,
            'baseline_stats': baseline_stats,
            'training_size': len(df),
            'categories': categorical_data['category'].unique().tolist() if categorical_data is not None and 'category' in categorical_data.columns else []
        }
        
        logging.info(f"Trained ensemble ML models on {len(df)} processes with {len(numerical_features)} features")
        
        return model_info
        
    except Exception as e:
        logging.error(f"Error training ML models: {e}")
        # Add this import to the top of the file or inside this function
        import traceback
        logging.error(traceback.format_exc())
        return None

def detect_anomalies_ml(process_info, ml_model_info):
    """
    Detect process anomalies using ensemble ML models for more accurate detection.
    Returns detailed anomaly information with scores from multiple models and features.
    """
    if not ml_model_info or not ml_model_info.get('models'):
        return None
        
    try:
        import pandas as pd
        import numpy as np
        import time
        
        pid = process_info.get('pid')
        process_name = process_info.get('process_name', '').lower()
        
        # Skip system processes with PIDs below 5
        if pid <= 4 or process_name == 'system':
            return None
        
        # Get or initialize learning state
        learning_state = ml_model_info.get('learning_state', {
            'start_time': time.time(),
            'observation_period': 3600,  # 1 hour initial learning period
            'processes_seen': {},
            'learning_complete': False
        })
        
        # Update learning state in the model info
        ml_model_info['learning_state'] = learning_state
        
        # Check if we're still in the initial learning period
        current_time = time.time()
        in_learning_period = not learning_state['learning_complete'] and \
                           (current_time - learning_state['start_time'] < learning_state['observation_period'])
        
        # Track this process in our learning state
        if process_name not in learning_state['processes_seen']:
            learning_state['processes_seen'][process_name] = {
                'first_seen': current_time,
                'observations': 1
            }
        else:
            learning_state['processes_seen'][process_name]['observations'] += 1
        
        # Set baseline anomaly threshold
        baseline_threshold = 0.35
        
        # Initialize process-specific stats if needed
        process_specific_stats = ml_model_info.get('process_specific_stats', {})
        
        # If we have process-specific statistics from historical data, use them
        if process_name in process_specific_stats:
            proc_stats = process_specific_stats[process_name]
            
            # Calculate dynamic threshold based on historical data volatility
            # More volatile processes get higher thresholds to reduce false positives
            if 'volatility' in proc_stats:
                volatility = proc_stats['volatility']
                # Adjust threshold based on observed volatility (0.0-1.0 scale)
                dynamic_threshold = baseline_threshold + (volatility * 0.4)  # Max +0.4 adjustment
                anomaly_threshold = dynamic_threshold
            else:
                # No volatility data yet, use baseline
                anomaly_threshold = baseline_threshold
                
            # Track number of previous detections to identify repeat offenders
            # Processes that frequently trigger low-level alerts may need investigation
            if 'detection_count' in proc_stats and proc_stats['detection_count'] > 5:
                # For frequently alerting processes, slightly lower the threshold
                # This ensures we don't completely tune out recurring suspicious behavior
                anomaly_threshold = max(0.3, anomaly_threshold - 0.05)
        else:
            # No historical data for this process yet, use baseline
            anomaly_threshold = baseline_threshold
        
        # Get process stats
        process_stats = get_process_stats(pid)
        
        # Determine process category
        category = "system"
        if process_name.endswith(".exe"):
            if any(browser in process_name.lower() for browser in ["chrome", "firefox", "edge", "opera"]):
                category = "browser"
            elif any(server in process_name.lower() for server in ["httpd", "nginx", "apache", "iis", "w3wp"]):
                category = "webserver"
            elif any(db in process_name.lower() for db in ["sql", "oracle", "mysql", "postgres"]):
                category = "database"
            elif any(utility in process_name.lower() for utility in ["cmd", "powershell", "explorer"]):
                category = "utility"
            elif any(game in process_name.lower() for game in ["steam", "game", "uplay", "origin", "epic"]):
                category = "gaming"
        
        # Prepare features matching the trained model's feature set
        features = {
            'port': int(process_info.get('port', 0)) if isinstance(process_info.get('port', 0), (int, str)) and 
                                                   str(process_info.get('port', 0)).isdigit() else 0,
            'lineage_length': len(process_info.get('lineage', [])),
            'cmdline_length': len(process_info.get('cmdline', '')),
            'is_admin': 1 if 'admin' in process_info.get('user', '').lower() else 0,
            'is_system': 1 if 'system' in process_info.get('user', '').lower() else 0,
            'child_processes': process_stats.get('child_process_count', 0),
            'handle_count': process_stats.get('handle_count', 0),
            'thread_count': process_stats.get('thread_count', 0),
            'memory_usage_mb': process_stats.get('memory_usage_kb', 0) / 1024,
            'connection_count': process_stats.get('connection_count', 0),
            'cpu_percent': process_stats.get('cpu_percent', 0),
            'io_read_mb': process_stats.get('io_read_bytes', 0) / (1024 * 1024),
            'io_write_mb': process_stats.get('io_write_bytes', 0) / (1024 * 1024),
            # Derived features
            'memory_per_thread': (process_stats.get('memory_usage_kb', 0) / 1024) / 
                               max(process_stats.get('thread_count', 1), 1),
            'handles_per_thread': process_stats.get('handle_count', 0) / 
                                max(process_stats.get('thread_count', 1), 1),
            'connections_per_thread': process_stats.get('connection_count', 0) / 
                                    max(process_stats.get('thread_count', 1), 1)
        }
        
        # Add categorical features
        features['category'] = category
        
        # Ensure we only use features available in the model
        numerical_features = ml_model_info.get('features', [])
        categorical_features = ml_model_info.get('categorical_features', [])
        
        # Create prediction data frames
        num_prediction_features = {}
        for feature in numerical_features:
            if feature in features:
                num_prediction_features[feature] = features.get(feature, 0)
            else:
                num_prediction_features[feature] = 0
        
        cat_prediction_features = {}
        for feature in categorical_features:
            if feature in features:
                cat_prediction_features[feature] = features.get(feature, '')
            else:
                cat_prediction_features[feature] = ''
        
        # Apply preprocessing
        scaler = ml_model_info.get('scaler')
        if scaler:
            scaled_data = scaler.transform(pd.DataFrame([num_prediction_features]))
            scaled_df = pd.DataFrame(scaled_data, columns=numerical_features)
        else:
            scaled_df = pd.DataFrame([num_prediction_features])
        
        # Apply PCA if available
        pca = ml_model_info.get('pca')
        if pca:
            # Convert to numpy array without feature names to avoid the warning
            scaled_data_for_pca = scaled_df.values
            pca_components = pca.transform(scaled_data_for_pca)
            pca_df = pd.DataFrame(
                pca_components, 
                columns=[f'pc{i+1}' for i in range(pca_components.shape[1])]
            )
        
        # Initialize ensemble results
        ensemble_results = {
            'anomaly_scores': {},
            'is_anomaly': False,
            'combined_score': 0,
            'anomalous_features': [],
            'detection_methods': []
        }
        
        # Apply each model
        models = ml_model_info.get('models', {})
        baseline_stats = ml_model_info.get('baseline_stats', {})
        
        # 1. Isolation Forest
        if 'iforest' in models:
            iforest = models['iforest']
            iforest_pred = iforest.predict(scaled_df)[0]
            iforest_score = iforest.decision_function(scaled_df)[0]
            
            # More negative score = more anomalous
            normalized_score = -iforest_score  # Convert to positive = more anomalous
            ensemble_results['anomaly_scores']['iforest'] = normalized_score
            
            if iforest_pred == -1 and normalized_score > 0.1:  # -1 is anomaly, but add threshold
                ensemble_results['is_anomaly'] = True
                ensemble_results['detection_methods'].append('isolation_forest')
        
        # 2. DBSCAN
        if 'dbscan' in models:
            dbscan = models['dbscan']
            
            # Predict using the same data used for training
            if pca and ml_model_info.get('pca_components') is not None:
                dbscan_input = pca_df
            else:
                dbscan_input = scaled_df
                
            try:
                # For DBSCAN, predict returns cluster label (-1 for outliers)
                dbscan_label = dbscan.fit_predict(dbscan_input)[0]
                
                # If it's an outlier
                if dbscan_label == -1:
                    ensemble_results['is_anomaly'] = True
                    ensemble_results['detection_methods'].append('dbscan')
                    ensemble_results['anomaly_scores']['dbscan'] = 1.0  # Max score for outliers
                else:
                    ensemble_results['anomaly_scores']['dbscan'] = 0.0
            except Exception as e:
                logging.debug(f"Error applying DBSCAN to process {pid}: {e}")
        
        # 3. Category-specific model if available
        if 'category_models' in models and category in models['category_models']:
            try:
                cat_model = models['category_models'][category]
                cat_pred = cat_model.predict(scaled_df)[0]
                cat_score = cat_model.decision_function(scaled_df)[0]
                
                # Normalize score
                normalized_cat_score = -cat_score
                ensemble_results['anomaly_scores']['category_model'] = normalized_cat_score
                
                if cat_pred == -1 and normalized_cat_score > 0.1:
                    ensemble_results['is_anomaly'] = True
                    ensemble_results['detection_methods'].append(f'category_{category}')
            except Exception as e:
                logging.debug(f"Error applying category model for {category}: {e}")
        
        # 4. Statistical outlier detection (Z-score method)
        significant_deviations = []
        
        for feature in numerical_features:
            if feature in features and feature in baseline_stats:
                feature_value = features[feature]
                mean = baseline_stats[feature]['mean']
                std = baseline_stats[feature]['std']
                p95 = baseline_stats[feature]['p95']
                
                # Avoid division by zero
                if std > 0:
                    z_score = abs((feature_value - mean) / std)
                    
                    # Check for extreme values (Z-score > 3 or beyond 95th percentile)
                    if z_score > 3 or feature_value > p95:
                        # More weight to important metrics
                        importance_weight = 1.0
                        if feature in ['memory_usage_mb', 'cpu_percent', 'thread_count', 'connection_count']:
                            importance_weight = 2.0  # Double importance
                        
                        significant_deviations.append({
                            'feature': feature,
                            'value': feature_value,
                            'z_score': z_score,
                            'percentile': 95 if feature_value > p95 else 50,
                            'weight': importance_weight
                        })
        
        # If we found significant statistical deviations
        if significant_deviations:
            # Sort by z-score (highest first)
            significant_deviations.sort(key=lambda x: x['z_score'] * x['weight'], reverse=True)
            
            # Calculate weighted score based on deviations
            stat_score = sum(dev['z_score'] * dev['weight'] for dev in significant_deviations) / \
                        sum(dev['weight'] for dev in significant_deviations)
            
            ensemble_results['anomaly_scores']['statistical'] = min(stat_score / 10, 1.0)  # Normalize to 0-1
            ensemble_results['anomalous_features'] = significant_deviations
            
            # If statistical deviation is very high
            if stat_score > 5 or len(significant_deviations) >= 3:
                ensemble_results['is_anomaly'] = True
                ensemble_results['detection_methods'].append('statistical')
        
        # Calculate combined anomaly score
        all_scores = [score for score in ensemble_results['anomaly_scores'].values() if score > 0]
        if all_scores:
            # Average score from all active methods
            ensemble_results['combined_score'] = sum(all_scores) / len(all_scores)
        
        # If we're in learning period, just record the data but don't generate alerts
        if in_learning_period:
            # Record observations for this process in the learning state
            proc_learning = learning_state['processes_seen'].get(process_name, {})
            
            # Store feature observations for later analysis
            if 'feature_observations' not in proc_learning:
                proc_learning['feature_observations'] = {}
                
            for feature, value in features.items():
                if feature not in proc_learning['feature_observations']:
                    proc_learning['feature_observations'][feature] = []
                
                # Store only the last 10 observations to conserve memory
                observations = proc_learning['feature_observations'][feature]
                observations.append(value)
                if len(observations) > 10:
                    proc_learning['feature_observations'][feature] = observations[-10:]
            
            # Store anomaly score observations
            if 'anomaly_scores' not in proc_learning:
                proc_learning['anomaly_scores'] = []
                
            if ensemble_results['combined_score'] > 0:
                proc_learning['anomaly_scores'].append(ensemble_results['combined_score'])
                if len(proc_learning['anomaly_scores']) > 10:
                    proc_learning['anomaly_scores'] = proc_learning['anomaly_scores'][-10:]
            
            # Update the learning state
            learning_state['processes_seen'][process_name] = proc_learning
            
            # Check if it's time to finalize the learning period
            if current_time - learning_state['start_time'] >= learning_state['observation_period']:
                # Calculate process-specific stats from learning period
                for proc_name, proc_data in learning_state['processes_seen'].items():
                    if 'feature_observations' in proc_data and 'anomaly_scores' in proc_data:
                        # Initialize process-specific stats if needed
                        if proc_name not in process_specific_stats:
                            process_specific_stats[proc_name] = {
                                'first_seen': proc_data.get('first_seen', current_time),
                                'observations': proc_data.get('observations', 0),
                                'detection_count': 0,
                                'scores': []
                            }
                        
                        # Calculate initial volatility if we have enough data
                        anomaly_scores = proc_data.get('anomaly_scores', [])
                        if len(anomaly_scores) >= 3:
                            volatility = np.std(anomaly_scores) / max(np.mean(anomaly_scores), 0.01)
                            process_specific_stats[proc_name]['volatility'] = min(1.0, volatility)
                
                # Mark learning as complete
                learning_state['learning_complete'] = True
                logging.info("ML anomaly detection learning period complete, enabling alerts")
            
            # Don't generate alerts during learning period
            return None
            
        # Final decision - if any method detected an anomaly and score is high enough
        if ensemble_results['is_anomaly'] and ensemble_results['combined_score'] > anomaly_threshold:
            # Add process info to result for context
            ensemble_results['features'] = features
            ensemble_results['pid'] = pid
            ensemble_results['process_name'] = process_name
            ensemble_results['category'] = category
            
            # Classify the type of anomaly based on features
            ensemble_results['anomaly_type'] = classify_anomaly_type(ensemble_results)
            
            # Build a detailed explanation of why this is anomalous
            anomaly_explanation = []
            
            # Explain which detection methods triggered
            methods = ensemble_results['detection_methods']
            if methods:
                method_explanations = {
                    'isolation_forest': "unusual compared to baseline process behavior",
                    'dbscan': "forms an outlier cluster separate from normal processes",
                    'statistical': "shows statistically significant deviations in key metrics",
                    'category_model': f"unusual behavior for {category} processes"
                }
                
                # Add method-specific explanations
                for method in methods:
                    if method.startswith('category_'):
                        anomaly_explanation.append(method_explanations['category_model'])
                    elif method in method_explanations:
                        anomaly_explanation.append(method_explanations[method])
            
            # Add feature-specific anomaly explanations
            if ensemble_results['anomalous_features']:
                # Take the top 3 most significant anomalous features
                top_features = ensemble_results['anomalous_features'][:3]
                for feature in top_features:
                    feature_name = feature['feature']
                    feature_value = feature['value']
                    z_score = feature['z_score']
                    
                    # Create human-readable feature names
                    readable_names = {
                        'memory_usage_mb': 'memory usage',
                        'cpu_percent': 'CPU usage',
                        'thread_count': 'number of threads',
                        'connection_count': 'network connections',
                        'handle_count': 'handle count',
                        'child_processes': 'child processes',
                        'io_read_mb': 'disk read activity',
                        'io_write_mb': 'disk write activity',
                        'memory_per_thread': 'memory per thread ratio',
                        'handles_per_thread': 'handles per thread ratio'
                    }
                    
                    readable_name = readable_names.get(feature_name, feature_name)
                    
                    # Add contextual explanation based on feature
                    if feature_name == 'memory_usage_mb':
                        anomaly_explanation.append(f"unusual {readable_name} of {feature_value:.1f}MB ({z_score:.1f}x higher than normal)")
                    elif feature_name == 'cpu_percent':
                        anomaly_explanation.append(f"unusual {readable_name} of {feature_value:.1f}% ({z_score:.1f}x higher than normal)")
                    elif feature_name in ['thread_count', 'connection_count', 'handle_count', 'child_processes']:
                        anomaly_explanation.append(f"unusual {readable_name} of {int(feature_value)} ({z_score:.1f}x higher than normal)")
                    else:
                        anomaly_explanation.append(f"unusual {readable_name} ({z_score:.1f}x deviation from normal)")
            
            # Add anomaly type context
            anomaly_type = ensemble_results['anomaly_type']
            type_context = {
                'memory_abnormality': "may indicate memory leak or resource abuse",
                'excessive_threads': "could suggest parallel processing abuse or thread injection",
                'network_abnormality': "unusual network activity that could indicate command & control",
                'handle_leak': "possible resource leak or handle table manipulation",
                'potential_injection': "pattern consistent with code injection techniques",
                'privileged_network_activity': "privileged process with unusual network activity",
                'cpu_abnormality': "excessive CPU usage for this process type",
                'disk_io_abnormality': "unusual disk activity that could indicate data exfiltration"
            }
            
            if anomaly_type in type_context:
                anomaly_explanation.append(type_context[anomaly_type])
            
            # Combine explanations into a single detailed description
            ensemble_results['explanation'] = "; ".join(anomaly_explanation)
            
            # Create properly structured description for logging
            description = f"Anomaly type: {anomaly_type}; Confidence: {ensemble_results['combined_score']:.2f}; {ensemble_results['explanation']}"
            
            # Enhanced logging with detailed explanation
            logging.warning(f"ML detected anomaly in process {process_name} (PID: {pid}) - Score: {ensemble_results['combined_score']:.2f} - {ensemble_results['anomaly_type']}")
            logging.info(f"Anomaly details for {process_name} (PID: {pid}): {ensemble_results['explanation']}")
            
            # Add description to return value for use in alerts
            ensemble_results['description'] = description
            
            # Track this detection for future threshold adjustment
            if process_name not in process_specific_stats:
                process_specific_stats[process_name] = {
                    'detection_count': 1,
                    'last_detection_time': time.time(),
                    'scores': [ensemble_results['combined_score']]
                }
            else:
                process_specific_stats[process_name]['detection_count'] += 1
                process_specific_stats[process_name]['last_detection_time'] = time.time()
                
                # Keep only the last 10 scores to avoid unbounded growth
                scores = process_specific_stats[process_name].get('scores', [])
                scores.append(ensemble_results['combined_score'])
                if len(scores) > 10:
                    scores = scores[-10:]
                process_specific_stats[process_name]['scores'] = scores
                
                # Calculate volatility if we have enough data points
                if len(scores) >= 3:
                    # Standard deviation as a measure of volatility
                    volatility = np.std(scores) / max(np.mean(scores), 0.01)  # Normalized volatility
                    process_specific_stats[process_name]['volatility'] = min(1.0, volatility)
            
            # Update the model info with new statistics
            ml_model_info['process_specific_stats'] = process_specific_stats
            
            return ensemble_results
        
        return None
        
    except Exception as e:
        logging.error(f"Error detecting ML anomalies for PID {process_info.get('pid')}: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return None

def classify_anomaly_type(anomaly_result):
    """Classify the type of anomaly based on the anomalous features."""
    anomaly_type = "unknown"
    
    # Extract anomalous features
    anomalous_features = [feat['feature'] for feat in anomaly_result.get('anomalous_features', [])]
    features = anomaly_result.get('features', {})
    
    # Classify based on patterns
    if 'thread_count' in anomalous_features and features.get('thread_count', 0) > 20:
        anomaly_type = "excessive_threads"
    elif 'memory_usage_mb' in anomalous_features and features.get('memory_usage_mb', 0) > 500:
        anomaly_type = "memory_abnormality"
    elif 'connection_count' in anomalous_features and features.get('connection_count', 0) > 20:
        anomaly_type = "network_abnormality"
    elif 'cpu_percent' in anomalous_features and features.get('cpu_percent', 0) > 70:
        anomaly_type = "cpu_abnormality"
    elif 'handle_count' in anomalous_features and features.get('handle_count', 0) > 1000:
        anomaly_type = "handle_leak"
    elif 'io_write_mb' in anomalous_features or 'io_read_mb' in anomalous_features:
        anomaly_type = "disk_io_abnormality"
    
    # More complex patterns
    if 'memory_per_thread' in anomalous_features and 'thread_count' in anomalous_features:
        if features.get('thread_count', 0) > 10:
            anomaly_type = "potential_injection"
    
    if 'is_admin' in features and features['is_admin'] == 1 and 'connection_count' in anomalous_features:
        anomaly_type = "privileged_network_activity"
    
    return anomaly_type

def load_mitre_mapping():
    """Load MITRE ATT&CK technique mappings."""
    # Default mappings embedded directly in the function
    mappings = {
        "NEW_LISTENING_PROCESS": [{
            "technique_id": "T1059.003",
            "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution"
        }],
        "UNUSUAL_PORT_USE": [{
            "technique_id": "T1571", 
            "technique_name": "Non-Standard Port",
            "tactic": "Command and Control"
        }],
        "PROCESS_MODIFIED": [{
            "technique_id": "T1055", 
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion"
        }],
        "SUSPICIOUS_MEMORY_REGION": [{
            "technique_id": "T1055", 
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion"
        }],
        "LINEAGE_DEVIATION": [{
            "technique_id": "T1036", 
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion"
        }],
        "ML_DETECTED_ANOMALY": [{
            "technique_id": "T1036", 
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion"
        }],
        "SUSPICIOUS_BEHAVIOR": [{
            "technique_id": "T1059", 
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        }],
        "EXECUTABLE_PATH_MISMATCH": [{
            "technique_id": "T1036", 
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion"
        }],
        "HASH_MISMATCH": [{
            "technique_id": "T1036", 
            "technique_name": "Masquerading",
            "tactic": "Defense Evasion"
        }],
        "USER_MISMATCH": [{
            "technique_id": "T1078", 
            "technique_name": "Valid Accounts",
            "tactic": "Persistence"
        }],
        # Advanced attack techniques
        "PROCESS_HOLLOWING": [{
            "technique_id": "T1055.012",
            "technique_name": "Process Injection: Process Hollowing",
            "tactic": "Defense Evasion"
        }],
        "REFLECTIVE_DLL_INJECTION": [{
            "technique_id": "T1055.001",
            "technique_name": "Process Injection: Dynamic-link Library Injection",
            "tactic": "Defense Evasion"
        }],
        "THREAD_HIJACKING": [{
            "technique_id": "T1055.003",
            "technique_name": "Process Injection: Thread Execution Hijacking",
            "tactic": "Defense Evasion"
        }],
        "DLL_SEARCH_ORDER_HIJACKING": [{
            "technique_id": "T1574.001",
            "technique_name": "Hijack Execution Flow: DLL Search Order Hijacking",
            "tactic": "Persistence"
        }, {
            "technique_id": "T1574.001",
            "technique_name": "Hijack Execution Flow: DLL Search Order Hijacking",
            "tactic": "Privilege Escalation"
        }, {
            "technique_id": "T1574.001",
            "technique_name": "Hijack Execution Flow: DLL Search Order Hijacking",
            "tactic": "Defense Evasion"
        }],
        # New mappings for fileless processes and other detection types
        "FILELESS_PROCESS_DETECTED": [{
            "technique_id": "T1059.001", 
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        }, {
            "technique_id": "T1027", 
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        }],
        "PROCESS_RUNTIME_CHANGES": [{
            "technique_id": "T1055", 
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion"
        }]
    }
    
    return mappings

def classify_by_mitre_attck(event_type, process_info, detection_details=None):
    """Map detected activities to MITRE ATT&CK techniques using contextual analysis."""
    mitre_mapping = load_mitre_mapping()
    
    # Start with base techniques for the event type
    techniques = mitre_mapping.get(event_type, []).copy()
    
    # Process metadata for context-based classification
    process_name = process_info.get("process_name", "").lower()
    cmdline = process_info.get("cmdline", "").lower()
    user = process_info.get("user", "").lower()
    lineage = process_info.get("lineage", [])
    
    # Add context-based techniques
    context_techniques = []
    
    # Process type-specific techniques
    if process_name in ["powershell.exe", "pwsh.exe"]:
        context_techniques.append({
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        })
    elif process_name in ["cmd.exe"]:
        context_techniques.append({
            "technique_id": "T1059.003",
            "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution"
        })
    elif process_name in ["wscript.exe", "cscript.exe"]:
        context_techniques.append({
            "technique_id": "T1059.005",
            "technique_name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution"
        })
    elif process_name in ["rundll32.exe"]:
        context_techniques.append({
            "technique_id": "T1218.011",
            "technique_name": "Signed Binary Proxy Execution: Rundll32",
            "tactic": "Defense Evasion"
        })
    elif process_name in ["regsvr32.exe"]:
        context_techniques.append({
            "technique_id": "T1218.010",
            "technique_name": "Signed Binary Proxy Execution: Regsvr32",
            "tactic": "Defense Evasion"
        })
    
    # User context
    if "system" in user:
        context_techniques.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": "Persistence"
        })
    elif "administrator" in user or "admin" in user:
        context_techniques.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": "Persistence"
        })
    
    # Command line analysis
    if ("http:" in cmdline or "https:" in cmdline) and any(tool in cmdline for tool in 
        ["powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta"]):
        context_techniques.append({
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control"
        })
    
    if "-enc" in cmdline or "-encodedcommand" in cmdline or "frombase64string" in cmdline:
        context_techniques.append({
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        })
    
    # Special handling for suspicious behaviors
    if event_type == "SUSPICIOUS_BEHAVIOR" and isinstance(detection_details, list):
        for pattern in detection_details:
            pattern_lower = pattern.lower()
            
            if "temp directory" in pattern_lower or "unusual directory" in pattern_lower:
                context_techniques.append({
                    "technique_id": "T1074", 
                    "technique_name": "Data Staged",
                    "tactic": "Collection",
                    "evidence": pattern
                })
            
            elif "unusual port" in pattern_lower:
                context_techniques.append({
                    "technique_id": "T1571", 
                    "technique_name": "Non-Standard Port",
                    "tactic": "Command and Control",
                    "evidence": pattern
                })
            
            elif "encoded command" in pattern_lower or "powershell" in pattern_lower and "encoded" in pattern_lower:
                context_techniques.append({
                    "technique_id": "T1027", 
                    "technique_name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion",
                    "evidence": pattern
                })
            
            elif "webshell" in pattern_lower or "w3wp.exe" in pattern_lower and "cmd" in pattern_lower:
                context_techniques.append({
                    "technique_id": "T1505.003", 
                    "technique_name": "Server Software Component: Web Shell",
                    "tactic": "Persistence",
                    "evidence": pattern
                })
            
            elif "lolbin" in pattern_lower:
                context_techniques.append({
                    "technique_id": "T1218", 
                    "technique_name": "Signed Binary Proxy Execution",
                    "tactic": "Defense Evasion",
                    "evidence": pattern
                })
    
    # Memory-related issues
    if event_type == "SUSPICIOUS_MEMORY_REGION":
        # Look for specific memory injection techniques
        rwx_memory = False
        large_exec = False
        
        if detection_details and isinstance(detection_details, list):
            for region in detection_details:
                if isinstance(region, dict):
                    reason = region.get("reason", "").lower()
                    if "rwx" in reason:
                        rwx_memory = True
                    elif "large executable" in reason:
                        large_exec = True
        
        if rwx_memory:
            context_techniques.append({
                "technique_id": "T1055.001",
                "technique_name": "Process Injection: Dynamic-link Library Injection",
                "tactic": "Defense Evasion"
            })
        elif large_exec:
            context_techniques.append({
                "technique_id": "T1055.002",
                "technique_name": "Process Injection: Portable Executable Injection",
                "tactic": "Defense Evasion"
            })
    
    # ML anomaly details
    if event_type == "ML_DETECTED_ANOMALY" and isinstance(detection_details, dict):
        # Get info about which features contributed to anomaly
        features = detection_details.get("features", {})
        
        if features.get("connection_count", 0) > 30:
            context_techniques.append({
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "tactic": "Command and Control"
            })
        
        if features.get("child_processes", 0) > 10:
            context_techniques.append({
                "technique_id": "T1106",
                "technique_name": "Native API",
                "tactic": "Execution"
            })
    
    # Combine all techniques
    all_techniques = techniques + context_techniques
    
    # Deduplicate techniques
    unique_techniques = []
    seen_ids = set()
    
    for technique in all_techniques:
        technique_id = technique["technique_id"]
        if technique_id not in seen_ids:
            unique_techniques.append(technique)
            seen_ids.add(technique_id)
    
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
    """Calculate a threat score for a process based on detections and context."""
    base_score = 0
    reasons = []
    
    # Process metadata factors
    process_name = process_info.get("process_name", "").lower()
    user = process_info.get("user", "").lower()
    exe_path = process_info.get("exe_path", "").lower()
    port = process_info.get("port", 0)
    lineage = process_info.get("lineage", [])
    
    # Consider process age in scoring
    try:
        process = psutil.Process(process_info.get("pid", 0))
        process_age_seconds = time.time() - process.create_time()
        
        # New processes are more suspicious
        if process_age_seconds < 300:  # 5 minutes
            base_score += 10
            reasons.append("Recently created process")
    except:
        pass
    
    # 1. Score based on user context
    if "system" in user:
        base_score += 10
        reasons.append("Running as SYSTEM")
    elif "admin" in user or "administrator" in user:
        base_score += 8
        reasons.append("Running as Administrator")
    
    # 2. Score based on process lineage
    suspicious_ancestry = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", 
                         "rundll32.exe", "regsvr32.exe", "mshta.exe"]
                         
    for proc in lineage:
        proc_lower = proc.lower()
        if proc_lower in [s.lower() for s in suspicious_ancestry]:
            base_score += 15
            reasons.append(f"Suspicious process in lineage: {proc}")
            break
    
    # 3. Score based on execution path
    suspicious_paths = ["\\temp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", 
                      "\\users\\public\\", "\\programdata\\", "\\downloads\\"]
                      
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
        elif port > 10000 and port not in [27017, 28017, 50070, 50075, 50030, 50060, 8080, 8443]:
            base_score += 15
            reasons.append(f"Listening on high non-standard port: {port}")
    
    # 5. Score based on detection events
    for event in detection_events:
        event_type = event.get("type", "")
        
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
            anomaly_score = details.get("score", 0)
            
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
            patterns = event.get("details", [])
            if patterns:
                for pattern in patterns:
                    pattern_lower = pattern.lower() if isinstance(pattern, str) else ""
                    
                    if "webshell" in pattern_lower:
                        base_score += 40
                        reasons.append("Potential web shell detected")
                    elif "malicious port" in pattern_lower:
                        base_score += 30
                        reasons.append("Known malicious port detected")
                    elif "encoded command" in pattern_lower:
                        base_score += 35
                        reasons.append("Obfuscated command execution detected")
                    elif "powershell" in pattern_lower and "encoded" in pattern_lower:
                        base_score += 35
                        reasons.append("PowerShell encoded command detected")
                    elif "lolbin" in pattern_lower:
                        base_score += 30
                        reasons.append("LOLBin (Living Off The Land Binary) abuse detected")
                    else:
                        base_score += 15
                        reasons.append(f"Suspicious behavior: {pattern}")
            else:
                # Handle simple pattern
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
            
        elif event_type == "PROCESS_RUNTIME_CHANGES":
            # Look for specific changes
            if isinstance(event.get("details"), list):
                for change in event.get("details", []):
                    if isinstance(change, dict):
                        field = change.get("field", "")
                        if field == "thread_count":
                            # Calculate magnitude of thread change
                            delta = change.get("delta", 0)
                            if delta > 20:
                                base_score += 25
                                reasons.append(f"Extreme thread count increase: +{delta} threads")
                            elif delta > 10:
                                base_score += 15
                                reasons.append(f"Major thread count increase: +{delta} threads")
                        elif field == "cmdline":
                            base_score += 30
                            reasons.append("Command line modified during execution")
                        elif field == "user":
                            base_score += 40
                            reasons.append("Process user context changed during execution")
    
    # 6. Special cases for known malicious processes
    special_case_malware = [
        "mimikatz", "meterpreter", "cobaltstrike", "empire", "beacon"
    ]
    
    if any(malware in process_name or malware in exe_path 
           for malware in special_case_malware):
        base_score += 100
        reasons.append(f"Known malicious tool signature: {process_name}")
    
    # 7. Cap and categorize score
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

def check_process_name_consistency(process_info, integrity_state):
    """
    Check if a process name is used by another executable in integrity_state.
    This detects potential masquerading attacks using both executable path and process lineage.
    """
    process_name = process_info.get("process_name")
    exe_path = process_info.get("exe_path")
    process_hash = process_info.get("hash")
    process_lineage = process_info.get("lineage", [])
    
    # Skip check for invalid process info
    if not process_name or not exe_path or not process_hash:
        return None
    
    # Find all processes with the same name in integrity state
    matching_processes = []
    
    # *** CHANGE HERE: Add a tracking set to prevent duplicate alerts ***
    seen_alerts = set()
    
    for hash_key, stored_info in integrity_state.items():
        # Skip comparing with self
        if hash_key == process_hash:
            continue
            
        # Check if name matches
        if stored_info.get("process_name") == process_name:
            # Different path is immediate red flag
            if stored_info.get("exe_path") != exe_path:
                # *** CHANGE HERE: Create a unique key for this alert ***
                alert_key = f"{process_name}:{exe_path}:{stored_info.get('exe_path')}:path_mismatch"
                
                if alert_key not in seen_alerts:
                    seen_alerts.add(alert_key)
                    matching_processes.append({
                        "info": stored_info,
                        "reason": "Path mismatch",
                        "severity": "high"
                    })
                continue
                
            # Same path but different lineage
            stored_lineage = stored_info.get("lineage", [])
            if stored_lineage and process_lineage and stored_lineage != process_lineage:
                # Check if lineage differs in significant ways
                # For example, legitimate services usually have services.exe in lineage
                legitimate_service = any("services.exe" in parent.lower() for parent in stored_lineage)
                current_service = any("services.exe" in parent.lower() for parent in process_lineage)
                
                if legitimate_service != current_service:
                    # *** CHANGE HERE: Create a unique key for this alert ***
                    alert_key = f"{process_name}:{exe_path}:service_ancestry"
                    
                    if alert_key not in seen_alerts:
                        seen_alerts.add(alert_key)
                        matching_processes.append({
                            "info": stored_info,
                            "reason": "Lineage mismatch (service ancestry)",
                            "severity": "high"
                        })
                    continue
                
                # Check for suspicious parent processes in current lineage
                suspicious_parents = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
                has_suspicious_parent = any(parent.lower() in suspicious_parents 
                                           for parent in process_lineage)
                
                if has_suspicious_parent:
                    # *** CHANGE HERE: Create a unique key for this alert ***
                    alert_key = f"{process_name}:{exe_path}:suspicious_ancestor"
                    
                    if alert_key not in seen_alerts:
                        seen_alerts.add(alert_key)
                        matching_processes.append({
                            "info": stored_info,
                            "reason": "Suspicious ancestor in lineage",
                            "severity": "high"
                        })
                    continue
                
                # Significant lineage deviation
                if len(stored_lineage) > 0 and len(process_lineage) > 0:
                    # Compare top-level ancestors (often most significant)
                    if stored_lineage[0] != process_lineage[0]:
                        # *** CHANGE HERE: Create a unique key for this alert ***
                        alert_key = f"{process_name}:{exe_path}:root_ancestor"
                        
                        if alert_key not in seen_alerts:
                            seen_alerts.add(alert_key)
                            matching_processes.append({
                                "info": stored_info,
                                "reason": "Root ancestor mismatch",
                                "severity": "medium"
                            })
                        continue
    
    if not matching_processes:
        # No name conflict with different paths or suspicious lineage
        return None
    
    # Found processes with same name but issues - create alerts
    impersonation_alerts = []
    
    for match in matching_processes:
        matching_proc = match["info"]
        reason = match["reason"]
        severity = match["severity"]
        
        alert = {
            "type": "PROCESS_NAME_IMPERSONATION",
            "details": {
                "process_name": process_name,
                "reason": reason,
                "severity": severity,
                "original_process": {
                    "exe_path": matching_proc.get("exe_path"),
                    "hash": matching_proc.get("hash"),
                    "cmdline": matching_proc.get("cmdline"),
                    "user": matching_proc.get("user"),
                    "lineage": matching_proc.get("lineage")
                },
                "impersonating_process": {
                    "pid": process_info.get("pid"),
                    "exe_path": exe_path,
                    "hash": process_hash,
                    "cmdline": process_info.get("cmdline"),
                    "user": process_info.get("user"),
                    "lineage": process_lineage,
                    "port": process_info.get("port")
                }
            }
        }
        impersonation_alerts.append(alert)
    
    return impersonation_alerts if impersonation_alerts else None

def remove_malicious_process(process_hash, pid, integrity_state):
    """Remove malicious process information from integrity_state and save it."""
    if process_hash in integrity_state:
        logging.info(f"Removing malicious process with hash {process_hash} from integrity file")
        del integrity_state[process_hash]
        save_process_metadata(integrity_state)
        return True
    return False

def check_application_existence():
    """Validate processes in integrity file and remove those whose executables no longer exist."""
    integrity_state = load_process_metadata()
    modified = False
    
    # Create a copy of keys to avoid modification during iteration
    process_hashes = list(integrity_state.keys())
    
    for process_hash in process_hashes:
        process_info = integrity_state[process_hash]
        exe_path = process_info.get("exe_path", "")
        
        # Skip entries with invalid paths
        if not exe_path or exe_path == "ACCESS_DENIED":
            continue
        
        # Check if executable still exists
        if not os.path.exists(exe_path):
            logging.info(f"Removing process with missing executable: {exe_path}")
            del integrity_state[process_hash]
            modified = True
    
    # Save changes if any were made
    if modified:
        save_process_metadata(integrity_state)
        
    return modified

def periodic_cleanup(interval=3600):
    """Periodically validate and clean up integrity file."""
    global SERVICE_RUNNING
    
    logging.info("Starting periodic cleanup thread...")
    
    # Counter for less frequent maintenance
    maintenance_counter = 0
    
    while SERVICE_RUNNING:
        try:
            # Sleep first to avoid immediate cleanup on startup
            time.sleep(interval)
            
            if not SERVICE_RUNNING:
                break
                
            logging.info("Running periodic cleanup of integrity file...")
            
            # Standard cleanup (existing functionality)
            modified = check_application_existence()
            
            if modified:
                logging.info("Removed entries for non-existent applications from integrity file")
            else:
                logging.info("Integrity file is up-to-date")
            
            # Process group maintenance (run less frequently)
            maintenance_counter += 1
            if maintenance_counter >= 24:  # Run once per day (if interval is hourly)
                maintenance_counter = 0
                
                # Load latest state
                integrity_state = load_process_metadata()
                
                # Perform maintenance
                if maintain_process_groups(integrity_state):
                    # Save if modified
                    save_process_metadata(integrity_state)
                    logging.info("Process group maintenance completed with changes")
                else:
                    logging.info("Process group maintenance completed (no changes)")
                
        except Exception as e:
            logging.error(f"Error in periodic cleanup: {e}")
            logging.debug(traceback.format_exc())

def maintain_process_groups(integrity_state, max_age_days=30):
    """
    Maintain process groups by cleaning old hashes and merging similar groups.
    Returns True if changes were made to integrity_state.
    """
    if "process_groups" not in integrity_state:
        return False
    
    modified = False
    now = datetime.now()
    cutoff_date = now - timedelta(days=max_age_days)
    
    # 1. Clean old hashes
    for group_id, group in integrity_state["process_groups"].items():
        # Special handling for browsers and other multi-process applications
        browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"]
        is_browser = any(browser in group_id.lower() for browser in browser_processes)
        
        # Different retention policies based on process type
        group_cutoff = cutoff_date
        if is_browser:
            # Browsers can have many short-lived processes, use shorter retention
            # But keep at least the most recent 5 hashes regardless of age
            recent_hashes = sorted(
                [(h, d.get("last_seen", "")) for h, d in group["known_hashes"].items()],
                key=lambda x: x[1],
                reverse=True
            )
            
            # Keep the 5 most recent hashes regardless of age
            hashes_to_keep = set([h for h, _ in recent_hashes[:5]])
            
            # Use a shorter cutoff for browsers (15 days)
            browser_cutoff = now - timedelta(days=15)
            
            # Remove old hashes except the 5 most recent
            for hash_id in list(group["known_hashes"].keys()):
                if hash_id in hashes_to_keep:
                    continue
                    
                hash_data = group["known_hashes"][hash_id]
                last_seen_str = hash_data.get("last_seen")
                
                if not last_seen_str:
                    continue
                    
                try:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    if last_seen < browser_cutoff:
                        # This hash hasn't been seen recently, remove it
                        del group["known_hashes"][hash_id]
                        modified = True
                        logging.info(f"Removed old browser hash {hash_id} from {group_id}")
                except (ValueError, TypeError):
                    # Invalid date format, skip
                    continue
        else:
            # Standard retention policy for non-browser processes
            for hash_id in list(group["known_hashes"].keys()):
                hash_data = group["known_hashes"][hash_id]
                last_seen_str = hash_data.get("last_seen")
                
                if not last_seen_str:
                    continue
                    
                try:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    if last_seen < cutoff_date:
                        # This hash hasn't been seen in a long time, remove it
                        del group["known_hashes"][hash_id]
                        modified = True
                        logging.info(f"Removed old hash {hash_id} from {group_id}")
                except (ValueError, TypeError):
                    # Invalid date format, skip
                    continue
        
        # Clean up command line patterns for browsers
        # They can accumulate many different patterns with random data
        if is_browser and len(group["command_line_patterns"]) > 30:
            # Keep only the 30 most representative patterns
            group["command_line_patterns"] = group["command_line_patterns"][:30]
            modified = True
            logging.info(f"Trimmed excess command line patterns for {group_id}")
    
    # 2. Find and merge similar groups
    # Group process groups by process name
    name_to_groups = {}
    for group_id, group in integrity_state["process_groups"].items():
        process_name = group["process_name"].lower()
        if process_name not in name_to_groups:
            name_to_groups[process_name] = []
        name_to_groups[process_name].append((group_id, group))
    
    # Look for groups with the same name but different paths
    for process_name, groups in name_to_groups.items():
        if len(groups) <= 1:
            continue
            
        # Check if these groups are similar enough to merge
        for i in range(len(groups)):
            for j in range(i+1, len(groups)):
                group1_id, group1 = groups[i]
                group2_id, group2 = groups[j]
                
                # Skip already processed groups
                if group1_id not in integrity_state["process_groups"] or group2_id not in integrity_state["process_groups"]:
                    continue
                
                # Check path similarity
                path1 = group1["exe_path"].lower()
                path2 = group2["exe_path"].lower()
                
                # If paths are very similar (e.g., case difference or x86 vs x64 paths)
                if (path1 == path2 or
                    path1.replace("program files", "program files (x86)") == path2 or
                    path2.replace("program files", "program files (x86)") == path1):
                    
                    # Merge group2 into group1
                    logging.info(f"Merging similar process groups for {process_name}: {path1} and {path2}")
                    
                    # Merge known hashes
                    for hash_id, hash_data in group2["known_hashes"].items():
                        if hash_id not in group1["known_hashes"]:
                            group1["known_hashes"][hash_id] = hash_data
                        else:
                            # Update detection count if hash exists in both groups
                            group1["known_hashes"][hash_id]["detection_count"] += hash_data["detection_count"]
                            
                            # Use the more recent last_seen date
                            try:
                                last_seen1 = datetime.fromisoformat(group1["known_hashes"][hash_id]["last_seen"])
                                last_seen2 = datetime.fromisoformat(hash_data["last_seen"])
                                if last_seen2 > last_seen1:
                                    group1["known_hashes"][hash_id]["last_seen"] = hash_data["last_seen"]
                            except (ValueError, TypeError):
                                pass
                    
                    # Merge command line patterns
                    for pattern in group2["command_line_patterns"]:
                        if pattern not in group1["command_line_patterns"]:
                            group1["command_line_patterns"].append(pattern)
                    
                    # Merge lineage patterns
                    for lineage in group2["common_lineage_patterns"]:
                        if not any(match_lineage_pattern(lineage, pattern) for pattern in group1["common_lineage_patterns"]):
                            group1["common_lineage_patterns"].append(lineage)
                    
                    # Remove the merged group
                    del integrity_state["process_groups"][group2_id]
                    modified = True
    
    # 3. Clean up any individual process entries that no longer have executable files
    # First identify process entries to remove (not in process_groups)
    processes_to_remove = []
    for process_hash, process_info in integrity_state.items():
        # Skip process_groups and non-dictionary entries
        if process_hash == "process_groups" or not isinstance(process_info, dict):
            continue
            
        exe_path = process_info.get("exe_path", "")
        
        # If exe_path is provided and file doesn't exist, mark for removal
        if exe_path and exe_path != "ACCESS_DENIED" and not os.path.exists(exe_path):
            processes_to_remove.append(process_hash)
    
    # Remove the identified processes
    for process_hash in processes_to_remove:
        if process_hash in integrity_state:
            process_info = integrity_state[process_hash]
            logging.info(f"Removing process entry with missing executable: {process_info.get('process_name', '')} at {process_info.get('exe_path', '')}")
            del integrity_state[process_hash]
            modified = True
    
    if modified:
        logging.info(f"Process group maintenance completed with {len(integrity_state['process_groups'])} groups")
    
    return modified

def log_event_to_pim(event_type, file_path, previous_metadata, new_metadata, previous_hash, new_hash, priority=None):
    """Log security events to a central JSON file with clear change descriptions and MITRE ATT&CK classification."""
    try:
        # Import builtins in case open is undefined in this context
        import builtins
        
        # Define the log file path
        pim_log_file = os.path.join(BASE_DIR, "logs", "pim.json")
        os.makedirs(os.path.dirname(pim_log_file), exist_ok=True)
        
        # Determine what actually changed to create a more specific event type
        specific_event_type = event_type
        change_details = {}
        
        if event_type == "PROCESS_METADATA_CHANGED" and previous_metadata and new_metadata:
            # Compare metadata to identify specific changes
            specific_changes = []
            
            # Important fields to check
            key_fields = [
                ("port", "PORT_BINDING_CHANGED"),
                ("cmdline", "COMMAND_LINE_CHANGED"),
                ("user", "USER_CONTEXT_CHANGED"),
                ("exe_path", "EXECUTABLE_PATH_CHANGED"),
                ("ppid", "PARENT_PROCESS_CHANGED"),
                ("hash", "HASH_CHANGED")
            ]
            
            # Check for differences in key fields
            for field, field_event_type in key_fields:
                prev_value = previous_metadata.get(field)
                new_value = new_metadata.get(field)
                
                if prev_value != new_value:
                    # Add to list of specific changes
                    specific_changes.append(field_event_type)
                    
                    # Add detailed change info
                    change_details[field] = {
                        "previous": prev_value,
                        "current": new_value,
                        "description": f"{field.capitalize()} changed from '{prev_value}' to '{new_value}'"
                    }
            
            # Check for memory changes
            if "memory_rss_kb" in previous_metadata and "memory_rss_kb" in new_metadata:
                prev_mem = previous_metadata.get("memory_rss_kb", 0)
                new_mem = new_metadata.get("memory_rss_kb", 0)
                mem_delta = new_mem - prev_mem
                
                # Only flag significant memory changes (>50MB)
                if abs(mem_delta) > 51200:  # 50MB
                    specific_changes.append("MEMORY_USAGE_SIGNIFICANT_CHANGE")
                    change_details["memory"] = {
                        "previous": prev_mem,
                        "current": new_mem,
                        "delta": mem_delta,
                        "delta_mb": round(mem_delta / 1024, 2),
                        "description": f"Memory usage {'increased' if mem_delta > 0 else 'decreased'} by {abs(mem_delta // 1024)} MB"
                    }
            
            # Check for thread count changes
            if "thread_count" in previous_metadata and "thread_count" in new_metadata:
                prev_threads = previous_metadata.get("thread_count", 0)
                new_threads = new_metadata.get("thread_count", 0)
                thread_delta = new_threads - prev_threads
                
                # Calculate percentage change if previous count was non-zero
                thread_percentage = 0
                if prev_threads > 0:
                    thread_percentage = (new_threads / prev_threads * 100) - 100
                
                # Apply appropriate thresholds based on process type
                process_name = new_metadata.get("process_name", "").lower()
                benign_variable_processes = [
                    "nissrv.exe", "msmpeng.exe", "svchost.exe", "searchindexer.exe", 
                    "mssearch.exe", "sqlservr.exe", "w3wp.exe", "iisexpress.exe"
                ]
                
                is_benign_variable = process_name in benign_variable_processes
                
                # Only report significant thread changes
                if ((not is_benign_variable and (thread_delta > 10 or thread_percentage > 300)) or 
                    (is_benign_variable and thread_delta > 20 and thread_percentage > 500)):
                    specific_changes.append("THREAD_COUNT_SIGNIFICANT_CHANGE")
                    change_details["threads"] = {
                        "previous": prev_threads,
                        "current": new_threads,
                        "delta": thread_delta,
                        "percentage": round(thread_percentage, 1),
                        "description": f"Thread count {'increased' if thread_delta > 0 else 'decreased'} by {abs(thread_delta)} ({round(abs(thread_percentage), 1)}%)"
                    }
            
            # If no specific changes were identified, or only minor changes in benign processes,
            # return True without logging to reduce noise
            if not specific_changes:
                return True
            
            # If only minor thread changes in a benign process, skip logging
            if (len(specific_changes) == 1 and 
                specific_changes[0] == "THREAD_COUNT_SIGNIFICANT_CHANGE" and
                is_benign_variable and
                thread_delta <= 30):
                return True
            
            # Update the event type to be more specific
            if len(specific_changes) == 1:
                specific_event_type = specific_changes[0]
            else:
                # Join multiple changes with underscores
                specific_event_type = "MULTIPLE_CHANGES"
        
        elif event_type == "PROCESS_RUNTIME_CHANGES" and "detected_changes" in new_metadata:
            # Extract detailed change information from detected_changes
            changes = new_metadata.get("detected_changes", [])
            
            if changes:
                change_fields = [change.get("field", "") for change in changes]
                
                # Categorize based on most significant change
                if "user" in change_fields:
                    specific_event_type = "USER_CONTEXT_CHANGED"
                elif "cmdline" in change_fields:
                    specific_event_type = "COMMAND_LINE_MODIFIED_DURING_EXECUTION"
                elif "thread_count" in change_fields:
                    specific_event_type = "THREAD_COUNT_SIGNIFICANT_CHANGE"
                elif "memory_rss_kb" in change_fields:
                    specific_event_type = "MEMORY_USAGE_SIGNIFICANT_CHANGE"
                
                # Add detailed change descriptions
                for change in changes:
                    field = change.get("field", "")
                    severity = change.get("severity", "low")
                    
                    prev_value = change.get("previous", "")
                    current_value = change.get("current", "")
                    delta = change.get("delta", 0) if "delta" in change else None
                    
                    # Create descriptive message
                    if delta is not None:
                        if field == "thread_count":
                            description = f"Thread count {'increased' if delta > 0 else 'decreased'} by {abs(delta)}"
                            if "percentage" in change:
                                description += f" ({round(abs(change.get('percentage', 0)), 1)}%)"
                        elif field == "memory_rss_kb":
                            description = f"Memory usage {'increased' if delta > 0 else 'decreased'} by {abs(delta // 1024)} MB"
                        else:
                            description = f"{field.capitalize()} changed by {delta}"
                    else:
                        description = f"{field.capitalize()} changed from '{prev_value}' to '{current_value}'"
                    
                    change_details[field] = {
                        "previous": prev_value,
                        "current": current_value,
                        "delta": delta,
                        "severity": severity,
                        "description": description
                    }
        
        # Determine event priority if not specified
        if priority is None:
            if specific_event_type in ["USER_CONTEXT_CHANGED", "HASH_CHANGED", "EXECUTABLE_PATH_CHANGED", 
                                     "PROCESS_NAME_IMPERSONATION", "FILELESS_PROCESS_DETECTED"]:
                priority = "critical"
            elif specific_event_type in ["COMMAND_LINE_MODIFIED_DURING_EXECUTION", "PARENT_PROCESS_CHANGED",
                                       "SUSPICIOUS_MEMORY_REGION", "SUSPICIOUS_BEHAVIOR"]:
                priority = "high"
            elif specific_event_type in ["PORT_BINDING_CHANGED", "MEMORY_USAGE_SIGNIFICANT_CHANGE",
                                       "THREAD_COUNT_SIGNIFICANT_CHANGE", "UNUSUAL_PORT_USE"]:
                priority = "medium"
            else:
                priority = "info"
        
        # Apply MITRE ATT&CK classification
        mitre_techniques = []
        mitre_technique_names = []
        
        # Use existing MITRE classification if available
        if new_metadata and "mitre_techniques" in new_metadata:
            mitre_techniques = new_metadata.get("mitre_techniques", [])
            mitre_technique_names = new_metadata.get("mitre_technique_names", [])
        else:
            # Map specific event types to MITRE techniques
            event_mitre_map = {
                "USER_CONTEXT_CHANGED": ["T1078", "Valid Accounts"],
                "HASH_CHANGED": ["T1036", "Masquerading"],
                "EXECUTABLE_PATH_CHANGED": ["T1036", "Masquerading"],
                "COMMAND_LINE_MODIFIED_DURING_EXECUTION": ["T1055", "Process Injection"],
                "MEMORY_USAGE_SIGNIFICANT_CHANGE": ["T1055", "Process Injection"],
                "THREAD_COUNT_SIGNIFICANT_CHANGE": ["T1055", "Process Injection"],
                "PORT_BINDING_CHANGED": ["T1571", "Non-Standard Port"],
                "PARENT_PROCESS_CHANGED": ["T1055", "Process Injection"],
                "FILELESS_PROCESS_DETECTED": ["T1027", "Obfuscated Files or Information"]
            }
            
            # Get basic MITRE mapping
            if specific_event_type in event_mitre_map:
                technique_id, technique_name = event_mitre_map[specific_event_type]
                mitre_techniques.append(technique_id)
                mitre_technique_names.append(technique_name)
            
            # For more nuanced mapping, use the classify_by_mitre_attck function
            process_info = new_metadata if new_metadata else previous_metadata
            
            if process_info:
                # Use change_details as detection details
                mitre_info = classify_by_mitre_attck(specific_event_type, process_info, change_details)
                
                if mitre_info:
                    techniques = mitre_info.get("techniques", [])
                    for technique in techniques:
                        technique_id = technique.get("technique_id")
                        technique_name = technique.get("technique_name")
                        
                        if technique_id and technique_id not in mitre_techniques:
                            mitre_techniques.append(technique_id)
                            if technique_name:
                                mitre_technique_names.append(technique_name)
        
        # Create enhanced event data with specific change details
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": specific_event_type,
            "original_event_type": event_type if specific_event_type != event_type else None,
            "priority": priority,
            "file_path": file_path,
            "process_name": (new_metadata or previous_metadata or {}).get("process_name", "UNKNOWN"),
            "pid": (new_metadata or previous_metadata or {}).get("pid", 0),
            "change_details": change_details,
            "previous_metadata": previous_metadata,
            "new_metadata": new_metadata,
            "previous_hash": previous_hash,
            "new_hash": new_hash,
            "mitre_techniques": mitre_techniques,
            "mitre_technique_names": mitre_technique_names
        }
        
        # Get current events
        events = []
        if os.path.exists(pim_log_file):
            try:
                with builtins.open(pim_log_file, "r") as f:
                    events = json.load(f)
            except json.JSONDecodeError:
                logging.warning(f"Error parsing {pim_log_file}, starting fresh")
                events = []
            except Exception as e:
                logging.error(f"Error reading {pim_log_file}: {e}")
                events = []
        
        # Add new event
        events.append(event)
        
        # Keep only last 1000 events to prevent file from growing too large
        if len(events) > 1000:
            events = events[-1000:]
            
        # Write updated events with safer file handling
        temp_file = f"{pim_log_file}.tmp"
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(temp_file), exist_ok=True)
            
            # Write to temp file
            with builtins.open(temp_file, "w") as f:
                json.dump(events, f, indent=2)
            
            # Try different approaches for file replacement
            try:
                # First try regular atomic replacement
                if os.path.exists(pim_log_file):
                    # Try to set file permissions to allow writing
                    try:
                        os.chmod(pim_log_file, 0o666)  # Read/write for everyone
                    except:
                        pass
                
                # Now try the replacement
                os.replace(temp_file, pim_log_file)
                
            except PermissionError:
                # If replacement fails, try direct content copy
                with builtins.open(temp_file, "r") as src:
                    content = src.read()
                
                # Direct write
                with builtins.open(pim_log_file, "w") as f:
                    f.write(content)
                
                # Clean up temp file
                try:
                    os.remove(temp_file)
                except:
                    pass
            
            # Log detailed change information
            process_name = (new_metadata or previous_metadata or {}).get("process_name", "UNKNOWN")
            pid = (new_metadata or previous_metadata or {}).get("pid", 0)
            
            # Create descriptive log message
            log_descriptions = []
            for field, details in change_details.items():
                if "description" in details:
                    log_descriptions.append(details["description"])
            
            description_str = "; ".join(log_descriptions)
            mitre_str = ", ".join(mitre_techniques) if mitre_techniques else "None"
            
            # Log the specific changes that occurred
            logging.warning(f"{specific_event_type}: {process_name} (PID: {pid}) - {description_str} - MITRE: {mitre_str}")
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to write to temp log file: {e}")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            return False
            
    except Exception as e:
        logging.error(f"Failed to log event: {e}")
        return False

def periodic_integrity_scan(interval=120):
    """Periodically scan processes for integrity issues and changes."""
    global SERVICE_RUNNING
    
    logging.info("Starting periodic integrity scan...")
    
    # For tracking rapid termination and creation of processes (like browser tabs)
    recently_terminated_pids = {}  # Map PID to hash and timestamp
    suppression_timeout = 60  # Seconds to suppress alerts for same process type
    
    while SERVICE_RUNNING:
        try:
            logging.info("Running integrity check on listening processes...")
            
            # Load stored process metadata
            integrity_state = load_process_metadata()
            
            # Get current active processes
            current_processes = get_listening_processes()
            
            # Convert to hash-based structure
            current_hash_to_process = {}
            for process_info in current_processes.values():
                process_hash = process_info.get("hash")
                if process_hash and process_hash not in ["ERROR_HASHING_PERMISSION", "ERROR_FILE_NOT_FOUND"]:
                    current_hash_to_process[process_hash] = process_info
            
            # Check current processes against stored metadata
            for process_hash, current_info in current_hash_to_process.items():
                pid = current_info.get("pid")
                
                # Skip system process (PID 4)
                if pid == 4:
                    continue
                
                # Skip if no stored metadata for this hash
                if process_hash not in integrity_state:
                    process_name = current_info.get("process_name", "UNKNOWN")
                    if process_name != "UNKNOWN":  # Only log for valid processes
                        # Check if this is a browser or similar multi-process application
                        browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"]
                        is_browser = process_name.lower() in [b.lower() for b in browser_processes]
                        
                        # Suppress excessive notifications for browsers with multiple processes
                        # Check if we recently terminated a similar process name
                        suppress_alert = False
                        if is_browser:
                            current_time = time.time()
                            for term_pid, (term_hash, term_time, term_name) in list(recently_terminated_pids.items()):
                                # If this is a similar process and was terminated recently
                                if (term_name.lower() == process_name.lower() and
                                    current_time - term_time < suppression_timeout):
                                    suppress_alert = True
                                    logging.debug(f"Suppressing alert for new browser process {process_name} (PID: {pid}) - similar process recently terminated")
                                    break
                                # Clean up old entries
                                elif current_time - term_time > suppression_timeout:
                                    del recently_terminated_pids[term_pid]
                        
                        if not suppress_alert:
                            logging.warning(f"Untracked process detected: {process_name} (PID: {pid})")
                            log_event_to_pim(
                                event_type="NEW_UNTRACKED_PROCESS",
                                file_path=current_info.get("exe_path", ""),
                                previous_metadata=None,
                                new_metadata=current_info,
                                previous_hash=None,
                                new_hash=process_hash
                            )
                    continue
                
                # Get stored metadata
                stored_info = integrity_state[process_hash]
                
                # Check for metadata changes
                changes_detected = False
                key_fields = ["exe_path", "user", "port", "cmdline"]
                changed_fields = {}
                
                for field in key_fields:
                    if stored_info.get(field) != current_info.get(field):
                        # For browsers, don't treat every cmdline change as significant
                        if field == "cmdline" and is_browser_process(current_info.get("process_name", "")):
                            # Compare patterns instead of raw command lines
                            stored_pattern = simplify_command_line(stored_info.get(field, ""))
                            current_pattern = simplify_command_line(current_info.get(field, ""))
                            
                            # Only consider it changed if patterns differ significantly
                            if stored_pattern != current_pattern:
                                changed_fields[field] = {
                                    "previous": stored_info.get(field),
                                    "current": current_info.get(field)
                                }
                        else:
                            changed_fields[field] = {
                                "previous": stored_info.get(field),
                                "current": current_info.get(field)
                            }
                
                if changed_fields:
                    logging.warning(
                        f"Metadata changes detected for PID {pid}: {list(changed_fields.keys())}"
                    )
                    log_event_to_pim(
                        event_type="PROCESS_METADATA_CHANGED",
                        file_path=current_info.get("exe_path", ""),
                        previous_metadata=stored_info,
                        new_metadata=current_info,
                        previous_hash=stored_info.get("hash", ""),
                        new_hash=process_hash
                    )
                    changes_detected = True
                
                # Update tracking if changes were detected
                if changes_detected:
                    update_process_tracking(
                        current_info.get("exe_path", ""),
                        process_hash,
                        current_info
                    )
            
            # Sleep until next check
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in periodic integrity scan: {e}")
            logging.debug(traceback.format_exc())
            time.sleep(interval)

def detect_process_hollowing(pid, process_info):
    """
    Detect signs of process hollowing by checking for suspicious memory patterns
    and PEB inconsistencies.
    """
    suspicious_indicators = []
    
    try:
        # Get process executable path
        exe_path = process_info.get("exe_path", "")
        if not exe_path or exe_path == "ACCESS_DENIED":
            return []
            
        # Get memory regions for the process
        memory_regions = enumerate_process_memory_regions(pid)
        
        # Check for unmapped main module - a sign of hollowing
        main_module_found = False
        image_base_address = None
        has_unmapped_exec = False
        
        # Store regions by type for analysis
        image_regions = []
        private_regions = []
        
        for region in memory_regions:
            if region["type"] == "Image" and "0x" in region["address"]:
                # Convert to int for address comparison
                addr = int(region["address"].replace("0x", ""), 16)
                image_regions.append(region)
                
                # Store the lowest image base address (likely the main module)
                if image_base_address is None or addr < image_base_address:
                    image_base_address = addr
                    main_module_found = True
            elif region["type"] == "Private":
                private_regions.append(region)
                
                # Check for executable private memory
                if region["protection"]["executable"]:
                    has_unmapped_exec = True
        
        if not main_module_found and has_unmapped_exec:
            suspicious_indicators.append({
                "indicator": "Classic process hollowing",
                "description": "Process lacks main module mapping but has executable memory",
                "severity": "critical",
                "region": {"address": "N/A", "size_kb": 0}
            })
            
        # Check for PE header at beginning of private executable regions
        # This is a common pattern in process hollowing
        for region in private_regions:
            if (region["protection"]["executable"] and 
                region["size_kb"] > 10):  # Minimum size for a reasonable PE
                
                region_addr = int(region["address"].replace("0x", ""), 16) if "0x" in region["address"] else 0
                
                # Check if this region is NOT at the image base but is executable
                if image_base_address and region_addr != image_base_address and region["protection"]["executable"]:
                    suspicious_indicators.append({
                        "indicator": "Potential hollowed region",
                        "description": f"Executable memory at {region['address']} outside main module",
                        "severity": "high",
                        "region": region
                    })
        
        # Look for suspicious protection changes on Image regions
        for region in image_regions:
            # Process hollowing often changes protections of original sections
            if region["protection"]["writable"] and region["protection"]["executable"]:
                suspicious_indicators.append({
                    "indicator": "Suspicious image protection",
                    "description": f"Image at {region['address']} has RWX protection (unusual for legitimate code)",
                    "severity": "high",
                    "region": region
                })
            
        # Check for memory discrepancies in main executable
        # Process hollowing typically involves a process that has remarkably small memory usage
        # compared to what would be expected for the claimed executable
        process_size_total = sum(region["size_kb"] for region in memory_regions)
        typical_min_size = 1000  # Most legit processes have at least 1MB memory usage
        
        if process_size_total < typical_min_size and process_info.get("process_name", "").lower() not in ["cmd.exe", "notepad.exe"]:
            suspicious_indicators.append({
                "indicator": "Unusually small process size",
                "description": f"Process claims to be {process_info.get('process_name')} but only uses {process_size_total}KB of memory",
                "severity": "medium",
                "region": {"address": "N/A", "size_kb": process_size_total}
            })
            
    except Exception as e:
        logging.error(f"Error detecting process hollowing for PID {pid}: {e}")
    
    return suspicious_indicators

def is_browser_process(process_name):
    """
    Determine if a process is a known web browser or browser component.
    
    Args:
        process_name (str): Name of the process to check
        
    Returns:
        bool: True if process is a browser or browser component, False otherwise
    """
    browser_processes = [
        "chrome.exe", 
        "msedge.exe", 
        "firefox.exe", 
        "brave.exe", 
        "opera.exe",
        "iexplore.exe", 
        "safari.exe",
        "msedgewebview2.exe",  # Edge WebView component
        "chrome_elf.exe",      # Chrome component
        "firefox-bin.exe",     # Firefox component
        "browser_broker.exe",  # Edge component
        "crashpad_handler.exe" # Chromium crash handler
    ]
    
    return process_name.lower() in [browser.lower() for browser in browser_processes] 

def detect_reflective_dll_injection(pid, process_info):
    """
    Detect signs of reflective DLL injection by examining memory regions
    for PE headers not linked to loaded modules.
    """
    suspicious_indicators = []
    
    try:
        # Get memory regions for the process
        memory_regions = enumerate_process_memory_regions(pid)
        
        # Get process stats to check for anomalies
        process_stats = get_process_stats(pid)
        
        # Look for key indicators of reflective loading
        for region in memory_regions:
            if (region["protection"]["executable"] and 
                region["type"] == "Private" and
                region["size_kb"] > 20):  # Minimum reasonable size for a DLL
                
                # Key pattern: Executable & writable private memory
                if region["protection"]["writable"]:
                    suspicious_indicators.append({
                        "indicator": "RWX memory region",
                        "description": f"Memory at {region['address']} has RWX protection - typical for reflective loading",
                        "severity": "high",
                        "region": region
                    })
                else:
                    # Lower severity for RX-only memory, still suspicious if large enough
                    if region["size_kb"] > 100:
                        suspicious_indicators.append({
                            "indicator": "Large executable private memory",
                            "description": f"Large executable allocation at {region['address']} ({region['size_kb']}KB) - possible loaded code",
                            "severity": "medium",
                            "region": region
                        })
        
        # Look for suspicious allocations that don't align with typical module boundaries
        # Most legitimate modules are loaded at addresses aligned to 64K boundaries (0x10000)
        for region in memory_regions:
            if region["protection"]["executable"] and region["type"] == "Private" and "0x" in region["address"]:
                region_addr = int(region["address"].replace("0x", ""), 16)
                
                # Check for non-aligned executable memory allocations
                if region_addr % 0x10000 != 0 and region["size_kb"] > 40:
                    suspicious_indicators.append({
                        "indicator": "Non-standard memory alignment",
                        "description": f"Executable region at {region['address']} is not aligned to standard module boundaries",
                        "severity": "medium",
                        "region": region
                    })
        
        # Additional check: drastic increase in thread count often accompanies reflective injection
        if process_stats["thread_count"] > 40:
            suspicious_indicators.append({
                "indicator": "High thread count",
                "description": f"Process has {process_stats['thread_count']} threads which is unusually high",
                "severity": "medium",
                "region": {"address": "N/A", "size_kb": 0}
            })
        
        # Check for regions with suspiciously close proximity to stack/heap allocations
        # Reflective loaders often allocate memory near stack/heap to avoid detection
        regions_by_addr = []
        for region in memory_regions:
            if "0x" in region["address"]:
                addr = int(region["address"].replace("0x", ""), 16)
                regions_by_addr.append((addr, region))
        
        # Sort regions by address
        regions_by_addr.sort(key=lambda x: x[0])
        
        # Check for unusual groupings of regions
        for i in range(1, len(regions_by_addr)):
            prev_addr, prev_region = regions_by_addr[i-1]
            curr_addr, curr_region = regions_by_addr[i]
            
            # Check if we have executable memory right after stack/heap
            if (prev_region["type"] in ["Private"] and 
                not prev_region["protection"]["executable"] and
                curr_region["protection"]["executable"] and
                curr_addr - (prev_addr + prev_region["size_kb"] * 1024) < 4096):  # Close proximity threshold (4KB)
                
                suspicious_indicators.append({
                    "indicator": "Suspicious memory layout",
                    "description": f"Executable memory at {curr_region['address']} located suspiciously close to non-executable region",
                    "severity": "high",
                    "region": curr_region
                })
        
    except Exception as e:
        logging.error(f"Error detecting reflective DLL injection for PID {pid}: {e}")
    
    return suspicious_indicators

def initialize_dll_baseline(pid, process_info):
    """Initialize baseline of loaded DLLs for a process."""
    global PROCESS_DLL_BASELINE
    
    process_name = process_info.get("process_name", "")
    exe_path = process_info.get("exe_path", "")
    
    # Skip processes we can't properly analyze
    if not exe_path or exe_path == "ACCESS_DENIED":
        return
    
    try:
        # Use Windows API to enumerate loaded modules in process
        loaded_dlls = []
        process_dir = os.path.dirname(exe_path)
        system32_dir = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32')
        
        # In a real implementation, we would use CreateToolhelp32Snapshot and Module32First/Module32Next
        # to enumerate all loaded modules. For simplicity, we'll simulate this with psutil.
        try:
            # This is a simplified approach - real implementation would use Windows API
            process = psutil.Process(pid)
            if hasattr(process, 'memory_maps'):
                memory_maps = process.memory_maps()
                for module in memory_maps:
                    if module.path.lower().endswith('.dll'):
                        loaded_dlls.append({
                            "path": module.path,
                            "base_address": hex(module.addr),
                            "size": module.rss
                        })
        except (AttributeError, psutil.AccessDenied, psutil.NoSuchProcess) as e:
            logging.debug(f"Could not enumerate DLLs for PID {pid}: {e}")
            # Fallback to just storing the process info
            loaded_dlls = []
            
        # Store the baseline
        PROCESS_DLL_BASELINE[pid] = {
            "process_name": process_name,
            "exe_path": exe_path,
            "first_seen": datetime.now().isoformat(),
            "loaded_dlls": loaded_dlls,
            "process_dir": process_dir,
            "system32_dir": system32_dir
        }
    
    except Exception as e:
        logging.error(f"Error initializing DLL baseline for PID {pid}: {e}")

def detect_dll_search_order_hijacking(pid, process_info):
    """
    Detect signs of DLL search order hijacking by identifying suspicious DLL load locations.
    """
    global PROCESS_DLL_BASELINE
    suspicious_indicators = []
    
    # Get process executable path and name
    exe_path = process_info.get("exe_path", "")
    process_name = process_info.get("process_name", "")
    
    if not exe_path or exe_path == "ACCESS_DENIED":
        return []
        
    # Get process directory
    process_dir = os.path.dirname(exe_path)
    
    # Get system directories for comparison
    system_dir = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32')
    syswow64_dir = os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64')
    windows_dir = os.environ.get('SYSTEMROOT', 'C:\\Windows')
    
    # Initialize baseline if not already done
    if pid not in PROCESS_DLL_BASELINE:
        initialize_dll_baseline(pid, process_info)
        return []  # First time seeing this process - establish baseline only
        
    baseline = PROCESS_DLL_BASELINE[pid]
    
    try:
        # List of commonly hijacked system DLLs
        common_hijacked_dlls = [
            "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
            "version.dll", "wininet.dll", "cryptsp.dll", "urlmon.dll",
            "netapi32.dll", "secur32.dll", "oleaut32.dll", "msvcp140.dll",
            "ucrtbase.dll", "comctl32.dll", "ws2_32.dll", "ntdll.dll",
            "msvcp120.dll", "vcruntime140.dll", "msvcr100.dll", "api-ms-win-crt-runtime-l1-1-0.dll"
        ]
        
        # List of commonly hijacked application DLLs
        common_app_hijacked_dlls = [
            "sqlite3.dll", "libcurl.dll", "python*.dll", "java*.dll",
            "boost_*.dll", "openssl*.dll", "libeay32.dll", "ssleay32.dll"
        ]
        
        # Enhanced search order hijacking detection
        
        # 1. Check for system DLLs in non-system locations
        for dll_name in common_hijacked_dlls:
            potential_hijack_path = os.path.join(process_dir, dll_name)
            if os.path.exists(potential_hijack_path):
                # This is a red flag - system DLL in application directory
                suspicious_indicators.append({
                    "indicator": "System DLL in application directory",
                    "description": f"System DLL '{dll_name}' found in application directory: {process_dir}",
                    "severity": "high",
                    "dll_path": potential_hijack_path
                })
                
                # Also check for forged digital signatures
                try:
                    # Use Windows API to check signatures
                    import ctypes
                    from ctypes import wintypes
                    
                    wintrust = ctypes.WinDLL('wintrust.dll')
                    # Structure declarations for WinVerifyTrust
                    class GUID(ctypes.Structure):
                        _fields_ = [
                            ('Data1', wintypes.DWORD),
                            ('Data2', wintypes.WORD),
                            ('Data3', wintypes.WORD),
                            ('Data4', wintypes.BYTE * 8)
                        ]
                        
                    class WINTRUST_FILE_INFO(ctypes.Structure):
                        _fields_ = [
                            ('cbStruct', wintypes.DWORD),
                            ('pcwszFilePath', wintypes.LPCWSTR),
                            ('hFile', wintypes.HANDLE),
                            ('pgKnownSubject', ctypes.POINTER(GUID))
                        ]
                        
                    class WINTRUST_DATA(ctypes.Structure):
                        _fields_ = [
                            ('cbStruct', wintypes.DWORD),
                            ('pPolicyCallbackData', wintypes.LPVOID),
                            ('pSIPClientData', wintypes.LPVOID),
                            ('dwUIChoice', wintypes.DWORD),
                            ('fdwRevocationChecks', wintypes.DWORD),
                            ('dwUnionChoice', wintypes.DWORD),
                            ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                            ('dwStateAction', wintypes.DWORD),
                            ('hWVTStateData', wintypes.HANDLE),
                            ('pwszURLReference', wintypes.LPCWSTR),
                            ('dwProvFlags', wintypes.DWORD),
                            ('dwUIContext', wintypes.DWORD)
                        ]
                        
                    # Constants for WinVerifyTrust
                    WTD_UI_NONE = 2
                    WTD_REVOKE_NONE = 0
                    WTD_CHOICE_FILE = 1
                    WTD_STATEACTION_VERIFY = 1
                    WTD_STATEACTION_CLOSE = 2
                    
                    # GUID for WinVerifyTrust
                    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID()
                    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data1 = 0x00AAC56B
                    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data2 = 0xCD44
                    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data3 = 0x11D0
                    WINTRUST_ACTION_GENERIC_VERIFY_V2.Data4 = (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
                    
                    # Check the digital signature
                    file_info = WINTRUST_FILE_INFO()
                    file_info.cbStruct = ctypes.sizeof(file_info)
                    file_info.pcwszFilePath = potential_hijack_path
                    file_info.hFile = None
                    file_info.pgKnownSubject = None
                    
                    trust_data = WINTRUST_DATA()
                    trust_data.cbStruct = ctypes.sizeof(trust_data)
                    trust_data.pPolicyCallbackData = None
                    trust_data.pSIPClientData = None
                    trust_data.dwUIChoice = WTD_UI_NONE
                    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
                    trust_data.dwUnionChoice = WTD_CHOICE_FILE
                    trust_data.pFile = ctypes.pointer(file_info)
                    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
                    trust_data.hWVTStateData = None
                    trust_data.pwszURLReference = None
                    trust_data.dwProvFlags = 0
                    trust_data.dwUIContext = 0
                    
                    result = wintrust.WinVerifyTrust(
                        None,
                        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                        ctypes.byref(trust_data)
                    )
                    
                    # Clean up
                    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
                    wintrust.WinVerifyTrust(
                        None,
                        ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
                        ctypes.byref(trust_data)
                    )
                    
                    # Process result
                    if result != 0:
                        suspicious_indicators.append({
                            "indicator": "Unsigned system DLL in application directory",
                            "description": f"System DLL '{dll_name}' in app directory is unsigned or has invalid signature",
                            "severity": "critical",
                            "dll_path": potential_hijack_path
                        })
                except Exception as sig_err:
                    logging.debug(f"Error checking signature for {potential_hijack_path}: {sig_err}")
        
        # 2. Check for unorthodox DLL locations
        temp_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
        ]
        
        # Get current loaded DLLs
        current_dlls = []
        try:
            process = psutil.Process(pid)
            if hasattr(process, 'memory_maps'):
                memory_maps = process.memory_maps()
                for module in memory_maps:
                    if module.path.lower().endswith('.dll'):
                        current_dlls.append({
                            "path": module.path,
                            "base_address": hex(module.addr),
                            "size": module.rss
                        })
        except (AttributeError, psutil.AccessDenied, psutil.NoSuchProcess) as e:
            logging.debug(f"Could not enumerate current DLLs for PID {pid}: {e}")
            return suspicious_indicators
            
        # Compare with baseline
        baseline_dll_paths = [dll["path"].lower() for dll in baseline.get("loaded_dlls", [])]
        
        for dll in current_dlls:
            dll_path = dll["path"].lower()
            dll_name = os.path.basename(dll_path)
            
            # 3. Check for DLLs loaded from temp directories
            if any(temp_dir.lower() in dll_path.lower() for temp_dir in temp_dirs if temp_dir):
                suspicious_indicators.append({
                    "indicator": "DLL loaded from temp directory",
                    "description": f"DLL '{dll_name}' loaded from temporary location: {dll_path}",
                    "severity": "high",
                    "dll_path": dll_path
                })
            
            # 4. Check for DLLs with same names as system DLLs but in wrong locations
            if dll_name.lower() in [d.lower() for d in common_hijacked_dlls]:
                # Check if this DLL is not in system directories
                if (system_dir.lower() not in dll_path.lower() and 
                    syswow64_dir.lower() not in dll_path.lower() and
                    windows_dir.lower() not in dll_path.lower()):
                    suspicious_indicators.append({
                        "indicator": "System DLL loaded from non-system location",
                        "description": f"System DLL '{dll_name}' loaded from non-standard location: {dll_path}",
                        "severity": "high",
                        "dll_path": dll_path
                    })
            
            # 5. Check if this is a new DLL not in baseline with wildcard matching
            if not any(dll_path == baseline_path for baseline_path in baseline_dll_paths):
                # Check if matches any application DLL patterns
                for pattern in common_app_hijacked_dlls:
                    if '*' in pattern and pattern.replace('*', '') in dll_name.lower():
                        # This is a commonly hijacked application DLL, check its location
                        if not dll_path.lower().startswith(process_dir.lower()):
                            suspicious_indicators.append({
                                "indicator": "Application DLL loaded from unusual location",
                                "description": f"Application DLL '{dll_name}' loaded from outside application directory: {dll_path}",
                                "severity": "medium",
                                "dll_path": dll_path
                            })
                
                # 6. Check for user profile location DLLs (common in fileless malware)
                profile_dirs = [
                    os.environ.get('USERPROFILE', ''),
                    os.environ.get('APPDATA', ''),
                    os.environ.get('LOCALAPPDATA', '')
                ]
                
                if any(profile_dir.lower() in dll_path.lower() for profile_dir in profile_dirs if profile_dir):
                    # DLL loaded from user profile - typically suspicious for system processes
                    if process_name.lower() in ["svchost.exe", "lsass.exe", "services.exe", "winlogon.exe"]:
                        suspicious_indicators.append({
                            "indicator": "System process loading user profile DLL",
                            "description": f"System process '{process_name}' loaded DLL from user profile: {dll_path}",
                            "severity": "critical",
                            "dll_path": dll_path
                        })
                    else:
                        suspicious_indicators.append({
                            "indicator": "DLL loaded from user profile",
                            "description": f"Process loaded DLL from user profile location: {dll_path}",
                            "severity": "medium",
                            "dll_path": dll_path
                        })
                
                # Add this DLL to baseline for future comparisons
                baseline["loaded_dlls"].append({
                    "path": dll_path,
                    "base_address": dll["base_address"],
                    "size": dll["size"],
                    "first_seen": datetime.now().isoformat()
                })
        
        # 7. Check for unexpected proxy DLLs
        # These are DLLs that might be used for API hooking or redirection
        proxy_dlls = ["winhttp.dll", "wininet.dll", "ws2_32.dll", "urlmon.dll", "nspr4.dll"]
        
        for dll in current_dlls:
            dll_path = dll["path"].lower()
            dll_name = os.path.basename(dll_path)
            
            if dll_name.lower() in proxy_dlls:
                expected_path = os.path.join(system_dir, dll_name)
                expected_path_wow64 = os.path.join(syswow64_dir, dll_name)
                
                if dll_path.lower() != expected_path.lower() and dll_path.lower() != expected_path_wow64.lower():
                    suspicious_indicators.append({
                        "indicator": "Network proxy DLL hijacking",
                        "description": f"Network-related DLL '{dll_name}' loaded from unexpected location: {dll_path}",
                        "severity": "high",
                        "dll_path": dll_path
                    })
                
    except Exception as e:
        logging.error(f"Error detecting DLL search order hijacking for PID {pid}: {e}")
    
    return suspicious_indicators

def detect_thread_hijacking(pid, process_info):
    """
    Detect signs of thread execution hijacking by monitoring foreign thread creation
    and suspicious thread start addresses.
    """
    suspicious_indicators = []
    
    try:
        # Get memory regions for the process
        memory_regions = enumerate_process_memory_regions(pid)
        
        # Get process stats
        process_stats = get_process_stats(pid)
        
        # Get process name and exe_path for context
        process_name = process_info.get("process_name", "").lower()
        exe_path = process_info.get("exe_path", "").lower()
        
        # Check for small executable allocations that might be used for thread injection
        for region in memory_regions:
            if (region["protection"]["executable"] and 
                region["type"] == "Private" and
                4 <= region["size_kb"] <= 32):  # Thread shellcode is often small to medium size
                
                # Higher severity if also writable (RWX)
                if region["protection"]["writable"]:
                    suspicious_indicators.append({
                        "indicator": "Small RWX memory region",
                        "description": f"Small RWX memory at {region['address']} ({region['size_kb']}KB) - common shellcode size",
                        "severity": "high",
                        "region": region
                    })
                else:
                    suspicious_indicators.append({
                        "indicator": "Small executable region",
                        "description": f"Small executable memory at {region['address']} ({region['size_kb']}KB) - potential shellcode",
                        "severity": "medium",
                        "region": region
                    })
        
        # Thread count analysis - check for anomalous thread patterns
        # Adjust threshold based on the process type
        thread_count = process_stats["thread_count"]
        
        # Define known thread-intensive applications
        high_thread_apps = [
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",  # Browsers
            "w3wp.exe", "httpd.exe", "nginx.exe",  # Web servers
            "sqlservr.exe", "oracle.exe", "mysqld.exe",  # Databases
            "outlook.exe", "thunderbird.exe",  # Email clients
            "explorer.exe",  # File Explorer
            "winlogon.exe", "lsass.exe", "services.exe"  # System services
        ]
        
        # Determine expected thread count range based on process type
        if any(app in process_name for app in high_thread_apps):
            # Higher threshold for apps known to use many threads
            thread_threshold = 80
        else:
            # Lower threshold for regular applications
            thread_threshold = 25
        
        # Alert on excessive thread count
        if thread_count > thread_threshold:
            suspicious_indicators.append({
                "indicator": "Excessive thread count",
                "description": f"Process has {thread_count} threads which exceeds expected threshold ({thread_threshold})",
                "severity": "medium",
                "region": {"address": "N/A", "size_kb": 0}
            })
        
        # Check for suspicious memory patterns that suggest thread redirection
        # Thread hijacking often hooks important APIs or patches memory
        for region in memory_regions:
            # Look for suspicious memory around key system DLL regions
            if (region["protection"]["writable"] and 
                region["protection"]["executable"] and
                region["type"] == "Mapped" and
                region["size_kb"] < 64):  # Small mapped RWX regions are very suspicious
                
                suspicious_indicators.append({
                    "indicator": "Suspicious mapped RWX memory",
                    "description": f"Small mapped RWX region at {region['address']} - potential API hook",
                    "severity": "high",
                    "region": region
                })
            
            # Look for suspicious protection changes around image regions
            # (indicating potential inline hooks)
            if (region["type"] == "Image" and
                region["protection"]["writable"] and
                region["protection"]["executable"]):
                
                suspicious_indicators.append({
                    "indicator": "Writable executable image",
                    "description": f"Image region at {region['address']} has writable+executable protection - likely hook point",
                    "severity": "high",
                    "region": region
                })
        
        # Check for the existence of small isolated memory allocations
        # Thread hijackers often create small trampolines to redirect execution
        private_regions = [r for r in memory_regions if r["type"] == "Private"]
        
        # Sort regions by address for adjacency analysis
        if len(private_regions) > 0:
            # Convert addresses to integers for sorting
            private_regions_sorted = []
            for region in private_regions:
                if "0x" in region["address"]:
                    addr = int(region["address"].replace("0x", ""), 16)
                    private_regions_sorted.append((addr, region))
            
            # Sort by address
            private_regions_sorted.sort(key=lambda x: x[0])
            
            # Look for isolated small executable regions
            for i, (addr, region) in enumerate(private_regions_sorted):
                if region["protection"]["executable"] and region["size_kb"] < 16:
                    # Check if this region is isolated from other regions
                    isolated = True
                    
                    # Check previous region
                    if i > 0:
                        prev_addr, _ = private_regions_sorted[i-1]
                        if addr - prev_addr < 1024*1024:  # Within 1MB
                            isolated = False
                    
                    # Check next region
                    if i < len(private_regions_sorted) - 1:
                        next_addr, _ = private_regions_sorted[i+1]
                        if next_addr - addr < 1024*1024:  # Within 1MB
                            isolated = False
                    
                    if isolated:
                        suspicious_indicators.append({
                            "indicator": "Isolated small executable region",
                            "description": f"Small isolated executable region at {region['address']} - potential trampoline",
                            "severity": "high",
                            "region": region
                        })
                
    except Exception as e:
        logging.error(f"Error detecting thread hijacking for PID {pid}: {e}")
    
    return suspicious_indicators

def get_all_system_processes():
    """Get detailed information about all processes running on the system."""
    all_processes = {}

    try:
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                pid = proc.info['pid']
                
                # Skip system process (PID 0 and 4)
                if pid <= 4:
                    continue
                
                # Get process name with robust error handling
                try:
                    proc_name = proc.info['name']
                    if not proc_name:
                        # Try alternative method to get name
                        proc_name = proc.name()
                except (AttributeError, psutil.AccessDenied, psutil.NoSuchProcess):
                    try:
                        # Try using Windows API as fallback
                        import ctypes
                        from ctypes import wintypes

                        psapi = ctypes.WinDLL('psapi.dll')
                        kernel32 = ctypes.WinDLL('kernel32.dll')

                        PROCESS_QUERY_INFORMATION = 0x0400
                        PROCESS_VM_READ = 0x0010
                        MAX_PATH = 260

                        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                        if process_handle:
                            try:
                                image_name = (ctypes.c_char * MAX_PATH)()
                                if psapi.GetProcessImageFileNameA(process_handle, image_name, MAX_PATH) > 0:
                                    proc_name = os.path.basename(image_name.value.decode('utf-8'))
                                else:
                                    proc_name = f"Process_{pid}"
                            finally:
                                kernel32.CloseHandle(process_handle)
                        else:
                            proc_name = f"Process_{pid}"
                    except:
                        proc_name = f"Process_{pid}"
                
                # Get process executable path with robust error handling
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, FileNotFoundError, psutil.NoSuchProcess):
                    # Try Windows API to get executable path
                    try:
                        import ctypes
                        from ctypes import wintypes

                        psapi = ctypes.WinDLL('psapi.dll')
                        kernel32 = ctypes.WinDLL('kernel32.dll')

                        PROCESS_QUERY_INFORMATION = 0x0400
                        PROCESS_VM_READ = 0x0010
                        MAX_PATH = 260

                        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                        if process_handle:
                            try:
                                image_name = (ctypes.c_char * MAX_PATH)()
                                if psapi.GetModuleFileNameExA(process_handle, None, image_name, MAX_PATH) > 0:
                                    exe_path = image_name.value.decode('utf-8')
                                else:
                                    exe_path = "ACCESS_DENIED"
                            finally:
                                kernel32.CloseHandle(process_handle)
                        else:
                            exe_path = "ACCESS_DENIED"
                    except:
                        exe_path = "ACCESS_DENIED"
                
                # Get command line arguments with robust error handling
                try:
                    cmdline_list = proc.cmdline()
                    cmdline = " ".join(cmdline_list) if cmdline_list else ""
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    # Try Windows API to get command line
                    try:
                        import wmi
                        c = wmi.WMI()
                        for process in c.Win32_Process(ProcessId=pid):
                            cmdline = process.CommandLine or ""
                            break
                        else:
                            cmdline = "ACCESS_DENIED"
                    except:
                        cmdline = "ACCESS_DENIED"
                
                # Convert creation time to human-readable format
                try:
                    start_time = time.strftime('%Y-%m-%d %H:%M:%S', 
                                            time.localtime(proc.create_time()))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    start_time = "UNKNOWN"
                
                # Get process owner
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "UNKNOWN"
                
                # Get parent process ID
                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = "UNKNOWN"
                
                # Get process lineage with robust error handling
                lineage = resolve_lineage(pid)
                
                # Get process hash if executable exists
                if exe_path != "ACCESS_DENIED" and os.path.exists(exe_path):
                    process_hash = get_process_hash(exe_path, cmdline)
                else:
                    # Handle special processes by creating a deterministic hash based on available info
                    if lineage and len(lineage) > 0:
                        # Create a stable identifier using lineage, name, and other metadata
                        hash_input = f"{proc_name}:{','.join(lineage)}:{ppid}:{username}"
                        process_hash = f"DERIVED_{hashlib.md5(hash_input.encode()).hexdigest()}"
                    else:
                        process_hash = "ERROR_FILE_NOT_FOUND"
                
                # Check if this is likely a fileless process using our improved detection
                is_fileless = detect_fileless_process(pid, exe_path, cmdline, process_hash, lineage)
                
                # Store process information
                process_key = f"{pid}"
                all_processes[process_key] = {
                    "pid": pid,
                    "exe_path": exe_path,
                    "process_name": proc_name,
                    "user": username,
                    "start_time": start_time,
                    "cmdline": cmdline,
                    "hash": process_hash,
                    "ppid": ppid,
                    "lineage": lineage,
                    "fileless": is_fileless,
                    "memory_rss_kb": 0,
                    "memory_vms_kb": 0,
                    "thread_count": 0
                }
                
                # Add memory statistics
                try:
                    memory_info = proc.memory_info()
                    all_processes[process_key]["memory_rss_kb"] = memory_info.rss // 1024
                    all_processes[process_key]["memory_vms_kb"] = memory_info.vms // 1024
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Add thread count
                try:
                    all_processes[process_key]["thread_count"] = proc.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logging.debug(f"Error accessing process: {e}")
                continue
    
    except Exception as e:
        logging.error(f"Failed to enumerate system processes: {e}")
    
    return all_processes

def get_process_name_by_pid(pid):
    """Get process name using Windows API as a fallback method."""
    try:
        import ctypes
        from ctypes import wintypes

        psapi = ctypes.WinDLL('psapi.dll')
        kernel32 = ctypes.WinDLL('kernel32.dll')

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MAX_PATH = 260

        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if process_handle:
            try:
                image_name = (ctypes.c_char * MAX_PATH)()
                if psapi.GetProcessImageFileNameA(process_handle, image_name, MAX_PATH) > 0:
                    name = os.path.basename(image_name.value.decode('utf-8'))
                    return name
            finally:
                kernel32.CloseHandle(process_handle)
        return f"Process_{pid}"
    except Exception as e:
        logging.debug(f"Error getting process name by PID: {e}")
        return f"Process_{pid}"

def get_exe_path_win_api(pid):
    """Get executable path using Windows API as a fallback method."""
    try:
        import ctypes
        from ctypes import wintypes

        psapi = ctypes.WinDLL('psapi.dll')
        kernel32 = ctypes.WinDLL('kernel32.dll')

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        MAX_PATH = 260

        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if process_handle:
            try:
                image_name = (ctypes.c_char * MAX_PATH)()
                if psapi.GetModuleFileNameExA(process_handle, None, image_name, MAX_PATH) > 0:
                    path = image_name.value.decode('utf-8')
                    return path
            finally:
                kernel32.CloseHandle(process_handle)
        return "ACCESS_DENIED"
    except Exception as e:
        logging.debug(f"Error getting executable path by PID: {e}")
        return "ACCESS_DENIED"

def get_cmdline_win_api(pid):
    """Get command line using Windows API as a fallback method."""
    try:
        # This requires more advanced techniques using WMI
        import wmi
        c = wmi.WMI()
        for process in c.Win32_Process(ProcessId=pid):
            return process.CommandLine or ""
        return "ACCESS_DENIED"
    except Exception as e:
        logging.debug(f"Error getting command line by PID: {e}")
        return "ACCESS_DENIED"

def detect_fileless_process(pid, exe_path, cmdline, process_hash, lineage=None):
    """Detect whether a process is likely fileless based on various indicators."""
    # If lineage wasn't passed, try to get it
    if lineage is None:
        try:
            lineage = resolve_lineage(pid)
        except:
            lineage = []
    
    # If we have a valid lineage but can't access the executable, it might be
    # a legitimate process with restricted access rather than fileless malware
    if lineage and len(lineage) > 0 and exe_path == "ACCESS_DENIED":
        # Check if this is a child of a legitimate system process
        legitimate_parents = ["wininit.exe", "services.exe", "svchost.exe", 
                             "lsass.exe", "system", "smss.exe"]
        
        # If the process has a legitimate parent, it's likely not fileless malware
        if any(parent.lower() in [p.lower() for p in lineage] for parent in legitimate_parents):
            # Additional check - if part of a VM or container infrastructure
            vm_indicators = ["vm", "virtual", "container", "wsl", "docker"]
            
            for indicator in vm_indicators:
                if any(indicator in p.lower() for p in lineage):
                    # This is likely a VM or container process, not fileless malware
                    return False
    
    # Skip empty process names or paths
    if not exe_path and not cmdline:
        return False
    
    # Skip processes with empty path but ACCESS_DENIED cmdline
    # These are likely system processes we can't access
    if not exe_path and cmdline == "ACCESS_DENIED":
        return False
    
    # If hash indicates file not found but we have a non-empty exe_path, this is suspicious
    if process_hash == "ERROR_FILE_NOT_FOUND" and exe_path and exe_path != "ACCESS_DENIED":
        # Additional check - if this is a WSL or VM process with a non-standard path format
        if exe_path and ("wsl" in exe_path.lower() or "vm" in exe_path.lower()):
            # This is likely a VM-related process, not fileless malware
            return False
        return True
    
    # Check for PowerShell with encoded commands (common in fileless malware)
    powershell_encoded = False
    if cmdline and "powershell" in cmdline.lower() and any(enc in cmdline.lower() 
                                           for enc in ["-enc", "-encodedcommand", 
                                                      "-e", "frombase64string"]):
        powershell_encoded = True
    
    # Check for memory-only execution indicators
    memory_exec_indicators = [
        "reflective", "runpe", "inmemory", "memorymodule",
        "memoryloadlibrary", "virtualalloc", "heapalloc"
    ]
    
    memory_only_indicators = cmdline and any(ind in cmdline.lower() for ind in memory_exec_indicators)
    
    # Check for WMI process execution (common fileless technique)
    wmi_exec = cmdline and "wmic" in cmdline.lower() and "process call create" in cmdline.lower()
    
    # Check for .NET in-memory execution via Assembly.Load
    dotnet_memory_load = cmdline and any(term in cmdline.lower() for term in 
                          ["assembly.load", "loadfrom", "reflection.assembly"])
    
    # Return true if any fileless indicators are found
    return (process_hash == "ERROR_FILE_NOT_FOUND" or 
            powershell_encoded or 
            memory_only_indicators or 
            wmi_exec or 
            dotnet_memory_load)

def monitor_listening_processes(interval=3):
    """Main monitoring loop for detecting suspicious processes with process group tracking."""
    global SERVICE_RUNNING
    
    # Setup tracking
    known_processes = {}  # Store by key: process_hash
    known_pids = {}       # Track PIDs to detect terminations
    ml_model_info = None
    ml_retrain_counter = 0
    alerted_processes = set()  # Avoid duplicate alerts
    recently_terminated_pids = {}  # Map PID to hash and timestamp
    suppression_timeout = 60  # Seconds to suppress alerts for same process type
    
    # Initialize ML model if available
    if ML_LIBRARIES_AVAILABLE:
        ml_model_info = implement_behavioral_baselining()
        logging.info("ML behavioral baselining completed")
    
    logging.info("Starting process monitoring with process group tracking...")
    
    # Load integrity state
    integrity_state = load_process_metadata()
    
    # Initialize process_groups if needed
    if "process_groups" not in integrity_state:
        integrity_state["process_groups"] = {}
        save_process_metadata(integrity_state)
    
    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
    # Flag for first iteration - no process termination alerts on first run
    first_run = True
    
    while SERVICE_RUNNING:
        try:
            # Get current listening processes
            current_processes = get_listening_processes()
            
            # Create mappings for current processes
            current_hash_to_process = {}
            current_pids = {}
            
            for process_key, process_info in current_processes.items():
                process_hash = process_info.get("hash")
                pid = process_info.get("pid")
                
                if process_hash and process_hash not in ["ERROR_HASHING_PERMISSION", "ERROR_FILE_NOT_FOUND"]:
                    current_hash_to_process[process_hash] = process_info
                    current_pids[pid] = process_hash
            
            # For first run, initialize known_pids from current processes
            # This avoids false termination alerts on startup
            if first_run:
                for pid, process_hash in current_pids.items():
                    process_info = current_hash_to_process[process_hash]
                    process_name = process_info.get("process_name", "")
                    exe_path = process_info.get("exe_path", "")
                    
                    # Check if process exists in integrity state
                    if process_hash in integrity_state:
                        # Process exists in integrity state, update with current PID
                        stored_info = integrity_state[process_hash]
                        stored_info["pid"] = pid
                        stored_info["start_time"] = process_info.get("start_time")
                        
                        # Log that we're updating an existing process silently
                        logging.debug(f"Silently updating existing process: {process_name} (PID: {pid})")
                        
                        # Update in integrity state without generating logs
                        update_process_tracking(
                            process_info.get("exe_path"),
                            process_hash,
                            stored_info
                        )
                    else:
                        # Check process groups
                        found_in_group = False
                        if "process_groups" in integrity_state:
                            # Create the process group ID
                            process_group_id = f"{exe_path}|{process_name}".lower()
                            
                            if process_group_id in integrity_state["process_groups"]:
                                group = integrity_state["process_groups"][process_group_id]
                                
                                # Check if hash exists in known_hashes
                                if process_hash in group.get("known_hashes", {}):
                                    # Known hash in group - update last_seen and count
                                    logging.debug(f"Silently updating known hash in process group: {process_name} (PID: {pid})")
                                    
                                    # Update last_seen and detection_count
                                    group["known_hashes"][process_hash]["last_seen"] = datetime.now().isoformat()
                                    group["known_hashes"][process_hash]["detection_count"] += 1
                                    
                                    # Save changes
                                    save_process_metadata(integrity_state)
                                    found_in_group = True
                                else:
                                    # New hash for existing process group - add to known_hashes
                                    logging.debug(f"Adding new hash to existing process group: {process_name} (PID: {pid})")
                                    
                                    # Initialize known_hashes if needed
                                    if "known_hashes" not in group:
                                        group["known_hashes"] = {}
                                    
                                    # Add new hash entry
                                    group["known_hashes"][process_hash] = {
                                        "first_seen": datetime.now().isoformat(),
                                        "last_seen": datetime.now().isoformat(),
                                        "detection_count": 1
                                    }
                                    
                                    # Save changes
                                    save_process_metadata(integrity_state)
                                    found_in_group = True
                        
                        # If not found in any group, this is a genuinely new process
                        if not found_in_group:
                            logging.info(f"New listening process: {process_name} (PID: {pid}) on port {process_info.get('port', 'UNKNOWN')}")
                            # Add to integrity state
                            update_process_tracking(
                                exe_path,
                                process_hash,
                                process_info
                            )
                    
                    # Add to known_pids
                    known_pids[pid] = process_hash
                
                # Set first_run to False after initial processing
                first_run = False
                # Skip the rest of the loop
                continue
            
            # For subsequent runs, detect terminated processes by PID
            for pid in list(known_pids.keys()):
                if pid not in current_pids:
                    process_hash = known_pids[pid]
                    
                    # Get process info from integrity_state
                    if process_hash in integrity_state:
                        term_process = integrity_state[process_hash]
                        process_name = term_process.get("process_name", "UNKNOWN")
                        port = term_process.get("port", "UNKNOWN")
                        
                        logging.warning(f"Process terminated: {process_name} (PID: {pid}) on port {port}")
                        
                        # Store in recently terminated for duplicate alert suppression
                        recently_terminated_pids[pid] = (process_hash, time.time(), process_name)
                        
                        # Generate alert for terminated process
                        try:
                            log_event_to_pim(
                                event_type="PROCESS_TERMINATED",
                                file_path=term_process.get("exe_path", ""),
                                previous_metadata=term_process,
                                new_metadata=None,
                                previous_hash=process_hash,
                                new_hash=None
                            )
                        except Exception as log_err:
                            logging.error(f"Error logging process termination: {log_err}")
                        
                        # Remove pid from known_pids but KEEP in integrity_state
                        # for legitimate processes
                        del known_pids[pid]
            
            # Process new or changed processes
            for pid, process_hash in current_pids.items():
                if pid not in known_pids or known_pids[pid] != process_hash:
                    try:
                        process_info = current_hash_to_process[process_hash]
                        process_name = process_info.get("process_name", "UNKNOWN")
                        # FIX: Handle potentially missing port with a safe default
                        port = process_info.get("port", "UNKNOWN")
                        # Make sure port is properly formatted
                        if isinstance(port, int):
                            port_str = str(port)
                        else:
                            port_str = str(port) if port else "UNKNOWN"
                        exe_path = process_info.get("exe_path", "")
                        
                        # Skip if this is a PID/process that's already been flagged
                        if pid in alerted_processes:
                            continue
                        
                        # Check if this is a known hash (which means it was seen before)
                        if process_hash in integrity_state:
                            stored_info = integrity_state[process_hash]
                            
                            # If PID changed, it's a process restart
                            old_pid = stored_info.get("pid")
                            if old_pid != pid:
                                logging.info(f"Process restarted: {process_name} (PID: {pid}, old PID: {old_pid})")
                                
                                # Update with new PID
                                stored_info["pid"] = pid
                                stored_info["start_time"] = process_info.get("start_time")
                                update_process_tracking(exe_path, process_hash, stored_info)
                            
                            # Check for other metadata changes
                            changes_detected = False
                            key_fields = ["exe_path", "user", "port", "cmdline"]
                            changed_fields = {}
                            
                            for field in key_fields:
                                if stored_info.get(field) != process_info.get(field):
                                    # For browsers, don't treat every cmdline change as significant
                                    if field == "cmdline" and is_browser_process(process_info.get("process_name", "")):
                                        # Compare patterns instead of raw command lines
                                        stored_pattern = simplify_command_line(stored_info.get(field, ""))
                                        current_pattern = simplify_command_line(process_info.get(field, ""))
                                        
                                        # Only consider it changed if patterns differ significantly
                                        if stored_pattern != current_pattern:
                                            changed_fields[field] = {
                                                "previous": stored_info.get(field),
                                                "current": process_info.get(field)
                                            }
                                    else:
                                        changed_fields[field] = {
                                            "previous": stored_info.get(field),
                                            "current": process_info.get(field)
                                        }
                            
                            if changed_fields:
                                logging.warning(
                                    f"Metadata changes detected for PID {pid}: {list(changed_fields.keys())}"
                                )
                                try:
                                    log_event_to_pim(
                                        event_type="PROCESS_METADATA_CHANGED",
                                        file_path=process_info.get("exe_path", ""),
                                        previous_metadata=stored_info,
                                        new_metadata=process_info,
                                        previous_hash=stored_info.get("hash", ""),
                                        new_hash=process_hash
                                    )
                                except Exception as log_err:
                                    logging.error(f"Error logging metadata change: {log_err}")
                                
                                changes_detected = True
                            
                            # Update tracking if changes were detected
                            if changes_detected:
                                update_process_tracking(
                                    process_info.get("exe_path"),
                                    process_hash,
                                    process_info
                                )
                        else:
                            # Hash not directly in integrity_state, check process groups
                            found_in_group = False
                            if "process_groups" in integrity_state:
                                process_group_id = f"{exe_path}|{process_name}".lower()
                                
                                if process_group_id in integrity_state["process_groups"]:
                                    group = integrity_state["process_groups"][process_group_id]
                                    
                                    # Check if hash exists in known_hashes
                                    if process_hash in group.get("known_hashes", {}):
                                        # Known hash in group - update last_seen and count
                                        logging.debug(f"Updating known hash in process group: {process_name} (PID: {pid})")
                                        
                                        # Update last_seen and detection_count
                                        group["known_hashes"][process_hash]["last_seen"] = datetime.now().isoformat()
                                        group["known_hashes"][process_hash]["detection_count"] += 1
                                        
                                        # Save changes
                                        save_process_metadata(integrity_state)
                                        found_in_group = True
                                    else:
                                        # Check for browser processes and similar - be more lenient
                                        browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "msedgewebview2.exe"]
                                        if process_name.lower() in [bp.lower() for bp in browser_processes]:
                                            # Browser process - check if we recently terminated a similar process
                                            suppress_alert = False
                                            current_time = time.time()
                                            
                                            for term_pid, (term_hash, term_time, term_name) in list(recently_terminated_pids.items()):
                                                # If this is a similar process and was terminated recently
                                                if (term_name.lower() == process_name.lower() and
                                                    current_time - term_time < suppression_timeout):
                                                    suppress_alert = True
                                                    logging.debug(f"Suppressing alert for new browser process {process_name} (PID: {pid}) - similar process recently terminated")
                                                    break
                                                # Clean up old entries
                                                elif current_time - term_time > suppression_timeout:
                                                    del recently_terminated_pids[term_pid]
                                            
                                            if not suppress_alert:
                                                # New hash for existing browser group - add to known_hashes
                                                logging.info(f"New hash for browser process group: {process_name} (PID: {pid})")
                                        else:
                                            # Non-browser process with new hash
                                            logging.info(f"New hash for process group: {process_name} (PID: {pid})")
                                        
                                        # Initialize known_hashes if needed
                                        if "known_hashes" not in group:
                                            group["known_hashes"] = {}
                                        
                                        # Add new hash entry
                                        group["known_hashes"][process_hash] = {
                                            "first_seen": datetime.now().isoformat(),
                                            "last_seen": datetime.now().isoformat(),
                                            "detection_count": 1
                                        }
                                        
                                        # Save changes
                                        save_process_metadata(integrity_state)
                                        found_in_group = True
                            
                            # If not found in any group, this is a genuinely new process
                            if not found_in_group:
                                # Check for suppression due to recently terminated similar process
                                suppress_alert = False
                                browser_processes = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe", "msedgewebview2.exe"]
                                is_browser = process_name.lower() in [bp.lower() for bp in browser_processes]
                                
                                if is_browser:
                                    current_time = time.time()
                                    for term_pid, (term_hash, term_time, term_name) in list(recently_terminated_pids.items()):
                                        # If this is a similar process and was terminated recently
                                        if (term_name.lower() == process_name.lower() and
                                            current_time - term_time < suppression_timeout):
                                            suppress_alert = True
                                            logging.debug(f"Suppressing alert for new browser process {process_name} (PID: {pid}) - similar process recently terminated")
                                            break
                                        # Clean up old entries
                                        elif current_time - term_time > suppression_timeout:
                                            del recently_terminated_pids[term_pid]
                                
                                if not suppress_alert:
                                    logging.info(f"New listening process: {process_name} (PID: {pid}) on port {port_str}")
                                    
                                    # Collect all alerts/detections for this process
                                    process_alerts = []
                                    
                                    # Add lineage alerts if any
                                    if not check_lineage_baseline(process_info, integrity_state):
                                        lineage_alert = {
                                            "type": "LINEAGE_DEVIATION",
                                            "details": {
                                                "process": process_name,
                                                "lineage": process_info.get("lineage", []),
                                                "severity": "medium"
                                            }
                                        }
                                        process_alerts.append(lineage_alert)
                                        logging.warning(f"Process {process_name} has suspicious lineage deviation")
                                    
                                    # Add port alerts if any
                                    port_alerts = check_for_unusual_port_use(process_info, integrity_state)
                                    if port_alerts:
                                        process_alerts.extend(port_alerts)
                                        for port_alert in port_alerts:
                                            alert_port = port_alert.get("details", {}).get("port", "unknown")
                                            logging.warning(f"Process {process_name} has unusual port usage: {alert_port}")
                                    
                                    # Add name impersonation alerts if any
                                    name_alerts = check_process_name_consistency(process_info, integrity_state)
                                    if name_alerts:
                                        process_alerts.extend(name_alerts)
                                        logging.warning(f"Process {process_name} may be impersonating a legitimate process")
                                    
                                    # Add process group legitimacy alerts if any
                                    group_alerts = check_process_group_legitimacy(process_info, integrity_state)
                                    if group_alerts:
                                        process_alerts.extend(group_alerts)
                                        logging.warning(f"Process {process_name} has suspicious deviations from its group baseline")
                                    
                                    # Add memory scanning alerts if MEMORY_SCAN_ENABLED
                                    if MEMORY_SCAN_ENABLED:
                                        suspicious_memory = scan_process_memory(pid, process_info)
                                        if suspicious_memory:
                                            memory_alert = {
                                                "type": "SUSPICIOUS_MEMORY_REGION",
                                                "details": suspicious_memory
                                            }
                                            process_alerts.append(memory_alert)
                                            logging.warning(f"Process {process_name} has suspicious memory regions")
                                    
                                    # Add behavior analysis alerts
                                    suspicious_behaviors = analyze_process_behavior(pid, process_info)
                                    if suspicious_behaviors:
                                        behavior_alert = {
                                            "type": "SUSPICIOUS_BEHAVIOR",
                                            "details": suspicious_behaviors
                                        }
                                        process_alerts.append(behavior_alert)
                                        behavior_str = ", ".join(suspicious_behaviors[:3])
                                        if len(suspicious_behaviors) > 3:
                                            behavior_str += "..."
                                        logging.warning(f"Process {process_name} exhibits suspicious behaviors: {behavior_str}")
                                    
                                    # Calculate threat score if we have any alerts
                                    if process_alerts:
                                        threat_assessment = calculate_threat_score(process_info, process_alerts)
                                        threat_score = threat_assessment.get("score", 0)
                                        severity = threat_assessment.get("severity", "informational")
                                        reasons = threat_assessment.get("reasons", [])
                                        
                                        # Log threat assessment
                                        if threat_score > 0:
                                            reason_str = "; ".join(reasons)
                                            logging.warning(f"Threat assessment for {process_name} (PID: {pid}): Score={threat_score}, Severity={severity}")
                                            logging.warning(f"Reasons: {reason_str}")
                                            
                                            # Generate alert with threat assessment
                                            try:
                                                log_event_to_pim(
                                                    event_type="THREAT_ASSESSMENT",
                                                    file_path=exe_path,
                                                    previous_metadata=None,
                                                    new_metadata={
                                                        "process_name": process_name,
                                                        "pid": pid,
                                                        "exe_path": exe_path,
                                                        "port": port_str,
                                                        "lineage": process_info.get("lineage", []),
                                                        "threat_score": threat_score,
                                                        "severity": severity,
                                                        "reasons": reasons
                                                    },
                                                    previous_hash=None,
                                                    new_hash=process_hash
                                                )
                                            except Exception as log_err:
                                                logging.error(f"Error logging threat assessment: {log_err}")
                                            
                                            # Take action based on threat score
                                            if threat_score >= 70:  # Lowered threshold for testing
                                                logging.critical(f"Taking action against critical threat: {process_name} (PID: {pid})")
                                                
                                                try:
                                                    # Terminate the process
                                                    process = psutil.Process(pid)
                                                    process.terminate()
                                                    
                                                    # Wait briefly to see if termination worked
                                                    time.sleep(0.5)
                                                    
                                                    # If still running, try to kill
                                                    if psutil.pid_exists(pid):
                                                        process.kill()
                                                        
                                                    # Remove from integrity tracking
                                                    remove_malicious_process(process_hash, pid, integrity_state)
                                                    
                                                    # Log the action
                                                    try:
                                                        log_event_to_pim(
                                                            event_type="MALICIOUS_PROCESS_TERMINATED",
                                                            file_path=exe_path,
                                                            previous_metadata=None,
                                                            new_metadata={
                                                                "process_name": process_name,
                                                                "pid": pid,
                                                                "exe_path": exe_path,
                                                                "port": port_str,
                                                                "threat_score": threat_score,
                                                                "reasons": reasons
                                                            },
                                                            previous_hash=None,
                                                            new_hash=process_hash,
                                                            priority="critical"
                                                        )
                                                    except Exception as log_err:
                                                        logging.error(f"Error logging malicious process termination: {log_err}")
                                                    
                                                    # Add to known malicious list to prevent readdition
                                                    alerted_processes.add(pid)
                                                    
                                                    # Skip normal process tracking
                                                    continue
                                                    
                                                except Exception as e:
                                                    logging.error(f"Failed to terminate malicious process {process_name} (PID: {pid}): {e}")
                                    
                                    # If we haven't terminated the process, add it to tracking
                                    update_process_tracking(exe_path, process_hash, process_info)
                        
                        # Update known_pids to reflect current state
                        known_pids[pid] = process_hash
                        
                    except Exception as proc_err:
                        logging.error(f"Error processing PID {pid}: {proc_err}")
                        import traceback
                        logging.debug(traceback.format_exc())
            
            # Reload integrity state after updates
            integrity_state = load_process_metadata()
            
            # Sleep until next interval
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            logging.debug(traceback.format_exc())
            
            # Sleep a bit longer on error to avoid error loops
            time.sleep(max(interval, 5))

class KneeLocator:
    """
    Knee-point detection in a curve.
    Implements kneedle algorithm for detecting knee points in a curve.
    """
    def __init__(self, x, y, curve='concave', direction='increasing'):
        self.x = x
        self.y = y
        self.curve = curve
        self.direction = direction
        self.knee = self._find_knee()
        
    def _find_knee(self):
        """Find knee point using kneedle algorithm."""
        n_points = len(self.x)
        if n_points <= 2:
            return None
            
        # Normalize data
        x_norm = [float(i)/max(self.x) for i in self.x]
        y_norm = [float(i)/max(self.y) for i in self.y]
        
        # Calculate difference curve
        if self.curve == 'concave' and self.direction == 'increasing':
            # Find point of maximum curvature
            diffs = []
            for i in range(n_points):
                # Calculate distance from point to line
                x1, y1 = 0, 0  # First point
                x2, y2 = 1, 1  # Last point
                
                # Distance from point to line formula
                numer = abs((y2-y1)*x_norm[i] - (x2-x1)*y_norm[i] + x2*y1 - y2*x1)
                denom = ((y2-y1)**2 + (x2-x1)**2)**0.5
                
                # Store distances
                diffs.append(numer/denom)
            
            # Find the point with maximum difference
            knee_idx = diffs.index(max(diffs))
            return knee_idx
        elif self.curve == 'convex' and self.direction == 'increasing':
            # For convex increasing curve, find point of minimum second derivative
            # or maximum first derivative
            diffs = [y_norm[i+1] - y_norm[i] for i in range(n_points-1)]
            if len(diffs) <= 1:
                return None
                
            # Find largest change in first derivative
            sec_diffs = [diffs[i+1] - diffs[i] for i in range(len(diffs)-1)]
            if not sec_diffs:
                return None
                
            # Find the elbow as the point with max rate of change
            # Add 1 because we used differences
            knee_idx = sec_diffs.index(min(sec_diffs)) + 1
            return knee_idx
        else:

            return None

def save_process_metadata(processes):
    """Save full process metadata to integrity_processes.json safely."""
    return safe_write_json(INTEGRITY_PROCESS_FILE, processes)

def monitor_all_processes(interval=5):
    """Main monitoring loop for tracking all processes on the system."""
    global SERVICE_RUNNING
    
    # Setup tracking
    known_processes = {}  # Store by key: pid
    known_hashes = {}     # Track process hashes
    ml_model_info = None
    alerted_processes = set()  # Avoid duplicate alerts
    
    # Define special system processes that should be excluded from alerting
    special_system_processes = [
        "registry", "memcompression", "secure system", 
        "system", "idle", "memory compression"
    ]
    
    # Initialize ML model if available
    if ML_LIBRARIES_AVAILABLE:
        ml_model_info = implement_behavioral_baselining()
        logging.info("ML behavioral baselining for all-process monitoring completed")
    
    logging.info("Starting all-process monitoring...")
    
    # Load integrity state (we'll use the same file as listening processes)
    integrity_state = load_process_metadata()
    
    while SERVICE_RUNNING:
        try:
            # Get all current processes
            current_processes = get_all_system_processes()
            
            # Create mappings for current processes
            current_pids = set()
            
            for process_key, process_info in current_processes.items():
                pid = process_info.get("pid")
                process_hash = process_info.get("hash")
                process_name = process_info.get("process_name", "").lower()
                current_pids.add(pid)
                
                # Skip special system processes
                if process_name in special_system_processes or process_info.get("is_system_process", False):
                    if pid not in known_processes:
                        known_processes[pid] = process_info
                    continue
                
                # Process new or restarted processes
                if pid not in known_processes:
                    process_name = process_info.get("process_name", "UNKNOWN")
                    exe_path = process_info.get("exe_path", "")
                    
                    # Check for fileless processes first
                    if process_info.get("fileless", False):
                        logging.warning(f"Detected potential fileless process: {process_name} (PID: {pid})")
                        logging.warning(f"Command line: {process_info.get('cmdline', 'UNKNOWN')}")
                        
                        # Generate alert for fileless process
                        log_event_to_pim(
                            event_type="FILELESS_PROCESS_DETECTED",
                            file_path=exe_path if exe_path != "ACCESS_DENIED" else "",
                            previous_metadata=None,
                            new_metadata=process_info,
                            previous_hash=None,
                            new_hash=process_hash
                        )
                        
                        # Add to alerted processes to avoid duplicate alerts
                        alerted_processes.add(pid)
                    
                    # Skip further processing if this process generated an alert
                    if pid in alerted_processes:
                        continue
                    
                    # Analyze behavior for suspicious patterns
                    suspicious_behaviors = analyze_process_behavior(pid, process_info)
                    
                    if suspicious_behaviors:
                        behavior_str = ", ".join(suspicious_behaviors)
                        logging.warning(f"Suspicious behavior detected in process {process_name} (PID: {pid}): {behavior_str}")
                        
                        # Log the alert
                        log_event_to_pim(
                            event_type="SUSPICIOUS_BEHAVIOR",
                            file_path=exe_path,
                            previous_metadata=None,
                            new_metadata=process_info,
                            previous_hash=None,
                            new_hash=process_hash
                        )
                        
                        # Add to alerted processes
                        alerted_processes.add(pid)
                        continue
                    
                    # ML-based anomaly detection if available
                    if ML_LIBRARIES_AVAILABLE and ml_model_info:
                        anomaly = detect_anomalies_ml(process_info, ml_model_info)
                        
                        if anomaly and anomaly.get("is_anomaly", False):
                            logging.warning(f"ML detected anomaly in process {process_name} (PID: {pid}) - Score: {anomaly.get('score', 0)}")
                            
                            # Log the alert
                            log_event_to_pim(
                                event_type="ML_DETECTED_ANOMALY",
                                file_path=exe_path,
                                previous_metadata=None,
                                new_metadata=process_info,
                                previous_hash=None,
                                new_hash=process_hash
                            )
                            
                            # Add to alerted processes
                            alerted_processes.add(pid)
                            continue
                    
                    # Process was clean - store in known processes
                    logging.info(f"New process: {process_name} (PID: {pid})")
                    known_processes[pid] = process_info
                    
                    # If the process has a valid hash, add it to known_hashes
                    if process_hash and process_hash not in ["ERROR_HASHING_PERMISSION", "ERROR_FILE_NOT_FOUND"]:
                        known_hashes[process_hash] = pid
                        
                        # Only add to integrity state if not already there
                        if process_hash not in integrity_state:
                            update_process_tracking(exe_path, process_hash, process_info)
                
                # Process already known - check for changes
                else:
                    # Get stored process info
                    stored_info = known_processes[pid]
                    
                    # Check for significant changes in process
                    changes = []
                    
                    # Check for command line changes (could indicate code injection)
                    if stored_info.get("cmdline") != process_info.get("cmdline"):
                        changes.append({
                            "field": "cmdline",
                            "previous": stored_info.get("cmdline"),
                            "current": process_info.get("cmdline"),
                            "severity": "high"  # Command line changes are high severity
                        })
                    
                    # Check for user changes (potential privilege escalation)
                    if stored_info.get("user") != process_info.get("user"):
                        changes.append({
                            "field": "user",
                            "previous": stored_info.get("user"),
                            "current": process_info.get("user"),
                            "severity": "critical"  # User changes are critical severity
                        })
                    
                    # Check for memory growth (potential heap spray or injection)
                    prev_mem = stored_info.get("memory_rss_kb", 0)
                    current_mem = process_info.get("memory_rss_kb", 0)
                    
                    # Alert on significant memory increases (>100MB)
                    if current_mem - prev_mem > 102400:  # 100MB in KB
                        changes.append({
                            "field": "memory_rss_kb",
                            "previous": prev_mem,
                            "current": current_mem,
                            "delta": current_mem - prev_mem,
                            "severity": "medium"
                        })
                    
                    # Check for thread count increase with improved thresholds
                    prev_threads = stored_info.get("thread_count", 0)
                    current_threads = process_info.get("thread_count", 0)
                    
                    # Skip if previous count is zero (initialization)
                    if prev_threads > 0:
                        thread_increase = current_threads - prev_threads
                        percentage_increase = ((current_threads / prev_threads) * 100) - 100 if prev_threads > 0 else 0
                        
                        # Process type-specific thresholds
                        benign_variable_processes = [
                            "nissrv.exe", "msmpeng.exe", "svchost.exe", "searchindexer.exe", 
                            "mssearch.exe", "sqlservr.exe", "w3wp.exe", "iisexpress.exe"
                        ]
                        
                        is_benign_variable = process_name in benign_variable_processes
                        
                        # Apply appropriate thresholds
                        if ((not is_benign_variable and (thread_increase > 10 or percentage_increase > 300)) or 
                            (is_benign_variable and thread_increase > 20 and percentage_increase > 500)):
                            changes.append({
                                "field": "thread_count",
                                "previous": prev_threads,
                                "current": current_threads,
                                "delta": thread_increase,
                                "percentage": int(percentage_increase),
                                "severity": "medium"
                            })
                    
                    # Check for handle count increase (common in poorly written malware)
                    prev_handles = stored_info.get("handle_count", 0)
                    current_handles = process_info.get("handle_count", 0)
                    
                    if prev_handles > 0 and (current_handles - prev_handles) > 100:
                        changes.append({
                            "field": "handle_count",
                            "previous": prev_handles,
                            "current": current_handles,
                            "delta": current_handles - prev_handles,
                            "severity": "low"
                        })
                    
                    # If significant changes detected, log and alert
                    if changes:
                        # Only alert on medium or higher severity changes
                        significant_changes = [c for c in changes if c.get("severity") in ["medium", "high", "critical"]]
                        
                        if significant_changes:
                            process_name = process_info.get("process_name", "UNKNOWN")
                            logging.warning(f"Significant changes detected in process {process_name} (PID: {pid}):")
                            
                            for change in significant_changes:
                                severity = change.get("severity", "").upper()
                                if "delta" in change:
                                    logging.warning(f"  [{severity}] {change['field']}: {change['previous']} -> {change['current']} (delta: {change['delta']})")
                                else:
                                    logging.warning(f"  [{severity}] {change['field']}: '{change['previous']}' -> '{change['current']}'")
                            
                            # Add the changes to process_info for logging
                            process_info["detected_changes"] = significant_changes
                            
                            # Log the alert
                            log_event_to_pim(
                                event_type="PROCESS_RUNTIME_CHANGES",
                                file_path=process_info.get("exe_path", ""),
                                previous_metadata=stored_info,
                                new_metadata=process_info,
                                previous_hash=process_info.get("hash", ""),
                                new_hash=process_info.get("hash", "")
                            )
                            
                            # Add to alerted processes to prevent duplicate alerts
                            alerted_processes.add(pid)
                    
                    # Update stored information
                    known_processes[pid] = process_info
            
            # Detect terminated processes
            for pid in list(known_processes.keys()):
                if pid not in current_pids:
                    process_info = known_processes[pid]
                    process_name = process_info.get("process_name", "UNKNOWN")
                    process_hash = process_info.get("hash", "UNKNOWN")
                    
                    # Skip logging for special system processes to reduce noise
                    if process_name.lower() in special_system_processes or process_info.get("is_system_process", False):
                        del known_processes[pid]
                        continue
                    
                    logging.info(f"Process terminated: {process_name} (PID: {pid})")
                    
                    # Remove from known_processes
                    del known_processes[pid]
                    
                    # Remove from known_hashes if applicable
                    if process_hash in known_hashes and known_hashes[process_hash] == pid:
                        del known_hashes[process_hash]
                    
                    # Generate alert for terminated process
                    log_event_to_pim(
                        event_type="PROCESS_TERMINATED",
                        file_path=process_info.get("exe_path", ""),
                        previous_metadata=process_info,
                        new_metadata=None,
                        previous_hash=process_hash,
                        new_hash=None
                    )
            
            # Sleep until next interval
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in all-process monitoring loop: {e}")
            logging.debug(traceback.format_exc())
            
            # Sleep a bit longer on error to avoid error loops
            time.sleep(max(interval, 5))

class ProcessMonitorService(win32serviceutil.ServiceFramework):
    """Windows Service implementation for Process Integrity Monitor."""
    
    _svc_name_ = "MoniSecPIM"
    _svc_display_name_ = "MoniSec Process Integrity Monitor"
    _svc_description_ = "Monitors system processes for security integrity violations"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = False
        
        # Setup logging
        log_file = os.path.join(LOG_DIR, "pim_service.log")
        os.makedirs(LOG_DIR, exist_ok=True)
        
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def SvcStop(self):
        """Stop the service."""
        global SERVICE_RUNNING
        
        logging.info("Service stop requested...")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        SERVICE_RUNNING = False
        self.is_running = False
    
    def SvcDoRun(self):
        """Run the service."""
        global SERVICE_RUNNING
        
        logging.info("Service starting...")
        
        # Initialize directories
        ensure_directories()
        ensure_file_exists(INTEGRITY_PROCESS_FILE, {}, is_json=True)
        ensure_file_exists(FILE_MONITOR_JSON, {}, is_json=True)
        
        import servicemanager
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        SERVICE_RUNNING = True
        self.is_running = True
        
        # Start monitor threads
        try:
            # Start integrity scan thread
            integrity_thread = threading.Thread(
                target=periodic_integrity_scan,
                daemon=True
            )
            integrity_thread.start()
            
            # Start the all-process monitoring thread
            all_process_thread = threading.Thread(
                target=monitor_all_processes,
                daemon=True
            )
            all_process_thread.start()
            
            # Run network listening process monitoring in main thread
            monitor_listening_processes()
            
        except Exception as e:
            logging.error(f"Service error: {e}")
            logging.debug(traceback.format_exc())
            self.SvcStop()

def force_cleanup(max_age_days=30, verbose=True):
    """
    Force a cleanup of the integrity_processes.json file.
    Removes old entries and consolidates process groups.
    
    Args:
        max_age_days: Maximum age of entries to keep (in days)
        verbose: Whether to print detailed logs
        
    Returns:
        dict: Stats about the cleanup operation
    """
    # Import datetime and timedelta
    from datetime import datetime, timedelta
    
    stats = {
        "old_hashes_removed": 0,
        "empty_groups_removed": 0,
        "missing_executables_removed": 0,
        "groups_merged": 0,
        "total_before": 0,
        "total_after": 0
    }
    
    try:
        # Load integrity state
        integrity_state = load_process_metadata()
        
        # Count initial entries
        process_entries = 0
        group_entries = 0
        
        for key in integrity_state:
            if key == "process_groups":
                if isinstance(integrity_state[key], dict):
                    group_entries = len(integrity_state[key])
            else:
                process_entries += 1
                
        stats["total_before"] = process_entries
        
        # Perform cleanup of process groups
        if "process_groups" in integrity_state:
            if verbose:
                logging.info(f"Cleaning up process groups (max age: {max_age_days} days)...")
            
            # Track groups and hashes before cleanup
            groups_before = len(integrity_state["process_groups"])
            total_hashes_before = sum(
                len(group.get("known_hashes", {})) 
                for group in integrity_state["process_groups"].values()
            )
            
            # Clean process groups
            maintain_process_groups(integrity_state, max_age_days)
            
            # Track groups and hashes after cleanup
            groups_after = len(integrity_state["process_groups"])
            total_hashes_after = sum(
                len(group.get("known_hashes", {})) 
                for group in integrity_state["process_groups"].values()
            )
            
            # Update stats
            stats["groups_merged"] = groups_before - groups_after
            stats["old_hashes_removed"] = total_hashes_before - total_hashes_after
            
            # Remove empty groups
            empty_groups = []
            for group_id, group in integrity_state["process_groups"].items():
                if not group.get("known_hashes", {}):
                    empty_groups.append(group_id)
            
            for group_id in empty_groups:
                del integrity_state["process_groups"][group_id]
                if verbose:
                    logging.info(f"Removed empty process group: {group_id}")
            
            stats["empty_groups_removed"] = len(empty_groups)
        
        # Remove individual process entries with missing executables
        process_to_remove = []
        for process_hash, process_info in integrity_state.items():
            if process_hash == "process_groups" or not isinstance(process_info, dict):
                continue
                
            exe_path = process_info.get("exe_path", "")
            if exe_path and exe_path != "ACCESS_DENIED" and not os.path.exists(exe_path):
                process_to_remove.append(process_hash)
                if verbose:
                    process_name = process_info.get("process_name", "UNKNOWN")
                    logging.info(f"Removing process with missing executable: {process_name} ({exe_path})")
        
        for process_hash in process_to_remove:
            del integrity_state[process_hash]
            
        stats["missing_executables_removed"] = len(process_to_remove)
        
        # Save changes
        save_process_metadata(integrity_state)
        
        # Count final entries
        process_entries = 0
        for key in integrity_state:
            if key != "process_groups":
                process_entries += 1
                
        stats["total_after"] = process_entries
        
        if verbose:
            logging.info(f"Cleanup complete. Removed {stats['old_hashes_removed']} old hashes, "
                        f"{stats['empty_groups_removed']} empty groups, and "
                        f"{stats['missing_executables_removed']} entries with missing executables.")
        
        return stats
        
    except Exception as e:
        logging.error(f"Error during forced cleanup: {e}")
        logging.debug(traceback.format_exc())
        return stats

def safe_write_text(file_path, data):
    """Safely write text data to a file with proper error handling and ACL checks."""
    temp_file = f"{file_path}.tmp"
    backup_file = f"{file_path}.bak"
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        # First write to temp file
        with open(temp_file, "w") as f:
            f.write(data)
        
        # Set secure permissions on temp file
        set_secure_permissions(temp_file)
        
        # If original file exists, create backup first
        if os.path.exists(file_path):
            try:
                # Try to create backup of original
                if os.path.exists(backup_file):
                    os.remove(backup_file)
                os.rename(file_path, backup_file)
            except Exception as e:
                logging.warning(f"Could not create backup file {backup_file}: {e}")
        
        # Now try to rename temp to target
        try:
            os.rename(temp_file, file_path)
        except OSError as e:
            # If rename fails due to permissions, try direct copy
            if e.winerror == 5:  # Access denied
                with open(temp_file, "r") as src:
                    content = src.read()
                    
                # Try direct write with admin privileges
                try:
                    # Use win32 API for privileged write
                    with open(file_path, "w") as f:
                        f.write(content)
                    
                    # Set secure permissions
                    set_secure_permissions(file_path)
                    
                    # Remove temp file
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        
                    return True
                except Exception as inner_e:
                    logging.error(f"Failed direct write to {file_path}: {inner_e}")
                    
                    # Try to restore from backup
                    if os.path.exists(backup_file):
                        try:
                            os.rename(backup_file, file_path)
                        except:
                            pass
                    
                    return False
            else:
                raise
        
        # Successful rename, clear backup
        if os.path.exists(backup_file):
            try:
                os.remove(backup_file)
            except:
                pass
                
        # Remove temp file if it still exists
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
                
        return True
    except Exception as e:
        logging.error(f"Failed to write to {file_path}: {e}")
        
        # Try to restore from backup
        if os.path.exists(backup_file) and not os.path.exists(file_path):
            try:
                os.rename(backup_file, file_path)
            except:
                pass
        
        # Clean up temp file
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
                
        return False

def safe_write_json(file_path, data):
    """Safely write JSON data to a file with proper error handling and ACL checks."""
    try:
        json_str = json.dumps(data, indent=4)
        return safe_write_text(file_path, json_str)
    except Exception as e:
        logging.error(f"Failed to serialize JSON for {file_path}: {e}")
        return False

def run_as_console():
    """Run the monitor in console mode."""
    global SERVICE_RUNNING
    
    # Configure logging to console and file
    log_file = os.path.join(LOG_DIR, "pim_console.log")
    os.makedirs(LOG_DIR, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logging.info("Starting Process Integrity Monitor in console mode...")
    
    # Initialize directories
    ensure_directories()
    ensure_file_exists(INTEGRITY_PROCESS_FILE, {}, is_json=True)
    ensure_file_exists(FILE_MONITOR_JSON, [], is_json=True)
    
    # Set signal handlers
    def handle_shutdown(signum=None, frame=None):
        global SERVICE_RUNNING
        logging.info("Shutdown signal received, stopping...")
        SERVICE_RUNNING = False
        sys.exit(0)
    
    # Register signal handlers safely
    try:
        # Only register signals that exist in this environment
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, handle_shutdown)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_shutdown)
            
        # Set up Windows-specific signal handling
        try:
            win32api.SetConsoleCtrlHandler(
                lambda event_type: handle_shutdown() if event_type in (0, 1) else None, 
                True
            )
        except Exception as e:
            logging.warning(f"Could not set Windows console control handler: {e}")
    except NameError as e:
        logging.warning(f"Could not set up signal handlers: {e}")
    except Exception as e:
        logging.warning(f"Error setting up signal handlers: {e}")
    
    SERVICE_RUNNING = True
    
    # Start monitor threads
    try:
        # Start integrity scan thread
        integrity_thread = threading.Thread(
            target=periodic_integrity_scan,
            daemon=True
        )
        integrity_thread.start()
        
        # Start the all-process monitoring thread
        all_process_thread = threading.Thread(
            target=monitor_all_processes,
            daemon=True
        )
        all_process_thread.start()
        
        # Run main monitoring loop in main thread
        monitor_listening_processes()
        
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, stopping...")
        SERVICE_RUNNING = False
    except Exception as e:
        logging.error(f"Error in console mode: {e}")
        logging.debug(traceback.format_exc())
        SERVICE_RUNNING = False
        sys.exit(0)
    
    # Register signal handlers safely
    try:
        # Only register signals that exist in this environment
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, handle_shutdown)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_shutdown)
            
        # Set up Windows-specific signal handling
        try:
            win32api.SetConsoleCtrlHandler(
                lambda event_type: handle_shutdown() if event_type in (0, 1) else None, 
                True
            )
        except Exception as e:
            logging.warning(f"Could not set Windows console control handler: {e}")
    except NameError as e:
        logging.warning(f"Could not set up signal handlers: {e}")
    except Exception as e:
        logging.warning(f"Error setting up signal handlers: {e}")
    
    SERVICE_RUNNING = True
    
    # Start monitor threads
    try:
        # Start integrity scan thread
        integrity_thread = threading.Thread(
            target=periodic_integrity_scan,
            daemon=True
        )
        integrity_thread.start()
        
        # Run main monitoring loop
        monitor_listening_processes()
        
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, stopping...")
        SERVICE_RUNNING = False
    except Exception as e:
        logging.error(f"Error in console mode: {e}")
        logging.debug(traceback.format_exc())
        SERVICE_RUNNING = False

def print_help():
    """Print help information."""
    help_text = """
Process Integrity Monitor (PIM) for Windows - Help Menu

Usage:
  python pim.py               Start the PIM monitoring service in console mode
  python pim.py install       Install the PIM service
  python pim.py remove        Remove the PIM service
  python pim.py start         Start the installed PIM service
  python pim.py stop          Stop the PIM service
  python pim.py restart       Restart the PIM service
  python pim.py cleanup       Clean up old entries in the integrity file
  python pim.py debug         Run in debug mode with extra logging
  python pim.py help          Show this help message

"""
    print(help_text.strip())

if __name__ == "__main__":
    # Check for administrator privileges
    if not is_admin():
        print("[WARNING] This script requires administrator privileges for full functionality.")
        print("         Some features like memory scanning will be limited.")
        print("         Please run as administrator for complete monitoring capabilities.")

    # Process command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "help":
            print_help()
            
        elif command == "install":
            try:
                # Ensure script path is absolute
                script_path = os.path.abspath(__file__)
                pythonpath = sys.executable
                
                win32serviceutil.InstallService(
                    pythonClassString=f"{os.path.basename(__file__).replace('.py', '')}.ProcessMonitorService",
                    serviceName="MoniSecPIM",
                    displayName="MoniSec Process Integrity Monitor",
                    description="Monitors system processes for security integrity violations",
                    startType=win32service.SERVICE_AUTO_START
                )
                print("[SUCCESS] MoniSec PIM service installed successfully.")
            except Exception as e:
                print(f"[ERROR] Failed to install service: {e}")
                
        elif command == "remove":
            try:
                win32serviceutil.RemoveService("MoniSecPIM")
                print("[SUCCESS] MoniSec PIM service removed successfully.")
            except Exception as e:
                print(f"[ERROR] Failed to remove service: {e}")
                
        elif command == "start":
            try:
                win32serviceutil.StartService("MoniSecPIM")
                print("[SUCCESS] MoniSec PIM service started.")
            except Exception as e:
                print(f"[ERROR] Failed to start service: {e}")
                
        elif command == "stop":
            try:
                win32serviceutil.StopService("MoniSecPIM")
                print("[SUCCESS] MoniSec PIM service stopped.")
            except Exception as e:
                print(f"[ERROR] Failed to stop service: {e}")
                
        elif command == "restart":
            try:
                win32serviceutil.RestartService("MoniSecPIM")
                print("[SUCCESS] MoniSec PIM service restarted.")
            except Exception as e:
                print(f"[ERROR] Failed to restart service: {e}")
                
        elif command == "cleanup":
            print("[INFO] Running integrity file cleanup...")
            try:
                # Setup logging for cleanup operation
                log_file = os.path.join(LOG_DIR, "pim_cleanup.log")
                os.makedirs(LOG_DIR, exist_ok=True)
                
                logging.basicConfig(
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(log_file),
                        logging.StreamHandler()
                    ]
                )
                
                # Load integrity state
                integrity_state = load_process_metadata()
                
                # Perform cleanup
                if maintain_process_groups(integrity_state, max_age_days=30):
                    # Check application existence
                    application_changes = check_application_existence()
                    
                    # Save changes
                    save_process_metadata(integrity_state)
                    
                    print(f"[SUCCESS] Integrity file cleanup completed. See {log_file} for details.")
                else:
                    print("[INFO] No cleanup needed - integrity file is up-to-date.")
            except Exception as e:
                print(f"[ERROR] Cleanup failed: {e}")
                
        elif command == "debug":
            # Special debug mode with extra logging
            print("[INFO] Starting in debug mode with extra logging...")
            logging.getLogger('').setLevel(logging.DEBUG)
            run_as_console()
        
        elif command == "cleanup":
            print("[INFO] Running integrity file cleanup...")
            try:
                # Setup logging for cleanup operation
                log_file = os.path.join(LOG_DIR, "pim_cleanup.log")
                os.makedirs(LOG_DIR, exist_ok=True)
                
                logging.basicConfig(
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler(log_file),
                        logging.StreamHandler()
                    ]
                )
                
                # Parse additional arguments
                max_age = 30  # Default
                if len(sys.argv) > 2:
                    try:
                        max_age = int(sys.argv[2])
                    except ValueError:
                        print(f"[WARNING] Invalid max age value: {sys.argv[2]}. Using default of 30 days.")
                
                # Run the cleanup
                stats = force_cleanup(max_age_days=max_age, verbose=True)
                
                # Print summary
                print(f"[SUCCESS] Integrity file cleanup completed. See {log_file} for details.")
                print(f"Summary:")
                print(f"  - Removed {stats['old_hashes_removed']} old hashes")
                print(f"  - Removed {stats['empty_groups_removed']} empty groups")
                print(f"  - Removed {stats['missing_executables_removed']} entries with missing executables")
                print(f"  - Merged {stats['groups_merged']} similar groups")
                print(f"  - Total entries before: {stats['total_before']}")
                print(f"  - Total entries after: {stats['total_after']}")
            except Exception as e:
                print(f"[ERROR] Cleanup failed: {e}")
        
        elif command in ["--service", "--foreground"]:
            # When the service manager executes the service
            win32serviceutil.HandleCommandLine(ProcessMonitorService)
            
        else:
            print(f"[ERROR] Unknown command: {command}")
            print_help()
    
    else:
        # Default: run in console mode
        run_as_console()
