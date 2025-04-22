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

# Optional ML imports with proper error handling
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries not found. ML-based detection disabled.")
    ML_LIBRARIES_AVAILABLE = False

# Define paths for Windows
BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
FILE_MONITOR_JSON = os.path.join(LOG_DIR, "file_monitor.json")

# Global flags
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

def get_process_hash(exe_path, cmdline=None):
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

        # Optionally include command-line arguments in hashing
        if cmdline and isinstance(cmdline, str):
            hash_obj.update(cmdline.encode("utf-8"))

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

def save_process_metadata(processes):
    """Save full process metadata to integrity_processes.json safely."""
    return safe_write_json(INTEGRITY_PROCESS_FILE, processes)

def update_process_tracking(exe_path, process_hash, metadata):
    """Update process tracking files with new or modified processes, using hash as primary key."""
    # Load existing data
    integrity_state = load_process_metadata()

    # Use hash as the primary key instead of PID
    if process_hash != "ERROR_HASHING_PERMISSION" and process_hash != "ERROR_FILE_NOT_FOUND":
        # Store metadata by hash
        integrity_state[process_hash] = metadata

    # Save updates
    success = save_process_metadata(integrity_state)
    return success

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

def check_lineage_baseline(process_info, integrity_state):
    """Check if a process's lineage matches the baseline, using integrity_state."""
    proc_name = process_info["process_name"]
    lineage = process_info.get("lineage", [])

    if not lineage:
        return False

    # Find baseline lineage from existing processes
    baseline = None
    for hash_key, existing_proc in integrity_state.items():
        if existing_proc.get("process_name") == proc_name and existing_proc.get("lineage"):
            # Found a matching process name with established lineage
            baseline = existing_proc.get("lineage")
            break

    if not baseline:
        # First time seeing this process - return true (no deviation)
        logging.info(f"Baseline lineage established for {proc_name}: {lineage}")
        return True
    elif lineage != baseline:
        # Lineage deviation detected
        logging.warning(f"Lineage deviation for {proc_name}:")
        logging.warning(f"  Expected: {baseline}")
        logging.warning(f"  Found:    {lineage}")
        return False
    
    return True

def check_for_unusual_port_use(process_info, integrity_state):
    """Check if a process is listening on a non-standard port using integrity_state."""
    if not integrity_state:
        return []  # Return empty list if no baseline
        
    proc_name = process_info.get("process_name")
    proc_port = process_info.get("port")
    
    # Skip if this is the first time we're seeing this process
    proc_port = int(proc_port) if isinstance(proc_port, (int, str)) and str(proc_port).isdigit() else 0
    
    # Find existing ports for this process name
    expected_ports = []
    baseline_metadata = None
    
    for hash_key, existing_proc in integrity_state.items():
        if existing_proc.get("process_name") == proc_name:
            port = existing_proc.get("port")
            if port and port not in expected_ports:
                port_int = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else 0
                if port_int > 0:
                    expected_ports.append(port_int)
            
            # Use the first match as baseline metadata
            if baseline_metadata is None:
                baseline_metadata = existing_proc
    
    alerts = []
    
    # If we found baseline data and it's a mismatch
    if expected_ports and proc_port > 0 and proc_port not in expected_ports:
        logging.warning(f"{proc_name} listening on unexpected port {proc_port}. Expected: {expected_ports}")
        alerts.append({
            "type": "UNUSUAL_PORT_USE",
            "details": {
                "process": proc_name,
                "expected_ports": expected_ports,
                "actual_port": proc_port
            }
        })
    
    # Check for other metadata mismatches if we have a baseline
    if baseline_metadata:
        if baseline_metadata.get("exe_path") != process_info.get("exe_path"):
            logging.warning(f"Executable path mismatch for {proc_name}: expected '{baseline_metadata.get('exe_path')}', got '{process_info.get('exe_path')}'")
            alerts.append({
                "type": "EXECUTABLE_PATH_MISMATCH",
                "details": {
                    "process": proc_name,
                    "expected_path": baseline_metadata.get("exe_path"),
                    "actual_path": process_info.get("exe_path")
                }
            })
        
        if baseline_metadata.get("hash") != process_info.get("hash") and "ERROR" not in baseline_metadata.get("hash", "") and "ERROR" not in process_info.get("hash", ""):
            logging.warning(f"Binary hash mismatch for {proc_name}: expected '{baseline_metadata.get('hash')}', got '{process_info.get('hash')}'")
            alerts.append({
                "type": "HASH_MISMATCH",
                "details": {
                    "process": proc_name,
                    "expected_hash": baseline_metadata.get("hash"),
                    "actual_hash": process_info.get("hash")
                }
            })
        
        if baseline_metadata.get("user") != process_info.get("user"):
            logging.warning(f"User mismatch for {proc_name}: expected '{baseline_metadata.get('user')}', got '{process_info.get('user')}'")
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
                    log_event_to_fim(
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
    """Get detailed statistics about a process for behavioral analysis."""
    stats = {
        "memory_usage_kb": 0,
        "cpu_percent": 0,
        "handle_count": 0,
        "thread_count": 0,
        "child_process_count": 0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
        "connection_count": 0
    }
    
    try:
        process = psutil.Process(pid)
        
        # CPU and memory stats
        stats["cpu_percent"] = process.cpu_percent(interval=0.1)
        stats["memory_usage_kb"] = process.memory_info().rss // 1024
        
        # Resource usage
        stats["handle_count"] = process.num_handles() if hasattr(process, 'num_handles') else 0
        stats["thread_count"] = process.num_threads()
        
        # Child processes
        stats["child_process_count"] = len(process.children())
        
        # IO stats
        try:
            io_counters = process.io_counters()
            stats["io_read_bytes"] = io_counters.read_bytes
            stats["io_write_bytes"] = io_counters.write_bytes
        except (psutil.AccessDenied, AttributeError):
            pass
        
        # Network connections - use net_connections() instead of connections()
        try:
            # Use the new net_connections() method
            connections = process.net_connections()
            stats["connection_count"] = len(connections)
        except (psutil.AccessDenied, AttributeError) as e:
            logging.debug(f"Could not get network connections for PID {pid}: {e}")
            stats["connection_count"] = 0
            
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
    Analyze a process for suspicious behavior patterns, including fileless malware indicators.
    Returns a list of detected suspicious behaviors.
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
        
        # Get process stats
        process_stats = get_process_stats(pid)
        
        # 1. Check for command shells in lineage of server processes
        shell_in_lineage = any(shell.lower() in [p.lower() for p in lineage] 
                            for shell in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'])
        
        server_process = any(server in process_name 
                          for server in ['w3wp', 'httpd', 'tomcat', 'nginx', 'iis'])
                          
        if shell_in_lineage and server_process:
            suspicious_patterns.append(f"Unusual process ancestry: command shell in lineage of web server")
        
        # 2. Check if running from unusual directory
        suspicious_dirs = ["\\temp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", 
                       "\\programdata\\temp\\", "\\users\\public\\", "\\downloads\\"]
                       
        for suspect_dir in suspicious_dirs:
            if suspect_dir in exe_path:
                suspicious_patterns.append(f"Executing from suspicious location: {suspect_dir}")
                break
        
        # 3. Check for unusual port (excluding common alternative ports)
        common_high_ports = [8080, 8443, 3000, 3001, 5000, 5001, 8000, 8008, 8888]
        if isinstance(port, int) and port > 1024 and port not in common_high_ports:
            suspicious_patterns.append(f"Listening on unusual high port: {port}")
        
        # 4. Windows-specific process relationship checks
        if "services.exe" not in lineage and process_name == "svchost.exe":
            suspicious_patterns.append("svchost.exe running without services.exe as ancestor")
        
        # 5. PowerShell encoded command detection
        if "powershell" in exe_path and any(enc in cmdline 
                                         for enc in ["-encodedcommand", "-enc", "-e", "frombase64string"]):
            suspicious_patterns.append("PowerShell with encoded command detected")
        
        # 6. LOLBins (Living Off The Land Binaries) detection
        lolbins = {
            "certutil.exe": ["/urlcache", "/verifyctl", "/decode"],
            "regsvr32.exe": ["scrobj.dll", "/i:", "/u", "/s"],
            "mshta.exe": ["javascript:", "vbscript:", ".hta"],
            "rundll32.exe": ["advpack.dll", "setupapi.dll", "shdocvw.dll", "javascript:"],
            "msiexec.exe": ["/y", "/z"],
            "installutil.exe": ["/logfile=", "/u"],
            "regasm.exe": ["/quiet"],
            "regedt32.exe": ["/i"],
            "wmic.exe": ["process call create", "shadowcopy"]
        }
        
        for lolbin, flags in lolbins.items():
            if lolbin.lower() == process_name:
                for flag in flags:
                    if flag.lower() in cmdline:
                        suspicious_patterns.append(f"Potential LOLBin abuse: {lolbin} with {flag}")
                        break
        
        # 7. Unusual parent-child relationships
        unusual_parents = {
            "lsass.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
            "svchost.exe": ["cmd.exe", "powershell.exe", "rundll32.exe"]
        }
        
        for child, suspicious_parents in unusual_parents.items():
            if process_name == child and lineage and lineage[0].lower() in [p.lower() for p in suspicious_parents]:
                suspicious_patterns.append(f"Unusual parent process {lineage[0]} for {child}")
        
        # 8. High resource usage for certain processes
        if process_stats["cpu_percent"] > 80 and process_name in ["svchost.exe", "lsass.exe", "csrss.exe"]:
            suspicious_patterns.append(f"Unusually high CPU usage ({process_stats['cpu_percent']}%) for {process_name}")
        
        # 9. Very high connection count for non-server processes
        if (process_stats["connection_count"] > 50 and 
            not any(server in process_name for server in ["iis", "apache", "nginx", "w3wp", "httpd", "tomcat"])):
            suspicious_patterns.append(f"High connection count ({process_stats['connection_count']}) for non-server process")
        
        # 10. Game processes may have high memory usage or many DLLs loaded - reduce false positives
        if "game" in process_name.lower() or "game" in exe_path.lower():
            # Filter out common game-related behaviors that might trigger alerts
            suspicious_patterns = [pattern for pattern in suspicious_patterns 
                                 if not ("high port" in pattern.lower() or 
                                        "connection count" in pattern.lower())]
        
        #-------------------------------------------------------------------------
        # New Part: Enhanced fileless malware detection
        #-------------------------------------------------------------------------
        
        # 11. Check for fileless execution techniques
        # 11.1 Detect file not found but process exists (potential fileless process)
        if not os.path.exists(exe_path) and exe_path != "ACCESS_DENIED":
            suspicious_patterns.append("Fileless process detected: executable path doesn't exist")
        
        # 11.2 Windows Script Host execution with remote content
        if process_name in ["wscript.exe", "cscript.exe"]:
            if "http:" in cmdline or "https:" in cmdline:
                suspicious_patterns.append("Windows Script Host executing remote script content")
        
        # 11.3 Evidence of reflective loading in .NET
        if process_name in ["powershell.exe", "powershell_ise.exe"] or ".exe" not in process_name:
            for reflective_term in ["reflection.assembly", "assembly.load", "loadfrom", "loadfile"]:
                if reflective_term in cmdline:
                    suspicious_patterns.append(f".NET reflection loading detected: {reflective_term}")
                    break
        
        # 11.4 Memory analysis for fileless indicators if admin privileges available
        if is_admin():
            try:
                # Only perform memory scanning if already found suspicious indicators
                # or for processes with missing executable
                if suspicious_patterns or not os.path.exists(exe_path):
                    memory_regions = enumerate_process_memory_regions(pid)
                    
                    # Count suspicious memory regions
                    rwx_regions = 0
                    executable_private_regions = 0
                    
                    for region in memory_regions:
                        if region["protection"]["executable"] and region["type"] == "Private":
                            executable_private_regions += 1
                            
                            if region["protection"]["writable"]:
                                rwx_regions += 1
                    
                    # Alert on excessive RWX memory regions
                    if rwx_regions > 3:
                        suspicious_patterns.append(f"Excessive RWX memory regions: {rwx_regions} - potential shellcode")
                    
                    # Alert on excessive executable private memory
                    if executable_private_regions > 5:
                        suspicious_patterns.append(f"Excessive executable allocations: {executable_private_regions} - potential code injection")
            except Exception as e:
                logging.debug(f"Error scanning memory for fileless indicators: {e}")
        
        # 11.5 Detect memory-only execution tricks in command line
        memory_exec_indicators = [
            "virtualalloc", "heapalloc", "memoryapi", "writeprocessmemory",
            "createremotethread", "ntwritevirtualmemory", "shellcode"
        ]
        
        for indicator in memory_exec_indicators:
            if indicator in cmdline:
                suspicious_patterns.append(f"Memory manipulation API in command line: {indicator}")
                break
        
        # 11.6 Additional WMI process execution detection
        if "wmic" in cmdline and "process call create" in cmdline:
            suspicious_patterns.append("WMI used to create process - potential living off the land technique")
        
        # 11.7 Check for DLL hijacking (process running with unexpected DLLs)
        if pid > 0:
            try:
                dll_indicators = detect_dll_search_order_hijacking(pid, process_info)
                if dll_indicators:
                    for indicator in dll_indicators:
                        if "description" in indicator:
                            suspicious_patterns.append(indicator["description"])
            except Exception as e:
                logging.debug(f"Error checking for DLL hijacking: {e}")
        
    except Exception as e:
        logging.error(f"Error analyzing process behavior for PID {pid}: {e}")
    
    return suspicious_patterns

def implement_behavioral_baselining():
    """Train an ML model for process behavior anomaly detection if libraries are available."""
    if not ML_LIBRARIES_AVAILABLE:
        logging.warning("ML libraries not available - skipping behavioral baselining")
        return None
        
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np
        import pandas as pd
        
        # Define system processes that should have special treatment
        system_processes = ["system", "smss.exe", "csrss.exe", "wininit.exe", 
                          "services.exe", "lsass.exe", "svchost.exe"]
        
        # Collect historical process behavior data
        processes_data = []
        integrity_state = load_process_metadata()
        
        for hash_key, process in integrity_state.items():
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
                        "connection_count": 0
                    }
                except:
                    current_stats = {
                        "memory_usage_kb": 0,
                        "cpu_percent": 0,
                        "handle_count": 0, 
                        "thread_count": 0,
                        "child_process_count": 0,
                        "connection_count": 0
                    }
                
                # Get port with proper error handling
                try:
                    port = int(process.get('port', 0)) if process.get('port') and str(process.get('port')).isdigit() else 0
                except (ValueError, TypeError):
                    port = 0
                
                # Basic features from stored metadata
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
                    'connection_count': current_stats.get('connection_count', 0)
                }
                
                processes_data.append(features)
            except Exception as e:
                logging.error(f"Error extracting ML features for process info: {e}")
        
        # Return empty model info if not enough data
        if len(processes_data) < 5:
            logging.warning("Not enough process data for ML model training")
            return {
                'model': None,
                'features': [],
                'system_processes': system_processes
            }
        
        # Create dataframe and train model
        df = pd.DataFrame(processes_data)
        numerical_features = [col for col in df.columns if col != 'pid' and 
                            df[col].dtype in [np.int64, np.float64, np.bool_]]
        
        # Train isolation forest with auto contamination
        contamination = min(0.1, 1/len(df))  # At most 10% anomalies, or 1 if few samples
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(df[numerical_features])
        
        logging.info(f"Trained ML model on {len(df)} processes with {len(numerical_features)} features")
        
        # Store model info
        model_info = {
            'model': model,
            'features': numerical_features,
            'system_processes': system_processes,
            'training_size': len(df)
        }
        
        return model_info
        
    except Exception as e:
        logging.error(f"Error training ML model: {e}")
        return None

def detect_anomalies_ml(process_info, ml_model_info):
    """Detect process anomalies using the trained ML model."""
    if not ml_model_info or not ml_model_info.get('model'):
        return None
        
    try:
        import pandas as pd
        
        pid = process_info.get('pid')
        process_name = process_info.get('process_name', '').lower()
        
        # Skip system processes
        if (process_name in ml_model_info.get('system_processes', []) and 
            (pid <= 4 or process_name == 'system')):
            return None
        
        # Get process stats
        process_stats = get_process_stats(pid)
        
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
            'connection_count': process_stats.get('connection_count', 0)
        }
        
        # Ensure we only use features available in the model
        prediction_features = {}
        for feature in ml_model_info['features']:
            prediction_features[feature] = features.get(feature, 0)
        
        # Make prediction and get anomaly score
        model = ml_model_info['model']
        prediction = model.predict(pd.DataFrame([prediction_features]))[0]
        
        if prediction == -1:  # Anomaly detected
            score = model.decision_function(pd.DataFrame([prediction_features]))[0]
            
            # Filter out weak anomalies to reduce noise
            if score < -0.1:
                return {
                    'is_anomaly': True,
                    'score': score,
                    'features': features
                }
        
        return None
        
    except Exception as e:
        logging.error(f"Error detecting ML anomalies for PID {process_info.get('pid')}: {e}")
        return None

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
    
    for hash_key, stored_info in integrity_state.items():
        # Skip comparing with self
        if hash_key == process_hash:
            continue
            
        # Check if name matches
        if stored_info.get("process_name") == process_name:
            # Different path is immediate red flag
            if stored_info.get("exe_path") != exe_path:
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

def monitor_listening_processes(interval=3):
    """Main monitoring loop for detecting suspicious processes."""
    global SERVICE_RUNNING
    
    # Setup tracking
    known_processes = {}  # Store by key: process_hash
    known_pids = {}       # Track PIDs to detect terminations
    ml_model_info = None
    ml_retrain_counter = 0
    alerted_processes = set()  # Avoid duplicate alerts
    
    # Initialize ML model if available
    if ML_LIBRARIES_AVAILABLE:
        ml_model_info = implement_behavioral_baselining()
        logging.info("ML behavioral baselining completed")
    
    logging.info("Starting process monitoring...")
    
    # Load integrity state
    integrity_state = load_process_metadata()
    
    # Initialize known_pids from integrity_state
    for process_hash, process_info in integrity_state.items():
        try:
            pid = int(process_info.get("pid", 0))
            if pid > 0:
                known_pids[pid] = process_hash
        except (ValueError, TypeError):
            continue
    
    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
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
            
            # Detect terminated processes by PID
            for pid in list(known_pids.keys()):
                if pid not in current_pids:
                    process_hash = known_pids[pid]
                    
                    # Get process info from integrity_state
                    if process_hash in integrity_state:
                        term_process = integrity_state[process_hash]
                        process_name = term_process.get("process_name", "UNKNOWN")
                        port = term_process.get("port", "UNKNOWN")
                        
                        logging.warning(f"Process terminated: {process_name} (PID: {pid}) on port {port}")
                        
                        # Generate alert for terminated process
                        log_event_to_fim(
                            event_type="PROCESS_TERMINATED",
                            file_path=term_process.get("exe_path", ""),
                            previous_metadata=term_process,
                            new_metadata=None,
                            previous_hash=process_hash,
                            new_hash=None
                        )
                        
                        # Remove pid from known_pids but KEEP in integrity_state
                        # for legitimate processes
                        del known_pids[pid]
            
            # Process new or restarted processes
            for pid, process_hash in current_pids.items():
                if pid not in known_pids:
                    process_info = current_hash_to_process[process_hash]
                    process_name = process_info.get("process_name", "UNKNOWN")
                    port = process_info.get("port", "UNKNOWN")
                    exe_path = process_info.get("exe_path", "")
                    
                    # IMPORTANT: First check for process name impersonation
                    # This needs to happen before we check for process restarts
                    name_alerts = check_process_name_consistency(process_info, integrity_state)
                    
                    if name_alerts:
                        for alert in name_alerts:
                            # Log critical alert for process impersonation
                            impersonated_name = alert["details"]["process_name"]
                            original_path = alert["details"]["original_process"]["exe_path"]
                            impersonating_path = alert["details"]["impersonating_process"]["exe_path"]
                            reason = alert["details"].get("reason", "Executable path mismatch")
                            severity = alert["details"].get("severity", "high")
                            
                            logging.critical(f"ALERT: Process name impersonation detected!")
                            logging.critical(f"Process '{impersonated_name}' at path '{impersonating_path}' appears to be impersonating legitimate process from '{original_path}'")
                            logging.critical(f"Reason: {reason} (Severity: {severity})")
                            
                            # Add more detailed lineage information to the log
                            original_lineage = alert["details"]["original_process"].get("lineage", [])
                            impersonating_lineage = alert["details"]["impersonating_process"].get("lineage", [])
                            
                            if original_lineage and impersonating_lineage:
                                logging.critical(f"Original process lineage: {' → '.join(original_lineage)}")
                                logging.critical(f"Impersonating process lineage: {' → '.join(impersonating_lineage)}")
                            
                            # Log security event
                            log_event_to_fim(
                                event_type="PROCESS_NAME_IMPERSONATION",
                                file_path=process_info.get("exe_path", ""),
                                previous_metadata=alert["details"]["original_process"],
                                new_metadata=alert["details"]["impersonating_process"],
                                previous_hash=alert["details"]["original_process"].get("hash", ""),
                                new_hash=process_hash
                            )
                            
                            # Try to kill the suspicious process
                            try:
                                logging.critical(f"Attempting to terminate suspicious impersonating process {pid}")
                                os.kill(pid, signal.SIGTERM)
                                logging.info(f"Successfully terminated process {pid}")
                                
                                # Remove malicious process from integrity file if it was added
                                if process_hash in integrity_state:
                                    remove_malicious_process(process_hash, pid, integrity_state)
                                
                                # Set a flag to skip further processing
                                alerted_processes.add(pid)
                            except Exception as e:
                                logging.error(f"Failed to terminate suspicious process {pid}: {e}")
                    
                    # Skip further processing if this process generated an alert
                    if pid in alerted_processes:
                        continue
                    
                    # After impersonation check, proceed with normal processing
                    # Check if this hash exists in the integrity file (restarted process)
                    if process_hash in integrity_state:
                        stored_info = integrity_state[process_hash]
                        
                        # Check for metadata mismatches with existing record
                        metadata_mismatches = []
                        
                        # Check exe_path
                        if stored_info.get("exe_path") != process_info.get("exe_path"):
                            metadata_mismatches.append({
                                "field": "exe_path",
                                "previous": stored_info.get("exe_path"),
                                "current": process_info.get("exe_path")
                            })
                        
                        # Check process_name
                        if stored_info.get("process_name") != process_info.get("process_name"):
                            metadata_mismatches.append({
                                "field": "process_name",
                                "previous": stored_info.get("process_name"),
                                "current": process_info.get("process_name")
                            })
                        
                        # Check cmdline
                        if stored_info.get("cmdline") != process_info.get("cmdline"):
                            metadata_mismatches.append({
                                "field": "cmdline",
                                "previous": stored_info.get("cmdline"),
                                "current": process_info.get("cmdline")
                            })
                        
                        if metadata_mismatches:
                            # Metadata mismatch for same hash - potentially malicious
                            logging.critical(f"ALERT: Process hash matches but metadata differs for {process_name} (PID: {pid})")
                            for mismatch in metadata_mismatches:
                                logging.critical(f"  {mismatch['field']}: '{mismatch['previous']}' -> '{mismatch['current']}'")
                            
                            # Log security event
                            log_event_to_fim(
                                event_type="HASH_IMPERSONATION",
                                file_path=process_info.get("exe_path", ""),
                                previous_metadata=stored_info,
                                new_metadata=process_info,
                                previous_hash=process_hash,
                                new_hash=process_hash
                            )
                            
                            # Try to kill the suspicious process
                            try:
                                logging.critical(f"Attempting to terminate suspicious process {pid}")
                                os.kill(pid, signal.SIGTERM)
                                logging.info(f"Successfully terminated process {pid}")
                                
                                # Remove malicious process from integrity file
                                remove_malicious_process(process_hash, pid, integrity_state)
                                
                                # Set a flag to skip further processing
                                alerted_processes.add(pid)
                                continue
                            except Exception as e:
                                logging.error(f"Failed to terminate suspicious process {pid}: {e}")
                        else:
                            # Process restarted with same metadata - normal behavior
                            logging.info(f"Process restarted with consistent metadata: {process_name} (PID: {pid})")
                            
                            # Update the process metadata with new PID and start time
                            updated_info = stored_info.copy()
                            updated_info["pid"] = pid
                            updated_info["start_time"] = process_info.get("start_time")
                            
                            # Update in integrity state
                            update_process_tracking(
                                process_info.get("exe_path"),
                                process_hash,
                                updated_info
                            )
                    else:
                        # Check if similar process with different hash exists (application update case)
                        updated_process = False
                        similar_processes = []
                        
                        for stored_hash, stored_info in integrity_state.items():
                            # Check for same process name and path but different hash (likely an update)
                            if (stored_info.get("process_name") == process_name and
                                stored_info.get("exe_path") == exe_path and
                                stored_hash != process_hash):
                                similar_processes.append((stored_hash, stored_info))
                        
                        if similar_processes:
                            # Found similar process - likely a software update
                            old_hash, old_info = similar_processes[0]  # Take the first match
                            
                            logging.info(f"Detected updated process: {process_name} (PID: {pid})")
                            logging.info(f"Previous hash: {old_hash}")
                            logging.info(f"New hash: {process_hash}")
                            
                            # Log the update event
                            log_event_to_fim(
                                event_type="PROCESS_UPDATED",
                                file_path=exe_path,
                                previous_metadata=old_info,
                                new_metadata=process_info,
                                previous_hash=old_hash,
                                new_hash=process_hash
                            )
                            
                            # Remove old hash entry and add new one
                            del integrity_state[old_hash]
                            update_process_tracking(exe_path, process_hash, process_info)
                            updated_process = True
                        
                        if not updated_process:
                            # New process
                            logging.info(f"New listening process: {process_name} (PID: {pid}) on port {port}")
                            
                            # Only track in integrity file if not flagged as malicious
                            if pid not in alerted_processes:
                                update_process_tracking(
                                    process_info.get("exe_path"),
                                    process_hash,
                                    process_info
                                )
                    
                    # Add to known_pids (unless flagged as malicious)
                    if pid not in alerted_processes:
                        known_pids[pid] = process_hash
            
            # Reload integrity state after updates
            integrity_state = load_process_metadata()
            
            # Sleep until next interval
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            logging.debug(traceback.format_exc())
            
            # Sleep a bit longer on error to avoid error loops
            time.sleep(max(interval, 5))

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
    
    while SERVICE_RUNNING:
        try:
            # Sleep first to avoid immediate cleanup on startup
            time.sleep(interval)
            
            if not SERVICE_RUNNING:
                break
                
            logging.info("Running periodic cleanup of integrity file...")
            modified = check_application_existence()
            
            if modified:
                logging.info("Removed entries for non-existent applications from integrity file")
            else:
                logging.info("Integrity file is up-to-date")
                
        except Exception as e:
            logging.error(f"Error in periodic cleanup: {e}")
            logging.debug(traceback.format_exc())

def log_event_to_fim(event_type, file_path, previous_metadata, new_metadata, previous_hash, new_hash):
    """Log security events to a central JSON file for reporting with improved permissions handling."""
    try:
        # Import builtins in case open is undefined in this context
        import builtins
        
        # Define the log file path
        pim_log_file = os.path.join(BASE_DIR, "logs", "pim.json")
        os.makedirs(os.path.dirname(pim_log_file), exist_ok=True)
        
        # Create event data
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "file_path": file_path,
            "previous_metadata": previous_metadata,
            "new_metadata": new_metadata,
            "previous_hash": previous_hash,
            "new_hash": new_hash
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
            
            logging.debug(f"Event logged successfully: {event_type}")
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
                        logging.warning(f"Untracked process detected: {process_name} (PID: {pid})")
                        log_event_to_fim(
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
                        changed_fields[field] = {
                            "previous": stored_info.get(field),
                            "current": current_info.get(field)
                        }
                
                if changed_fields:
                    logging.warning(
                        f"Metadata changes detected for PID {pid}: {list(changed_fields.keys())}"
                    )
                    log_event_to_fim(
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
        
        for region in memory_regions:
            if region["type"] == "Image" and "0x" in region["address"]:
                # Convert to int for address comparison
                addr = int(region["address"].replace("0x", ""), 16)
                
                # Store the lowest image base address (likely the main module)
                if image_base_address is None or addr < image_base_address:
                    image_base_address = addr
                    main_module_found = True
        
        if not main_module_found:
            suspicious_indicators.append({
                "indicator": "Missing main module",
                "description": "Process lacks expected main module memory mapping",
                "severity": "high"
            })
            
        # Check for executable memory not part of the main module
        for region in memory_regions:
            if (region["protection"]["executable"] and 
                region["type"] == "Private" and 
                "0x" in region["address"]):
                
                addr = int(region["address"].replace("0x", ""), 16)
                
                # If executable memory outside main module base
                if addr != image_base_address:
                    suspicious_indicators.append({
                        "indicator": "Executable memory outside main module",
                        "description": f"Executable memory at {region['address']} not part of main module",
                        "severity": "medium"
                    })
                    
    except Exception as e:
        logging.error(f"Error detecting process hollowing for PID {pid}: {e}")
    
    return suspicious_indicators

def detect_reflective_dll_injection(pid, process_info):
    """
    Detect signs of reflective DLL injection by examining memory regions
    for PE headers not linked to loaded modules.
    """
    suspicious_indicators = []
    
    try:
        # Get memory regions for the process
        memory_regions = enumerate_process_memory_regions(pid)
        
        # Look for PE signatures in private memory regions
        for region in memory_regions:
            if (region["protection"]["executable"] and 
                region["type"] == "Private" and
                region["size_kb"] > 10):  # Minimum size for a DLL
                
                suspicious_indicators.append({
                    "indicator": "Potential reflective DLL",
                    "description": f"Executable private memory at {region['address']} with size {region['size_kb']}KB",
                    "severity": "high" if region["protection"]["writable"] else "medium"
                })
        
    except Exception as e:
        logging.error(f"Error detecting reflective DLL injection for PID {pid}: {e}")
    
    return suspicious_indicators

# Global dictionary to store baseline DLL information for processes
PROCESS_DLL_BASELINE = {}

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
    
    # Initialize baseline if not already done
    if pid not in PROCESS_DLL_BASELINE:
        initialize_dll_baseline(pid, process_info)
        return []  # First time seeing this process - establish baseline only
        
    baseline = PROCESS_DLL_BASELINE[pid]
    
    try:
        # Check for known DLLs in suspicious locations
        # List of commonly hijacked DLLs
        common_hijacked_dlls = [
            "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll",
            "version.dll", "wininet.dll", "cryptsp.dll", "urlmon.dll",
            "netapi32.dll", "secur32.dll", "oleaut32.dll", "msvcp140.dll"
        ]
        
        # Check for these DLLs in application directory
        for dll_name in common_hijacked_dlls:
            potential_hijack_path = os.path.join(process_dir, dll_name)
            if os.path.exists(potential_hijack_path):
                # This is a red flag - system DLL in application directory
                suspicious_indicators.append({
                    "indicator": "Potential DLL search order hijacking",
                    "description": f"System DLL '{dll_name}' found in application directory: {process_dir}",
                    "severity": "high",
                    "dll_path": potential_hijack_path
                })
                
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
            
            # Check if this is a new DLL not in baseline
            if dll_path not in baseline_dll_paths:
                # Check if DLL is loaded from suspicious location
                if dll_name.lower() in [d.lower() for d in common_hijacked_dlls]:
                    # System DLL loaded from non-system directory
                    if "system32" not in dll_path.lower() and "syswow64" not in dll_path.lower():
                        suspicious_indicators.append({
                            "indicator": "System DLL loaded from non-system directory",
                            "description": f"System DLL '{dll_name}' loaded from {os.path.dirname(dll_path)}",
                            "severity": "high",
                            "dll_path": dll_path
                        })
                
                # Check for DLLs in temp directories or user profile
                suspicious_dirs = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
                for sus_dir in suspicious_dirs:
                    if sus_dir in dll_path.lower():
                        suspicious_indicators.append({
                            "indicator": "DLL loaded from suspicious location",
                            "description": f"DLL '{dll_name}' loaded from suspicious location: {os.path.dirname(dll_path)}",
                            "severity": "high",
                            "dll_path": dll_path
                        })
                        break
                        
                # Add this DLL to baseline for future comparisons
                baseline["loaded_dlls"].append({
                    "path": dll_path,
                    "base_address": dll["base_address"],
                    "size": dll["size"],
                    "first_seen": datetime.now().isoformat()
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
        
        # Check for small executable allocations that might be used for thread injection
        for region in memory_regions:
            if (region["protection"]["executable"] and 
                region["type"] == "Private" and
                4 <= region["size_kb"] <= 16):  # Thread shellcode is often small
                
                suspicious_indicators.append({
                    "indicator": "Potential thread injection target",
                    "description": f"Small executable memory region at {region['address']} ({region['size_kb']}KB)",
                    "severity": "medium"
                })
                
        # Get process stats
        process_stats = get_process_stats(pid)
        
        # Unusual thread count could indicate hijacking
        if process_stats["thread_count"] > 20:  # Adjust threshold as needed
            suspicious_indicators.append({
                "indicator": "High thread count",
                "description": f"Process has {process_stats['thread_count']} threads which is unusual",
                "severity": "low"
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
        "registry", "memcompression", "vmmem", "secure system", 
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
                        log_event_to_fim(
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
                        log_event_to_fim(
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
                            log_event_to_fim(
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
                            "current": process_info.get("cmdline")
                        })
                    
                    # Check for user changes (potential privilege escalation)
                    if stored_info.get("user") != process_info.get("user"):
                        changes.append({
                            "field": "user",
                            "previous": stored_info.get("user"),
                            "current": process_info.get("user")
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
                            "delta": current_mem - prev_mem
                        })
                    
                    # Check for thread count increase (potential thread injection)
                    prev_threads = stored_info.get("thread_count", 0)
                    current_threads = process_info.get("thread_count", 0)
                    
                    if current_threads - prev_threads > 5:  # Arbitrary threshold
                        changes.append({
                            "field": "thread_count",
                            "previous": prev_threads,
                            "current": current_threads,
                            "delta": current_threads - prev_threads
                        })
                    
                    # If significant changes detected, log and alert
                    if changes:
                        process_name = process_info.get("process_name", "UNKNOWN")
                        logging.warning(f"Significant changes detected in process {process_name} (PID: {pid}):")
                        
                        for change in changes:
                            if "delta" in change:
                                logging.warning(f"  {change['field']}: {change['previous']} -> {change['current']} (delta: {change['delta']})")
                            else:
                                logging.warning(f"  {change['field']}: '{change['previous']}' -> '{change['current']}'")
                        
                        # Log the alert
                        log_event_to_fim(
                            event_type="PROCESS_RUNTIME_CHANGES",
                            file_path=process_info.get("exe_path", ""),
                            previous_metadata=stored_info,
                            new_metadata=process_info,
                            previous_hash=process_hash,
                            new_hash=process_hash
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
                    log_event_to_fim(
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
  python pim.py debug         Run in debug mode with extra logging
  python pim.py help          Show this help message

Description:
  The Process Integrity Monitor continuously monitors system processes for:
    - New or terminated listening processes
    - All system processes (not just those with network connections)
    - Fileless process detection and behavioral analysis
    - Non-standard port use by known binaries
    - Unexpected changes in process metadata (user, hash, command line, etc.)
    - Suspicious memory regions (e.g., shellcode injection or unsigned code)
    - Windows-specific behavioral anomalies
    - Machine learning based anomaly detection
    - Process runtime changes (command line, memory usage, thread count)

  It logs alerts and integrates with SIEM tools.

Note:
  Administrative privileges are required for full functionality.
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
                
        elif command == "debug":
            # Special debug mode with extra logging
            print("[INFO] Starting in debug mode with extra logging...")
            logging.getLogger('').setLevel(logging.DEBUG)
            run_as_console()
        
        elif command in ["--service", "--foreground"]:
            # When the service manager executes the service
            win32serviceutil.HandleCommandLine(ProcessMonitorService)
            
        else:
            print(f"[ERROR] Unknown command: {command}")
            print_help()
    
    else:
        # Default: run in console mode
        run_as_console()
