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
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
FILE_MONITOR_JSON = os.path.join(LOG_DIR, "file_monitor.json")
KNOWN_PORTS_FILE = os.path.join(OUTPUT_DIR, "known_ports.json")
KNOWN_LINEAGES_FILE = os.path.join(OUTPUT_DIR, "known_lineages.json")
MITRE_MAPPING_FILE = os.path.join(OUTPUT_DIR, "mitre_mappings.json")

# Global flags
SERVICE_RUNNING = True

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

def safe_write_json(file_path, data):
    """Safely write JSON data to a file with proper error handling and atomic operations."""
    temp_file = f"{file_path}.tmp"
    try:
        with open(temp_file, "w") as f:
            json.dump(data, f, indent=4)
            
        # Replace original file with temp file (atomic operation)
        os.replace(temp_file, file_path)
        set_secure_permissions(file_path)
        return True
    except Exception as e:
        logging.error(f"Failed to write to {file_path}: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        return False

def safe_write_text(file_path, data):
    """Safely write text data to a file with proper error handling and atomic operations."""
    temp_file = f"{file_path}.tmp"
    try:
        with open(temp_file, "w") as f:
            f.write(data)
            
        # Replace original file with temp file (atomic operation)
        os.replace(temp_file, file_path)
        set_secure_permissions(file_path)
        return True
    except Exception as e:
        logging.error(f"Failed to write to {file_path}: {e}")
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass
        return False

def load_process_hashes():
    """Load stored process hashes from process_hashes.txt."""
    if os.path.exists(PROCESS_HASHES_FILE):
        try:
            with open(PROCESS_HASHES_FILE, "r") as f:
                return dict(line.strip().split(":", 1) for line in f if ":" in line)
        except Exception as e:
            logging.error(f"Failed to load process hashes: {e}")
            return {}
    return {}

def save_process_hashes(process_hashes):
    """Save process hashes to process_hashes.txt safely."""
    lines = []
    for exe_path, hash_value in process_hashes.items():
        lines.append(f"{exe_path}:{hash_value}")
    
    return safe_write_text(PROCESS_HASHES_FILE, "\n".join(lines))

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
    """Update process tracking files with new or modified processes."""
    # Load existing data
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    pid = metadata["pid"]  # Use PID as a unique key
    
    # Store metadata by PID
    integrity_state[str(pid)] = metadata
    
    # Update hash tracking separately
    if process_hash != "ERROR_HASHING_PERMISSION" and process_hash != "ERROR_FILE_NOT_FOUND":
        process_hashes[exe_path] = process_hash

    # Save updates
    success1 = save_process_metadata(integrity_state)
    success2 = save_process_hashes(process_hashes)
    
    return success1 and success2

def remove_process_tracking(pid):
    """Remove process metadata from integrity_processes.json and process_hashes.txt."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()
    known_lineages = load_known_lineages()

    pid_str = str(pid)

    if pid_str in integrity_state:
        process_info = integrity_state[pid_str]
        proc_name = process_info.get("process_name", "UNKNOWN")
        lineage = process_info.get("lineage", [])

        # Remove the process metadata
        del integrity_state[pid_str]
        save_process_metadata(integrity_state)

        # Check if lineage for that process name should be retained
        still_running_with_same_lineage = any(
            p.get("process_name") == proc_name and p.get("lineage") == known_lineages.get(proc_name)
            for p in integrity_state.values()
        )

        if proc_name in known_lineages and not still_running_with_same_lineage:
            logging.info(f"Removing lineage for {proc_name} from known_lineages.json")
            del known_lineages[proc_name]
            save_known_lineages(known_lineages)

        # Remove from hash tracking if necessary
        exe_path = process_info.get("exe_path")
        if exe_path and exe_path in process_hashes:
            del process_hashes[exe_path]
            save_process_hashes(process_hashes)

        logging.info(f"Process {pid_str} removed from tracking")
        return True
    else:
        logging.warning(f"No matching process found for PID: {pid_str}")
        return False

def load_known_lineages():
    """Load the known process lineage mapping."""
    if not os.path.exists(KNOWN_LINEAGES_FILE):
        logging.debug("known_lineages.json does not exist, starting fresh")
        return {}
    try:
        with open(KNOWN_LINEAGES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load known_lineages.json: {e}")
        return {}

def save_known_lineages(lineages):
    """Save the process lineage mapping to known_lineages.json."""
    return safe_write_json(KNOWN_LINEAGES_FILE, lineages)

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

def check_lineage_baseline(process_info, known_lineages):
    """Check if a process's lineage matches the baseline."""
    proc_name = process_info["process_name"]
    lineage = process_info.get("lineage", [])

    if not lineage:
        return False

    baseline = known_lineages.get(proc_name)

    if not baseline:
        # First time seeing this process - establish baseline
        known_lineages[proc_name] = lineage
        logging.info(f"Baseline lineage established for {proc_name}: {lineage}")
        save_known_lineages(known_lineages)
        return True
    elif lineage != baseline:
        # Lineage deviation detected
        logging.warning(f"Lineage deviation for {proc_name}:")
        logging.warning(f"  Expected: {baseline}")
        logging.warning(f"  Found:    {lineage}")
        return False
    
    return True

def load_known_ports():
    """Load the known process-port mapping."""
    if not os.path.exists(KNOWN_PORTS_FILE):
        return {}
    try:
        with open(KNOWN_PORTS_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load known_ports.json: {e}")
        return {}

def save_known_ports(mapping):
    """Save the process-port mapping to known_ports.json."""
    return safe_write_json(KNOWN_PORTS_FILE, mapping)

def build_known_ports_baseline(processes):
    """Build a baseline of known process-port mappings."""
    known_ports = {}

    for proc in processes.values():
        proc_name = proc.get("process_name", "UNKNOWN")
        if proc_name == "UNKNOWN":
            continue

        if proc_name not in known_ports:
            known_ports[proc_name] = {
                "ports": [],
                "metadata": proc  # store full metadata
            }

        port = proc.get("port")
        if port not in known_ports[proc_name]["ports"]:
            known_ports[proc_name]["ports"].append(port)

    success = safe_write_json(KNOWN_PORTS_FILE, known_ports)
    logging.info(f"Port baseline created: {len(known_ports)} processes recorded")
    return success

def check_for_unusual_port_use(process_info):
    """Check if a process is listening on a non-standard port."""
    known_ports = load_known_ports()
    if not known_ports:
        return []  # Return empty list, not False
        
    proc_name = process_info.get("process_name")
    proc_port = str(process_info.get("port"))
    
    # Skip if we don't know about this process yet
    if proc_name not in known_ports:
        return []  # Return empty list, not False
        
    expected_ports = list(map(str, known_ports[proc_name].get("ports", [])))
    baseline_metadata = known_ports[proc_name].get("metadata", {})
    
    alerts = []
    
    # Check for port mismatch
    if proc_port not in expected_ports:
        logging.warning(f"{proc_name} listening on unexpected port {proc_port}. Expected: {expected_ports}")
        alerts.append({
            "type": "UNUSUAL_PORT_USE",
            "details": {
                "process": proc_name,
                "expected_ports": expected_ports,
                "actual_port": proc_port
            }
        })
    
    # Check for other metadata mismatches
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
        
    return alerts  # Always return a list, even if empty

def get_listening_processes():
    """Get detailed information about all listening processes."""
    listening_processes = {}

    try:
        # Use netstat to get processes listening on TCP ports
        netstat_output = subprocess.check_output("netstat -ano -p TCP", shell=True, text=True)
        
        # Build a map of PID to port
        pid_to_ports = {}
        
        for line in netstat_output.splitlines():
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
                
                # Store info for each port
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
        
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )
        
        if not handle:
            logging.error(f"Failed to open process {pid}: {ctypes.GetLastError()}")
            return regions
            
        try:
            # Define memory region structure
            class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)
                ]
            
            # Memory protection constants
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
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            while ctypes.windll.kernel32.VirtualQueryEx(
                handle,
                address,
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ):
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
                    
                    # Store region info
                    regions.append({
                        "address": f"0x{address:X}",
                        "size_kb": mbi.RegionSize // 1024,
                        "protection": {
                            "executable": is_executable,
                            "writable": is_writable,
                            "readable": is_readable
                        },
                        "type": region_type,
                        "allocation_base": f"0x{mbi.AllocationBase:X}"
                    })
                
                # Move to next region
                address += mbi.RegionSize
                
                # Prevent infinite loop
                if address > 0x7FFFFFFF0000:
                    break
        
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    
    except Exception as e:
        logging.error(f"Error enumerating memory regions for PID {pid}: {e}")
    
    return regions

def scan_process_memory(pid, process_info=None):
    """Scan process memory for potential code injection or malicious behaviors."""
    if not is_admin():
        logging.warning("Administrator privileges required for memory scanning")
        return []
        
    suspicious_regions = []
    
    try:
        memory_regions = enumerate_process_memory_regions(pid)
        if not memory_regions:
            return []
            
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
        
        if suspicious_regions:
            logging.warning(f"Found {len(suspicious_regions)} suspicious memory regions in PID {pid} ({process_name})")
            
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
        
        # Network connections
        try:
            connections = process.connections()
            stats["connection_count"] = len(connections)
        except (psutil.AccessDenied, AttributeError):
            pass
            
    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        logging.debug(f"Could not get complete stats for PID {pid}: {e}")
        
    return stats

def analyze_process_behavior(pid, process_info):
    """Analyze a process for suspicious behavior patterns."""
    suspicious_patterns = []
    
    try:
        # Skip system processes
        if process_info.get("process_name", "").lower() in ["system", "smss.exe", "csrss.exe"] and pid <= 4:
            return []
            
        # Get process stats
        process_stats = get_process_stats(pid)
        
        # Get process lineage and other metadata
        lineage = process_info.get("lineage", [])
        exe_path = process_info.get("exe_path", "").lower()
        cmdline = process_info.get("cmdline", "").lower()
        port = process_info.get("port", 0)
        user = process_info.get("user", "").lower()
        
        # 1. Check for command shells in lineage of server processes
        shell_in_lineage = any(shell.lower() in [p.lower() for p in lineage] 
                            for shell in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'])
        
        server_process = any(server in process_info.get("process_name", "").lower() 
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
        if "services.exe" not in lineage and process_info.get("process_name", "").lower() == "svchost.exe":
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
        
        process_name = process_info.get("process_name", "").lower()
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
        
        for pid_str, process in integrity_state.items():
            pid = int(pid_str)
            process_name = process.get("process_name", "").lower()
            
            # Skip system processes in the training data
            if process_name in system_processes and pid <= 4:
                continue
                
            # Extract features
            try:
                # Get additional stats if process is still running
                try:
                    current_stats = get_process_stats(pid)
                except:
                    current_stats = {
                        "memory_usage_kb": 0,
                        "cpu_percent": 0,
                        "handle_count": 0, 
                        "thread_count": 0,
                        "child_process_count": 0,
                        "connection_count": 0
                    }
                
                # Basic features from stored metadata
                features = {
                    'pid': pid,
                    'port': int(process.get('port', 0)) if isinstance(process.get('port', 0), (int, str)) and 
                                                       str(process.get('port', 0)).isdigit() else 0,
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
                logging.error(f"Error extracting ML features for PID {pid}: {e}")
        
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
    """Load MITRE ATT&CK technique mappings from file or use defaults."""
    if os.path.exists(MITRE_MAPPING_FILE):
        try:
            with open(MITRE_MAPPING_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load MITRE mappings: {e}")
    
    # Default mappings as fallback - Windows specific
    return {
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
        }]
    }

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

def monitor_listening_processes(interval=3):
    """Main monitoring loop for detecting suspicious processes."""
    global SERVICE_RUNNING
    
    # Setup tracking
    known_processes = {}  # Store by key: pid:port
    terminated_processes = set()  # Track terminated processes
    ml_model_info = None
    ml_retrain_counter = 0
    alerted_processes = set()  # Avoid duplicate alerts
    
    # Initialize ML model if available
    if ML_LIBRARIES_AVAILABLE:
        ml_model_info = implement_behavioral_baselining()
        logging.info("ML behavioral baselining completed")
    
    logging.info("Starting process monitoring...")
    
    # Load baselines
    known_lineages = load_known_lineages()
    known_ports_mapping = load_known_ports()
    
    while SERVICE_RUNNING:
        try:
            # Get current listening processes
            current_processes = get_listening_processes()
            
            # Identify new and terminated processes
            current_keys = set(current_processes.keys())
            known_keys = set(known_processes.keys())
            
            new_process_keys = current_keys - known_keys
            terminated_process_keys = known_keys - current_keys
            
            # Process newly discovered listening processes
            for key in new_process_keys:
                process_info = current_processes[key]
                pid = process_info.get("pid")
                process_name = process_info.get("process_name")
                port = process_info.get("port")
                
                logging.info(f"New listening process: {process_name} (PID: {pid}) on port {port}")
                
                # Save process info
                update_process_tracking(
                    process_info.get("exe_path"), 
                    process_info.get("hash"), 
                    process_info
                )
                
                # Create baseline if none exists
                if not known_ports_mapping:
                    build_known_ports_baseline(current_processes)
                    known_ports_mapping = load_known_ports()
                
                # Check for unusual port usage
                port_alerts = check_for_unusual_port_use(process_info)
                
                # Check lineage
                lineage_match = check_lineage_baseline(process_info, known_lineages)
                if not lineage_match and process_info.get("lineage"):
                    logging.warning(f"Lineage deviation detected for {process_name}")
                    if port_alerts is False:
                        port_alerts = []
                    elif port_alerts is None:
                        port_alerts = []
                        
                    # Create a new alert dictionary instead of trying to modify an existing string
                    port_alerts.append({
                        "type": "LINEAGE_DEVIATION",
                        "details": {
                            "process": process_name,
                            "expected_lineage": known_lineages.get(process_name),
                            "actual_lineage": process_info.get("lineage")
                        }
                    })
                
                # Log alerts for the new process
                if port_alerts and isinstance(port_alerts, list):  # Make sure it's a list before iterating
                    for alert in port_alerts:
                        # Make sure alert is a dictionary
                        if not isinstance(alert, dict):
                            continue
                            
                        alert_type = alert.get("type", "UNKNOWN_ALERT")
                        alert_details = alert.get("details", {})
                        
                        # Get MITRE ATT&CK classification
                        mitre_info = classify_by_mitre_attck(alert_type, process_info, alert_details)
                        
                        logging.warning(f"Alert: {alert_type} for {process_name} (PID: {pid})")
                        log_event_to_fim(
                            event_type=alert_type,
                            file_path=process_info.get("exe_path", ""),
                            previous_metadata=None,
                            new_metadata={
                                "process_info": process_info,
                                "alert_details": alert_details,
                                "mitre_mapping": mitre_info
                            },
                            previous_hash=None,
                            new_hash=process_info.get("hash", "")
                        )
            
            # Process all active processes for behavioral/memory anomalies (not just new ones)
            for key, process_info in current_processes.items():
                # Skip if we've already alerted on this process recently
                process_key = process_info.get("pid")
                if process_key in alerted_processes:
                    continue
                
                pid = process_info.get("pid")
                
                # Skip system process PID 4
                if pid == 4:
                    continue
                    
                process_name = process_info.get("process_name")
                detection_events = []
                
                # 1. Memory analysis if admin privileges are available
                if is_admin():
                    try:
                        suspicious_memory = scan_process_memory(pid, process_info)
                        if suspicious_memory:
                            logging.warning(f"Suspicious memory regions in PID {pid} ({process_name})")
                            detection_events.append({
                                "type": "SUSPICIOUS_MEMORY_REGION",
                                "details": suspicious_memory
                            })
                    except Exception as e:
                        logging.error(f"Error scanning memory for PID {pid}: {e}")
                
                # 2. Behavior analysis
                try:
                    suspicious_behaviors = analyze_process_behavior(pid, process_info)
                    if suspicious_behaviors:
                        logging.warning(f"Suspicious behavior in PID {pid} ({process_name})")
                        detection_events.append({
                            "type": "SUSPICIOUS_BEHAVIOR",
                            "details": suspicious_behaviors
                        })
                except Exception as e:
                    logging.error(f"Error analyzing behavior for PID {pid}: {e}")
                
                # 3. ML-based anomaly detection
                if ml_model_info and ml_model_info.get('model'):
                    try:
                        anomaly_result = detect_anomalies_ml(process_info, ml_model_info)
                        if anomaly_result and anomaly_result.get('is_anomaly'):
                            score = anomaly_result.get('score', 0)
                            logging.warning(
                                f"ML-detected anomaly in PID {pid} ({process_name}), score: {score:.4f}"
                            )
                            detection_events.append({
                                "type": "ML_DETECTED_ANOMALY",
                                "details": anomaly_result
                            })
                    except Exception as e:
                        logging.error(f"Error detecting ML anomalies for PID {pid}: {e}")
                
                # If we found detection events, calculate threat score and log them
                if detection_events:
                    # Calculate threat score
                    try:
                        threat_assessment = calculate_threat_score(process_info, detection_events)
                        severity = threat_assessment.get("severity", "").upper()
                        score = threat_assessment.get("score", 0)
                        
                        logging.warning(
                            f"Threat assessment: {severity} (Score: {score}) - PID {pid} ({process_name})"
                        )
                        
                        # Log all detections
                        for event in detection_events:
                            event_type = event.get("type")
                            details = event.get("details")
                            
                            # Get MITRE mapping
                            mitre_info = classify_by_mitre_attck(event_type, process_info, details)
                            
                            # Log to FIM system
                            log_event_to_fim(
                                event_type=event_type,
                                file_path=process_info.get("exe_path", ""),
                                previous_metadata=None,
                                new_metadata={
                                    "process_info": process_info,
                                    "detection_details": details,
                                    "mitre_mapping": mitre_info,
                                    "threat_assessment": threat_assessment
                                },
                                previous_hash=None,
                                new_hash=process_info.get("hash", "")
                            )
                        
                        # Mark as alerted to avoid duplicate alerts
                        alerted_processes.add(process_key)
                    except Exception as e:
                        logging.error(f"Error processing detection events for PID {pid}: {e}")
            
            # Handle terminated processes
            for key in terminated_process_keys:
                process_info = known_processes[key]
                pid = process_info.get("pid")
                process_name = process_info.get("process_name")
                
                logging.info(f"Process terminated: {process_name} (PID: {pid})")
                
                # Remove from tracking
                remove_process_tracking(pid)
                
                # Log event
                log_event_to_fim(
                    event_type="PROCESS_TERMINATED",
                    file_path=process_info.get("exe_path", ""),
                    previous_metadata=process_info,
                    new_metadata=None,
                    previous_hash=process_info.get("hash", ""),
                    new_hash=None
                )
            
            # Periodically retrain ML model and reset alerts
            ml_retrain_counter += 1
            if ml_retrain_counter >= 20:  # Every ~60 seconds with 3s interval
                logging.info("Retraining ML model and resetting alerts...")
                if ML_LIBRARIES_AVAILABLE:
                    ml_model_info = implement_behavioral_baselining()
                ml_retrain_counter = 0
                alerted_processes.clear()  # Allow processes to trigger alerts again
            
            # Update known processes
            known_processes = current_processes
            
            # Sleep until next interval
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in monitoring loop: {e}")
            logging.debug(traceback.format_exc())
            
            # Sleep a bit longer on error to avoid error loops
            time.sleep(max(interval, 5))

def log_event_to_fim(event_type, file_path, previous_metadata, new_metadata, previous_hash, new_hash):
    """Log security events to a central JSON file for reporting."""
    try:
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
                with open(pim_log_file, "r") as f:
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
            
        # Write updated events atomically
        temp_file = f"{pim_log_file}.tmp"
        try:
            with open(temp_file, "w") as f:
                json.dump(events, f, indent=2)
                
            # Replace original file with temp file (atomic operation)
            os.replace(temp_file, pim_log_file)
            
            # Set secure permissions
            set_secure_permissions(pim_log_file)
            
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
            
            # Check each active process against stored metadata
            for key, current_info in current_processes.items():
                pid_str = str(current_info.get("pid"))
                
                # Skip system process (PID 4)
                if current_info.get("pid") == 4:
                    continue
                
                # Skip if no stored metadata for this PID
                if pid_str not in integrity_state:
                    process_name = current_info.get("process_name", "UNKNOWN")
                    if process_name != "UNKNOWN":  # Only log for valid processes
                        logging.warning(f"Untracked process detected: PID {pid_str} ({process_name})")
                        log_event_to_fim(
                            event_type="NEW_UNTRACKED_PROCESS",
                            file_path=current_info.get("exe_path", ""),
                            previous_metadata=None,
                            new_metadata=current_info,
                            previous_hash=None,
                            new_hash=current_info.get("hash", "")
                        )
                    continue
                
                # Get stored metadata
                stored_info = integrity_state[pid_str]
                
                # Check for changes
                changes_detected = False
                
                # Check for hash mismatch (only if valid hashes)
                if (stored_info.get("hash") != current_info.get("hash") and 
                    "ERROR" not in stored_info.get("hash", "") and 
                    "ERROR" not in current_info.get("hash", "")):
                    
                    logging.warning(f"Hash mismatch detected for PID {pid_str} ({current_info.get('exe_path')})")
                    log_event_to_fim(
                        event_type="PROCESS_MODIFIED",
                        file_path=current_info.get("exe_path", ""),
                        previous_metadata=stored_info,
                        new_metadata=current_info,
                        previous_hash=stored_info.get("hash", ""),
                        new_hash=current_info.get("hash", "")
                    )
                    changes_detected = True
                
                # Check for metadata changes
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
                        f"Metadata changes detected for PID {pid_str}: {list(changed_fields.keys())}"
                    )
                    log_event_to_fim(
                        event_type="PROCESS_METADATA_CHANGED",
                        file_path=current_info.get("exe_path", ""),
                        previous_metadata=stored_info,
                        new_metadata=current_info,
                        previous_hash=stored_info.get("hash", ""),
                        new_hash=current_info.get("hash", "")
                    )
                    changes_detected = True
                
                # Update tracking if changes were detected
                if changes_detected:
                    update_process_tracking(
                        current_info.get("exe_path", ""),
                        current_info.get("hash", ""),
                        current_info
                    )
            
            # Sleep until next check
            time.sleep(interval)
            
        except Exception as e:
            logging.error(f"Error in periodic integrity scan: {e}")
            logging.debug(traceback.format_exc())
            time.sleep(interval)
            
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
        ensure_file_exists(PROCESS_HASHES_FILE)
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
            
            # Run main monitoring loop
            monitor_listening_processes()
            
        except Exception as e:
            logging.error(f"Service error: {e}")
            logging.debug(traceback.format_exc())
            self.SvcStop()

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
    ensure_file_exists(PROCESS_HASHES_FILE)
    ensure_file_exists(INTEGRITY_PROCESS_FILE, {}, is_json=True)
    ensure_file_exists(FILE_MONITOR_JSON, [], is_json=True)
    
    # Set signal handlers
    def handle_shutdown(signum=None, frame=None):
        global SERVICE_RUNNING
        logging.info("Shutdown signal received, stopping...")
        SERVICE_RUNNING = False
        sys.exit(0)
    
    # Register signal handlers if possible
    try:
        # Windows doesn't support all signals, use what's available
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, handle_shutdown)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_shutdown)
            
        # Set up Windows-specific signal handling
        win32api.SetConsoleCtrlHandler(
            lambda event_type: handle_shutdown() if event_type in (0, 1) else None, 
            True
        )
    except Exception as e:
        logging.warning(f"Could not set up all signal handlers: {e}")
    
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
    - Non-standard port use by known binaries
    - Unexpected changes in process metadata (user, hash, command line, etc.)
    - Suspicious memory regions (e.g., shellcode injection or unsigned code)
    - Windows-specific behavioral anomalies
    - Machine learning based anomaly detection

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
