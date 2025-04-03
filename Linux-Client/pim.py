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
# New imports for ML and analysis
import numpy as np  # For numerical operations
import pandas as pd  # For data manipulation
from sklearn.ensemble import IsolationForest  # For anomaly detection
# Optional: for better error handling with ML libraries
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries (numpy, pandas, scikit-learn) not found. ML-based detection will be disabled.")
    ML_LIBRARIES_AVAILABLE = False

OUTPUT_DIR = os.path.abspath("./output")
LOG_DIR = os.path.abspath("./logs")  # Change from absolute path
LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
FILE_MONITOR_JSON = os.path.abspath(os.path.join("logs", "file_monitor.json"))
KNOWN_PORTS_FILE = os.path.join(OUTPUT_DIR, "known_ports.json")
KNOWN_LINEAGES_FILE = os.path.join(OUTPUT_DIR, "known_lineages.json")

# Preserve environment variables for sudo and command execution
daemon_env = os.environ.copy()
daemon_env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"

def ensure_output_dir():
    """Ensure that the output directory and necessary files exist."""
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)

    # Ensure process hashes file exists
    if not os.path.exists(PROCESS_HASHES_FILE):
        with open(PROCESS_HASHES_FILE, "w") as f:
            f.write("")
        os.chmod(PROCESS_HASHES_FILE, 0o600)

    # Ensure integrity state file exists
    if not os.path.exists(INTEGRITY_PROCESS_FILE):
        with open(INTEGRITY_PROCESS_FILE, "w") as f:
            json.dump({}, f, indent=4)
        os.chmod(INTEGRITY_PROCESS_FILE, 0o600)

def ensure_file_monitor_json():
    """Ensure that the file_monitor.json file exists and create logs directory if needed."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)  # ✅ Ensure logs directory exists

    if not os.path.exists(FILE_MONITOR_JSON):
        with open(FILE_MONITOR_JSON, "w") as f:
            json.dump({}, f, indent=4)
        os.chmod(FILE_MONITOR_JSON, 0o600)

ensure_file_monitor_json()

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

def load_process_hashes():
    """Load stored process hashes from process_hashes.txt."""
    if os.path.exists(PROCESS_HASHES_FILE):
        with open(PROCESS_HASHES_FILE, "r") as f:
            try:
                return dict(line.strip().split(":", 1) for line in f if ":" in line)
            except ValueError:
                return {}
    return {}

def save_process_hashes(process_hashes):
    """Save process hashes to process_hashes.txt safely."""
    temp_file = f"{PROCESS_HASHES_FILE}.tmp"
    with open(temp_file, "w") as f:
        for exe_path, hash_value in process_hashes.items():
            f.write(f"{exe_path}:{hash_value}\n")

    os.replace(temp_file, PROCESS_HASHES_FILE)
    os.chmod(PROCESS_HASHES_FILE, 0o600)

def load_process_metadata():
    """Load stored process metadata from integrity_processes.json."""
    if os.path.exists(INTEGRITY_PROCESS_FILE):
        try:
            with open(INTEGRITY_PROCESS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_process_metadata(processes):
    """Save full process metadata to integrity_processes.json safely."""
    temp_file = f"{INTEGRITY_PROCESS_FILE}.tmp"
    try:
        with open(temp_file, "w") as f:
            json.dump(processes, f, indent=4)

        os.replace(temp_file, INTEGRITY_PROCESS_FILE)
        os.chmod(INTEGRITY_PROCESS_FILE, 0o600)
#        print(f"[DEBUG] Successfully wrote integrity metadata to {INTEGRITY_PROCESS_FILE}")

    except Exception as e:
        print(f"[ERROR] Failed to write to {INTEGRITY_PROCESS_FILE}: {e}", file=sys.stderr)

def get_process_hash(exe_path, cmdline=None):
    """Generate SHA-256 hash of the process executable and optionally include cmdline."""
    try:
        hash_obj = hashlib.sha256()

        # Hash the executable file
        with open(exe_path, "rb") as f:
            hash_obj.update(f.read())

        # Optionally include command-line arguments in hashing
        if cmdline:
            hash_obj.update(cmdline.encode("utf-8"))

        return hash_obj.hexdigest()

    except Exception:
        return "ERROR_HASHING"

def get_listening_processes():
    """Retrieve all listening processes and their metadata."""
    listening_processes = {}

    try:
        lsof_command = "sudo -n /usr/bin/lsof -i -P -n | /bin/grep LISTEN"
        output = subprocess.getoutput(lsof_command)

        if not output:
            print("[ERROR] lsof returned no output. Check sudo permissions.")

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue

            pid = parts[1]
            exe_path = f"/proc/{pid}/exe"

            try:
                exe_real_path = subprocess.getoutput(f"sudo -n /usr/bin/readlink -f {exe_path}").strip()
                if "Permission denied" in exe_real_path or not exe_real_path:
                    raise PermissionError("Could not read process executable path")
                cmdline_raw = subprocess.getoutput(f"sudo -n /bin/cat /proc/{pid}/cmdline 2>/dev/null").strip()
                cmdline = cmdline_raw.replace("\x00", " ")
                process_hash = get_process_hash(exe_real_path, cmdline)
            except (PermissionError, FileNotFoundError, subprocess.CalledProcessError):
                exe_real_path = "PERMISSION_DENIED"
                process_hash = "UNKNOWN"
                cmdline = ""

            try:
                port = parts[-2].split(':')[-1]
                if not port.isdigit():
                    port = "UNKNOWN"
                else:
                    port = int(port)
            except IndexError:
                port = "UNKNOWN"

            try:
                user = subprocess.getoutput(f"sudo -n /bin/ps -o user= -p {pid}").strip()
                start_time = subprocess.getoutput(f"sudo -n /bin/ps -o lstart= -p {pid}").strip()
                ppid = subprocess.getoutput(f"sudo -n /bin/ps -o ppid= -p {pid}").strip()
                ppid = int(ppid) if ppid.isdigit() else "UNKNOWN"
                if not user:
                    user = "UNKNOWN"
            except Exception:
                user, start_time, ppid = "UNKNOWN", "UNKNOWN", "UNKNOWN"

            pid_int = int(pid)
            lineage = resolve_lineage(pid_int)

            listening_processes[pid_int] = {
                "pid": pid_int,
                "exe_path": exe_real_path,
                "process_name": os.path.basename(exe_real_path) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN",
                "port": port,
                "user": user,
                "start_time": start_time,
                "cmdline": cmdline,
                "hash": process_hash,
                "ppid": ppid,
                "lineage": lineage  # ✅ resolved dynamically and included
            }

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] subprocess error in get_listening_processes: {e}")

    return listening_processes

def load_known_ports():
    """Load the known process-port mapping."""
    if not os.path.exists(KNOWN_PORTS_FILE):
        return {}
    with open(KNOWN_PORTS_FILE, "r") as f:
        return json.load(f)

def save_known_ports(mapping):
    """Save the process-port mapping to known_ports.json."""
    with open(KNOWN_PORTS_FILE, "w") as f:
        json.dump(mapping, f, indent=4)
    os.chmod(KNOWN_PORTS_FILE, 0o600)

def build_known_ports_baseline(processes):
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

    with open(KNOWN_PORTS_FILE, "w") as f:
        json.dump(known_ports, f, indent=4)
    os.chmod(KNOWN_PORTS_FILE, 0o600)

def check_for_unusual_port_use(process_info):
    """Check if a process is listening on a non-standard port or has unexpected metadata."""
    if not os.path.exists(KNOWN_PORTS_FILE):
        return

    try:
        with open(KNOWN_PORTS_FILE, "r") as f:
            known_ports = json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not read known_ports.json: {e}")
        return

    from fim_client import log_event

    proc_name = process_info.get("process_name")
    proc_port = str(process_info.get("port"))

    if proc_name not in known_ports:
        return

    expected_ports = list(map(str, known_ports[proc_name].get("ports", [])))
    baseline_metadata = known_ports[proc_name].get("metadata", {})

    if proc_port not in expected_ports:
        print(f"[ALERT] {proc_name} listening on unexpected port {proc_port}. Expected: {expected_ports}")
        log_event(
            event_type="UNUSUAL_PORT_USE",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

    # Individual alerts for specific metadata mismatches
    if baseline_metadata.get("exe_path") != process_info.get("exe_path"):
        print(f"[ALERT] Executable path mismatch for {proc_name}: expected '{baseline_metadata.get('exe_path')}', got '{process_info.get('exe_path')}'")
        log_event(
            event_type="EXECUTABLE_PATH_MISMATCH",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

    if baseline_metadata.get("cmdline") != process_info.get("cmdline"):
        print(f"[ALERT] Command-line mismatch for {proc_name}: expected '{baseline_metadata.get('cmdline')}', got '{process_info.get('cmdline')}'")
        log_event(
            event_type="CMDLINE_MISMATCH",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

    if baseline_metadata.get("hash") != process_info.get("hash"):
        print(f"[ALERT] Binary hash mismatch for {proc_name}: expected '{baseline_metadata.get('hash')}', got '{process_info.get('hash')}'")
        log_event(
            event_type="HASH_MISMATCH",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

    if baseline_metadata.get("user") != process_info.get("user"):
        print(f"[ALERT] User mismatch for {proc_name}: expected '{baseline_metadata.get('user')}', got '{process_info.get('user')}'")
        log_event(
            event_type="USER_MISMATCH",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

def monitor_listening_processes(interval=2):
    """Enhanced monitoring loop with ML-based detection and improved systemd handling."""
    known_lineages = load_known_lineages()
    known_processes = get_listening_processes()
    terminated_pids = set()
    
    # Train initial ML model
    ml_model_info = implement_behavioral_baselining()
    ml_retrain_counter = 0
    
    # Initialize detection history and already alerted processes
    detection_history = {}
    alerted_processes = set()
    
    print("[INFO] Starting enhanced process monitoring with ML-based detection...")
    
    while True:
        try:
            current_processes = get_listening_processes()
            new_processes = {pid: info for pid, info in current_processes.items() if pid not in known_processes}
            terminated_processes = {pid: info for pid, info in known_processes.items() if pid not in current_processes}
            
            from fim_client import log_event
            
            # Process all currently active processes
            for pid, info in current_processes.items():
                # Skip if we've already alerted on this process recently
                if pid in alerted_processes:
                    continue
                
                detection_events = []
                
                # 1. Memory analysis for code injection
                suspicious_memory = scan_process_memory(pid)
                if suspicious_memory:
                    print(f"[ALERT] Suspicious memory regions detected in PID {pid} ({info.get('process_name', 'unknown')})")
                    detection_events.append({
                        "event_type": "SUSPICIOUS_MEMORY_REGION",
                        "details": suspicious_memory
                    })
                
                # 1.5 Behavioral pattern detection
                behavioral_patterns = analyze_process_for_anomalies(pid, info)
                if behavioral_patterns:
                    print(f"[ALERT] Suspicious behavioral patterns detected in PID {pid} ({info.get('process_name', 'unknown')})")
                    for pattern in behavioral_patterns.get("suspicious_patterns", []):
                        print(f"  - {pattern}")
                    
                    detection_events.append({
                        "event_type": "SUSPICIOUS_BEHAVIOR",
                        "details": behavioral_patterns
                    })
                
                # 2. ML-based anomaly detection if model exists
                if ml_model_info and ml_model_info['model'] and len(current_processes) >= 5:
                    model = ml_model_info['model']
                    feature_names = ml_model_info['features']
                    system_processes = ml_model_info.get('system_processes', [])
                    
                    # Skip ML detection for certain system processes with PID 1
                    process_name = info.get('process_name', '')
                    if process_name in system_processes and pid == 1:
                        continue
                    
                    # Prepare features for this process
                    process_features = {}
                    try:
                        process_features = {
                            'port': int(info.get('port', 0)) if isinstance(info.get('port', 0), (int, str)) and str(info.get('port', 0)).isdigit() else 0,
                            'lineage_length': len(info.get('lineage', [])),
                            'cmdline_length': len(info.get('cmdline', '')),
                            'user_is_root': 1 if info.get('user') == 'root' else 0,
                            'child_processes': get_child_process_count(pid),
                            'fd_count': get_open_fd_count(pid) 
                        }
                        
                        mem_usage = get_process_memory_usage(pid)
                        if mem_usage:
                            process_features['memory_usage'] = mem_usage
                    except Exception as e:
                        print(f"[ERROR] Error extracting features for ML prediction on PID {pid}: {e}")
                        continue
                    
                    # Create a DataFrame with proper feature names
                    features_for_prediction = {}
                    for feature in feature_names:
                        features_for_prediction[feature] = process_features.get(feature, 0)
                    
                    import pandas as pd
                    prediction = model.predict(pd.DataFrame([features_for_prediction]))[0]
                    
                    if prediction == -1:  # Anomaly
                        # Calculate anomaly score
                        anomaly_score = model.decision_function(pd.DataFrame([features_for_prediction]))[0]
                        
                        # Only alert on more significant anomalies
                        if anomaly_score < -0.1:  # Threshold to reduce noise
                            print(f"[ALERT] ML-detected anomaly in process behavior: PID {pid} ({info.get('process_name', 'unknown')})")
                            print(f"  Anomaly score: {anomaly_score:.4f}")
                            print(f"  Command: {info.get('cmdline', 'N/A')}")
                            
                            detection_events.append({
                                "event_type": "ML_DETECTED_ANOMALY",
                                "details": {
                                    "anomaly_score": anomaly_score,
                                    "features": process_features
                                }
                            })
                
                # Calculate threat score if we have any detection events
                if detection_events:
                    threat_assessment = calculate_threat_score(info, detection_events)
                    print(f"[THREAT SCORE] PID {pid} ({info.get('process_name', 'unknown')}): {threat_assessment['score']}/100")
                    print(f"[THREAT SEVERITY] {threat_assessment['severity'].upper()}")
                    for reason in threat_assessment['reasons']:
                        print(f"  - {reason}")
                    
                    # Add threat score to all events
                    for event in detection_events:
                        event["threat_assessment"] = threat_assessment
                
                # 3. MITRE ATT&CK classification for any detections
                for event in detection_events:
                    details = event.get("details")
                    mitre_info = classify_by_mitre_attck(event["event_type"], info, details)
                    if mitre_info:
                        event["mitre"] = mitre_info
                
                # 4. Log all detection events
                if detection_events:
                    # Add to detection history and mark as alerted
                    if pid not in detection_history:
                        detection_history[pid] = []
                    detection_history[pid].extend(detection_events)
                    alerted_processes.add(pid)
                    
                    # Log each event
                    for event in detection_events:
                        log_event(
                            event_type=event["event_type"],
                            file_path=info.get("exe_path", "UNKNOWN"),
                            previous_metadata=None,
                            new_metadata={
                                "process_info": info,
                                "detection_details": event.get("details", {}),
                                "mitre_mapping": event.get("mitre", {}),
                                "threat_assessment": event.get("threat_assessment", {})
                            },
                            previous_hash=None,
                            new_hash=info.get("hash", "UNKNOWN")
                        )
            
            # Handle new processes (original functionality)
            for pid, info in new_processes.items():
                log_event(
                    event_type="NEW_LISTENING_PROCESS",
                    file_path=info["exe_path"],
                    previous_metadata=None,
                    new_metadata=info,
                    previous_hash=None,
                    new_hash=info.get("hash", "UNKNOWN")
                )
                update_process_tracking(info["exe_path"], info["hash"], info)
                check_for_unusual_port_use(info)
                check_lineage_baseline(info, known_lineages)
            
            # Handle terminated processes (original functionality)
            for pid, info in terminated_processes.items():
                if pid in terminated_pids:
                    continue
                
                stored_info = load_process_metadata().get(str(pid), None)
                log_event(
                    event_type="PROCESS_TERMINATED",
                    file_path=info["exe_path"] if stored_info else "UNKNOWN",
                    previous_metadata=stored_info if stored_info else "UNKNOWN",
                    new_metadata=None,
                    previous_hash=stored_info["hash"] if stored_info else "UNKNOWN",
                    new_hash=None
                )
                remove_process_tracking(str(pid))
                terminated_pids.add(pid)
                
                # Remove from detection history when process terminates
                if pid in detection_history:
                    del detection_history[pid]
                if pid in alerted_processes:
                    alerted_processes.remove(pid)
            
            # Periodically clear the alerted_processes set and retrain model
            ml_retrain_counter += 1
            if ml_retrain_counter >= 60:  # Every ~2 minutes
                print("[INFO] Retraining ML model and resetting alerts...")
                ml_model_info = implement_behavioral_baselining()
                ml_retrain_counter = 0
                alerted_processes.clear()  # Allow processes to trigger alerts again
            
            known_processes = current_processes
            time.sleep(interval)
            
        except Exception as e:
            print(f"[ERROR] Exception in enhanced monitoring loop: {e}")
            traceback.print_exc()
            continue

def rescan_listening_processes(interval=120):
    """Periodically scans listening processes and ensures accurate tracking."""
    while True:
        try:
            print("[PERIODIC SCAN] Running integrity check on listening processes...")

            from fim_client import log_event

            integrity_state = load_process_metadata()  # Load stored metadata indexed by PID
            current_processes = get_listening_processes()  # Get active processes

            for pid, current_info in current_processes.items():
                pid_str = str(pid)  # Ensure PID is a string for key lookup

                if pid_str in integrity_state:
                    stored_info = integrity_state[pid_str]

                    # Ensure process hash and metadata match before reporting changes
                    if stored_info["hash"] != current_info["hash"]:
                        print(f"[ALERT] Hash mismatch detected for PID {pid_str} ({current_info['exe_path']})")
                        log_event(
                            event_type="PROCESS_MODIFIED",
                            file_path=current_info["exe_path"],
                            previous_metadata=stored_info,
                            new_metadata=current_info,
                            previous_hash=stored_info["hash"],
                            new_hash=current_info["hash"]
                        )

                    # Check for metadata changes
                    changed_fields = {}
                    for key in ["user", "port", "cmdline"]:
                        if stored_info[key] != current_info[key]:
                            changed_fields[key] = {
                                "previous": stored_info[key],
                                "current": current_info[key]
                            }

                    if changed_fields:
                        print(f"[ALERT] Metadata changes detected for PID {pid_str}: {changed_fields}")
                        log_event(
                            event_type="PROCESS_METADATA_CHANGED",
                            file_path=current_info["exe_path"],
                            previous_metadata=stored_info,
                            new_metadata=current_info,
                            previous_hash=stored_info["hash"],
                            new_hash=current_info["hash"]
                        )

                else:
                    # Process is missing in integrity records → log as new
                    print(f"[ALERT] New untracked process detected: PID {pid_str} ({current_info['exe_path']})")
                    log_event(
                        event_type="NEW_UNTRACKED_PROCESS",
                        file_path=current_info["exe_path"],
                        previous_metadata="N/A",
                        new_metadata=current_info,
                        previous_hash="N/A",
                        new_hash=current_info["hash"]
                    )

            time.sleep(interval)

        except Exception as e:
            print(f"[ERROR] Exception in periodic scan: {e}")

def load_known_lineages():
    if not os.path.exists(KNOWN_LINEAGES_FILE):
        print("[DEBUG] known_lineages.json does not exist, starting fresh.")
        return {}
    try:
        with open(KNOWN_LINEAGES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load known_lineages.json: {e}")
        return {}

def save_known_lineages(lineages):
    try:
        temp_file = f"{KNOWN_LINEAGES_FILE}.tmp"
        with open(temp_file, "w") as f:
            json.dump(lineages, f, indent=4)

        os.replace(temp_file, KNOWN_LINEAGES_FILE)
        os.chmod(KNOWN_LINEAGES_FILE, 0o600)
        print("[DEBUG] Saved updated known_lineages.json")
    except Exception as e:
        print(f"[ERROR] Failed to save known_lineages.json: {e}")

def check_lineage_baseline(process_info, known_lineages):
    proc_name = process_info["process_name"]
    lineage = process_info.get("lineage", [])

    if not lineage:
        return

    baseline = known_lineages.get(proc_name)

    if not baseline:
        known_lineages[proc_name] = lineage
        print(f"[INFO] Baseline lineage established for {proc_name}: {lineage}")
        save_known_lineages(known_lineages)
    elif lineage != baseline:
        print(f"[ALERT] Lineage deviation for {proc_name}:")
        print(f"  Expected: {baseline}")
        print(f"  Found:    {lineage}")
        from fim_client import log_event
        log_event(
            event_type="LINEAGE_DEVIATION",
            file_path=process_info["exe_path"],
            previous_metadata={"lineage": baseline},
            new_metadata={"lineage": lineage},
            previous_hash="N/A",
            new_hash=process_info.get("hash", "UNKNOWN")
        )

def resolve_lineage(pid):
    """Walks the PPID chain to build the process lineage as a list of process names."""
    lineage = []

    try:
        seen = set()
        while pid not in seen:
            seen.add(pid)
            status_path = f"/proc/{pid}/status"
            if not os.path.exists(status_path):
                break

            with open(status_path, "r") as f:
                lines = f.readlines()

            name = None
            ppid = None
            for line in lines:
                if line.startswith("Name:"):
                    name = line.split()[1]
                elif line.startswith("PPid:"):
                    ppid = int(line.split()[1])

            if name:
                lineage.insert(0, name)

            if not ppid or ppid == 0 or ppid == pid:
                break
            pid = ppid

    except Exception as e:
        print(f"[ERROR] Failed to resolve lineage for PID {pid}: {e}")
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
    
    for pid, process in integrity_state.items():
        process_name = process.get("process_name", "")
        
        # Skip system processes in the training data (to prevent them from affecting the model)
        if process_name in system_processes and int(pid) == 1:
            continue
            
        # Extract features
        try:
            features = {
                'pid': int(pid),
                'port': int(process['port']) if isinstance(process['port'], (int, str)) and str(process['port']).isdigit() else 0,
                'lineage_length': len(process.get('lineage', [])),
                'cmdline_length': len(process.get('cmdline', '')),
                'user_is_root': 1 if process.get('user') == 'root' else 0,
                'child_processes': get_child_process_count(int(pid))
            }
            
            # Add memory usage as a feature
            mem_usage = get_process_memory_usage(int(pid))
            if mem_usage:
                features['memory_usage'] = mem_usage
                
            # Add open file descriptor count
            fd_count = get_open_fd_count(int(pid))
            if fd_count:
                features['fd_count'] = fd_count
                
            processes_data.append(features)
        except Exception as e:
            print(f"[ERROR] Error extracting features for PID {pid}: {e}")
    
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
        
        # Check for unusual port
        if isinstance(info.get('port'), int) and info.get('port') > 1024 and info.get('port') not in [8080, 8443]:
            suspicious_patterns.append(f"Unusual port: {info.get('port')}")
        
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
            from fim_client import log_event
            log_event(
                event_type="SUSPICIOUS_MEMORY_REGION",
                file_path=exe_path,
                previous_metadata=None,
                new_metadata={
                    "pid": pid,
                    "process_name": process_name,
                    "suspicious_regions": [f"{r['region']['addr_range']} ({r['region']['perms']}) - {r['reason']}" for r in suspicious_regions]
                },
                previous_hash=None,
                new_hash=None
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
    """Map detected activities to MITRE ATT&CK techniques using dynamic classification."""
    # Load MITRE ATT&CK mappings from a JSON file if it exists
    mitre_mapping_file = os.path.join(OUTPUT_DIR, "mitre_mappings.json")
    
    if os.path.exists(mitre_mapping_file):
        try:
            with open(mitre_mapping_file, "r") as f:
                mitre_mapping = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load MITRE mappings: {e}")
            mitre_mapping = {}
    else:
        # Default mappings as fallback
        mitre_mapping = {
            "NEW_LISTENING_PROCESS": [{
                "technique_id": "T1059", 
                "technique_name": "Command and Scripting Interpreter",
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
                }
            ],
            "SUSPICIOUS_BEHAVIOR": [
                {
                    "technique_id": "T1059", 
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution"
                }
            ]
        }
    
    # Context-based classification enhancements
    process_name = process_info.get("process_name", "").lower()
    cmdline = process_info.get("cmdline", "").lower()
    user = process_info.get("user", "").lower()
    
    # Build contextual insights
    context_insights = []
    
    # Special handling for SUSPICIOUS_BEHAVIOR events with pattern field
    if event_type == "SUSPICIOUS_BEHAVIOR" and detection_details:
        # Handle the old pattern-based format
        if "pattern" in detection_details:
            pattern = detection_details.get("pattern", "")
            
            if pattern == "unusual_shell_ancestry":
                context_insights.append({
                    "technique_id": "T1059.004",
                    "technique_name": "Command and Scripting Interpreter: Unix Shell",
                    "tactic": "Execution"
                })
                
            elif pattern == "ephemeral_port_listener":
                context_insights.append({
                    "technique_id": "T1571",
                    "technique_name": "Non-Standard Port",
                    "tactic": "Command and Control"
                })
                
            elif pattern == "privileged_port_by_non_root":
                context_insights.append({
                    "technique_id": "T1068",
                    "technique_name": "Exploitation for Privilege Escalation",
                    "tactic": "Privilege Escalation"
                })
                
            elif pattern == "encoded_command_execution":
                context_insights.append({
                    "technique_id": "T1027",
                    "technique_name": "Obfuscated Files or Information",
                    "tactic": "Defense Evasion"
                })
                
            elif pattern == "connection_to_unusual_port":
                context_insights.append({
                    "technique_id": "T1071",
                    "technique_name": "Application Layer Protocol",
                    "tactic": "Command and Control"
                })
                
            elif pattern == "execution_from_unusual_location":
                context_insights.append({
                    "technique_id": "T1074",
                    "technique_name": "Data Staged",
                    "tactic": "Collection"
                })
        
        # Handle the new patterns list format
        if "patterns" in detection_details:
            patterns = detection_details.get("patterns", [])
            
            for pattern in patterns:
                pattern_lower = pattern.lower()
                
                if "unusual directory" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1074", 
                        "technique_name": "Data Staged",
                        "tactic": "Collection",
                        "evidence": pattern
                    })
                    
                elif "malicious port" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1571", 
                        "technique_name": "Non-Standard Port",
                        "tactic": "Command and Control",
                        "evidence": pattern
                    })
                    
                elif "encoded command" in pattern_lower or "base64" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1027", 
                        "technique_name": "Obfuscated Files or Information",
                        "tactic": "Defense Evasion",
                        "evidence": pattern
                    })
                    
                elif "webshell" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1505.003", 
                        "technique_name": "Server Software Component: Web Shell",
                        "tactic": "Persistence",
                        "evidence": pattern
                    })
                    
                elif "network utility" in pattern_lower or "netcat" in pattern_lower or "nc " in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1219", 
                        "technique_name": "Remote Access Software",
                        "tactic": "Command and Control",
                        "evidence": pattern
                    })
    
    # Other event types handling
    elif event_type == "ML_DETECTED_ANOMALY":
        if process_name in ["python", "perl", "ruby", "node", "java"]:
            context_insights.append({
                "technique_id": "T1059.006",
                "technique_name": "Command and Scripting Interpreter: Python",
                "tactic": "Execution"
            })
        elif process_name in ["bash", "sh", "zsh", "dash"]:
            context_insights.append({
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution"
            })
        elif user == "root":
            context_insights.append({
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation"
            })
    
    # Add context-based techniques based on process info, regardless of event type
    
    # Special handling for privileged processes run as non-root
    if user != "root" and isinstance(process_info.get("port"), int) and process_info.get("port") < 1024:
        context_insights.append({
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation"
        })
    
    # Special handling for credential access pattern
    if "shadow" in cmdline or "passwd" in cmdline:
        context_insights.append({
            "technique_id": "T1003",
            "technique_name": "OS Credential Dumping",
            "tactic": "Credential Access"
        })
    
    # Merge base classifications with context-specific insights
    techniques = mitre_mapping.get(event_type, []) + context_insights
    
    # Deduplicate techniques
    unique_techniques = []
    seen_ids = set()
    for technique in techniques:
        if technique["technique_id"] not in seen_ids:
            unique_techniques.append(technique)
            seen_ids.add(technique["technique_id"])
    
    if unique_techniques:
        # Log all applicable techniques
        technique_list = [f"{t['technique_id']} ({t['technique_name']})" for t in unique_techniques]
        print(f"[MITRE ATT&CK] Event {event_type} mapped to: {', '.join(technique_list)}")
        
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
    
def remove_process_tracking(pid):
    """Remove process metadata from integrity_processes.json and process_hashes.txt using PID reference."""
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

        # Check if lineage for that process name should still be retained
        still_running_with_same_lineage = any(
            p.get("process_name") == proc_name and p.get("lineage") == known_lineages.get(proc_name)
            for p in integrity_state.values()
        )

        if proc_name in known_lineages and not still_running_with_same_lineage:
            print(f"[INFO] Removing lineage for {proc_name} from known_lineages.json")
            del known_lineages[proc_name]
            save_known_lineages(known_lineages)

        # Remove from hash tracking if necessary
        exe_path = process_info.get("exe_path")
        if exe_path and exe_path in process_hashes:
            del process_hashes[exe_path]
            save_process_hashes(process_hashes)

        print(f"[INFO] Process {pid_str} removed from tracking.")
    else:
        print(f"[WARNING] No matching process found for PID: {pid_str}. It may have already been removed.")

def update_process_tracking(exe_path, process_hash, metadata):
    """Update process tracking files with new or modified processes."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    pid = metadata["pid"]  # Ensure PID is used as a unique key

    # Ensure we store entries separately even if they have the same exe_path
    integrity_state[str(pid)] = metadata  # Store by PID instead of exe_path

    # Update hash tracking separately
    process_hashes[exe_path] = process_hash

    # Save the updated process metadata and hashes
    save_process_metadata(integrity_state)
    save_process_hashes(process_hashes)

def save_process_hashes(process_hashes):
    """Save process hashes to process_hashes.txt."""
    temp_file = f"{PROCESS_HASHES_FILE}.tmp"
    try:
        with open(temp_file, "w") as f:
            for exe_path, hash_value in process_hashes.items():
                f.write(f"{exe_path}:{hash_value}\n")

        os.replace(temp_file, PROCESS_HASHES_FILE)
        os.chmod(PROCESS_HASHES_FILE, 0o600)
#        print(f"[DEBUG] Successfully wrote process hashes to {PROCESS_HASHES_FILE}")

    except Exception as e:
        print(f"[ERROR] Failed to write to {PROCESS_HASHES_FILE}: {e}", file=sys.stderr)

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

def run_monitor():
    """Run the process monitoring loop and start periodic integrity checks."""
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        ensure_output_dir()

        if "--daemon" in sys.argv:
            sys.stdout = open(LOG_FILE, "a", buffering=1)
            sys.stderr = sys.stdout

        signal.signal(signal.SIGINT, lambda signum, frame: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(0))

        print("[INFO] Logging all listening processes on startup...")
        initial_processes = get_listening_processes()

        # ✅ Generate baseline if not present
        if not os.path.exists(KNOWN_PORTS_FILE):
            build_known_ports_baseline(initial_processes)

        # ✅ Load existing lineage map or create new one
        known_lineages = load_known_lineages()

        # ✅ Track and validate lineage for all currently listening processes
        for pid, info in initial_processes.items():
            update_process_tracking(info["exe_path"], info["hash"], info)
            check_lineage_baseline(info, known_lineages)

        print("[INFO] Initial process tracking complete.")

        integrity_thread = threading.Thread(target=rescan_listening_processes, daemon=True)
        integrity_thread.start()

        monitor_listening_processes()  # ⬅ Main monitoring loop

    except Exception as e:
        print(f"[ERROR] PIM encountered an error: {e}")
        traceback.print_exc()

def print_help():
    help_text = """
Process Integrity Monitor (PIM) - Help Menu

Usage:
  python pim               Start the PIM monitoring service in foreground mode
  python pim -s or stop    Stop the PIM service if running in background (daemon) mode
  python pim restart       Restart the PIM monitoring service
  python pim -d or daemon  Run PIM in background (daemon) mode
  python pim help        Show this help message

Description:
  The Process Integrity Monitor continuously monitors system processes for:
    - New or terminated listening processes
    - Non-standard port use by known binaries
    - Unexpected changes in process metadata (user, hash, command line, etc.)
    - Suspicious memory regions (e.g., shellcode injection or anonymous executable pages)

  It uses logging and alerting to flag any anomalies and supports integration with SIEM tools.

Note:
  Use the `-d` option to run PIM in background mode (daemon). This is recommended for long-term monitoring.
"""
    print(help_text.strip())

if __name__ == "__main__":
    ensure_output_dir()
    ensure_file_monitor_json()

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
        print("[INFO] Running PIM in daemon mode...")
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
        print("[INFO] Restarting PIM in daemon mode...")
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
        print("[INFO] Running PIM in foreground mode...")
        run_monitor()
