# 3. MITRE ATT&CK classification for any detections
                for event in detection_events:
                    details = event.get("details")
                    mitre_info = classify_by_mitre_attck_windows(event["event_type"], info, details)
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
                if ML_LIBRARIES_AVAILABLE:
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
    while SERVICE_RUNNING:
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
                    if stored_info["hash"] != current_info["hash"] and stored_info["hash"] != "ACCESS_DENIED" and current_info["hash"] != "ACCESS_DENIED":
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
                    # Process is missing in integrity records ? log as new
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
        # Set Windows file security
        try:
            sd = win32security.GetFileSecurity(
                KNOWN_LINEAGES_FILE, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                KNOWN_LINEAGES_FILE, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            print(f"[ERROR] Failed to set secure permissions on {KNOWN_LINEAGES_FILE}: {e}")
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
    """Walks the parent process chain to build the process lineage using Windows APIs."""
    lineage = []
    
    try:
        seen_pids = set()
        current_pid = pid
        
        while current_pid not in seen_pids and current_pid > 0:
            seen_pids.add(current_pid)
            
            try:
                process = psutil.Process(current_pid)
                process_name = process.name()
                
                # Insert at the beginning to get the ancestry in the right order
                lineage.insert(0, process_name)
                
                # Get parent PID
                parent_pid = process.ppid()
                
                # Break the loop if we've reached the System process or the same process
                if parent_pid == 0 or parent_pid == 4 or parent_pid == current_pid:
                    break
                
                current_pid = parent_pid
                
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[DEBUG] Could not access process {current_pid}: {e}")
                break
    
    except Exception as e:
        print(f"[ERROR] Failed to resolve lineage for PID {pid}: {e}")
    
    return lineage

def implement_behavioral_baselining():
    """Implement ML-based behavioral baselining for Windows process activity."""
    if not ML_LIBRARIES_AVAILABLE:
        print("[WARNING] ML libraries are not available. Skipping behavioral baselining.")
        return None
        
    from sklearn.ensemble import IsolationForest
    import numpy as np
    import pandas as pd
    
    # Define system processes that should have special treatment
    system_processes = ["system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "svchost.exe"]
    
    # Collect historical process behavior data
    processes_data = []
    integrity_state = load_process_metadata()
    
    for pid, process in integrity_state.items():
        process_name = process.get("process_name", "").lower()
        
        # Skip system processes in the training data
        if process_name in system_processes and int(pid) <= 4:
            continue
            
        # Extract features
        try:
            features = {
                'pid': int(pid),
                'port': int(process['port']) if isinstance(process['port'], (int, str)) and str(process['port']).isdigit() else 0,
                'lineage_length': len(process.get('lineage', [])),
                'cmdline_length': len(process.get('cmdline', '')),
                'user_is_admin': 1 if 'admin' in process.get('user', '').lower() else 0,
                'child_processes': get_child_process_count_windows(int(pid))
            }
            
            # Add memory usage as a feature
            mem_usage = get_process_memory_usage_windows(int(pid))
            if mem_usage:
                features['memory_usage'] = mem_usage
                
            # Add handle count
            handle_count = get_handle_count_windows(int(pid))
            if handle_count:
                features['handle_count'] = handle_count
                
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

def analyze_process_for_windows_anomalies(pid, info):
    """Analyze a Windows process for anomalies using Windows-specific detection techniques."""
    # Skip certain system processes
    if info.get('process_name', '').lower() in ['system', 'smss.exe', 'csrss.exe'] and pid <= 4:
        return None
        
    try:
        # Extract features for anomaly detection
        features = {
            'port': int(info.get('port', 0)) if isinstance(info.get('port', 0), (int, str)) and str(info.get('port', 0)).isdigit() else 0,
            'lineage_length': len(info.get('lineage', [])),
            'cmdline_length': len(info.get('cmdline', '')),
            'user_is_admin': 1 if 'admin' in info.get('user', '').lower() else 0,
            'child_processes': get_child_process_count_windows(pid),
            'handle_count': get_handle_count_windows(pid) 
        }
        
        mem_usage = get_process_memory_usage_windows(pid)
        if mem_usage:
            features['memory_usage'] = mem_usage
            
        # Check for suspicious patterns through lineage
        lineage = info.get('lineage', [])
        suspicious_patterns = []
        
        # Check for command shells in lineage of server processes
        shell_in_lineage = any(shell.lower() in [name.lower() for name in lineage] for shell in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'])
        unexpected_execution = shell_in_lineage and any(x in info.get('process_name', '').lower() for x in ['w3wp', 'httpd', 'tomcat', 'nginx', 'iis'])
        
        if unexpected_execution:
            suspicious_patterns.append(f"Unusual process ancestry for {info.get('process_name')}: includes command shell")
        
        # Check if running from unusual directory
        exe_path = info.get('exe_path', '').lower()
        non_standard_dirs = ["\\temp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", "\\programdata\\temp\\", "\\users\\public\\"]
        for unusual_dir in non_standard_dirs:
            if unusual_dir in exe_path:
                suspicious_patterns.append(f"Running from unusual directory: {unusual_dir}")
                break
        
        # Check for unusual port
        if isinstance(info.get('port'), int) and info.get('port') > 1024 and info.get('port') not in [8080, 8443, 3000, 3001, 5000, 5001]:
            suspicious_patterns.append(f"Unusual port: {info.get('port')}")
        
        # Windows-specific checks
        
        # Check for unusual parent-child relationships
        if "services.exe" not in lineage and info.get('process_name', '').lower() == "svchost.exe":
            suspicious_patterns.append("svchost.exe running without services.exe as ancestor")
        
        # Process running from %TEMP% directory
        temp_dir_patterns = ["\\local\\temp\\", "\\temp\\", "\\tmp\\", "\\windows\\temp\\"]
        if any(pattern in exe_path for pattern in temp_dir_patterns):
            suspicious_patterns.append(f"Process running from temporary directory: {exe_path}")
        
        # Check for PowerShell with encoded commands
        cmdline = info.get('cmdline', '').lower()
        if "powershell" in exe_path.lower() and any(flag in cmdline for flag in ["-encodedcommand", "-enc", "-e"]):
            suspicious_patterns.append("PowerShell with encoded command detected")
        
        # Detect LOLBAS (Living Off The Land Binaries And Scripts)
        lolbas_binaries = ["certutil.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe", "msiexec.exe", "installutil.exe", "regasm.exe", "regedt32.exe"]
        for binary in lolbas_binaries:
            if binary.lower() in exe_path.lower() and any(flag in cmdline for flag in ["/urlcache", "/url", "javascript:", "vbscript:", "http:", "https:", "-Sta", "-W", "hidden"]):
                suspicious_patterns.append(f"Potential LOLBin abuse: {binary}")
        
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

def get_process_memory_usage_windows(pid):
    """Get memory usage of a Windows process in KB."""
    try:
        process = psutil.Process(pid)
        # Return the working set size (resident memory) in KB
        return process.memory_info().rss // 1024
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[DEBUG] Could not get memory usage for PID {pid}: {e}")
        return None

def get_child_process_count_windows(pid):
    """Count child processes of the given PID in Windows."""
    try:
        # Use psutil to get children
        process = psutil.Process(pid)
        children = process.children(recursive=False)
        return len(children)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[DEBUG] Could not get child process count for PID {pid}: {e}")
        return 0

def get_handle_count_windows(pid):
    """Count open handles for a Windows process."""
    try:
        process = psutil.Process(pid)
        return process.num_handles()
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
        print(f"[DEBUG] Could not get handle count for PID {pid}: {e}")
        return 0

def scan_process_memory_windows(pid):
    """Scan Windows process memory for potential code injection using VAD (Virtual Address Descriptor) analysis."""
    suspicious_regions = []
    exe_path = ""
    
    try:
        # Get process information
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
            process_name = os.path.basename(exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[DEBUG] Could not get process information for PID {pid}: {e}")
            return []
            
        # Use PowerShell to query memory regions with executable permissions
        # This requires administrative privileges
        if not is_admin():
            print("[WARNING] Administrator privileges required for memory scanning")
            return []
        
        # Use memory_maps from psutil to enumerate memory regions
        try:
            memory_regions = enumerate_process_memory_regions(pid)
            
            # Apply heuristics to detect suspicious memory regions
            for region in memory_regions:
                # Executable, non-image memory is suspicious (often used for shellcode)
                if region.get('is_executable') and not region.get('is_image') and region.get('type') in ['Private', 'MEM_PRIVATE']:
                    suspicious_regions.append({
                        'region': region,
                        'reason': 'Executable non-image memory',
                        'severity': 'high'
                    })
                
                # RWX memory is highly suspicious in legitimate applications
                elif region.get('is_executable') and region.get('is_writable') and region.get('type') in ['Private', 'MEM_PRIVATE']:
                    suspicious_regions.append({
                        'region': region,
                        'reason': 'Memory region with RWX permissions',
                        'severity': 'high'
                    })
                
                # Large executable allocations in heap or not mapped to a DLL
                elif region.get('is_executable') and not region.get('mapped_file') and region.get('size', 0) > 1024 * 1024:
                    suspicious_regions.append({
                        'region': region,
                        'reason': 'Large executable memory allocation',
                        'severity': 'medium'
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
                        "suspicious_regions": [f"{r['region'].get('address', 'Unknown')} - {r['reason']}" for r in suspicious_regions]
                    },
                    previous_hash=None,
                    new_hash=None
                )
        except Exception as e:
            print(f"[ERROR] Failed to enumerate memory regions for PID {pid}: {e}")
    
    except Exception as e:
        print(f"[ERROR] Failed to scan memory for PID {pid}: {e}")
    
    return suspicious_regions

def enumerate_process_memory_regions(pid):
    """Get memory regions for a process using Windows API via Python."""
    memory_regions = []
    
    try:
        # Use WMI to get process modules (DLLs) for context
        loaded_modules = {}
        try:
            process = psutil.Process(pid)
            modules = process.memory_maps(grouped=False)
            for module in modules:
                base_address = module.addr.split('-')[0]
                loaded_modules[base_address] = {
                    'path': module.path,
                    'size': int(module.rss),
                    'is_image': True
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[DEBUG] Could not get modules for PID {pid}: {e}")
        
        # Get memory regions
        try:
            # Use psutil.Process.memory_maps() to get memory regions
            process = psutil.Process(pid)
            memory_maps = process.memory_maps(grouped=False)
            
            for memory_map in memory_maps:
                # Parse address range
                addr_range = memory_map.addr.split('-')
                if len(addr_range) != 2:
                    continue
                
                start_addr = int(addr_range[0], 16)
                end_addr = int(addr_range[1], 16)
                size = end_addr - start_addr
                
                # Parse permissions
                perms = memory_map.perms
                is_readable = 'r' in perms
                is_writable = 'w' in perms
                is_executable = 'x' in perms
                is_private = 'p' in perms
                is_shared = 's' in perms
                
                # Determine type
                mem_type = 'MEM_PRIVATE' if is_private else 'MEM_MAPPED'
                
                # Determine if this is an image (DLL or EXE)
                mapped_file = memory_map.path if hasattr(memory_map, 'path') else None
                is_image = mapped_file.lower().endswith(('.dll', '.exe')) if mapped_file else False
                
                memory_regions.append({
                    'address': f"0x{start_addr:X}",
                    'size': size,
                    'is_readable': is_readable,
                    'is_writable': is_writable,
                    'is_executable': is_executable,
                    'type': mem_type,
                    'is_image': is_image,
                    'mapped_file': mapped_file
                })
        
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[DEBUG] Could not get memory maps for PID {pid}: {e}")
            
    except Exception as e:
        print(f"[ERROR] Failed to enumerate memory regions: {e}")
        
    return memory_regions

def classify_by_mitre_attck_windows(event_type, process_info, detection_details=None):
    """Map detected activities to MITRE ATT&CK techniques using Windows-specific classifications."""
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
        # Default mappings as fallback - Windows specific
        mitre_mapping = {
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
    
    # Context-based classification enhancements for Windows
    process_name = process_info.get("process_name", "").lower()
    cmdline = process_info.get("cmdline", "").lower()
    user = process_info.get("user", "").lower()
    
    # Build contextual insights
    context_insights = []
    
    # Windows-specific process name checks
    if process_name in ["powershell.exe", "pwsh.exe"]:
        context_insights.append({
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        })
    elif process_name in ["cmd.exe"]:
        context_insights.append({
            "technique_id": "T1059.003",
            "technique_name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": "Execution"
        })
    elif process_name in ["wscript.exe", "cscript.exe"]:
        context_insights.append({
            "technique_id": "T1059.005",
            "technique_name": "Command and Scripting Interpreter: Visual Basic",
            "tactic": "Execution"
        })
    elif process_name in ["rundll32.exe"]:
        context_insights.append({
            "technique_id": "T1218.011",
            "technique_name": "Signed Binary Proxy Execution: Rundll32",
            "tactic": "Defense Evasion"
        })
    elif process_name in ["regsvr32.exe"]:
        context_insights.append({
            "technique_id": "T1218.010",
            "technique_name": "Signed Binary Proxy Execution: Regsvr32",
            "tactic": "Defense Evasion"
        })
    
    # Special handling for user context
    if "system" in user or "administrator" in user:
        context_insights.append({
            "technique_id": "T1078.003",
            "technique_name": "Valid Accounts: Local Accounts",
            "tactic": "Persistence"
        })
    
    # Special handling for command line analysis
    if "http:" in cmdline or "https:" in cmdline:
        # Look for suspicious URL invocation patterns
        if any(tool in cmdline for tool in ["powershell", "cmd", "wscript", "cscript", "rundll32", "regsvr32", "mshta"]):
            context_insights.append({
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": "Command and Control"
            })
    
    # PowerShell encoded command
    if "-enc" in cmdline or "-encodedcommand" in cmdline:
        context_insights.append({
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion"
        })
    
    # Special handling for SUSPICIOUS_BEHAVIOR events with pattern field
    if event_type == "SUSPICIOUS_BEHAVIOR" and detection_details:
        # Handle the patterns list format
        if "suspicious_patterns" in detection_details:
            patterns = detection_details.get("suspicious_patterns", [])
            
            for pattern in patterns:
                pattern_lower = pattern.lower()
                
                if "unusual directory" in pattern_lower or "temp directory" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1074", 
                        "technique_name": "Data Staged",
                        "tactic": "Collection",
                        "evidence": pattern
                    })
                    
                elif "unusual port" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1571", 
                        "technique_name": "Non-Standard Port",
                        "tactic": "Command and Control",
                        "evidence": pattern
                    })
                    
                elif "encoded command" in pattern_lower or "powershell" in pattern_lower and ("encoded" in pattern_lower or "-enc" in pattern_lower):
                    context_insights.append({
                        "technique_id": "T1027", 
                        "technique_name": "Obfuscated Files or Information",
                        "tactic": "Defense Evasion",
                        "evidence": pattern
                    })
                    
                elif "webshell" in pattern_lower or "w3wp.exe" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1505.003", 
                        "technique_name": "Server Software Component: Web Shell",
                        "tactic": "Persistence",
                        "evidence": pattern
                    })
                    
                elif "lolbin" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1218", 
                        "technique_name": "Signed Binary Proxy Execution",
                        "tactic": "Defense Evasion",
                        "evidence": pattern
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
    
def calculate_threat_score_windows(process_info, detection_events):
    """Calculate a threat score for a Windows process based on its behavior and detections."""
    base_score = 0
    reasons = []
    
    # Process metadata factors
    process_name = process_info.get("process_name", "").lower()
    user = process_info.get("user", "").lower()
    exe_path = process_info.get("exe_path", "").lower()
    port = process_info.get("port", 0)
    lineage = process_info.get("lineage", [])
    
    # 1. Score based on user (system/admin processes get higher baseline)
    if "system" in user or "administrator" in user:
        base_score += 10
        reasons.append("Running as privileged user")
    
    # 2. Score based on process lineage
    suspicious_lineage = False
    suspicious_ancestry = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe"]
    for proc in lineage:
        proc_lower = proc.lower()
        if proc_lower in suspicious_ancestry:
            suspicious_lineage = True
            base_score += 15
            reasons.append(f"Suspicious process in lineage: {proc}")
            break
    
    # 3. Score based on execution path
    suspicious_paths = ["\\temp\\", "\\windows\\temp\\", "\\appdata\\local\\temp\\", "\\users\\public\\", "\\programdata\\"]
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
            patterns = event.get("details", {}).get("suspicious_patterns", [])
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

# Windows Service class for PIM
class PIMService(win32serviceutil.ServiceFramework):
    _svc_name_ = "MoniSecPIM"
    _svc_display_name_ = "MoniSec Process Integrity Monitor"
    _svc_description_ = "Monitors system processes for security integrity violations"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = False
        
    def SvcStop(self):
        """Stop the Windows service."""
        global SERVICE_RUNNING
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        SERVICE_RUNNING = False
        self.running = False
    
    def SvcDoRun(self):
        """Run the Windows service."""
        global SERVICE_RUNNING
        self.running = True
        SERVICE_RUNNING = True
        
        import servicemanager
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Initialize the monitoring system
        self.initialize_and_run()
    
    def initialize_and_run(self):
        """Initialize the PIM monitoring system and run it."""
        try:
            ensure_output_dir()
            ensure_file_monitor_json()
            
            # Write PID file
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
                
            # Start the monitoring
            print("[INFO] MoniSec Process Integrity Monitor service started")
            
            # Log all listening processes on startup
            print("[INFO] Logging all listening processes on startup...")
            initial_processes = get_listening_processes()
            
            # Generate baseline if not present
            if not os.path.exists(KNOWN_PORTS_FILE):
                build_known_ports_baseline(initial_processes)
                
            # Load existing lineage map or create new one
            known_lineages = load_known_lineages()
            
            # Track and validate lineage for all currently listening processes
            for pid, info in initial_processes.items():
                update_process_tracking(info["exe_path"], info["hash"], info)
                check_lineage_baseline(info, known_lineages)
                
            print("[INFO] Initial process tracking complete.")
            
            # Start the periodic integrity check thread
            integrity_thread = threading.Thread(target=rescan_listening_processes, daemon=True)
            integrity_thread.start()
            
            # Run the main monitoring loop
            monitor_listening_processes()
            
        except Exception as e:
            print(f"[ERROR] Error in PIM service: {e}")
            traceback.print_exc()

def run_as_console():
    """Run the PIM service in console mode."""
    try:
        ensure_output_dir()
        ensure_file_monitor_json()
        
        # Write PID file
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        
        print("[INFO] MoniSec Process Integrity Monitor started in console mode")
        
        # Set signal handlers for graceful shutdown
        def handle_shutdown(signum, frame):
            global SERVICE_RUNNING
            print("\n[INFO] Shutdown signal received, stopping...")
            SERVICE_RUNNING = False
            sys.exit(0)
            
        # Register signal handlers if possible
        try:
            signal.signal(signal.SIGINT, handle_shutdown)
            signal.signal(signal.SIGTERM, handle_shutdown)
        except (AttributeError, ValueError):
            # Some signals might not be available on Windows
            pass
        
        # Log all listening processes on startup
        print("[INFO] Logging all listening processes on startup...")
        initial_processes = get_listening_processes()
        
        # Generate baseline if not present
        if not os.path.exists(KNOWN_PORTS_FILE):
            build_known_ports_baseline(initial_processes)
            
        # Load existing lineage map or create new one
        known_lineages = load_known_lineages()
        
        # Track and validate lineage for all currently listening processes
        for pid, info in initial_processes.items():
            update_process_tracking(info["exe_path"], info["hash"], info)
            check_lineage_baseline(info, known_lineages)
            
        print("[INFO] Initial process tracking complete.")
        
        # Start the periodic integrity check thread
        integrity_thread = threading.Thread(target=rescan_listening_processes, daemon=True)
        integrity_thread.start()
        
        # Run the main monitoring loop
        monitor_listening_processes()
        
    except Exception as e:
        print(f"[ERROR] Error in PIM console mode: {e}")
        traceback.print_exc()
    finally:
        # Clean up on exit
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

def print_help():
    help_text = """
Process Integrity Monitor (PIM) for Windows - Help Menu

Usage:
  python pim.py               Start the PIM monitoring service in console mode
  python pim.py install       Install the PIM service
  python pim.py remove        Remove the PIM service
  python pim.py start         Start the installed PIM service
  python pim.py stop          Stop the PIM service
  python pim.py restart       Restart the PIM service
  python pim.py help          Show this help message

Description:
  The Process Integrity Monitor continuously monitors system processes for:
    - New or terminated listening processes
    - Non-standard port use by known binaries
    - Unexpected changes in process metadata (user, hash, command line, etc.)
    - Suspicious memory regions (e.g., shellcode injection or unsigned code)
    - Windows-specific behavioral anomalies

  It uses logging and alerting to flag any anomalies and supports integration with SIEM tools.

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
                win32serviceutil.InstallService(
                    pythonClassString=f"{os.path.basename(__file__).replace('.py', '')}.PIMService",
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
            logging.basicConfig(level=logging.DEBUG)
            run_as_console()
        
        # For service operation
        elif command in ["--service", "--foreground"]:
            # When the service manager executes the service
            win32serviceutil.HandleCommandLine(PIMService)
            
        else:
            print(f"[ERROR] Unknown command: {command}")
            print_help()
    
    else:
        # Default: run in console mode
        run_as_console()
1059", 
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
    
    # Context-based classification enhancements for Windows
    process_name = process_info.get("process_name", "").lower()
    cmdline = process_info.get("cmdline", "").lower()
    user = process_info.get("user", "").lower()
    
    # Build contextual insights
    context_insights = []
    
    # Special handling for SUSPICIOUS_BEHAVIOR events with pattern field
    if event_type == "SUSPICIOUS_BEHAVIOR" and detection_details:
        # Handle the patterns list format
        if "suspicious_patterns" in detection_details:
            patterns = detection_details.get("suspicious_patterns", [])
            
            for pattern in patterns:
                pattern_lower = pattern.lower()
                
                if "unusual directory" in pattern_lower or "temp directory" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1074", 
                        "technique_name": "Data Staged",
                        "tactic": "Collection",
                        "evidence": pattern
                    })
                    
                elif "unusual port" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1571", 
                        "technique_name": "Non-Standard Port",
                        "tactic": "Command and Control",
                        "evidence": pattern
                    })
                    
                elif "encoded command" in pattern_lower or "powershell" in pattern_lower and ("encoded" in pattern_lower or "-enc" in pattern_lower):
                    context_insights.append({
                        "technique_id": "T1027", 
                        "technique_name": "Obfuscated Files or Information",
                        "tactic": "Defense Evasion",
                        "evidence": pattern
                    })
                    
                elif "webshell" in pattern_lower or "w3wp.exe" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1505.003", 
                        "technique_name": "Server Software Component: Web Shell",
                        "tactic": "Persistence",
                        "evidence": pattern
                    })
                    
                elif "lolbin" in pattern_lower:
                    context_insights.append({
                        "technique_id": "T1218", 
                        "technique_name": "Signed Binary Proxy Execution",
                        "tactic": "Defense Evasion",
                        "evidence": pattern
                    })
    
    # Windows-specific process name checks
    if process_name in ["powershell.exe", "pwsh.exe"]:
        context_insights.append({
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution"
        })
    elif process_name in ["cmd.exe"]:
        context_insights.append({
            "technique_id": "T# =============================================================================
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
import signal
import argparse
import threading
import traceback
import win32api
import win32con
import win32service
import win32serviceutil
import win32process
import win32security
import win32file
import wmi
import psutil
import socket
import ctypes
from pathlib import Path

# New imports for ML and analysis
# Optional: for better error handling with ML libraries
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    print("[WARNING] Machine learning libraries (numpy, pandas, scikit-learn) not found. ML-based detection will be disabled.")
    ML_LIBRARIES_AVAILABLE = False

# Define BASE_DIR for Windows
BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")

# Update paths for Windows
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.join(OUTPUT_DIR, "pim.pid")
FILE_MONITOR_JSON = os.path.join(LOG_DIR, "file_monitor.json")
KNOWN_PORTS_FILE = os.path.join(OUTPUT_DIR, "known_ports.json")
KNOWN_LINEAGES_FILE = os.path.join(OUTPUT_DIR, "known_lineages.json")

# Global WMI connection for better performance
try:
    WMI_CONNECTION = wmi.WMI()
except Exception as e:
    print(f"[ERROR] Failed to initialize WMI connection: {e}")
    WMI_CONNECTION = None

# Global flag to control service operation
SERVICE_RUNNING = True

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def ensure_output_dir():
    """Ensure that the output directory and necessary files exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Ensure process hashes file exists
    if not os.path.exists(PROCESS_HASHES_FILE):
        with open(PROCESS_HASHES_FILE, "w") as f:
            f.write("")
        # Set Windows file security (Admins only)
        try:
            sd = win32security.GetFileSecurity(
                PROCESS_HASHES_FILE, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                PROCESS_HASHES_FILE, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            print(f"[ERROR] Failed to set secure permissions on {PROCESS_HASHES_FILE}: {e}")

    # Ensure integrity state file exists
    if not os.path.exists(INTEGRITY_PROCESS_FILE):
        with open(INTEGRITY_PROCESS_FILE, "w") as f:
            json.dump({}, f, indent=4)
        # Set Windows file security
        try:
            sd = win32security.GetFileSecurity(
                INTEGRITY_PROCESS_FILE, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                INTEGRITY_PROCESS_FILE, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            print(f"[ERROR] Failed to set secure permissions on {INTEGRITY_PROCESS_FILE}: {e}")

def ensure_file_monitor_json():
    """Ensure that the file_monitor.json file exists and create logs directory if needed."""
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(FILE_MONITOR_JSON):
        with open(FILE_MONITOR_JSON, "w") as f:
            json.dump({}, f, indent=4)
        # Set Windows file security
        try:
            sd = win32security.GetFileSecurity(
                FILE_MONITOR_JSON, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                FILE_MONITOR_JSON, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            print(f"[ERROR] Failed to set secure permissions on {FILE_MONITOR_JSON}: {e}")

# Initialize directories
ensure_file_monitor_json()

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
    # Set Windows file security
    try:
        sd = win32security.GetFileSecurity(
            PROCESS_HASHES_FILE, 
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()
        
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
        
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            PROCESS_HASHES_FILE, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
    except Exception as e:
        print(f"[ERROR] Failed to set secure permissions on {PROCESS_HASHES_FILE}: {e}")

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
        # Set Windows file security
        try:
            sd = win32security.GetFileSecurity(
                INTEGRITY_PROCESS_FILE, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                INTEGRITY_PROCESS_FILE, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            print(f"[ERROR] Failed to set secure permissions on {INTEGRITY_PROCESS_FILE}: {e}")

    except Exception as e:
        print(f"[ERROR] Failed to write to {INTEGRITY_PROCESS_FILE}: {e}", file=sys.stderr)

def get_process_hash(exe_path, cmdline=None):
    """Generate SHA-256 hash of the process executable and optionally include cmdline."""
    try:
        hash_obj = hashlib.sha256()

        # Hash the executable file
        try:
            with open(exe_path, "rb") as f:
                hash_obj.update(f.read())
        except PermissionError:
            # Try to open with read sharing for Windows system files
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
                        hr, data = win32file.ReadFile(handle, min(buffer_size, file_size - chunks_read))
                        hash_obj.update(data)
                        chunks_read += len(data)
                        
                finally:
                    win32file.CloseHandle(handle)
            except Exception as e:
                print(f"[ERROR] Failed to hash file {exe_path}: {e}")
                return "ERROR_HASHING"

        # Optionally include command-line arguments in hashing
        if cmdline:
            hash_obj.update(cmdline.encode("utf-8"))

        return hash_obj.hexdigest()

    except Exception as e:
        print(f"[ERROR] Failed to hash {exe_path}: {e}")
        return "ERROR_HASHING"

def get_listening_processes():
    """Retrieve all listening processes and their metadata using Windows APIs."""
    listening_processes = {}

    try:
        # Use netstat to get listening ports
        netstat_output = subprocess.check_output("netstat -ano -p TCP", shell=True, text=True)
        netstat_lines = netstat_output.splitlines()
        
        # Extract port and PID information
        for line in netstat_lines:
            if "LISTENING" not in line:
                continue
                
            parts = line.strip().split()
            if len(parts) < 5:
                continue
                
            # Extract local address and PID
            local_address = parts[1]
            pid = int(parts[4])
            
            # Extract port number
            try:
                port = int(local_address.split(":")[-1])
            except (IndexError, ValueError):
                port = "UNKNOWN"
            
            # Get process information using psutil
            try:
                proc = psutil.Process(pid)
                
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, FileNotFoundError):
                    exe_path = "ACCESS_DENIED"
                
                try:
                    cmdline = " ".join(proc.cmdline())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = "ACCESS_DENIED"
                
                try:
                    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(proc.create_time()))
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
                if exe_path != "ACCESS_DENIED":
                    process_hash = get_process_hash(exe_path, cmdline)
                else:
                    process_hash = "ACCESS_DENIED"
                
                # Get process lineage
                lineage = resolve_lineage(pid)
                
                # Store process information
                listening_processes[pid] = {
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
                print(f"[ERROR] Failed to get information for PID {pid}: {e}")
    
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to execute netstat command: {e}")
    
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
    # Set Windows file security
    try:
        sd = win32security.GetFileSecurity(
            KNOWN_PORTS_FILE, 
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()
        
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
        
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            KNOWN_PORTS_FILE, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
    except Exception as e:
        print(f"[ERROR] Failed to set secure permissions on {KNOWN_PORTS_FILE}: {e}")

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
    # Set Windows file security
    try:
        sd = win32security.GetFileSecurity(
            KNOWN_PORTS_FILE, 
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = win32security.ACL()
        
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
        
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            KNOWN_PORTS_FILE, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
    except Exception as e:
        print(f"[ERROR] Failed to set secure permissions on {KNOWN_PORTS_FILE}: {e}")

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
    """Enhanced monitoring loop with ML-based detection for Windows processes."""
    known_lineages = load_known_lineages()
    known_processes = get_listening_processes()
    terminated_pids = set()
    
    # Initialize ML model if available
    ml_model_info = None
    if ML_LIBRARIES_AVAILABLE:
        ml_model_info = implement_behavioral_baselining()
    ml_retrain_counter = 0
    
    # Initialize detection history and already alerted processes
    detection_history = {}
    alerted_processes = set()
    
    print("[INFO] Starting enhanced process monitoring with ML-based detection...")
    
    while SERVICE_RUNNING:
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
                
                # 1. Memory analysis for code injection (Windows-specific)
                suspicious_memory = scan_process_memory_windows(pid)
                if suspicious_memory:
                    print(f"[ALERT] Suspicious memory regions detected in PID {pid} ({info.get('process_name', 'unknown')})")
                    detection_events.append({
                        "event_type": "SUSPICIOUS_MEMORY_REGION",
                        "details": suspicious_memory
                    })
                
                # 1.5 Behavioral pattern detection
                behavioral_patterns = analyze_process_for_windows_anomalies(pid, info)
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
                    
                    # Skip ML detection for certain system processes
                    process_name = info.get('process_name', '')
                    if process_name.lower() in system_processes and pid <= 4:
                        continue
                    
                    # Prepare features for this process
                    process_features = {}
                    try:
                        process_features = {
                            'port': int(info.get('port', 0)) if isinstance(info.get('port', 0), (int, str)) and str(info.get('port', 0)).isdigit() else 0,
                            'lineage_length': len(info.get('lineage', [])),
                            'cmdline_length': len(info.get('cmdline', '')),
                            'user_is_admin': 1 if info.get('user', '').lower().endswith('administrator') else 0,
                            'child_processes': get_child_process_count_windows(pid),
                            'handle_count': get_handle_count_windows(pid) 
                        }
                        
                        mem_usage = get_process_memory_usage_windows(pid)
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
                    threat_assessment = calculate_threat_score_windows(info, detection_events)
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
                    mitre_info = classify_by_mitre_attck_windows(event["event_type"], info, details)
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
            
            # Handle new processes
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
            
            # Handle terminated processes
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
                if ML_LIBRARIES_AVAILABLE:
                    ml_model_info = implement_behavioral_baselining()
                ml_retrain_counter = 0
                alerted_processes.clear()  # Allow processes to trigger alerts again
            
            known_processes = current_processes
            time.sleep(interval)
            
        except Exception as e:
            print(f"[ERROR] Exception in enhanced monitoring loop: {e}")
            traceback.print_exc()
            continue
