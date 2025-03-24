import os
import time
import json
import sys
import subprocess
import hashlib
import signal
import argparse
import daemon
import threading
import traceback

OUTPUT_DIR = os.path.abspath("./output")
LOG_DIR = os.path.abspath("./logs")  # Change from absolute path
LOG_FILE = os.path.join(LOG_DIR, "process_monitor.log")
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.abspath("pim.pid")
FILE_MONITOR_JSON = os.path.join(LOG_DIR, "file_monitor.json")
KNOWN_PORTS_FILE = os.path.join(OUTPUT_DIR, "known_ports.json")

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
        # Use full path for `lsof` to avoid daemon path issues
        lsof_command = "sudo -n /usr/bin/lsof -i -P -n | /bin/grep LISTEN"
        output = subprocess.getoutput(lsof_command)

        if not output:
            print("[ERROR] lsof returned no output. Check sudo permissions.", file=sys.stderr)

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue

            pid = parts[1]
            exe_path = f"/proc/{pid}/exe"

            try:
                # Read actual executable path
                exe_real_path = subprocess.getoutput(f"sudo -n /usr/bin/readlink -f {exe_path}").strip()

                if "Permission denied" in exe_real_path or not exe_real_path:
                    raise PermissionError("Could not read process executable path")

                # Extract full command line to locate the script being executed
                cmdline_raw = subprocess.getoutput(f"sudo -n /bin/cat /proc/{pid}/cmdline 2>/dev/null").strip()
                cmdline = cmdline_raw.replace("\x00", " ")

                # Generate process hash from the actual script or binary
                process_hash = get_process_hash(exe_real_path, cmdline)

            except (PermissionError, FileNotFoundError, subprocess.CalledProcessError):
                exe_real_path = "PERMISSION_DENIED"
                process_hash = "UNKNOWN"

            # Extract port safely
            try:
                port = parts[-2].split(':')[-1]
                if not port.isdigit():
                    port = "UNKNOWN"
                else:
                    port = int(port)
            except IndexError:
                port = "UNKNOWN"

            try:
                # Capture additional process details
                user = subprocess.getoutput(f"sudo -n /bin/ps -o user= -p {pid}").strip()
                start_time = subprocess.getoutput(f"sudo -n /bin/ps -o lstart= -p {pid}").strip()
                ppid = subprocess.getoutput(f"sudo -n /bin/ps -o ppid= -p {pid}").strip()
                ppid = int(ppid) if ppid.isdigit() else "UNKNOWN"

                if not user:
                    user = "UNKNOWN"

            except Exception:
                user, start_time, ppid = "UNKNOWN", "UNKNOWN", "UNKNOWN"

            listening_processes[int(pid)] = {
                "pid": int(pid),
                "exe_path": exe_real_path,
                "process_name": os.path.basename(exe_real_path) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN",
                "port": port,
                "user": user,
                "start_time": start_time,
                "cmdline": cmdline,
                "hash": process_hash,
                "ppid": ppid,
            }

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] subprocess error in get_listening_processes: {e}", file=sys.stderr)

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

    # Check for critical metadata mismatches
    mismatches = {}
    for field in ["exe_path", "cmdline", "hash", "user"]:
        expected = baseline_metadata.get(field)
        actual = process_info.get(field)
        if expected and actual and expected != actual:
            mismatches[field] = {"expected": expected, "actual": actual}

    if mismatches:
        print(f"[ALERT] Metadata mismatch detected for {proc_name}: {mismatches}")
        log_event(
            event_type="PROCESS_METADATA_MISMATCH",
            file_path=process_info.get("exe_path", "UNKNOWN"),
            previous_metadata=baseline_metadata,
            new_metadata=process_info,
            previous_hash=baseline_metadata.get("hash", "UNKNOWN"),
            new_hash=process_info.get("hash", "UNKNOWN")
        )

def monitor_listening_processes(interval=2):
    """Continuously monitors for new and terminated listening processes and detects non-standard port usage."""
    known_processes = get_listening_processes()
    terminated_pids = set()

    while True:
        try:
            current_processes = get_listening_processes()
            new_processes = {pid: info for pid, info in current_processes.items() if pid not in known_processes}
            terminated_processes = {pid: info for pid, info in known_processes.items() if pid not in current_processes}

            from fim_client import log_event

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

                # Check for unusual port or metadata
                check_for_unusual_port_use(info)

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

            known_processes = current_processes
            time.sleep(interval)

        except Exception as e:
            print(f"[ERROR] Exception in real-time monitoring loop: {e}")
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

def remove_process_tracking(pid):
    """Remove process metadata from integrity_processes.json and process_hashes.txt using PID reference."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    pid_str = str(pid)  # Convert PID to string since JSON keys are strings

    if pid_str in integrity_state:
        del integrity_state[pid_str]  # ✅ Remove from integrity records

        # Save updated metadata
        save_process_metadata(integrity_state)
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

        for pid, info in initial_processes.items():
            update_process_tracking(info["exe_path"], info["hash"], info)

        print("[INFO] Initial process tracking complete.")

        integrity_thread = threading.Thread(target=rescan_listening_processes, daemon=True)
        integrity_thread.start()

        monitor_listening_processes()  # ⬅ Main monitoring loop

    except Exception as e:
        print(f"[ERROR] PIM encountered an error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Integrity Monitor (PIM)")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run PIM in daemon mode")
    parser.add_argument("-s", "--stop", action="store_true", help="Stop PIM daemon")
    args = parser.parse_args()

    if args.stop:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            os.remove(PID_FILE)
            print("[INFO] PIM daemon stopped.")
        else:
            print("[ERROR] PIM daemon is not running.")
        exit(0)

    if args.daemon:
        print("[INFO] Running PIM in daemon mode...")

        # Set environment manually before daemonizing
        os.environ["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"

        with daemon.DaemonContext(working_directory=os.getcwd()):
            run_monitor()
    else:
        print("[INFO] Running PIM in foreground mode...")
        run_monitor()
