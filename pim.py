import os
import time
import json
import subprocess
import hashlib
import signal
import argparse
import daemon

OUTPUT_DIR = os.path.abspath("./output")
LOG_FILE = os.path.abspath("./logs/process_monitor.log")
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")
PID_FILE = os.path.abspath("pim.pid")

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
    except Exception:
        pass

def get_process_hash(exe_path):
    """Generate SHA-256 hash of the process executable."""
    try:
        with open(exe_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "ERROR_HASHING"

def get_listening_processes():
    """Retrieve all listening processes and their metadata."""
    listening_processes = {}

    try:
        lsof_command = "sudo lsof -i -P -n | grep LISTEN"
        output = subprocess.check_output(lsof_command, shell=True, text=True)

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue

            pid = parts[1]
            exe_path = f"/proc/{pid}/exe"

            try:
                exe_real_path = subprocess.check_output(f"sudo readlink -f {exe_path}", shell=True, text=True).strip()
                process_hash = get_process_hash(exe_real_path) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN"
            except (PermissionError, FileNotFoundError, subprocess.CalledProcessError):
                exe_real_path = "PERMISSION_DENIED"
                process_hash = "UNKNOWN"

            port = parts[-2].split(':')[-1]
            if port.isdigit():
                port = int(port)

            listening_processes[int(pid)] = {
                "pid": int(pid),
                "exe_path": exe_real_path,
                "process_name": os.path.basename(exe_real_path) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN",
                "port": port,
                "user": subprocess.getoutput(f"ps -o user= -p {pid}").strip(),
                "start_time": subprocess.getoutput(f"ps -o lstart= -p {pid}").strip(),
                "cmdline": subprocess.getoutput(f"tr '\\0' ' ' < /proc/{pid}/cmdline").strip(),
                "hash": process_hash,
                "ppid": int(subprocess.getoutput(f"ps -o ppid= -p {pid}").strip()) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN",
            }

    except subprocess.CalledProcessError:
        pass

    return listening_processes

def monitor_listening_processes(interval=2):
    """Continuously monitors for new and terminated listening processes."""
    known_processes = get_listening_processes()
    terminated_processes = set()

    while True:
        current_processes = get_listening_processes()
        new_processes = {pid: info for pid, info in current_processes.items() if pid not in known_processes}
        terminated_pids = {pid: info for pid, info in known_processes.items() if pid not in current_processes}

        from fim_client import log_event

        for pid, info in current_processes.items():
            update_process_tracking(info["exe_path"], info["hash"], info)

        for pid, info in new_processes.items():
            log_event(
                event_type="NEW_LISTENING_PROCESS",
                file_path=info["exe_path"],
                previous_metadata=None,
                new_metadata=info,
                previous_hash=None,
                new_hash=info.get("hash", "UNKNOWN")
            )

        for pid, info in terminated_pids.items():
            if pid in terminated_processes:
                continue

            log_event(
                event_type="PROCESS_TERMINATED",
                file_path=info["exe_path"],
                previous_metadata=info,
                new_metadata=None,
                previous_hash=info.get("hash", "UNKNOWN"),
                new_hash=None
            )

            remove_process_tracking(info["exe_path"])
            terminated_processes.add(pid)

        known_processes = current_processes
        time.sleep(interval)

def remove_process_tracking(exe_path):
    """Remove process hash and metadata when a process terminates."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    if exe_path in process_hashes:
        del process_hashes[exe_path]

    if exe_path in integrity_state:
        del integrity_state[exe_path]

    save_process_hashes(process_hashes)
    save_process_metadata(integrity_state)

def update_process_tracking(exe_path, process_hash, metadata):
    """Update process tracking files with new or modified processes."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    process_hashes[exe_path] = process_hash
    integrity_state[exe_path] = metadata

    save_process_hashes(process_hashes)
    save_process_metadata(integrity_state)

def save_process_hashes(process_hashes):
    """Save process hashes to process_hashes.txt."""
    temp_file = f"{PROCESS_HASHES_FILE}.tmp"
    with open(temp_file, "w") as f:
        for exe_path, hash_value in process_hashes.items():
            f.write(f"{exe_path}:{hash_value}\n")

    os.replace(temp_file, PROCESS_HASHES_FILE)
    os.chmod(PROCESS_HASHES_FILE, 0o600)

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
    """Run the process monitoring loop and write PID for management."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    ensure_output_dir()

    # Redirect stdout and stderr to a log file when running as a daemon
    if os.fork() > 0:
        exit(0)  # Parent process exits, child continues as daemon

    # Close standard input, output, and error to avoid crashes
    sys.stdout = open(LOG_FILE, "a", buffering=1)
    sys.stderr = sys.stdout

    print("[INFO] Process monitoring started in daemon mode.")

    monitor_listening_processes()

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Process Integrity Monitor (PIM)")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run PIM in background")
    parser.add_argument("-s", "--stop", action="store_true", help="Stop daemon process")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()

    if args.stop:
        stop_daemon()
    elif args.daemon:
        print("[INFO] Running in background mode...")
        with daemon.DaemonContext():
            run_monitor()
    else:
        print("[INFO] Running in foreground mode...")
        run_monitor()
