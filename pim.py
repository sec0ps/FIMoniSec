import os
import time
import json
import subprocess
import hashlib
from pathlib import Path

OUTPUT_DIR = os.path.abspath("./output")
LOG_FILE = os.path.abspath("./logs/process_monitor.log")
PROCESS_HASHES_FILE = os.path.join(OUTPUT_DIR, "process_hashes.txt")
INTEGRITY_PROCESS_FILE = os.path.join(OUTPUT_DIR, "integrity_processes.json")

def ensure_output_dir():
    """Ensure that the output directory exists with appropriate permissions."""
    os.makedirs(OUTPUT_DIR, mode=0o700, exist_ok=True)

def ensure_log_file():
    """Ensure the log directory and log file exist with appropriate permissions."""
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, mode=0o700, exist_ok=True)  # Ensure directory exists
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    os.chmod(LOG_FILE, 0o600)

def load_process_hashes():
    """Load stored process hashes from process_hashes.txt."""
    if os.path.exists(PROCESS_HASHES_FILE):
        with open(PROCESS_HASHES_FILE, "r") as f:
            return dict(line.strip().split(":") for line in f if ":" in line)
    return {}

def save_process_hashes(process_hashes):
    """Save updated process hashes."""
    with open(PROCESS_HASHES_FILE, "w") as f:
        for exe_path, hash_value in process_hashes.items():
            f.write(f"{exe_path}:{hash_value}\n")

def load_process_metadata():
    """Load stored process metadata from integrity_processes.json."""
    if os.path.exists(INTEGRITY_PROCESS_FILE):
        with open(INTEGRITY_PROCESS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_process_metadata(integrity_state):
    """Save updated process metadata."""
    with open(INTEGRITY_PROCESS_FILE, "w") as f:
        json.dump(integrity_state, f, indent=4)

def get_process_hash(exe_path):
    """Generate SHA-256 hash of the process executable."""
    try:
        with open(exe_path, "rb") as f:
            hash_value = hashlib.sha256(f.read()).hexdigest()
            return hash_value
    except Exception as e:
        print(f"[ERROR] Could not generate hash for {exe_path}: {e}")
        return "ERROR_HASHING"

def log_new_process(event_type, file_path, metadata):
    """Logs new listening process without causing circular import."""
    from fim_client import log_event  # Import inside function to avoid circular import

    log_event(
        event_type=event_type,
        file_path=file_path,
        previous_metadata=None,
        new_metadata=metadata,
        previous_hash=None,
        new_hash=metadata.get("hash", "UNKNOWN")
    )

def get_listening_processes():
    """Retrieve all listening processes and their metadata."""
    listening_processes = {}

    try:
        lsof_command = "sudo lsof -i -P -n | grep LISTEN"
        output = subprocess.check_output(lsof_command, shell=True, text=True)

        for line in output.splitlines():
            parts = line.split()
            pid = parts[1]  # Second column is PID
            exe_path = f"/proc/{pid}/exe"

            try:
                # Use sudo to resolve permission issues
                exe_real_path = subprocess.check_output(f"sudo readlink -f {exe_path}", shell=True, text=True).strip()
                process_hash = get_process_hash(exe_real_path) if exe_real_path != "PERMISSION_DENIED" else "UNKNOWN"

            except (PermissionError, FileNotFoundError, subprocess.CalledProcessError):
                exe_real_path = "PERMISSION_DENIED"
                process_hash = "UNKNOWN"

            port = parts[-2].split(':')[-1]  # Extract port number
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

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to retrieve listening processes: {e}")

    return listening_processes

def monitor_listening_processes(interval=2):
    """Continuously monitors for new and terminated listening processes."""
    known_processes = get_listening_processes()  # Get initial known processes
    terminated_processes = set()  # Track terminated processes to avoid repeat logging

    while True:
        current_processes = get_listening_processes()

        new_processes = {
            pid: info for pid, info in current_processes.items()
            if pid not in known_processes
        }

        terminated_pids = {
            pid: info for pid, info in known_processes.items()
            if pid not in current_processes
        }

        from fim_client import log_event  # Import inside function to avoid circular import

        # 🔹 Logging new processes
        for pid, info in new_processes.items():
            print(f"[ALERT] New listening process detected! PID: {pid}, Executable: {info['exe_path']}, Port: {info['port']}")

            log_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "NEW_LISTENING_PROCESS",
                "pid": pid,
                "exe_path": info["exe_path"],
                "port": info["port"],
                "hash": info.get("hash", "UNKNOWN")
            }

            # Log locally
            with open(LOG_FILE, "a") as log:
                log.write(json.dumps(log_data) + "\n")

            # Log event to FIM system
            log_event(
                event_type="NEW_LISTENING_PROCESS",
                file_path=info["exe_path"],
                previous_metadata=None,
                new_metadata=log_data,
                previous_hash=None,
                new_hash=info.get("hash", "UNKNOWN")
            )

            # Update process hash and metadata tracking
            update_process_tracking(info["exe_path"], info["hash"], info)

        # 🔹 Logging terminated processes (ONLY ONCE)
        for pid, info in terminated_pids.items():
            if pid in terminated_processes:
                continue  # Skip already logged terminations

            print(f"[INFO] Process terminated: PID: {pid}, Executable: {info['exe_path']}, Port: {info['port']}")

            log_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": "PROCESS_TERMINATED",
                "pid": pid,
                "exe_path": info["exe_path"],
                "port": info["port"],
                "hash": info.get("hash", "UNKNOWN")
            }

            # Log locally
            with open(LOG_FILE, "a") as log:
                log.write(json.dumps(log_data) + "\n")

            # Log event to FIM system
            log_event(
                event_type="PROCESS_TERMINATED",
                file_path=info["exe_path"],
                previous_metadata=None,
                new_metadata=None,
                previous_hash=info.get("hash", "UNKNOWN"),
                new_hash=None
            )

            # Remove process from tracking files
            remove_process_tracking(info["exe_path"])

            # Mark process as terminated to prevent duplicate logging
            terminated_processes.add(pid)

        known_processes = current_processes  # Update process tracking
        time.sleep(interval)

def remove_process_tracking(exe_path):
    """Remove process hash and metadata when a process terminates."""
    process_hashes = load_process_hashes()
    integrity_state = load_process_metadata()

    # Remove process from process_hashes.txt
    if exe_path in process_hashes:
        del process_hashes[exe_path]

    # Remove process from integrity_processes.json
    if exe_path in integrity_state:
        del integrity_state[exe_path]

    # Save updated files
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
    with open(PROCESS_HASHES_FILE, "w") as f:
        for exe_path, hash_value in process_hashes.items():  # Fix: Correct iteration
            f.write(f"{exe_path}:{hash_value}\n")  # Fix: Using correct dictionary structure
    os.chmod(PROCESS_HASHES_FILE, 0o600)

def save_integrity_processes(processes):
    """Save full process metadata to integrity_processes.json."""
    with open(INTEGRITY_PROCESS_FILE, "w") as f:
        json.dump(processes, f, indent=4)
    os.chmod(INTEGRITY_PROCESS_FILE, 0o600)

if __name__ == "__main__":
    ensure_log_file()

    print("[INFO] Listening process monitoring started...")

    # Run the listener detection
    monitor_listening_processes()
