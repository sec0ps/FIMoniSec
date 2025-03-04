import os
import time
import json
import subprocess
#from fim_client import log_event  # Import logging function

LOG_FILE = os.path.abspath("./logs/process_monitor.log")

def ensure_log_file():
    """Ensure the log directory and log file exist with appropriate permissions."""
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, mode=0o700, exist_ok=True)  # Ensure directory exists
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    os.chmod(LOG_FILE, 0o600)

def log_new_process(event_type, file_path, metadata):
    """Logs new listening process without circular import."""
    from fim_client import log_event  # Import only when function runs
    log_event(event_type, file_path, previous_metadata=None, new_metadata=metadata)

def get_listening_processes():
    """Get all processes currently listening on a port using `lsof`."""
    listening_processes = {}

    try:
        # Ensure 'sudo' is used with lsof and preserve environment
        lsof_command = "sudo -E lsof -i -P -n | grep LISTEN"
        output = subprocess.check_output(lsof_command, shell=True, text=True)

        for line in output.splitlines():
            parts = line.split()
            pid = parts[1]  # Second column is PID
            exe_path = f"/proc/{pid}/exe"

            try:
                # Get actual executable path from /proc
                if os.path.exists(exe_path):
                    exe_real_path = os.readlink(exe_path)
                else:
                    exe_real_path = "PERMISSION_DENIED"

                port = parts[-2].split(':')[-1]  # Extract port number
                if port.isdigit():
                    port = int(port)

                listening_processes[int(pid)] = {
                    "exe_path": exe_real_path,
                    "port": port,
                }
            except (PermissionError, FileNotFoundError):
                listening_processes[int(pid)] = {
                    "exe_path": "PERMISSION_DENIED",
                    "port": port,
                }

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to retrieve listening processes: {e}")

    return listening_processes

def monitor_listening_processes(interval=2):
    """Continuously monitors for new listening processes."""
    known_processes = get_listening_processes()  # Get initial known processes

    while True:
        current_processes = get_listening_processes()

        new_processes = {
            pid: info for pid, info in current_processes.items()
            if pid not in known_processes
        }

        if new_processes:
            for pid, info in new_processes.items():
                print(f"[ALERT] New listening process detected! PID: {pid}, Executable: {info['exe_path']}, Port: {info['port']}")

                log_data = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type": "NEW_LISTENING_PROCESS",
                    "pid": pid,
                    "exe_path": info["exe_path"],
                    "port": info["port"]
                }

                # Log locally
                with open(LOG_FILE, "a") as log:
                    log.write(json.dumps(log_data) + "\n")

                # Import log_event only when it's needed to avoid circular import
                from fim_client import log_event  # Import only when needed
                log_event(
                    event_type="NEW_LISTENING_PROCESS",
                    file_path=info["exe_path"],
                    previous_metadata=None,
                    new_metadata=log_data
                )

            # Update known processes
            known_processes.update(new_processes)

        time.sleep(interval)

if __name__ == "__main__":
    ensure_log_file()

    print("[INFO] Listening process monitoring started...")

    # Run the listener detection
    monitor_listening_processes()
