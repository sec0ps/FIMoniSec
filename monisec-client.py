import os
import time
import psutil
import subprocess
import logging
import sys
import signal
import remote
import threading
import json
import socket
import hmac
import hashlib

# Ensure logs directory exists
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "monisec-endpoint.log")

# Set log file permissions to 600 (read/write for user only)
try:
    with open(LOG_FILE, 'a') as f:
        pass
    os.chmod(LOG_FILE, 0o600)
except Exception as e:
    print(f"Failed to set log file permissions: {e}")

# Configure logging to write to file and optionally to console
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
log_handler = logging.FileHandler(LOG_FILE)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.DEBUG)
logging_handlers = [log_handler]

# Only add console output if not running in daemon mode
if not (len(sys.argv) > 1 and sys.argv[1] == "-d"):
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.DEBUG)
    logging_handlers.append(console_handler)

logging.basicConfig(level=logging.DEBUG, handlers=logging_handlers)

# List of monitored processes
PROCESSES = {
    "fim_client": "python3 fim_client.py -d",
    "pim": "python3 pim.py -d",
}

def start_process(name):
    if name in PROCESSES:
        if is_process_running(PROCESSES[name]):
            logging.info(f"{name} is already running.")
        else:
            logging.info(f"Starting {name}...")
            process = psutil.Popen(PROCESSES[name].split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            time.sleep(2)  # Wait for process to start
            if is_process_running(PROCESSES[name]):
                logging.info(f"{name} started successfully with PID {process.pid}.")
            else:
                logging.error(f"Failed to start {name}.")

def stop_process(name):
    if name == "monisec_client":
        logging.info("Stopping monisec_client and all related processes...")
        stop_process("fim_client")
        stop_process("pim")
        sys.exit(0)  # Exit the script after stopping related processes
    elif name in PROCESSES:
        pid = is_process_running(PROCESSES[name])
        if pid:
            logging.info(f"Stopping {name} with PID {pid}...")
            os.kill(pid, signal.SIGTERM)
        else:
            logging.info(f"{name} is not running.")
    else:
        logging.warning(f"Attempted to stop unknown process: {name}")

# Function to restart a process
def restart_process(name):
    stop_process(name)
    time.sleep(2)
    start_process(name)

def is_process_running(full_command):
    """Check if a process is running by matching the full command line."""
    for proc in psutil.process_iter(attrs=['pid', 'cmdline']):
        try:
            if proc.info['cmdline'] and " ".join(proc.info['cmdline']) == full_command:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None

# Handle graceful shutdown on keyboard interrupt
def handle_exit(signum, frame):
    logging.info("Keyboard interrupt received. Stopping MoniSec client and all related processes...")
    stop_process("fim_client")
    stop_process("pim")

    # Ensure processes are fully stopped before exiting
    time.sleep(2)
    logging.info("MoniSec client shutdown complete.")
    sys.exit(0)

# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

def monitor_processes():
    while True:
        all_running = True
        for name, command in PROCESSES.items():
            if not is_process_running(command):
                logging.warning(f"{name} is not running. Restarting...")
                start_process(name)
                all_running = False

        if all_running:
            time.sleep(60)  # Increase sleep time if no issues detected
        else:
            time.sleep(10)  # Check more frequently if issues occur

def import_psk(psk_value):
    """Imports a PSK and stores it locally."""
    token_data = {"psk": psk_value}
    with open("auth_token.json", "w") as f:
        json.dump(token_data, f)
    os.chmod("auth_token.json", 0o600)
    print("[INFO] PSK imported and stored securely.")
def authenticate_with_server(server_ip, client_name):
    """Authenticates with the MoniSec server using a stored PSK."""
    token_file = "auth_token.json"

    # Load stored PSK
    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
            psk = token_data.get("psk", None)
            if not psk:
                raise ValueError("No PSK found.")
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        print("[ERROR] No valid PSK found. Import the PSK before connecting.")
        return False

    nonce = os.urandom(16).hex()
    client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, 5555))

        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))
        response = sock.recv(1024).decode("utf-8")

        if response == "AUTH_SUCCESS":
            print("[SUCCESS] Authentication successful.")
            return True
        else:
            print("[ERROR] Authentication failed.")
            return False
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        action = sys.argv[1]
        if action in ["start", "stop", "restart"] and len(sys.argv) > 2:
            target_process = sys.argv[2]
            if action == "start":
                start_process(target_process)
            elif action == "stop":
                stop_process(target_process)
            elif action == "restart":
                restart_process(target_process)
        elif action == "-d":
            pid = os.fork()
            if pid > 0:
                sys.exit(0)  # Exit parent process
            os.setsid()
            os.umask(0)
            sys.stdin = open(os.devnull, 'r')
            logging.info("MoniSec Endpoint Monitor started in daemon mode.")

            # Start remote command listener in a separate thread
            listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
            listener_thread.start()

            monitor_processes()
        else:
            print("Usage: python3 monisec-endpoint.py [start|stop|restart] [fim_client|pim|monisec_client] or -d to run in daemon mode.")
    else:
        logging.info("MoniSec Endpoint Monitor started in foreground.")

        # Start remote command listener in a separate thread
        listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
        listener_thread.start()

        monitor_processes()
