import json
import os
import time
import socket

APP_CONFIG_FILE = os.path.abspath("app.config")
LOG_DIR = os.path.abspath("./logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

def ensure_log_directory():
    """Ensure the logs directory exists."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

def configure_siem():
    """Prompt user for SIEM server configuration and save it to app.config."""
    siem_ip = input("Enter SIEM server IP address: ").strip()
    siem_port = input("Enter TCP port for log transmission: ").strip()

    try:
        siem_port = int(siem_port)
    except ValueError:
        print("[ERROR] Invalid port number. Please enter a numeric value.")
        return

    config_data = {
        "siem_server": siem_ip,
        "siem_port": siem_port
    }

    with open(APP_CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

    print(f"[INFO] SIEM server configuration saved to {APP_CONFIG_FILE}.")

def load_siem_config():
    """Load SIEM server configuration from app.config."""
    if not os.path.exists(APP_CONFIG_FILE):
        print("[ERROR] SIEM server configuration not found. Run with -l to configure.")
        return None

    with open(APP_CONFIG_FILE, "r") as f:
        return json.load(f)

def send_to_splunk(log_entry):
    """Send logs to Splunk over a basic TCP connection."""
    config = load_siem_config()
    if not config:
        return

    siem_ip = config.get("siem_server")
    siem_port = config.get("siem_port")

    if not siem_ip or not siem_port:
        print("[ERROR] SIEM server configuration is incomplete.")
        return

    try:
        with socket.create_connection((siem_ip, siem_port), timeout=5) as sock:
            sock.sendall(json.dumps(log_entry).encode() + b"\n")
    except Exception as e:
        print(f"[ERROR] Failed to send log to Splunk: {e}")

def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None):
    """Log file change events in JSON format with detailed metadata."""
    ensure_log_directory()  # Ensure logs directory exists

    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": previous_metadata,
        "new_metadata": new_metadata,
        "previous_hash": previous_hash,
        "new_hash": new_hash
    }

    # Write to audit.log in logs directory
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

    # Send log to Splunk if configured
    send_to_splunk(log_entry)
