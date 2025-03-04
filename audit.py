import json
import os
import time
import socket
from fim_client import load_config  # Import load_config from fim-client.py

LOG_DIR = os.path.abspath("./logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")
CONFIG_FILE = os.path.abspath("fim.config")

def ensure_log_directory():
    """Ensure the logs directory exists."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

def configure_siem():
    """Prompt user for SIEM server configuration and save it in fim.config."""
    config = load_config()  # Load existing configuration
    siem_ip = input("Enter SIEM server IP address: ").strip()
    siem_port = input("Enter TCP port for log transmission: ").strip()

    try:
        siem_port = int(siem_port)
    except ValueError:
        print("[ERROR] Invalid port number. Please enter a numeric value.")
        return

    # Update configuration with SIEM settings
    config["siem"] = {
        "server": siem_ip,
        "port": siem_port
    }

    # Save the updated configuration
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

    print(f"[INFO] SIEM server configuration saved in {CONFIG_FILE}.")

def load_siem_config():
    """Load SIEM server configuration from fim.config."""
    if not os.path.exists(CONFIG_FILE):
        print("[ERROR] Configuration file not found.")
        return None

    with open(CONFIG_FILE, "r") as f:
        try:
            config = json.load(f)
            siem_config = config.get("siem")  # Ensure "siem" key is used
            if not siem_config:
                print("[ERROR] 'siem' key missing in fim.config.")
                return None
            return siem_config
        except json.JSONDecodeError:
            print("[ERROR] Invalid JSON format in fim.config.")
            return None

def send_to_siem(log_entry):
    """Send log entry to the configured SIEM server via TCP if enabled."""
    siem_config = load_siem_config()
    if not siem_config:
        print("[ERROR] SIEM configuration is missing or invalid.")
        return

    siem_host = siem_config.get("server")
    siem_port = siem_config.get("port")

    if not siem_host or not siem_port:
        print("[ERROR] SIEM server or port not configured, skipping log transmission.")
        return

    log_data = json.dumps(log_entry) + "\n"
#    print(f"[DEBUG] Sending log data to SIEM: {log_data}")  # Debugging step

    try:
        with socket.create_connection((siem_host, siem_port), timeout=5) as sock:
            sock.sendall(log_data.encode("utf-8"))
#            print(f"[INFO] Log successfully sent to SIEM: {siem_host}:{siem_port}")
    except socket.timeout:
        print(f"[ERROR] Connection to SIEM timed out: {siem_host}:{siem_port}")
    except ConnectionRefusedError:
        print(f"[ERROR] Connection refused by SIEM: {siem_host}:{siem_port}")
    except Exception as e:
        print(f"[ERROR] Failed to send log to SIEM: {e}")

def log_event(event_type, file_path, previous_metadata=None, new_metadata=None, previous_hash=None, new_hash=None):
    """Log file change events in JSON format and send to SIEM."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "file_path": file_path,
        "previous_metadata": previous_metadata,
        "new_metadata": new_metadata,
        "previous_hash": previous_hash,
        "new_hash": new_hash
    }

    # Write log to local file
    with open(LOG_FILE, "a") as log:
        log.write(json.dumps(log_entry) + "\n")

    # Send log to SIEM
    send_to_splunk(log_entry)
