import os
import json
import socket
import time
import logging

CONFIG_FILE = "monisec-server.config"
SIEM_LOG_FILE = "./logs/siem-forwarding.log"


def ensure_siem_log():
    """Ensure the SIEM log directory and log file exist with correct permissions."""
    log_dir = os.path.dirname(SIEM_LOG_FILE)

    # Create logs directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o700)  # ✅ Set directory permissions to 700

    # Create log file if it doesn't exist
    if not os.path.exists(SIEM_LOG_FILE):
        with open(SIEM_LOG_FILE, "w") as f:
            f.write("")  # ✅ Create empty log file
        os.chmod(SIEM_LOG_FILE, 0o600)  # ✅ Set file permissions to 600

# Ensure SIEM log file exists before setting up logging
ensure_siem_log()

# Ensure separate logging for SIEM logs
siem_log_handler = logging.FileHandler(SIEM_LOG_FILE)
siem_log_handler.setLevel(logging.INFO)
siem_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Get the SIEM logger and add the handler
siem_logger = logging.getLogger("SIEM")
siem_logger.setLevel(logging.INFO)
siem_logger.addHandler(siem_log_handler)

def configure_siem():
    """Prompt user for SIEM server configuration and update monisec-server.config without overwriting other settings."""
    siem_ip = input("Enter SIEM server IP address: ").strip()
    siem_port = input("Enter TCP port for log transmission: ").strip()

    try:
        siem_port = int(siem_port)
    except ValueError:
        print("[ERROR] Invalid port number. Please enter a numeric value.")
        return

    # Load existing config if available
    config = {}

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
        except json.JSONDecodeError:
            print("[ERROR] Invalid JSON format in config file. Resetting to default.")
            config = {}

    # Update config with SIEM settings (preserve other configurations)
    config["siem_settings"] = {
        "enabled": True,
        "siem_server": siem_ip,
        "siem_port": siem_port
    }

    # Save updated config
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

    print(f"[INFO] SIEM configuration updated and saved: {CONFIG_FILE}")

def load_siem_config():
    """Load SIEM server configuration from monisec-server.config."""
    if not os.path.exists(CONFIG_FILE):
        return None  # No config file found

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            return config.get("siem_settings", None)
    except json.JSONDecodeError:
        return None  # Invalid JSON format

def send_to_siem(log_entry):
    """Send log entry to SIEM only if it is configured and enabled."""
    siem_config = load_siem_config()

    if not siem_config or not siem_config.get("enabled", False):
        return  # Do nothing if SIEM is disabled

    siem_host = siem_config.get("siem_server")
    siem_port = siem_config.get("siem_port")

    if not siem_host or not siem_port:
        logging.error("[ERROR] SIEM not properly configured. Skipping.")
        return

    log_data = json.dumps(log_entry) + "\n"

    try:
        with socket.create_connection((siem_host, siem_port), timeout=5) as sock:
            sock.sendall(log_data.encode("utf-8"))
        logging.info(f"[INFO] Log sent to SIEM: {siem_host}:{siem_port}")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send log to SIEM: {e}")

def forward_log_to_siem(log_entry, client_name):
    """Processes logs received from clients and forwards them to the SIEM."""
    if not isinstance(log_entry, dict):
        logging.error("[ERROR] Received malformed log entry; expected dictionary.")
        return

    formatted_log = {
        "timestamp": log_entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
        "event_type": log_entry.get("event_type", "UNKNOWN"),
        "client_name": client_name,  # ✅ Ensure correct client_name is forwarded
        "file_path": log_entry.get("file_path", "N/A"),
        "metadata": {
            "previous": log_entry.get("previous_metadata", {}) if isinstance(log_entry.get("previous_metadata", {}), dict) else {},
            "new": log_entry.get("new_metadata", {}) if isinstance(log_entry.get("new_metadata", {}), dict) else {},
        },
        "hashes": {
            "previous": log_entry.get("previous_hash", "N/A"),
            "new": log_entry.get("new_hash", "N/A"),
        },
        "changes": log_entry.get("changes", "N/A"),
    }

    send_to_siem(formatted_log)
