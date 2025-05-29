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
# Purpose: This script is part of the DumpSec-Py tool, which is designed to
#          perform detailed security audits on Windows systems. It covers
#          user rights, services, registry permissions, file/share permissions,
#          group policy enumeration, risk assessments, and more.
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
import json
import socket
import time
import logging

base_dir = "/opt/FIMoniSec/Monisec-Server"
logs_dir = os.path.join(base_dir, "logs")
CONFIG_FILE = os.path.join(base_dir, "monisec-server.config")
SIEM_LOG_FILE = os.path.join(logs_dir, "siem-forwarding.log")

def ensure_siem_log():
    """Ensure the SIEM log directory and log file exist with correct permissions."""
    # Create logs directory if it doesn't exist
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir, mode=0o700, exist_ok=True)

    # Create log file if it doesn't exist
    if not os.path.exists(SIEM_LOG_FILE):
        open(SIEM_LOG_FILE, "w").close()  # Create empty file

# ✅ Ensure SIEM log file exists before setting up logging
ensure_siem_log()

# ✅ Setup separate logging for SIEM logs
siem_log_handler = logging.FileHandler(SIEM_LOG_FILE)
siem_log_handler.setLevel(logging.INFO)
siem_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# ✅ Get the SIEM logger and add the handler
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

    if not siem_config.get("enabled"):
        return  # ✅ Do nothing if SIEM is disabled

    siem_host = siem_config.get("siem_server")
    siem_port = siem_config.get("siem_port")

    if not siem_host or not siem_port:
        siem_logger.error("[ERROR] SIEM not properly configured. Skipping.")
        return

    log_data = json.dumps(log_entry) + "\n"

    try:
        with socket.create_connection((siem_host, siem_port), timeout=5) as sock:
            sock.sendall(log_data.encode("utf-8"))
        siem_logger.info(f"[INFO] Log sent to SIEM: {siem_host}:{siem_port}")
    except Exception as e:
        siem_logger.error(f"[ERROR] Failed to send log to SIEM: {e}")

def forward_log_to_siem(log_entry, client_name):
    """Processes logs received from clients and forwards them to the SIEM with enhanced error handling."""
    try:
        if not isinstance(log_entry, dict):
            siem_logger.error(f"[ERROR] Received malformed log entry from {client_name}; expected dictionary, got {type(log_entry)}")
            return

        # Use explicit log_type field - much more reliable than auto-detection
        log_type = log_entry.get("log_type", "UNKNOWN")
        
        if log_type == "UNKNOWN":
            siem_logger.warning(f"[WARNING] Log entry missing log_type field from {client_name}")
            # Fallback to basic detection for backward compatibility
            if "process_hash" in log_entry:
                log_type = "PIM"
            elif any(field in log_entry for field in ["attack_name", "mitre_id", "log_category"]):
                log_type = "LIM"
            elif any(field in log_entry for field in ["file_path", "event_type"]):
                log_type = "FIM"
            else:
                log_type = "GENERIC"

        # Format based on explicit log type
        try:
            if log_type == "PIM":
                # PIM log format - extract data from nested metadata with None safety
                current_data = log_entry.get("new_metadata")
                previous_data = log_entry.get("previous_metadata")
                
                # Ensure we have dictionaries, not None values
                if current_data is None or not isinstance(current_data, dict):
                    current_data = {}
                if previous_data is None or not isinstance(previous_data, dict):
                    previous_data = {}
                
                formatted_log = {
                    "timestamp": log_entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "log_source": "PIM",
                    "client_name": client_name,
                    "event_type": log_entry.get("event_type", "UNKNOWN"),
                    "process_hash": log_entry.get("process_hash", "N/A"),
                    "process_name": current_data.get("process_name", "N/A"),
                    "pid": current_data.get("pid", "N/A"),
                    "exe_path": current_data.get("exe_path", "N/A"),
                    "user": current_data.get("user", "N/A"),
                    "cmdline": current_data.get("cmdline", "N/A"),
                    "port": current_data.get("port", "N/A"),
                    "is_listening": current_data.get("is_listening", False),
                    "lineage": current_data.get("lineage", []),
                    "changes_description": log_entry.get("changes_description", "N/A"),
                    "mitre_mapping": log_entry.get("mitre_mapping", {}),
                    "previous_metadata": previous_data,
                    "new_metadata": current_data,
                    "runtime_seconds": current_data.get("runtime_seconds", "N/A"),
                    "ppid": current_data.get("ppid", "N/A"),
                    "state": current_data.get("state", "N/A")
                }
                
            elif log_type == "LIM":
                # LIM log format
                formatted_log = {
                    "timestamp": log_entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "log_source": "LIM", 
                    "client_name": client_name,
                    "attack_name": log_entry.get("attack_name", "UNKNOWN"),
                    "mitre_id": log_entry.get("mitre_id", "N/A"),
                    "severity": log_entry.get("severity", "low"),
                    "detection_type": log_entry.get("detection_type", "signature"),
                    "log_file": log_entry.get("log_file", "N/A"),
                    "log_category": log_entry.get("log_category", "other"),
                    "entry": log_entry.get("entry", "N/A"),
                    "parsed": log_entry.get("parsed", {}),
                    "anomaly_score": log_entry.get("anomaly_score", "N/A")
                }
                
            elif log_type == "FIM":
                # FIM log format with None safety
                prev_metadata = log_entry.get("previous_metadata")
                new_metadata = log_entry.get("new_metadata")
                
                # Ensure we have dictionaries, not None values
                if prev_metadata is None or not isinstance(prev_metadata, dict):
                    prev_metadata = {}
                if new_metadata is None or not isinstance(new_metadata, dict):
                    new_metadata = {}
                
                formatted_log = {
                    "timestamp": log_entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "log_source": "FIM",
                    "client_name": client_name,
                    "event_type": log_entry.get("event_type", "UNKNOWN"),
                    "file_path": log_entry.get("file_path", "N/A"),
                    "previous_hash": log_entry.get("previous_hash", "N/A"),
                    "new_hash": log_entry.get("new_hash", "N/A"),
                    "changes": log_entry.get("changes", "N/A"),
                    "old_path": log_entry.get("old_path", "N/A"),
                    "mitre_mapping": log_entry.get("mitre_mapping", {}),
                    "config_changes": log_entry.get("config_changes", {}),
                    "metadata": {
                        "previous": prev_metadata,
                        "new": new_metadata,
                    }
                }
                
            else:
                # Unknown log type - use generic format
                formatted_log = {
                    "timestamp": log_entry.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
                    "log_source": log_type,
                    "client_name": client_name,
                    "raw_log_entry": log_entry
                }
                siem_logger.warning(f"[WARNING] Unknown log_type '{log_type}' from {client_name}, using generic format")

            send_to_siem(formatted_log)
            
        except Exception as format_error:
            siem_logger.error(f"[ERROR] Failed to format {log_type} log from {client_name}: {format_error}")
            siem_logger.error(f"[ERROR] Format error traceback: {traceback.format_exc()}")
            # Try to send raw log as fallback
            fallback_log = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "log_source": "FALLBACK",
                "client_name": client_name,
                "error": f"Format error: {str(format_error)}",
                "original_log_type": log_type,
                "raw_log_entry": str(log_entry)  # Convert to string to avoid further issues
            }
            send_to_siem(fallback_log)
            
    except Exception as e:
        siem_logger.error(f"[ERROR] Critical error in forward_log_to_siem for {client_name}: {e}")
        siem_logger.error(f"[ERROR] Critical error traceback: {traceback.format_exc()}")
