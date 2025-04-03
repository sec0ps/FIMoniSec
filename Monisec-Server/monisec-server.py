# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
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
import sys
import socket
import threading
import logging
import os
import hmac
import hashlib
import json
import daemon
import daemon.pidfile
import clients
import signal
import server_siem
import updater

CONFIG_FILE = "monisec-server.config"
server_socket = None  # Global reference to the server socket
shutdown_event = threading.Event()  # Event to signal shutdown

DEFAULT_CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": 5555,
    "LOG_DIR": "./logs",
    "LOG_FILE": "monisec-server.log",
    "PSK_STORE_FILE": "psk_store.json",
    "MAX_CLIENTS": 10,
    "siem_settings": {  # ✅ Ensure SIEM settings are initialized
        "enabled": False,
        "siem_server": "",
        "siem_port": 0
    }
}

# List of valid modules for the restart command
VALID_MODULES = ["monisec_client", "fim_client", "pim", "lim"]

# Function to create default config file if missing
def create_default_config():
    """Creates a valid JSON configuration file if missing."""
    default_config = {
        "HOST": "0.0.0.0",
        "PORT": 5555,
        "LOG_DIR": "./logs",
        "LOG_FILE": "monisec-server.log",
        "PSK_STORE_FILE": "psk_store.json",
        "MAX_CLIENTS": 10,
        "siem_settings": {
            "enabled": False,
            "siem_server": "",
            "siem_port": 0
        }
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)  # ✅ Store in proper JSON format

def load_config():
    """Loads the configuration from monisec-server.config, ensuring it remains valid JSON."""
    if not os.path.exists(CONFIG_FILE):
        print(f"{CONFIG_FILE} not found. Creating default configuration.")
        create_default_config()

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)  # ✅ Read JSON properly
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON format in config file. Resetting to default.")
        create_default_config()
        return load_config()  # ✅ Reload the default config

config = load_config()  # ✅ Load config first

# ✅ Use values from the config file dynamically
HOST = config["HOST"]
PORT = config["PORT"]
LOG_DIR = config["LOG_DIR"]
LOG_FILE = os.path.join(LOG_DIR, config["LOG_FILE"])
PSK_STORE_FILE = config["PSK_STORE_FILE"]
MAX_CLIENTS = config["MAX_CLIENTS"]
SIEM_CONFIG = config.get("siem_settings", {})
PID_FILE = os.path.join(LOG_DIR, "monisec-server.pid")

def handle_shutdown(signum, frame):
    logging.info("[INFO] Shutting down MoniSec Server...")
    shutdown_event.set()

    if server_socket:
        server_socket.close()

    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            logging.info(f"[INFO] Removed PID file: {PID_FILE}")
    except Exception as e:
        logging.warning(f"[WARNING] Failed to remove PID file: {e}")

    logging.info("[INFO] MoniSec Server stopped.")
    sys.exit(0)

# Register SIGINT (CTRL+C) and SIGTERM (kill command) for graceful shutdown
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

def run_server():
    siem_config = server_siem.load_siem_config()
    if siem_config:
        logging.info("[INFO] SIEM integration is enabled.")

    initialize_log_storage()

    # ✅ Setup logging here AFTER daemon starts
    server_log_handler = logging.FileHandler(LOG_FILE)
    server_log_handler.setLevel(logging.DEBUG)
    server_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.handlers = []  # Clear existing
    logger.addHandler(server_log_handler)

    # Verify PID file was created properly
    verify_pid_file()
    
    logging.info("Starting MoniSec Server...")
    logging.info(f"Server PID: {os.getpid()}")
    start_server()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(10)
    logging.info("[INFO] MoniSec Server listening on 0.0.0.0:5555")

    try:
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(target=clients.handle_client, args=(client_socket, client_address))
            client_thread.start()
    except Exception as e:
        logging.error(f"[ERROR] Server encountered an error: {e}")
    finally:
        logging.info("[INFO] Cleaning up server resources...")
        server.close()

def initialize_log_storage():
    """Ensures necessary log directories and files exist with proper permissions."""
    try:
        # Ensure logs directory exists
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

        # Ensure main MoniSec Server log file exists
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("")  # Create an empty file
            os.chmod(LOG_FILE, 0o600)  # Secure permissions

        # Ensure SIEM log file exists
        SIEM_LOG_FILE = os.path.join(LOG_DIR, "siem-forwarding.log")
        if not os.path.exists(SIEM_LOG_FILE):
            with open(SIEM_LOG_FILE, "w") as f:
                f.write("")  # Create empty file
            os.chmod(SIEM_LOG_FILE, 0o600)  # Secure permissions

        logging.info(f"Log storage initialized. Logs directory: {LOG_DIR}")

    except Exception as e:
        logging.error(f"Failed to initialize log storage: {e}")

def ensure_directories():
    """Ensures necessary directories exist with proper permissions."""
    try:
        # Ensure logs directory exists
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        logging.info(f"Ensured logs directory exists: {LOG_DIR}")
    except Exception as e:
        print(f"[ERROR] Failed to create directories: {e}")
        sys.exit(1)

# Add this new function to your code
def verify_pid_file():
    """Verifies that PID file exists and contains the current process ID."""
    if not os.path.exists(PID_FILE):
        logging.error(f"[ERROR] PID file {PID_FILE} was not created properly")
        # Try to create it manually as a fallback
        try:
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
            logging.info(f"[INFO] Created PID file manually: {PID_FILE}")
            os.chmod(PID_FILE, 0o644)  # Make sure it's readable
            return True
        except Exception as e:
            logging.error(f"[ERROR] Failed to create PID file manually: {e}")
            return False
    return True
    
def print_help():
    """Prints the available command-line options for monisec-server.py"""
    print("""
Usage: python monisec-server.py [command] [options]

Management Commands:
  add-agent <agent_name>         Add a new client and generate a unique PSK.
  remove-agent <agent_name>      Remove an existing client.
  list-agents                    List all registered clients.
  configure-siem                 Configure SIEM settings for log forwarding.

Remote Commands:
  <module> [client_name]         Directly restart a module on all clients or a specific client.
                                 Example: python monisec-server.py fim_client server1
  restart <module> [client_name] Alternative syntax for restarting modules.
                                 Example: python monisec-server.py restart fim_client server1
  
  Valid modules: monisec_client, fim_client, pim, lim
  
  yara-scan <client> <path>      Run a YARA scan on a client.
  ir-shell <client>              Spawn an incident response shell on a client.
  update <client>                Trigger a client update.

Server Control:
  -d                             Launch the MoniSec Server as a daemon.
  stop                           Stop the running MoniSec Server daemon.
  -h, --help                     Show this help message.

If no command is provided, the server will start normally.
""")

def restart_service(module, client_name=None):
    """Restart a service module on a client or all clients."""
    if module not in VALID_MODULES:
        print(f"[ERROR] Invalid module: {module}")
        print(f"Valid modules: {', '.join(VALID_MODULES)}")
        return False
    
    if client_name:
        # Restart module on a specific client
        print(f"[INFO] Sending restart command for {module} to client: {client_name}")
        result = clients.restart_client_service(client_name, module)
        
        if result.get("status") == "success":
            print(f"[SUCCESS] {module} restarted on {client_name}")
            return True
        else:
            print(f"[ERROR] Failed to restart {module} on {client_name}: {result.get('message')}")
            return False
    else:
        # Restart module on all clients
        print(f"[INFO] Sending restart command for {module} to all clients...")
        all_clients = clients.get_all_clients()
        success_count = 0
        
        for client in all_clients:
            print(f"[INFO] Restarting {module} on {client}...")
            result = clients.restart_client_service(client, module)
            
            if result.get("status") == "success":
                print(f"[SUCCESS] {module} restarted on {client}")
                success_count += 1
            else:
                print(f"[ERROR] Failed to restart {module} on {client}: {result.get('message')}")
        
        print(f"[INFO] Restart complete. Successful on {success_count}/{len(all_clients)} clients.")
        return success_count > 0

if __name__ == "__main__":
    should_run_updater = (len(sys.argv) == 1) or (len(sys.argv) > 1 and sys.argv[1] == "-d")

    if should_run_updater:
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")

    if len(sys.argv) > 1:
        action = sys.argv[1]

        # Check if the first argument is a valid module name
        if action in VALID_MODULES:
            # Handle direct module command: python monisec-server.py module_name [client_name]
            module = action
            client_name = sys.argv[2] if len(sys.argv) > 2 else None
            
            print(f"[INFO] Running restart command for module: {module}")
            if restart_service(module, client_name):
                sys.exit(0)
            else:
                sys.exit(1)
                
        elif action in ["-h", "--help", "help"]:
            print_help()
            sys.exit(0)

        elif action == "list-agents":
            clients.list_clients()
            sys.exit(0)

        elif action == "add-agent":
            clients.add_client()
            sys.exit(0)

        elif action == "remove-agent":
            if len(sys.argv) < 3:
                print("[ERROR] Please specify an agent name to remove.")
                sys.exit(1)
            agent_name = sys.argv[2]
            clients.remove_client(agent_name)
            sys.exit(0)

        elif action == "configure-siem":
            server_siem.configure_siem()
            sys.exit(0)
            
        elif action == "restart":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py restart <module> [client_name]")
                print(f"Valid modules: {', '.join(VALID_MODULES)}")
                sys.exit(1)
                
            module = sys.argv[2]
            client_name = sys.argv[3] if len(sys.argv) > 3 else None
            
            if restart_service(module, client_name):
                sys.exit(0)
            else:
                sys.exit(1)

        elif action == "yara-scan":
            if len(sys.argv) < 4:
                print("[ERROR] Usage: python monisec-server.py yara-scan <client_name> <target_path> [rule_name]")
                sys.exit(1)
                
            client_name = sys.argv[2]
            target_path = sys.argv[3]
            rule_name = sys.argv[4] if len(sys.argv) > 4 else None
            
            print(f"[INFO] Triggering YARA scan on {client_name} for path {target_path}...")
            result = clients.run_yara_scan(client_name, target_path, rule_name)
            
            if result.get("status") == "success":
                print(f"[SUCCESS] YARA scan completed on {client_name}")
                scan_results = result.get("results", [])
                if scan_results:
                    print(f"Found {len(scan_results)} matches:")
                    for match in scan_results:
                        print(f"  - Rule: {match.get('rule')}")
                        print(f"    File: {match.get('file')}")
                        print(f"    Tags: {', '.join(match.get('tags', []))}")
                        print("")
                else:
                    print("No YARA matches found.")
            else:
                print(f"[ERROR] YARA scan failed on {client_name}: {result.get('message')}")
            sys.exit(0)

        elif action == "ir-shell":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py ir-shell <client_name>")
                sys.exit(1)
                
            client_name = sys.argv[2]
            
            print(f"[INFO] Establishing IR shell with {client_name}...")
            clients.spawn_ir_shell(client_name)
            # The function will handle the interactive shell session
            sys.exit(0)

        elif action == "update":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py update <client_name>")
                sys.exit(1)
                
            client_name = sys.argv[2]
            
            print(f"[INFO] Triggering update on {client_name}...")
            result = clients.update_client(client_name)
            
            if result.get("status") == "success":
                print(f"[SUCCESS] Update triggered on {client_name}")
                update_info = result.get("update_info", {})
                print(f"New version: {update_info.get('version', 'Unknown')}")
            else:
                print(f"[ERROR] Failed to update {client_name}: {result.get('message')}")
            sys.exit(0)

        elif action == "-d":
            print("[INFO] Daemonizing MoniSec Server...")
            os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

            with open(LOG_FILE, 'a+') as log_stream:
                with daemon.DaemonContext(
                    pidfile=daemon.pidfile.TimeoutPIDLockFile(PID_FILE),
                    stdout=log_stream,
                    stderr=log_stream,
                    working_directory=os.path.dirname(os.path.abspath(__file__)),
                    umask=0o022
                ):
                    run_server()
            sys.exit(0)

        elif action == "stop":
            if not os.path.exists(PID_FILE):
                print(f"[ERROR] PID file not found: {PID_FILE}")
                sys.exit(1)
            try:
                with open(PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                print(f"[INFO] Stopping MoniSec Server (PID: {pid})...")
                os.kill(pid, signal.SIGTERM)
                print("[INFO] SIGTERM signal sent.")
            except ProcessLookupError:
                print("[WARNING] Process not found. Removing stale PID file.")
                os.remove(PID_FILE)
            except Exception as e:
                print(f"[ERROR] Failed to stop daemon: {e}")
                sys.exit(1)

            sys.exit(0)
        
        else:
            print("Unknown command. Use --help for available commands.")
            sys.exit(1)

    # No CLI args or unrecognized input — start server in foreground
    siem_config = server_siem.load_siem_config()
    if siem_config:
        logging.info("[INFO] SIEM integration is enabled.")

    initialize_log_storage()
    print("Starting MoniSec Server...")
    start_server()
