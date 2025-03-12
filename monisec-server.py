import sys
import socket
import threading
import logging
import os
import hmac
import hashlib
import json
import clients
import signal
import server_siem

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

ALLOWED_COMMANDS = {
    "monisec_client": ["start", "stop", "restart"],
    "fim_client": ["start", "stop", "restart"],
    "pim": ["start", "stop", "restart"]
}

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

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Set log file permissions
try:
    with open(LOG_FILE, 'a') as f:
        pass
    os.chmod(LOG_FILE, 0o600)
except Exception as e:
    print(f"Failed to set log file permissions: {e}")

# Ensure separate logging for MoniSec Server logs
server_log_handler = logging.FileHandler(LOG_FILE)
server_log_handler.setLevel(logging.DEBUG)
server_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Get the root logger and add the handler
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logger.addHandler(server_log_handler)

# Ensure PSK store exists
if not os.path.exists(PSK_STORE_FILE):
    with open(PSK_STORE_FILE, "w") as f:
        json.dump({}, f)

def handle_shutdown(signum, frame):
    """Gracefully shuts down the MoniSec Server on signal (CTRL+C)."""
    logging.info("[INFO] Shutting down MoniSec Server...")
    shutdown_event.set()  # Signal all threads to stop

    if server_socket:
        server_socket.close()  # Close server socket to free the port

    logging.info("[INFO] MoniSec Server stopped.")
    exit(0)

# Register SIGINT (CTRL+C) and SIGTERM (kill command) for graceful shutdown
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

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
    """Ensures the logs directory and endpoint-integrity-logs.json exist."""
    try:
        # Ensure logs directory exists
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
            logging.info(f"Created logs directory: {LOG_DIR}")

        # Ensure endpoint-integrity-logs.json exists
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("")  # Create an empty file
            logging.info(f"Created log file: {LOG_FILE}")

    except Exception as e:
        logging.error(f"Failed to initialize log storage: {e}")

def print_help():
    """Prints the available command-line options for monisec-server.py"""
    print("""
Usage: python monisec-server.py [command] [client_name]

Commands:
  add-client <client_name>     Add a new client and generate a unique PSK.
  remove-client <client_name>  Remove an existing client.
  list-clients                 List all registered clients.
  configure-siem               Configure SIEM settings for log forwarding.
  -h, --help                   Show this help message.

If no command is provided, the server will start normally.
""")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        action = sys.argv[1]

        if action in ["-h", "--help", "help"]:
            print_help()  # Display help message
            sys.exit(0)  # Exit before starting the server

        elif action == "list-agents":
            clients.list_clients()
            sys.exit(0)  # Exit before starting the server

        elif action == "add-client":
            clients.add_client()
            sys.exit(0)  # Exit before starting the server

        elif action == "remove-client":
            if len(sys.argv) < 3:
                print("[ERROR] Please specify an agent name to remove.")
                sys.exit(1)
            agent_name = sys.argv[2]
            clients.remove_client(agent_name)
            sys.exit(0)  # Exit before starting the server

        elif action == "configure-siem":  # ✅ New SIEM configuration option
            server_siem.configure_siem()
            sys.exit(0)  # Exit after configuring SIEM

    # ✅ Ensure SIEM settings are loaded
    siem_config = server_siem.load_siem_config()
    if siem_config:
        logging.info("[INFO] SIEM integration is enabled.")

    initialize_log_storage()
    print("Starting MoniSec Server...")
    start_server()  # Start the main server function
