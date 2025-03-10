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

CONFIG_FILE = "monisec-server.config"
server_socket = None  # Global reference to the server socket
shutdown_event = threading.Event()  # Event to signal shutdown

DEFAULT_CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": "5555",
    "LOG_DIR": "./logs",
    "LOG_FILE": "monisec-server.log",
    "PSK_STORE_FILE": "psk_store.json",
    "MAX_CLIENTS": "10"
}

ALLOWED_COMMANDS = {
    "monisec_client": ["start", "stop", "restart"],
    "fim_client": ["start", "stop", "restart"],
    "pim": ["start", "stop", "restart"]
}

# Function to create default config file if missing
def create_default_config():
    with open(CONFIG_FILE, "w") as f:
        for key, value in DEFAULT_CONFIG.items():
            f.write(f"{key} = {value}\n")

# Function to load config from file
def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"{CONFIG_FILE} not found. Creating default configuration.")
        create_default_config()

    config = {}
    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        exit(1)
    return config

config = load_config()

# Assign values from the config
HOST = config["HOST"]
PORT = int(config["PORT"])
LOG_DIR = config["LOG_DIR"]
LOG_FILE = os.path.join(LOG_DIR, config["LOG_FILE"])
PSK_STORE_FILE = config["PSK_STORE_FILE"]
MAX_CLIENTS = int(config["MAX_CLIENTS"])

# Ensure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Set log file permissions
try:
    with open(LOG_FILE, 'a') as f:
        pass
    os.chmod(LOG_FILE, 0o600)
except Exception as e:
    print(f"Failed to set log file permissions: {e}")

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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

def print_help():
    """Prints the available command-line options for monisec-server.py"""
    print("""
Usage: python monisec-server.py [command] [client_name]

Commands:
  add-client <client_name>     Add a new client and generate a unique PSK.
  remove-client <client_name>  Remove an existing client.
  list-clients                 List all registered clients.
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

    print("Starting MoniSec Server...")
    start_server()  # Start the main server function
