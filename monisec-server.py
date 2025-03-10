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

# Function to handle client connections and execute remote commands
def handle_client(client_socket, client_address):
    logging.info(f"New connection from {client_address}")

    client_id = authenticate_client(client_socket)
    if not client_id:
        logging.warning(f"Client {client_address} failed authentication. Disconnecting.")
        client_socket.close()
        return

    logging.info(f"Client {client_id} authenticated successfully.")

    try:
        while True:
            data = client_socket.recv(1024).decode("utf-8")
            if not data:
                break
            logging.info(f"Received from {client_id} ({client_address}): {data}")

            # Command Execution
            if data.startswith("COMMAND:"):
                command_parts = data.split(":", 1)[1].strip().split()

                if len(command_parts) != 2:
                    logging.warning(f"Invalid command format from {client_id}: {data}")
                    client_socket.sendall(b"ERROR: Invalid command format")
                else:
                    target, action = command_parts
                    if target in ALLOWED_COMMANDS and action in ALLOWED_COMMANDS[target]:
                        logging.info(f"Executing allowed command for {client_id}: {target} {action}")
                        client_socket.sendall(f"EXECUTE:{target} {action}".encode("utf-8"))
                    else:
                        logging.warning(f"Unauthorized command attempt from {client_id}: {target} {action}")
                        client_socket.sendall(b"ERROR: Unauthorized command")

                        client_socket.sendall(b"ACK")
    except Exception as e:
        logging.error(f"Error with client {client_id}: {e}")
    finally:
        logging.info(f"Closing connection with {client_id}")
        client_socket.close()

# Function to send commands to clients
def send_command(client_ip, command):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((client_ip, PORT))
        client_socket.sendall(f"COMMAND:{command}".encode("utf-8"))
        response = client_socket.recv(1024).decode("utf-8")
        logging.info(f"Client {client_ip} response: {response}")
        client_socket.close()
    except Exception as e:
        logging.error(f"Error sending command to {client_ip}: {e}")

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
    """Starts the MoniSec server and listens for incoming client connections."""
    global server_socket

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow immediate reuse of port
        server_socket.bind(("0.0.0.0", 5555))
        server_socket.listen(10)
        logging.info("[INFO] MoniSec Server listening on 0.0.0.0:5555")

        while not shutdown_event.is_set():
            try:
                server_socket.settimeout(1.0)  # Allow server to check shutdown event
                client_socket, client_address = server_socket.accept()
                threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
            except socket.timeout:
                continue  # Continue loop to check shutdown event

    except Exception as e:
        logging.error(f"[ERROR] Server encountered an error: {e}")

    finally:
        logging.info("[INFO] Cleaning up server resources...")
        if server_socket:
            server_socket.close()

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
        command = sys.argv[1]

        if command == "add-client":
            clients.add_client()
            sys.exit(0)
        elif command == "list-clients":
            clients.list_clients()
            sys.exit(0)
        elif command == "remove-client" and len(sys.argv) > 2:
            clients.remove_client(sys.argv[2])
            sys.exit(0)
        elif command in ["-h", "--help"]:
            print_help()
            sys.exit(0)

    print("Starting MoniSec Server...")
    start_server()
