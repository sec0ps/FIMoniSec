import socket
import threading
import logging
import os
import hmac
import hashlib
import json

# Config File
CONFIG_FILE = "monisec-server.config"

DEFAULT_CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": "5555",
    "LOG_DIR": "./logs",
    "LOG_FILE": "monisec-server.log",
    "PSK_STORE_FILE": "psk_store.json",
    "MAX_CLIENTS": "10"
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

# Assign Configuration Variables
HOST = config.get("HOST", "0.0.0.0")
PORT = int(config.get("PORT", 5555))
LOG_DIR = config.get("LOG_DIR", "./logs")
LOG_FILE = os.path.join(LOG_DIR, config.get("LOG_FILE", "monisec-server.log"))
PSK_STORE_FILE = config.get("PSK_STORE_FILE", "psk_store.json")
MAX_CLIENTS = int(config.get("MAX_CLIENTS", 10))

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

# Function to load PSKs from file
def load_psks():
    with open(PSK_STORE_FILE, "r") as f:
        return json.load(f)

# Function to save PSKs to file
def save_psks(psks):
    with open(PSK_STORE_FILE, "w") as f:
        json.dump(psks, f, indent=4)

# Function to generate a new PSK for a client
def generate_psk():
    return os.urandom(32).hex()

# Function to add a new client
def add_client(client_id):
    psks = load_psks()
    if client_id in psks:
        logging.warning(f"Client {client_id} already has a PSK.")
        return psks[client_id]
    
    new_psk = generate_psk()
    psks[client_id] = new_psk
    save_psks(psks)
    logging.info(f"Generated PSK for client {client_id}")
    return new_psk

# Function to remove a client
def remove_client(client_id):
    psks = load_psks()
    if client_id in psks:
        del psks[client_id]
        save_psks(psks)
        logging.info(f"Removed PSK for client {client_id}")
        return True
    return False

# Function to authenticate a client using PSK
def authenticate_client(client_socket):
    try:
        client_socket.sendall(b"AUTH_REQUEST")
        auth_data = client_socket.recv(1024).decode("utf-8")
        
        if not auth_data:
            return None
        
        client_id, nonce, client_hmac = auth_data.split(":")
        psks = load_psks()

        if client_id not in psks:
            logging.warning(f"Unknown client attempted authentication: {client_id}")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        expected_hmac = hmac.new(psks[client_id].encode(), nonce.encode(), hashlib.sha256).hexdigest()

        if hmac.compare_digest(client_hmac, expected_hmac):
            client_socket.sendall(b"AUTH_SUCCESS")
            return client_id
        else:
            client_socket.sendall(b"AUTH_FAILED")
            return None
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        return None

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
                command = data.split(":", 1)[1].strip()
                logging.info(f"Executing command for {client_id}: {command}")
                client_socket.sendall(f"EXECUTE:{command}".encode("utf-8"))

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

# Main server function
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CLIENTS)
    logging.info(f"MoniSec Server listening on {HOST}:{PORT} with max {MAX_CLIENTS} clients")

    while True:
        client_socket, client_address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()
