import socket
import threading
import logging
import os
import hmac
import hashlib
import json

# Ensure logs directory exists
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "monisec-server.log")

# Set log file permissions to 600 (read/write for user only)
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

# Server Configuration
HOST = "0.0.0.0"
PORT = 5555
PSK_STORE_FILE = "psk_store.json"  # Store client PSKs

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
    return os.urandom(32).hex()  # Generate a 32-byte secure key

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
        client_socket.sendall(b"AUTH_REQUEST")  # Ask for authentication
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

# Function to handle each client connection
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
            client_socket.sendall(b"ACK")
    except Exception as e:
        logging.error(f"Error with client {client_id}: {e}")
    finally:
        logging.info(f"Closing connection with {client_id}")
        client_socket.close()

# Main server function
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    logging.info(f"MoniSec Server listening on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    start_server()
