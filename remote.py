import socket
import threading
import logging
import sys
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

CLIENT_HOST = "0.0.0.0"  # Listen on all interfaces
CLIENT_PORT = 6000       # Port for receiving commands

def start_client_listener():
    """Starts a TCP server to receive and execute remote commands from monisec-server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((CLIENT_HOST, CLIENT_PORT))
    server_socket.listen(5)
    logging.info(f"MoniSec client listening for commands on {CLIENT_HOST}:{CLIENT_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Received connection from {addr}")
        client_thread = threading.Thread(target=handle_server_commands, args=(client_socket,))
        client_thread.start()

def handle_server_commands(client_socket):
    """Handles incoming commands from monisec-server and executes only allowed actions."""
    try:
        data = client_socket.recv(1024).decode("utf-8")
        if not data:
            return

        if data.startswith("EXECUTE:"):
            command_parts = data.split(":", 1)[1].strip().split()

            if len(command_parts) != 2:
                logging.warning(f"Invalid command format received: {data}")
                client_socket.sendall(b"ERROR: Invalid command format")
                return

            target, action = command_parts
            if target in PROCESSES and action in ["start", "stop", "restart"]:
                logging.info(f"Executing {action} on {target}")

                if action == "restart":
                    restart_process(target)
                elif action == "start":
                    start_process(target)
                elif action == "stop":
                    stop_process(target)

                client_socket.sendall(b"SUCCESS: Command executed")
            else:
                logging.warning(f"Unauthorized command received: {target} {action}")
                client_socket.sendall(b"ERROR: Unauthorized command")

    except Exception as e:
        logging.error(f"Error handling server command: {e}")
    finally:
        client_socket.close()

def import_psk(psk_value):
    """Imports a PSK and stores it locally."""
    token_data = {"psk": psk_value}
    with open("auth_token.json", "w") as f:
        json.dump(token_data, f)
    os.chmod("auth_token.json", 0o600)
    print("[INFO] PSK imported and stored securely.")
def authenticate_with_server(server_ip, client_name):
    """Authenticates with the MoniSec server using a stored PSK."""
    token_file = "auth_token.json"

    # Load stored PSK
    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
            psk = token_data.get("psk", None)
            if not psk:
                raise ValueError("No PSK found.")
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        print("[ERROR] No valid PSK found. Import the PSK before connecting.")
        return False

    nonce = os.urandom(16).hex()
    client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, 5555))

        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))
        response = sock.recv(1024).decode("utf-8")

        if response == "AUTH_SUCCESS":
            print("[SUCCESS] Authentication successful.")
            return True
        else:
            print("[ERROR] Authentication failed.")
            return False
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return Falsefs
