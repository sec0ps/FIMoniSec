import socket
import threading
import logging
import sys
import json
import os
import hmac
import hashlib
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

def import_psk():
    """Prompts user to enter the Server IP, Client Name, and PSK for authentication and stores them."""
    server_ip = input("Enter Server IP Address: ").strip()
    client_name = input("Enter Client Name: ").strip()
    psk_value = input("Enter PSK: ").strip()

    if not server_ip or not client_name or not psk_value:
        print("[ERROR] Server IP, Client Name, and PSK cannot be empty.")
        return

    token_data = {
        "server_ip": server_ip,
        "client_name": client_name,
        "psk": psk_value
    }

    with open("auth_token.json", "w") as f:
        json.dump(token_data, f, indent=4)
    os.chmod("auth_token.json", 0o600)

    print("[INFO] PSK imported and stored securely.")

def authenticate_with_server():
    """Authenticates with the MoniSec server using stored IP and PSK from auth_token.json."""

    token_file = "auth_token.json"

    print("[DEBUG] Loading authentication data...")

    # Load stored authentication data
    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
            server_ip = token_data.get("server_ip")
            psk = token_data.get("psk")
            client_name = token_data.get("client_name")

            if not server_ip or not psk or not client_name:
                raise ValueError("Missing Server IP, PSK, or Client Name in auth_token.json.")

        print(f"[DEBUG] Server IP: {server_ip}")
        print(f"[DEBUG] Client Name: {client_name}")
        print(f"[DEBUG] PSK Loaded: {psk[:6]}********")  # Masked for security

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to load authentication data: {e}")
        return False

    # Generate authentication HMAC
    nonce = os.urandom(16).hex()
    client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()

    print("[DEBUG] Connecting to server...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Prevent infinite hangs
        sock.connect((server_ip, 5555))

        print("[DEBUG] Sending authentication request...")
        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))

        response = sock.recv(1024).decode("utf-8")

        if response == "AUTH_SUCCESS":
            print("[SUCCESS] Authentication successful.")
            return True
        elif response == "AUTH_FAILED":
            print("[ERROR] Authentication failed.")
            return False
        else:
            print(f"[ERROR] Unexpected server response: {response}")
            return False
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False
