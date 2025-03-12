import socket
import threading
import logging
import sys
import json
import os
import hmac
import hashlib
import time
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

CLIENT_HOST = "0.0.0.0"  # Listen on all interfaces
CLIENT_PORT = 6000       # Port for receiving commands
AUTH_TOKEN_FILE = "auth_token.json"
LOG_FILES = ["./logs/monisec-client.log", "./logs/file_monitor.json"]

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

def send_logs_to_server():
    """Sends only newly appended logs from MoniSec client to MoniSec server in real-time."""

    # Load stored authentication data
    try:
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data.get("server_ip")
            client_name = token_data.get("client_name")
            psk = token_data.get("psk")

            if not server_ip or not client_name or not psk:
                raise ValueError("Missing Server IP, Client Name, or PSK in auth_token.json.")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        logging.error(f"Failed to load authentication data: {e}")
        return False

    try:
        logging.info(f"Connecting to MoniSec Server at {server_ip}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server_ip, 5555))

        # Authenticate first
        nonce = os.urandom(16).hex()
        client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))
        response = sock.recv(1024).decode("utf-8")

        if response != "AUTH_SUCCESS":
            logging.error(f"Authentication failed. Server response: {response}")
            sock.close()
            return False

        logging.info("Authentication successful. Monitoring logs...")

        file_positions = {log_file: 0 for log_file in LOG_FILES}

        # Move file pointers to end of file to avoid resending old logs
        for log_file in LOG_FILES:
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    f.seek(0, os.SEEK_END)
                    file_positions[log_file] = f.tell()  # Start at end of file

        # Infinite loop to continuously check for new log entries
        while True:
            logs_to_send = []

            for log_file in LOG_FILES:
                if os.path.exists(log_file):
                    with open(log_file, "r") as f:
                        f.seek(file_positions[log_file])  # Move to last read position
                        new_logs = f.read().strip()  # Read new appended logs
                        file_positions[log_file] = f.tell()  # Update position for next read

                    if new_logs:
                        try:
                            # Ensure proper JSON formatting and parsing
                            formatted_logs = "[" + new_logs.replace("}\n{", "}, {") + "]"
                            json_logs = json.loads(formatted_logs)
                            logs_to_send.extend(json_logs)
                        except json.JSONDecodeError as e:
                            logging.warning(f"Skipping malformed log entry in {log_file}: {e}")
                            logging.warning(f"Problematic log contents: {new_logs}")

            if logs_to_send:
                try:
                    log_data = {
                        "client_name": client_name,
                        "logs": logs_to_send  # Send as a batch
                    }
                    sock.sendall(json.dumps(log_data).encode("utf-8"))
                    logging.info(f"Sent {len(logs_to_send)} logs to server.")
                except Exception as send_error:
                    logging.error(f"Failed to send logs: {send_error}")

            time.sleep(2)  # Check for new logs every 2 seconds

    except Exception as e:
        logging.error(f"Connection to server failed: {e}")
    finally:
        logging.info("Closing log socket connection.")
        sock.close()

def check_auth_and_send_logs():
    """Checks if auth_token.json exists and starts log transmission if valid."""
    if os.path.exists(AUTH_TOKEN_FILE):
        try:
            with open(AUTH_TOKEN_FILE, "r") as f:
                token_data = json.load(f)
                server_ip = token_data.get("server_ip")
                client_name = token_data.get("client_name")
                psk = token_data.get("psk")

            if server_ip and client_name and psk:
                logging.info("[INFO] Authentication token found. Attempting to connect to server...")

                success = authenticate_with_server()
                if success:
                    logging.info("[INFO] Authentication successful. Starting real-time log transmission...")

                    # ✅ Start log transmission in a separate thread
                    log_thread = threading.Thread(target=send_logs_to_server, daemon=True)
                    log_thread.start()

                else:
                    logging.warning("[WARNING] Authentication failed. Logging locally only.")
            else:
                logging.warning("[WARNING] auth_token.json is incomplete. Logging locally only.")
        except (json.JSONDecodeError, FileNotFoundError, ValueError) as e:
            logging.error(f"[ERROR] Failed to parse auth_token.json: {e}")
    else:
        logging.info("[INFO] No authentication token found. Logging locally only.")
