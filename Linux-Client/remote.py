import socket
import threading
import logging
import sys
import json
import os
import hmac
import hashlib
import time
from pathlib import Path
from client_crypt import encrypt_data
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

def get_base_dir():
    """Get the base directory for the application based on script location"""
    return os.path.dirname(os.path.abspath(__file__))

# Set BASE_DIR
BASE_DIR = get_base_dir()

CLIENT_HOST = "0.0.0.0"  # Listen on all interfaces
CLIENT_PORT = 6000       # Port for receiving commands
AUTH_TOKEN_FILE = "auth_token.json"
LOG_FILES = ["./logs/file_monitor.json"]
LOG_FILE = "./logs/file_monitor.json"

def should_start_listener():
    """
    Checks if the auth_token.json file exists in BASE_DIR.
    Returns True if the file exists, False otherwise.
    """
    token_path = Path(BASE_DIR) / AUTH_TOKEN_FILE
    return token_path.exists()

def start_listener_if_authorized():
    """
    Starts the listening service only if the auth_token.json file exists.
    """
    if should_start_listener():
        # Start the listening service
        start_client_listener()  # Changed from start_listener to start_client_listener
        logging.info(f"Listening service started on {CLIENT_HOST}:{CLIENT_PORT}")
    else:
        logging.info("Auth token file not found. Listening service not started.")
        
def start_client_listener():
    """Starts a TCP server to receive and execute remote commands from monisec-server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Ensure this is working
    
    # Add a small delay to ensure the socket is properly released
    time.sleep(1)
    
    try:
        server_socket.bind((CLIENT_HOST, CLIENT_PORT))
        server_socket.listen(5)
        logging.info(f"MoniSec client listening for commands on {CLIENT_HOST}:{CLIENT_PORT}")

        while True:
            client_socket, addr = server_socket.accept()
            logging.info(f"Received connection from {addr}")
            client_thread = threading.Thread(target=handle_server_commands, args=(client_socket,))
            client_thread.start()
    except OSError as e:
        logging.error(f"Could not start listening service: {e}")
        # Gracefully exit or handle the error
        return

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

    # Load stored authentication data
    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
            server_ip = token_data.get("server_ip")
            client_name = token_data.get("client_name")

            if not server_ip or not client_name:
                raise ValueError("Missing Server IP or Client Name in auth_token.json.")

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to load authentication data: {e}")
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server_ip, 5555))

        # ✅ Send the initial JSON handshake with client_name
        handshake = json.dumps({ "client_name": client_name })
        sock.sendall(handshake.encode("utf-8"))

        logging.info("Handshake sent to server.")
        sock.close()
        return True

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

def connect_to_server(server_ip, client_name, psk):
    """Establishes a new connection to the MoniSec server and authenticates."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # Enable TCP Keep-Alive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        sock.connect((server_ip, 5555))

        nonce = os.urandom(16).hex()
        client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))

        response = sock.recv(1024).decode("utf-8")

        if response != "AUTH_SUCCESS":
            logging.error(f"Authentication failed. Server response: {response}")
            sock.close()
            return None

        logging.info("Authentication successful. Monitoring logs...")
        return sock

    except (socket.timeout, socket.error, BrokenPipeError) as e:
        logging.error(f"Connection to server failed: {e}. Retrying...")
        return None

def send_chunked_data(sock, data):
    """Send data in manageable chunks with length prefixes."""
    try:
        # Get total message size
        total_size = len(data)
        logging.debug(f"Sending total of {total_size} bytes")
        
        # Send in chunks of 4KB max
        CHUNK_SIZE = 4096
        position = 0
        
        while position < total_size:
            # Determine chunk size
            chunk = data[position:position + CHUNK_SIZE]
            chunk_size = len(chunk)
            
            # Send chunk size as a 4-byte header
            size_bytes = chunk_size.to_bytes(4, byteorder='big')
            sock.sendall(size_bytes)
            
            # Send the chunk
            sock.sendall(chunk)
            
            position += chunk_size
            logging.debug(f"Sent chunk of {chunk_size} bytes, position {position}/{total_size}")
        
        # Send a zero-length marker to indicate end of message
        sock.sendall((0).to_bytes(4, byteorder='big'))
        
        return True
    except Exception as e:
        logging.error(f"Error sending chunked data: {e}")
        return False

def send_logs_to_server():
    RETRIES = 5
    DELAY = 3  # seconds between retries
    # Threshold for using chunked transfer (bytes)
    CHUNKING_THRESHOLD = 4000

    try:
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data["server_ip"]
            client_name = token_data["client_name"]
            psk = token_data["psk"]  # Not used directly; client_crypt loads it

        sock = None
        for attempt in range(RETRIES):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((server_ip, 5555))

                # Send cleartext client_name as JSON handshake
                handshake = json.dumps({"client_name": client_name})
                sock.sendall(handshake.encode("utf-8"))

                logging.info(f"[INFO] Connected to server and sent handshake. Attempt {attempt + 1}")
                break
            except Exception as e:
                logging.error(f"[ERROR] Connection attempt {attempt + 1} failed: {e}")
                time.sleep(DELAY)
        else:
            logging.critical("[CRITICAL] Could not connect to server after multiple attempts.")
            return

        file_positions = {}
        for log_file in LOG_FILES:
            file_positions[log_file] = os.path.getsize(log_file) if os.path.exists(log_file) else 0
            logging.info(f"Initial position for {log_file}: {file_positions[log_file]}")

        while True:
            logs_to_send = []

            for log_file in LOG_FILES:
                if os.path.exists(log_file):
                    try:
                        current_size = os.path.getsize(log_file)
                        
                        if current_size <= file_positions[log_file]:
                            continue
                            
                        with open(log_file, "r") as f:
                            f.seek(file_positions[log_file])
                            new_logs = f.read()
                            new_position = f.tell()
                            
                            if new_logs:
                                file_positions[log_file] = new_position
                                entries = extract_valid_json_objects(new_logs)
                                logging.info(f"Extracted {len(entries)} valid entries from {log_file}")
                                
                                for entry in entries:
                                    if isinstance(entry, dict):
                                        # Clone the entry and add client_name
                                        full_entry = entry.copy()
                                        full_entry["client_name"] = client_name
                                        logs_to_send.append(full_entry)
                    except Exception as e:
                        logging.error(f"Error reading log file {log_file}: {e}")

            if logs_to_send:
                try:
                    message = json.dumps({"logs": logs_to_send})
                    message_size = len(message)
                    logging.debug(f"Sending {len(logs_to_send)} logs, message size: {message_size} bytes")
                    
                    encrypted = encrypt_data(message)
                    encrypted_size = len(encrypted)
                    
                    # Use chunked transfer for large messages
                    if encrypted_size > CHUNKING_THRESHOLD:
                        logging.info(f"Using chunked transfer for large message ({encrypted_size} bytes)")
                        success = send_chunked_data(sock, encrypted)
                        if not success:
                            logging.error("Failed to send chunked data")
                            break
                    else:
                        # Use original method for smaller messages
                        sock.sendall(encrypted)
                    
                    ack = sock.recv(1024)
                    if ack != b"ACK":
                        logging.warning(f"Unexpected server response: {ack}")
                        break
                    else:
                        logging.info(f"Successfully sent {len(logs_to_send)} logs to server")
                except Exception as e:
                    logging.error(f"[SEND ERROR] {e}")
                    break

            time.sleep(2)

    except Exception as e:
        logging.error(f"[CLIENT ERROR] {e}")
    finally:
        if sock:
            sock.close()
            logging.info("Connection to server closed")

def extract_valid_json_objects(buffer):
    """Extract valid JSON objects from a buffer, handling complete JSON objects at the root level."""
    logs = []
    if not buffer or not buffer.strip():
        return logs
    
    # Split by line and look for complete objects
    lines = buffer.strip().split('\n')
    
    # Handle multi-line JSON objects
    current_object = ""
    bracket_count = 0
    
    for line in lines:
        # Count opening and closing brackets to track JSON object boundaries
        bracket_count += line.count('{') - line.count('}')
        
        # Add this line to the current object we're building
        current_object += line
        
        # If brackets are balanced, we might have a complete object
        if bracket_count == 0 and current_object.strip():
            try:
                obj = json.loads(current_object)
                logs.append(obj)
                current_object = ""
            except json.JSONDecodeError:
                # Not a valid object yet, keep going
                pass
    
    # If we couldn't parse any objects the standard way, try as a last resort
    if not logs and buffer.strip():
        try:
            # Try to find all JSON objects in the buffer using regex
            import re
            json_pattern = r'\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\}'
            matches = re.findall(json_pattern, buffer)
            
            for match in matches:
                try:
                    obj = json.loads(match)
                    logs.append(obj)
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
    
    logging.info(f"Successfully extracted {len(logs)} log entries")
    return logs

# Add new functions for chunked transfers
def send_chunked_data(sock, data):
    """Send data in manageable chunks with length prefixes."""
    try:
        # Get total message size
        total_size = len(data)
        logging.debug(f"Sending total of {total_size} bytes")
        
        # Send in chunks of 4KB max
        CHUNK_SIZE = 4096
        position = 0
        
        while position < total_size:
            # Determine chunk size
            chunk = data[position:position + CHUNK_SIZE]
            chunk_size = len(chunk)
            
            # Send chunk size as a 4-byte header
            size_bytes = chunk_size.to_bytes(4, byteorder='big')
            sock.sendall(size_bytes)
            
            # Send the chunk
            sock.sendall(chunk)
            
            position += chunk_size
            logging.debug(f"Sent chunk of {chunk_size} bytes, position {position}/{total_size}")
        
        # Send a zero-length marker to indicate end of message
        sock.sendall((0).to_bytes(4, byteorder='big'))
        
        return True
    except Exception as e:
        logging.error(f"Error sending chunked data: {e}")
        return False

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
                logging.info("[INFO] Authentication token found. Connecting to server...")

                # Authenticate with server and proceed if successful
                success = authenticate_with_server()
                if success:
                    logging.info("[INFO] Authentication successful. Starting real-time log transmission...")
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

