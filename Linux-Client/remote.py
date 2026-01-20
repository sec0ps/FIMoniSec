# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
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
import socket
import asyncio
import websockets
import threading
import logging
import sys
import json
import os
import hmac
import hashlib
import time
import subprocess
import select
from pathlib import Path
from client_crypt import encrypt_data, decrypt_data
from fimonisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

# Global flag to track if an IR shell is currently active
ir_shell_active = False

# WebSocket connection state
websocket_client = None
websocket_connected = False
websocket_reconnect_delay = 5
websocket_max_reconnect_delay = 60
websocket_shutdown_event = threading.Event()
websocket_client_started = False
websocket_client_lock = threading.Lock()

BASE_DIR = "/opt/FIMoniSec/Linux-Client"
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

LOG_FILES = [
    os.path.join(LOG_DIR, "file_monitor.json"),
    os.path.join(LOG_DIR, "pim_monitor.json"),
    os.path.join(LOG_DIR, "lim_monitor.json")
]

# Update AUTH_TOKEN_FILE path
AUTH_TOKEN_FILE = os.path.join(BASE_DIR, "auth_token.json")

CLIENT_HOST = "0.0.0.0"  # Listen on all interfaces
CLIENT_PORT = 6000       # Port for receiving commands

def should_start_listener():
    """
    Checks if the auth_token.json file exists in BASE_DIR.
    Returns True if the file exists, False otherwise.
    """
    token_path = AUTH_TOKEN_FILE
    return os.path.exists(token_path)
    
def start_listener_if_authorized():
    """
    Start the client listener and WebSocket client if proper authorization exists,
    using NAT detection to determine the connection method.
    """
    # Validate authentication token
    is_valid, error_message = validate_auth_token()
    if not is_valid:
        return False
        
    # Authentication token is valid, proceed with connection setup
    try:
        with open(AUTH_TOKEN_FILE, 'r') as f:
            auth_data = json.load(f)
            
        server_ip = auth_data.get("server_ip")
        if not server_ip:
            logging.error("No server IP found in authentication token")
            return False
            
        # Detect NAT status to decide on connection method
        use_websocket = detect_nat_and_set_connection_mode()
        
        if use_websocket:
            # Start the WebSocket client in a thread
            websocket_thread = threading.Thread(target=start_websocket_client, daemon=True)
            websocket_thread.start()
            
            # No need to start TCP listener when using WebSocket due to NAT
            logging.info("NAT detected - using only WebSocket connection, TCP listener disabled")
            
        else:
            # Start the listener in a thread for direct commands with server IP restriction
            listener_thread = threading.Thread(target=lambda: start_client_listener(server_ip), daemon=True)
            listener_thread.start()
            
            # Also start WebSocket as a secondary channel
            websocket_thread = threading.Thread(target=start_websocket_client, daemon=True)
            websocket_thread.start()
        
        return True
        
    except Exception as e:
        logging.error(f"Error starting authorized listener: {e}")
        return False
        
def start_client_listener(allowed_server_ip=None):
    """
    Starts a TCP server to receive and execute remote commands from monisec-server.
    Only accepts connections from the specified allowed_server_ip if provided.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Add a small delay to ensure the socket is properly released
    time.sleep(1)
    
    try:
        server_socket.bind((CLIENT_HOST, CLIENT_PORT))
        server_socket.listen(5)
        logging.info(f"MoniSec client listening for commands on {CLIENT_HOST}:{CLIENT_PORT}")

        if allowed_server_ip:
            logging.info(f"Only accepting connections from authorized server: {allowed_server_ip}")

        while True:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            
            # Check if connection is from authorized server IP
            if allowed_server_ip and client_ip != allowed_server_ip:
                logging.warning(f"Rejected unauthorized connection from {client_ip}")
                client_socket.close()
                continue
                
            logging.info(f"Accepted connection from authorized server: {client_ip}")
            client_thread = threading.Thread(target=handle_server_commands, args=(client_socket,))
            client_thread.start()
    except OSError as e:
        logging.error(f"Could not start listening service: {e}")
        # Gracefully exit or handle the error
        return

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

    with open(AUTH_TOKEN_FILE, "w") as f:
        json.dump(token_data, f, indent=4)
    os.chmod(AUTH_TOKEN_FILE, 0o600)

    print("[INFO] PSK imported and stored securely.")
    
def validate_auth_token():
    """
    Validates the auth_token.json file exists and contains all required fields.
    Returns a tuple of (is_valid, error_message)
    """
    if not os.path.exists(AUTH_TOKEN_FILE):
        return False, "Authentication token file not found"
    
    try:
        with open(AUTH_TOKEN_FILE, 'r') as f:
            auth_data = json.load(f)
            
        # Check if all required fields exist and are populated
        required_fields = ["server_ip", "client_name", "psk"]
        for field in required_fields:
            if field not in auth_data or not auth_data[field]:
                return False, f"Authentication token missing or empty '{field}' field"
        
        return True, "Authentication token is valid"
    except json.JSONDecodeError:
        return False, "Authentication token file contains invalid JSON"
    except Exception as e:
        return False, f"Error validating authentication token: {str(e)}"
    
def authenticate_with_server():
    """Authenticates with the MoniSec server using stored IP and PSK from auth_token.json."""

    # Load stored authentication data
    try:
        with open(AUTH_TOKEN_FILE, "r") as f:
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
        
        # Send a zero-length marker to indicate end of message
        sock.sendall((0).to_bytes(4, byteorder='big'))
        
        return True
    except Exception as e:
        logging.error(f"Error sending chunked data: {e}")
        return False

def save_file_positions(positions):
    """Save file positions to disk for persistence across restarts."""
    positions_file = os.path.join(OUTPUT_DIR, "log_positions.json")
    try:
        with open(positions_file, "w") as f:
            # Convert dict keys to strings since all keys are paths anyway
            serializable_positions = {str(k): v for k, v in positions.items()}
            json.dump(serializable_positions, f)
    except Exception as e:
        logging.error(f"[LOGS] Failed to save file positions: {e}")

def load_file_positions():
    """Load file positions from disk."""
    positions_file = os.path.join(OUTPUT_DIR, "log_positions.json")
    if os.path.exists(positions_file):
        try:
            with open(positions_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"[LOGS] Failed to load file positions: {e}")
    return {}

def send_logs_to_server():
    """Continuously monitor log files and send new entries to the server."""
    RETRIES = 5
    DELAY = 3
    CHUNKING_THRESHOLD = 4000

    try:
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data["server_ip"]
            client_name = token_data["client_name"]
            psk = token_data["psk"]

        # NAT Detection
        try:
            sock_nat = socket.create_connection((server_ip, 5555), timeout=5)
            sock_nat.sendall(json.dumps({"command": "get_client_ip"}).encode("utf-8"))
            response = sock_nat.recv(1024)
            server_view = json.loads(response.decode("utf-8"))
            sock_nat.close()
        except Exception as e:
            logging.warning(f"NAT detection failed: {e}")

        sock = None
        for attempt in range(RETRIES):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((server_ip, 5555))

                handshake_data = {
                    "client_name": client_name,
                    "timestamp": time.time()
                }
                handshake_json = json.dumps(handshake_data)
                sock.sendall(handshake_json.encode("utf-8"))

                sock.settimeout(5)
                response = sock.recv(1024)

                if not response or response != b"OK":
                    if attempt < RETRIES - 1:
                        continue
                    raise ConnectionError("Bad handshake response")

                break
            except Exception as e:
                logging.error(f"Connection attempt {attempt + 1} failed: {e}")
                if sock:
                    sock.close()
                    sock = None
                time.sleep(DELAY)
        else:
            logging.critical("Could not connect to server after multiple attempts.")
            return

        # Load saved positions from disk or initialize
        saved_positions = load_file_positions()
        file_positions = {}
        
        for log_file in LOG_FILES:
            if str(log_file) in saved_positions and os.path.exists(log_file):
                file_size = os.path.getsize(log_file)
                saved_pos = int(saved_positions[str(log_file)])
                
                if saved_pos <= file_size:
                    file_positions[log_file] = saved_pos
                else:
                    logging.warning(f"Saved position {saved_pos} exceeds file size {file_size} for {log_file}. Using file size.")
                    file_positions[log_file] = file_size
            else:
                file_positions[log_file] = os.path.getsize(log_file) if os.path.exists(log_file) else 0

        while True:
            logs_to_send = {}
            total_entries = 0
            
            for log_file in LOG_FILES:
                if os.path.exists(log_file):
                    try:
                        current_size = os.path.getsize(log_file)
                        if current_size < file_positions[log_file]:
                            logging.warning(f"Log file {log_file} rotated/truncated. Resetting position.")
                            file_positions[log_file] = 0

                        if current_size <= file_positions[log_file]:
                            continue

                        with open(log_file, "r") as f:
                            f.seek(file_positions[log_file])
                            new_logs = f.read()
                            new_position = f.tell()

                            if new_logs:
                                # Determine log type
                                log_type = "UNKNOWN"
                                if "file_monitor.json" in log_file:
                                    log_type = "FIM"
                                elif "pim_monitor.json" in log_file:
                                    log_type = "PIM"
                                elif "lim_monitor.json" in log_file:
                                    log_type = "LIM"
                                
                                entries = extract_valid_json_objects(new_logs, log_file_name=log_file)
                                
                                valid_entries = []
                                for entry_num, entry in enumerate(entries, 1):
                                    if entry is None:
                                        logging.warning(f"Skipping None entry {entry_num} from {log_file}")
                                        continue
                                    if not isinstance(entry, dict):
                                        logging.warning(f"Skipping non-dict entry {entry_num} from {log_file}: {type(entry)}")
                                        continue
                                    
                                    # Add required fields
                                    entry["client_name"] = client_name
                                    entry["log_type"] = log_type
                                    
                                    # Ensure timestamp exists
                                    if not entry.get("timestamp"):
                                        entry["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                                    
                                    valid_entries.append(entry)
                                
                                logging.info(f"{log_file}: Validated {len(valid_entries)} of {len(entries)} entries")

                                if valid_entries:
                                    if log_file not in logs_to_send:
                                        logs_to_send[log_file] = {
                                            "entries": [],
                                            "new_position": new_position
                                        }
                                    logs_to_send[log_file]["entries"].extend(valid_entries)
                                    total_entries += len(valid_entries)
                                else:
                                    if new_logs.strip():
                                        logging.warning(f"{log_file}: Could not parse any valid entries from {len(new_logs)} characters")
                    except Exception as e:
                        logging.error(f"Error reading {log_file}: {e}")

            if total_entries > 0:
                try:
                    all_logs = []
                    for log_file, data in logs_to_send.items():
                        all_logs.extend(data["entries"])

                    # Final validation before sending
                    final_logs = []
                    for i, log_entry in enumerate(all_logs):
                        if log_entry is None:
                            logging.error(f"Detected None log entry {i+1} before sending, skipping")
                            continue
                        if not isinstance(log_entry, dict):
                            logging.error(f"Detected non-dict log entry {i+1} before sending: {type(log_entry)}, skipping")
                            continue
                        
                        # Additional validation for required fields
                        if not log_entry.get("log_type"):
                            logging.warning(f"Entry {i+1} missing log_type, adding default")
                            log_entry["log_type"] = "UNKNOWN"
                        
                        final_logs.append(log_entry)
                    
                    if not final_logs:
                        logging.warning("No valid log entries to send after final validation")
                        continue

                    # Log summary of what we're sending
                    by_type = {}
                    for entry in final_logs:
                        log_type = entry.get("log_type", "UNKNOWN")
                        by_type[log_type] = by_type.get(log_type, 0) + 1
                    
                    logging.info(f"Sending {len(final_logs)} entries: {dict(by_type)}")

                    message = json.dumps({
                        "logs": final_logs,
                        "client_name": client_name,
                        "total_entries": len(final_logs),
                        "breakdown": by_type
                    })

                    from client_crypt import encrypt_data
                    encrypted = encrypt_data(message)
                    
                    if len(encrypted) > CHUNKING_THRESHOLD:
                        success = send_chunked_data(sock, encrypted)
                        if not success:
                            raise ConnectionError("Chunked data send failed")
                    else:
                        sock.sendall(encrypted)

                    sock.settimeout(10)
                    ack = sock.recv(1024)
                    
                    if ack == b"ACK":
                        for log_file, data in logs_to_send.items():
                            file_positions[log_file] = data["new_position"]
                        save_file_positions(file_positions)
                        logging.info(f"Successfully sent and acknowledged {len(final_logs)} log entries")
                    elif ack == b"ERROR":
                        logging.error(f"Server returned ERROR when processing {len(final_logs)} log entries")
                        break
                    else:
                        logging.warning(f"Unexpected server response: {ack}")
                        if not ack:
                            raise ConnectionError("No response from server")

                except Exception as e:
                    logging.error(f"Send error: {e}")
                    try:
                        sock.close()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        sock.connect((server_ip, 5555))

                        handshake_data = {
                            "client_name": client_name,
                            "timestamp": time.time()
                        }
                        handshake_json = json.dumps(handshake_data)
                        sock.sendall(handshake_json.encode("utf-8"))

                        sock.settimeout(5)
                        response = sock.recv(1024)
                        
                        if not response or response != b"OK":
                            logging.warning(f"Reconnection failed: {response}")
                            raise ConnectionError("Failed to authenticate after reconnection")
                        
                        logging.info("Successfully reconnected after error")
                    except Exception as reconnect_err:
                        logging.error(f"Failed to reconnect: {reconnect_err}")
                        break

            time.sleep(2)

    except Exception as e:
        logging.error(f"Fatal client error: {e}")
    finally:
        if 'file_positions' in locals():
            save_file_positions(file_positions)
            
        if sock:
            sock.close()

def extract_valid_json_objects(buffer, log_file_name=None):
    """Extract valid JSON objects from a buffer, only accepting complete dictionary objects."""
    logs = []
    file_info = f" from {log_file_name}" if log_file_name else ""
    
    if not buffer or not buffer.strip():
        return logs
    
    buffer = buffer.strip()
    
    # Method 1: Try to parse using JSONDecoder for concatenated objects
    decoder = json.JSONDecoder()
    idx = 0
    
    while idx < len(buffer):
        # Skip whitespace
        while idx < len(buffer) and buffer[idx].isspace():
            idx += 1
            
        if idx >= len(buffer):
            break
            
        # Only try to parse if we're at the start of an object
        if buffer[idx] != '{':
            # Find the next '{' character
            next_brace = buffer.find('{', idx)
            if next_brace == -1:
                break
            idx = next_brace
            continue
            
        try:
            # Try to decode a JSON object starting at current position
            obj, end_idx = decoder.raw_decode(buffer, idx)
            
            # ONLY accept dictionary objects
            if isinstance(obj, dict) and obj:  # Must be non-empty dict
                logs.append(obj)
            
            # Move to the position after the parsed object
            idx += end_idx
            
        except json.JSONDecodeError as e:
            logging.warning(f"JSON decode error{file_info} at position {idx}: {e}")
            # Look for the next '{' that might start a valid object
            next_brace = buffer.find('{', idx + 1)
            if next_brace == -1:
                break
            idx = next_brace
            continue
        except Exception as e:
            logging.error(f"Unexpected parsing error{file_info}: {e}")
            break
    
    # Method 2: If no objects found, try line-by-line parsing
    if not logs:
        lines = buffer.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
                
            try:
                obj = json.loads(line)
                # ONLY accept dictionary objects
                if isinstance(obj, dict) and obj:  # Must be non-empty dict
                    logs.append(obj)
            except json.JSONDecodeError:
                continue
    
    # Method 3: Handle multi-line JSON objects if still no results
    if not logs:
        lines = buffer.split('\n')
        current_object = ""
        bracket_count = 0
        in_string = False
        escape_next = False
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Start building object only if we see an opening brace
            if not current_object and not line.startswith('{'):
                continue
                
            # Add this line to the current object we're building
            if current_object:
                current_object += "\n" + line
            else:
                current_object = line
            
            # Count brackets carefully, considering strings
            for char in line:
                if escape_next:
                    escape_next = False
                    continue
                    
                if char == '\\':
                    escape_next = True
                    continue
                    
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                    
                if not in_string:
                    if char == '{':
                        bracket_count += 1
                    elif char == '}':
                        bracket_count -= 1
            
            # If brackets are balanced and we have content, try to parse
            if bracket_count == 0 and current_object.strip():
                try:
                    obj = json.loads(current_object.strip())
                    # ONLY accept dictionary objects
                    if isinstance(obj, dict) and obj:  # Must be non-empty dict
                        logs.append(obj)
                    current_object = ""
                    bracket_count = 0
                except json.JSONDecodeError:
                    current_object = ""
                    bracket_count = 0
    
    # Filter out any remaining invalid objects
    valid_logs = []
    for i, log in enumerate(logs):
        if isinstance(log, dict) and log:  # Must be non-empty dictionary
            # Additional validation - ensure it has basic log structure
            if log.get("timestamp") or log.get("log_type") or log.get("event_type"):
                valid_logs.append(log)
    
    return valid_logs

def send_chunked_data(sock, data):
    """Send data in manageable chunks with length prefixes."""
    try:
        # Get total message size
        total_size = len(data)
        
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
        
        # Send a zero-length marker to indicate end of message
        sock.sendall((0).to_bytes(4, byteorder='big'))
        
        return True
    except Exception as e:
        logging.error(f"Error sending chunked data: {e}")
        return False

def check_auth_and_send_logs():
    """Checks if auth_token.json exists and starts log transmission if valid."""
    # Validate authentication token
    is_valid, error_message = validate_auth_token()
    if not is_valid:
        return False

    try:
        # Authenticate with server and proceed if successful
        success = authenticate_with_server()
        if success:
            # Start regular log transmission thread
            log_thread = threading.Thread(target=send_logs_to_server, daemon=True)
            log_thread.start()
            
            # Start WebSocket client for command channel
            start_websocket_client()
            return True
        else:
            return False
    except Exception as e:
        logging.error(f"Failed to initialize log transmission: {e}")
        
def handle_server_commands(client_socket):
    """Handles incoming commands from monisec-server and executes only allowed actions."""
    try:
        # Receive encrypted command data
        encrypted_data = client_socket.recv(8192)
        if not encrypted_data:
            logging.warning("[ERROR] Empty command received")
            client_socket.close()
            return

        # Decrypt the data using the existing decrypt_data function
        try:
            from client_crypt import decrypt_data
            command_data = decrypt_data(encrypted_data)
            
            if command_data is None:
                logging.warning("[ERROR] Failed to decrypt command data")
                send_error_response(client_socket, "Failed to decrypt command data")
                return
                
            if not isinstance(command_data, dict):
                logging.warning(f"[ERROR] Invalid command format: {command_data}")
                send_error_response(client_socket, "Invalid command format")
                return
                
            # Extract command and parameters
            command = command_data.get("command")
            params = command_data.get("params", {})
            
            # Process the command
            if command == "restart":
                result = handle_restart_command(params)
            elif command == "ir-shell-init":
                result = handle_ir_shell_init_command(params)
            elif command == "ir-shell-command":
                result = handle_ir_shell_command(params)
            elif command == "ir-shell-exit":
                result = handle_ir_shell_exit_command(params)
            elif command == "update":
                result = handle_update_command(params)
            else:
                result = {"status": "error", "message": f"Unknown command: {command}"}
                
            # Send the response
            send_response(client_socket, result)
            
        except Exception as e:
            logging.error(f"[ERROR] Command processing error: {e}")
            send_error_response(client_socket, f"Command processing error: {e}")
            
    except Exception as e:
        logging.error(f"[ERROR] Error handling server command: {e}")
    finally:
        client_socket.close()

def send_response(client_socket, response_data):
    """Send an encrypted response to the server."""
    try:
        # Serialize and encrypt the response
        serialized_response = json.dumps(response_data)
        
        # Import client_crypt to use its encrypt_data function
        from client_crypt import encrypt_data
        
        # Encrypt the response using the module's function
        encrypted_response = encrypt_data(serialized_response)
        
        # Send the response
        client_socket.sendall(encrypted_response)
    except Exception as e:
        logging.error(f"[ERROR] Failed to send response: {e}")
        try:
            # Try to send a simple error response
            from client_crypt import encrypt_data
            error_response = json.dumps({"status": "error", "message": f"Response error: {e}"})
            encrypted_error = encrypt_data(error_response)
            client_socket.sendall(encrypted_error)
        except Exception as err:
            logging.error(f"[ERROR] Failed to send error response: {err}")

def send_error_response(client_socket, error_message):
    """Send an error response to the server."""
    error_data = {"status": "error", "message": error_message}
    send_response(client_socket, error_data)

# Command handlers
def handle_restart_command(params):
    """Handle a restart command for a service."""
    service = params.get("service")
    
    if not service:
        return {"status": "error", "message": "Missing service parameter"}
        
    if service not in ["monisec_client", "fim_client", "pim", "lim"]:
        return {"status": "error", "message": f"Invalid service: {service}"}
    
    try:
        logging.info(f"[COMMAND] Restarting service: {service}")
        
        # Import here to avoid circular imports
        from monisec_client import restart_process
        
        # Execute the restart
        restart_process(service)
        
        return {
            "status": "success",
            "message": f"Service {service} restarted successfully"
        }
    except Exception as e:
        logging.error(f"[ERROR] Failed to restart {service}: {e}")
        return {
            "status": "error",
            "message": f"Failed to restart {service}: {e}"
        }

def handle_ir_shell_init_command(params):
    """Handle initialization of an IR shell session."""
    global ir_shell_active
    
    # Check if a shell is already active
    if ir_shell_active:
        return {"status": "error", "message": "An IR shell is already active"}
    
    try:
        logging.info("[COMMAND] Initializing IR shell session")
        
        # Set the global flag
        ir_shell_active = True
        
        return {
            "status": "success",
            "message": "IR shell initialized successfully"
        }
    except Exception as e:
        logging.error(f"[ERROR] Failed to initialize IR shell: {e}")
        ir_shell_active = False
        return {
            "status": "error",
            "message": f"Failed to initialize IR shell: {e}"
        }

def handle_ir_shell_command(params):
    """Handle a command within an IR shell session."""
    global ir_shell_active
    
    if not ir_shell_active:
        return {"status": "error", "message": "No active IR shell session"}
    
    command = params.get("command")
    if not command:
        return {"status": "error", "message": "Empty command"}
    
    try:
        # Execute the command using the existing IR command executor
        output = execute_ir_command(command)
        
        return {
            "status": "success",
            "output": output
        }
    except Exception as e:
        logging.error(f"[ERROR] IR shell command execution failed: {e}")
        return {
            "status": "error",
            "message": f"Command execution failed: {e}"
        }

def handle_ir_shell_exit_command(params):
    """Handle termination of an IR shell session."""
    global ir_shell_active
    
    if not ir_shell_active:
        return {"status": "success", "message": "No active IR shell session"}
    
    try:
        logging.info("[COMMAND] Terminating IR shell session")
        ir_shell_active = False
        
        return {
            "status": "success",
            "message": "IR shell terminated successfully"
        }
    except Exception as e:
        logging.error(f"[ERROR] Failed to terminate IR shell: {e}")
        return {
            "status": "error",
            "message": f"Failed to terminate IR shell: {e}"
        }

def handle_update_command(params):
    """Handle a client update command."""
    try:
        logging.info("[COMMAND] Triggering client update")
        
        # Import updater and run the update check
        import updater
        result = updater.check_for_updates(force=True)
        
        if result.get("updated"):
            return {
                "status": "success",
                "message": "Update successfully applied",
                "update_info": {
                    "version": result.get("version", "Unknown"),
                    "changes": result.get("changes", [])
                }
            }
        else:
            return {
                "status": "success",
                "message": "No updates available",
                "update_info": {
                    "version": result.get("version", "Current")
                }
            }
    except Exception as e:
        logging.error(f"[ERROR] Update failed: {e}")
        return {
            "status": "error",
            "message": f"Update failed: {e}"
        }

###### IR Shell code

def start_ir_shell(port):
    """Start a limited shell for incident response purposes."""
    global ir_shell_active
    
    try:
        # Create a socket server for the shell
        shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        shell_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        shell_socket.bind(("0.0.0.0", port))
        shell_socket.listen(1)
        
        logging.info(f"[IR-SHELL] Listening on port {port}")
        
        # Set a timeout for the shell (30 minutes)
        shell_socket.settimeout(1800)
        
        try:
            # Accept one connection
            client, addr = shell_socket.accept()
            logging.info(f"[IR-SHELL] Connection from {addr}")
            
            # Send banner
            client.sendall(b"MoniSec Incident Response Shell\n")
            client.sendall(b"Type 'help' for available commands\n")
            client.sendall(b"> ")
            
            # Handle the shell session
            while ir_shell_active:
                # Check for data with a short timeout
                readable, _, _ = select.select([client], [], [], 0.5)
                
                if readable:
                    # Receive command
                    command = client.recv(1024).decode("utf-8").strip()
                    
                    if not command:
                        break
                        
                    if command.lower() in ["exit", "quit"]:
                        client.sendall(b"Closing IR shell\n")
                        break
                        
                    # Process the command
                    result = execute_ir_command(command)
                    client.sendall(result.encode("utf-8"))
                    client.sendall(b"\n> ")
        except socket.timeout:
            logging.info("[IR-SHELL] Session timed out after 30 minutes")
        except Exception as e:
            logging.error(f"[IR-SHELL] Error in shell session: {e}")
        finally:
            if 'client' in locals():
                client.close()
    
    except Exception as e:
        logging.error(f"[IR-SHELL] Failed to start shell: {e}")
    finally:
        ir_shell_active = False
        if 'shell_socket' in locals():
            shell_socket.close()
        logging.info("[IR-SHELL] Shell terminated")

def execute_ir_command(command):
    """Execute a command in the IR shell with improved permissions while maintaining security."""
    # List of allowed commands for IR purposes
    allowed_commands = {
        "help": "Show this help message",
        "ps": "List running processes",
        "ps -ef": "List all running processes with full details",
        "ps aux": "List all running processes with resource usage",
        "top -n 1": "Show current process activity (non-interactive)",
        "netstat -an": "Show all network connections",
        "netstat -tuln": "Show listening ports",
        "ss -tuln": "Show socket statistics",
        "lsof": "List open files",
        "ifconfig": "Show network interfaces",
        "ip a": "Show IP address information",
        "ls": "List files in current directory",
        "ls -la": "List all files with details",
        "pwd": "Show current directory",
        "cat": "Show file contents",
        "head": "Show first lines of a file",
        "tail": "Show last lines of a file",
        "grep": "Search for patterns",
        "find": "Find files",
        "md5sum": "Calculate MD5 hash",
        "sha256sum": "Calculate SHA256 hash",
        "file": "Determine file type",
        "uname -a": "Show system information",
        "whoami": "Show current user",
        "id": "Show user identity",
        "w": "Show who is logged in",
        "who": "Show logged in users",
        "hostname": "Show system hostname",
        "date": "Show current date and time",
        "uptime": "Show system uptime",
        "df -h": "Show disk space usage",
        "du -sh": "Show directory size",
        "free -h": "Show memory usage",
        "last": "Show login history",
        "lastlog": "Show last login of all users",
        "history": "Show command history",
        "pstree": "Show process tree",
        "strings": "Extract text from binary files",
        "stat": "Display file or filesystem status",
        "which": "Show location of commands",
        "crontab -l": "List scheduled tasks",
        "systemctl list-timers": "Show systemd timers",
        "iptables -L": "List firewall rules",
        "journalctl -n 50": "Show recent system logs",
        # Custom built-in commands
        "sysinfo": "Show basic system information",
        "meminfo": "Show memory information",
        "procinfo": "Show process information",
        "netinfo": "Show network information",
        "loginfo": "Show log information",
        "secinfo": "Show security information"
    }
    
    # Parse the command
    cmd_parts = command.split(maxsplit=1)
    if not cmd_parts:
        return "Empty command"
        
    cmd = cmd_parts[0].lower()
    
    # Check if it's a help request
    if cmd == "help":
        result = "Available commands:\n"
        for cmd_name, cmd_desc in sorted(allowed_commands.items()):
            result += f"  {cmd_name:20} - {cmd_desc}\n"
        return result
    
    # Special handling for custom built-in commands
    if cmd == "sysinfo":
        return get_basic_system_info()
    elif cmd == "meminfo":
        return get_basic_memory_info()
    elif cmd == "procinfo":
        return get_basic_process_info()
    elif cmd == "netinfo":
        return get_basic_network_info()
    elif cmd == "loginfo":
        return get_basic_log_info()
    elif cmd == "secinfo":
        return get_basic_security_info()
    
    # Full command with arguments
    full_cmd = command.strip()
    
    # Check if the exact command is in our allowed list
    if full_cmd in allowed_commands:
        try:
            # Execute the full command with a reasonable timeout
            result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True, timeout=30)
            return result.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            return f"Command failed with code {e.returncode}:\n{e.output.decode('utf-8', errors='replace')}"
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            return f"Error executing command: {e}"
    
    # Extract base command for complex commands
    base_commands = [c.split()[0] for c in allowed_commands.keys()]
    
    # Check if the base command is allowed
    if cmd not in base_commands:
        return f"Command '{cmd}' not allowed in IR shell"
    
    # Handle command with arguments
    args = cmd_parts[1] if len(cmd_parts) > 1 else ""
    
    # Security check for arguments to prevent command injection
    if ";" in args or "|" in args or "&" in args or "`" in args or "$(" in args:
        return f"Invalid argument (security restriction): {args}"
    
    # Execute the command with arguments
    try:
        full_cmd = f"{cmd} {args}"
        result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True, timeout=30)
        return result.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        return f"Command failed with code {e.returncode}:\n{e.output.decode('utf-8', errors='replace')}"
    except subprocess.TimeoutExpired:
        return "Command timed out after 30 seconds"
    except Exception as e:
        return f"Error executing command: {e}"

def get_basic_system_info():
    """Return basic system information."""
    try:
        info = []
        info.append("--- System Information ---\n")
        
        # Basic OS info
        try:
            uname = subprocess.check_output("uname -a", shell=True).decode("utf-8")
            info.append(f"System: {uname}")
        except Exception as e:
            info.append(f"System information unavailable: {e}")
            
        # Hostname
        try:
            hostname = subprocess.check_output("hostname", shell=True).decode("utf-8").strip()
            info.append(f"Hostname: {hostname}")
        except Exception as e:
            info.append(f"Hostname unavailable: {e}")
            
        # Uptime
        try:
            uptime = subprocess.check_output("uptime", shell=True).decode("utf-8").strip()
            info.append(f"Uptime: {uptime}")
        except Exception as e:
            info.append(f"Uptime unavailable: {e}")
            
        # Kernel version
        try:
            kernel = subprocess.check_output("uname -r", shell=True).decode("utf-8").strip()
            info.append(f"Kernel version: {kernel}")
        except Exception as e:
            info.append(f"Kernel version unavailable: {e}")
        
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving system information: {e}"

def get_basic_memory_info():
    """Return basic memory information."""
    try:
        info = []
        info.append("--- Memory Information ---\n")
        
        # Memory usage with free
        try:
            memory = subprocess.check_output("free -h", shell=True).decode("utf-8")
            info.append(memory)
        except Exception as e:
            info.append(f"Memory usage unavailable: {e}")
            
        # Top memory consumers
        try:
            top_processes = subprocess.check_output(
                "ps aux --sort=-%mem | head -11", shell=True
            ).decode("utf-8")
            info.append("\nTop Memory Consumers:")
            info.append(top_processes)
        except Exception as e:
            info.append(f"Top memory consumers unavailable: {e}")
        
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving memory information: {e}"

def get_basic_process_info():
    """Return basic process information."""
    try:
        info = []
        info.append("--- Process Information ---\n")
        
        # Running processes count
        try:
            process_count = subprocess.check_output(
                "ps aux | wc -l", shell=True
            ).decode("utf-8").strip()
            info.append(f"Total processes: {int(process_count) - 1}")  # Subtract header
        except Exception as e:
            info.append(f"Process count unavailable: {e}")
            
        # Top CPU consumers
        try:
            top_cpu = subprocess.check_output(
                "ps aux --sort=-%cpu | head -11", shell=True
            ).decode("utf-8")
            info.append("\nTop CPU Consumers:")
            info.append(top_cpu)
        except Exception as e:
            info.append(f"Top CPU consumers unavailable: {e}")
            
        # Recently started processes
        try:
            recent = subprocess.check_output(
                "ps -eo pid,lstart,args --sort=-start_time | head -11", shell=True
            ).decode("utf-8")
            info.append("\nRecently Started Processes:")
            info.append(recent)
        except Exception as e:
            info.append(f"Recent processes unavailable: {e}")
        
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving process information: {e}"

def get_basic_network_info():
    """Return basic network information."""
    try:
        info = []
        info.append("--- Network Information ---\n")
        
        # Network interfaces
        try:
            interfaces = subprocess.check_output("ip a", shell=True).decode("utf-8")
            info.append("Network Interfaces:")
            info.append(interfaces)
        except Exception as e:
            try:
                # Fallback to ifconfig if ip command not available
                interfaces = subprocess.check_output("ifconfig", shell=True).decode("utf-8")
                info.append("Network Interfaces:")
                info.append(interfaces)
            except Exception as e2:
                info.append(f"Network interfaces unavailable: {e}, {e2}")
                
        # Listening ports
        try:
            listening = subprocess.check_output(
                "netstat -tuln | grep LISTEN", shell=True
            ).decode("utf-8")
            info.append("\nListening Ports:")
            info.append(listening)
        except Exception as e:
            try:
                # Fallback to ss if netstat not available
                listening = subprocess.check_output(
                    "ss -tuln | grep LISTEN", shell=True
                ).decode("utf-8")
                info.append("\nListening Ports:")
                info.append(listening)
            except Exception as e2:
                info.append(f"Listening ports unavailable: {e}, {e2}")
                
        # Established connections
        try:
            established = subprocess.check_output(
                "netstat -tn | grep ESTABLISHED | head -10", shell=True
            ).decode("utf-8")
            info.append("\nEstablished Connections (top 10):")
            info.append(established)
        except Exception as e:
            info.append(f"Established connections unavailable: {e}")
        
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving network information: {e}"

def get_basic_log_info():
    """Return basic log information."""
    try:
        info = []
        info.append("--- Log Information ---")
        
        # Recent system logs with sudo using full path
        try:
            if os.path.exists("/var/log/syslog"):
                log_file = "/var/log/syslog"
            elif os.path.exists("/var/log/messages"):
                log_file = "/var/log/messages"
            else:
                log_file = None
                
            if log_file:
                recent_logs = subprocess.check_output(
                    f"sudo /bin/cat {log_file} | sudo /usr/bin/tail -n 20", shell=True
                ).decode("utf-8")
                info.append(f"Recent System Logs ({log_file}):")
                info.append(recent_logs)
            else:
                info.append("No standard system log file found")
        except Exception as e:
            info.append(f"Recent system logs unavailable: {e}")
            
        # Recent auth logs with sudo using full path
        try:
            if os.path.exists("/var/log/auth.log"):
                auth_file = "/var/log/auth.log"
            elif os.path.exists("/var/log/secure"):
                auth_file = "/var/log/secure"
            else:
                auth_file = None
                
            if auth_file:
                auth_logs = subprocess.check_output(
                    f"sudo /bin/cat {auth_file} | sudo /usr/bin/tail -n 10", shell=True
                ).decode("utf-8")
                info.append(f"\nRecent Authentication Logs ({auth_file}):")
                info.append(auth_logs)
            else:
                info.append("\nNo standard authentication log file found")
        except Exception as e:
            info.append(f"\nRecent authentication logs unavailable: {e}")
            
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving log information: {e}"

def get_basic_security_info():
    """Return basic security information about the system."""
    try:
        info = []
        info.append("--- Security Information ---")
        
        # Check for active users
        try:
            who_output = subprocess.check_output("who", shell=True).decode("utf-8")
            info.append("Active Users:")
            info.append(who_output)
        except Exception as e:
            info.append(f"Active users unavailable: {e}")
        
        # Check for failed login attempts - UPDATED to use sudo with full path
        try:
            if os.path.exists("/var/log/auth.log"):
                grep_cmd = "sudo /bin/cat /var/log/auth.log | sudo /usr/bin/grep 'Failed password' | sudo /usr/bin/tail -5"
            elif os.path.exists("/var/log/secure"):
                grep_cmd = "sudo /bin/cat /var/log/secure | sudo /usr/bin/grep 'Failed password' | sudo /usr/bin/tail -5"
            else:
                grep_cmd = None
                
            if grep_cmd:
                failed_logins = subprocess.check_output(grep_cmd, shell=True).decode("utf-8")
                info.append("Recent Failed Login Attempts:")
                info.append(failed_logins if failed_logins.strip() else "No failed login attempts found")
            else:
                info.append("Could not locate authentication log files")
        except Exception as e:
            info.append("Recent Failed Login Attempts:")
            info.append(f"Could not access auth logs: {e}")
        
        # Check for listening ports
        try:
            netstat_output = subprocess.check_output(
                "netstat -tuln | grep LISTEN", shell=True
            ).decode("utf-8")
            info.append("Listening Ports:")
            info.append(netstat_output)
        except Exception as e:
            try:
                # Fallback to ss if netstat not available
                ss_output = subprocess.check_output(
                    "ss -tuln | grep LISTEN", shell=True
                ).decode("utf-8")
                info.append("Listening Ports:")
                info.append(ss_output)
            except Exception as e2:
                info.append(f"Listening ports unavailable: {e}, {e2}")
        
        # Check for SUID files - UPDATED to use sudo with full path
        try:
            # Safely limit the scope of SUID search to avoid performance issues
            suid_output = subprocess.check_output(
                "sudo /usr/bin/find /usr/bin -perm -4000 -ls 2>/dev/null | sudo /usr/bin/head -10", 
                shell=True, timeout=5
            ).decode("utf-8")
            info.append("SUID Files (limited to first 10 in /usr/bin):")
            info.append(suid_output if suid_output else "No SUID files found in /usr/bin")
        except Exception as e:
            info.append(f"SUID files search unavailable: {e}")
        
        return "\n".join(info)
    except Exception as e:
        return f"Error retrieving security information: {e}"

#### Start websocket IR shell code

async def websocket_client_connect(server_ip, client_name, psk):
    """Connect to WebSocket server, authenticate, and start command polling."""
    global websocket_connected, websocket_client, websocket_reconnect_delay

    uri = f"ws://{server_ip}:8765/ws"
    connection_error_logged = False
    local_reconnect_delay = 15  # Fixed 15 second delay as requested

    while not websocket_shutdown_event.is_set():
        try:
            async with websockets.connect(uri, ping_interval=15, ping_timeout=10) as websocket:
                # Connection successful
                if connection_error_logged:
                    connection_error_logged = False
                
                websocket_client = websocket
                websocket_connected = True
                websocket_reconnect_delay = 5  # Reset global delay on success

                # Authentication handshake
                await websocket.send(json.dumps({
                    "client_name": client_name,
                    "client_version": "1.0",
                    "nat_status": "detected"
                }))

                challenge_msg = await websocket.recv()
                challenge_data = json.loads(challenge_msg)
                challenge = challenge_data.get("challenge")

                response_hmac = hmac.new(psk.encode(), challenge.encode(), hashlib.sha256).hexdigest()
                await websocket.send(json.dumps({"hmac": response_hmac}))

                auth_result = json.loads(await websocket.recv())
                if auth_result.get("status") != "success":
                    if not connection_error_logged:
                        logging.error("[WEBSOCKET] Auth failed")
                        connection_error_logged = True
                    websocket_connected = False
                    await asyncio.sleep(local_reconnect_delay)
                    continue

                # Launch command poller and heartbeat tasks
                poll_task = asyncio.create_task(poll_for_commands(client_name, websocket))
                heartbeat_task = asyncio.create_task(maintain_heartbeat(websocket))

                # Send an immediate poll request after connection
                await poll_for_commands_now(websocket)

                try:
                    while not websocket_shutdown_event.is_set():
                        message = await websocket.recv()
                        await process_websocket_message(websocket, message)
                except websockets.exceptions.ConnectionClosed:
                    websocket_connected = False
                    if not connection_error_logged:
                        connection_error_logged = True
                finally:
                    # Cancel the background tasks when connection is closed
                    poll_task.cancel()
                    heartbeat_task.cancel()
                    try:
                        # Wait for tasks to complete their cancellation
                        await asyncio.gather(poll_task, heartbeat_task, return_exceptions=True)
                    except asyncio.CancelledError:
                        pass

        except Exception as e:
            websocket_connected = False
            
            # Only log the first error in a series of failures
            if not connection_error_logged:
                logging.warning("[WEBSOCKET] Connection error. Will retry every 15 seconds...")
                connection_error_logged = True
            
            # Use fixed delay as requested
            await asyncio.sleep(local_reconnect_delay)

async def websocket_heartbeat(websocket):
    """Enhanced heartbeat function with better failure detection."""
    heartbeat_interval = 30  # seconds
    missed_heartbeats = 0
    max_missed = 3  # Reconnect after 3 missed responses

    while not websocket_shutdown_event.is_set():
        try:
            # Send heartbeat message
            await websocket.send(json.dumps({
                "type": "heartbeat",
                "timestamp": time.time()
            }))

            # Wait for response with timeout
            try:
                # Use a shorter timeout than the heartbeat interval
                response_wait = asyncio.wait_for(websocket.recv(), timeout=10)
                response = await response_wait
                response_data = json.loads(response)
                
                if response_data.get("type") == "heartbeat_ack":
                    # Reset counter on successful heartbeat
                    missed_heartbeats = 0
                # If it's not a heartbeat_ack, we still got a response, so connection is alive
                
            except asyncio.TimeoutError:
                missed_heartbeats += 1
                logging.warning(f"[WEBSOCKET] Missed heartbeat response: {missed_heartbeats}/{max_missed}")
                
                if missed_heartbeats >= max_missed:
                    logging.error("[WEBSOCKET] Too many missed heartbeats, connection likely dead")
                    return  # Exit the function to trigger reconnection
            
            # Wait for the next interval
            await asyncio.sleep(heartbeat_interval)

        except Exception as e:
            logging.error(f"[WEBSOCKET] Heartbeat error: {e}")
            break  # Exit loop to allow reconnection

async def maintain_heartbeat(websocket):
    """Send periodic heartbeats to keep the connection alive."""
    try:
        while True:
            try:
                # Send heartbeat message
                await websocket.send(json.dumps({
                    "type": "heartbeat",
                    "timestamp": time.time()
                }))
                
                # Wait for the next interval
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
            except asyncio.CancelledError:
                return
            except Exception as e:
                logging.error(f"[WEBSOCKET] Heartbeat error: {e}")
                return  # Exit heartbeat process to allow reconnection
    except Exception as e:
        logging.error(f"[WEBSOCKET] Heartbeat task error: {e}")

async def process_shell_command(websocket, client_name, command, command_id):
    """Process a single shell command and send the response."""
    global ir_shell_active
    
    try:
        # Execute different command types
        if command == "ir-shell-init":
            ir_shell_active = True
            response = {
                "status": "success",
                "message": "IR shell initialized"
            }
            logging.info("[WEBSOCKET] IR shell initialized")
            
        elif command == "ir-shell-exit":
            ir_shell_active = False
            response = {
                "status": "success",
                "message": "IR shell terminated"
            }
            logging.info("[WEBSOCKET] IR shell terminated")
            
        else:
            # Execute command if IR shell is active
            if not ir_shell_active:
                response = {
                    "status": "error",
                    "message": "No active IR shell session"
                }
                logging.warning("[WEBSOCKET] Command rejected - IR shell not active")
            else:
                # Execute the command
                output = execute_ir_command(command)
                response = {
                    "status": "success",
                    "output": output
                }
                logging.info(f"[WEBSOCKET] Executed command: {command}")
        
        # Send the response
        await websocket.send(json.dumps({
            "type": "ir_shell_response",
            "command_id": command_id,
            "response": response
        }))
        #logging.info(f"[WEBSOCKET] Sent response for command ID: {command_id}")
        
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error processing command {command}: {e}")
        try:
            # Try to send error response
            await websocket.send(json.dumps({
                "type": "ir_shell_response",
                "command_id": command_id,
                "response": {
                    "status": "error",
                    "message": f"Error processing command: {str(e)}"
                }
            }))
        except:
            logging.error("[WEBSOCKET] Failed to send error response")

async def process_websocket_command(websocket, message):
    """Process commands received over WebSocket with proper handling of all message types."""
    global ir_shell_active

    try:
        # Parse the message as JSON
        data = json.loads(message)
        command_type = data.get("type")
        
        # Handle different message types
        if command_type == "ir_shell_command":
            # Extract command details
            command_id = data.get("command_id")
            command = data.get("command")
            
            # Process different IR shell commands
            if command == "ir-shell-init":
                # Initialize IR shell
                ir_shell_active = True
                response = {
                    "status": "success",
                    "message": "IR shell initialized"
                }
                
            elif command == "ir-shell-exit":
                # Terminate IR shell
                ir_shell_active = False
                response = {
                    "status": "success",
                    "message": "IR shell terminated"
                }
                
            else:
                # Execute command if IR shell is active
                if not ir_shell_active:
                    response = {
                        "status": "error",
                        "message": "No active IR shell session"
                    }
                    logging.warning("[WEBSOCKET] IR shell command received but no session is active")
                else:
                    # Execute the command
                    output = execute_ir_command(command)
                    response = {
                        "status": "success",
                        "output": output
                    }
            
            # Send the response
            await websocket.send(json.dumps({
                "type": "ir_shell_response",
                "command_id": command_id,
                "response": response
            }))
            
        elif command_type == "heartbeat":
            # Simply respond to the heartbeat with our own
            await websocket.send(json.dumps({
                "type": "heartbeat",
                "timestamp": time.time()
            }))
            
        elif command_type == "heartbeat_ack":
            # Just acknowledge the receipt
            pass
            
        else:
            logging.warning(f"[WEBSOCKET] Unknown command type received: {command_type}")
            
    except json.JSONDecodeError:
        logging.error(f"[WEBSOCKET] Invalid JSON message: {message[:100]}")
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error processing message: {e}")
        import traceback
        logging.error(traceback.format_exc())

async def process_websocket_message(websocket, message):
    """Process incoming WebSocket messages with improved logging and error handling."""
    global ir_shell_active
    
    try:
        data = json.loads(message)
        message_type = data.get("type")
        
        if message_type == "pending_commands":
            commands = data.get("commands", [])
            
            if not commands:
                return
            
            # Process each command
            for cmd in commands:
                # Get command details
                command = cmd.get("shell_command")
                command_id = cmd.get("command_id")
                
                if not command or not command_id:
                    logging.warning(f"[WEBSOCKET] Incomplete command data: {cmd}")
                    continue
                
                # Handle the command based on type
                if command == "ir-shell-init":
                    # Initialize IR shell
                    ir_shell_active = True
                    response = {
                        "status": "success",
                        "message": "IR shell initialized"
                    }
                    
                elif command == "ir-shell-exit":
                    # Terminate IR shell
                    ir_shell_active = False
                    response = {
                        "status": "success",
                        "message": "IR shell terminated"
                    }
                    
                else:
                    # Execute command if IR shell is active
                    if not ir_shell_active:
                        response = {
                            "status": "error",
                            "message": "No active IR shell session"
                        }
                        logging.warning("[WEBSOCKET] Command rejected - IR shell not active")
                    else:
                        # Execute the command
                        try:
                            output = execute_ir_command(command)
                            response = {
                                "status": "success",
                                "output": output
                            }
                        except Exception as e:
                            response = {
                                "status": "error",
                                "message": f"Command execution failed: {str(e)}"
                            }
                            logging.error(f"[WEBSOCKET] Command execution failed: {e}")
                
                # Send the response with the right format
                try:
                    response_msg = {
                        "type": "ir_shell_response",
                        "command_id": command_id,
                        "response": response
                    }
                    await websocket.send(json.dumps(response_msg))
                except Exception as e:
                    logging.error(f"[WEBSOCKET] Failed to send response for command {command_id}: {e}")
        
        elif message_type == "heartbeat":
            await websocket.send(json.dumps({
                "type": "heartbeat_ack",
                "timestamp": time.time()
            }))
            
        elif message_type == "heartbeat_ack":
            pass
            
        else:
            logging.warning(f"[WEBSOCKET] Unknown message type: {message_type}")
            
    except json.JSONDecodeError:
        logging.error(f"[WEBSOCKET] Invalid JSON message: {message[:100]}")
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error processing message: {e}")
        import traceback
        logging.error(traceback.format_exc())

def maintain_websocket_connection():
    """Maintain a persistent WebSocket connection with automatic reconnection."""
    global websocket_client, websocket_connected, websocket_client_started
    
    # First check if authentication is valid before attempting to maintain connection
    is_valid, _ = validate_auth_token()
    if not is_valid:
        return
    
    # Track state to minimize logging
    connection_error_shown = False
    last_connection_state = websocket_connected
    
    while not websocket_shutdown_event.is_set():
        try:
            # Check if we need to reconnect
            if not websocket_connected and not websocket_client_started:
                # Only log the initial disconnection, not every retry
                if last_connection_state or not connection_error_shown:
                    connection_error_shown = True
                
                # Start connection attempt
                start_websocket_client()
            elif websocket_connected and connection_error_shown:
                # We've reconnected, reset the error flag
                connection_error_shown = False
            
            # Store current state for next comparison
            last_connection_state = websocket_connected
            
            # Check connection every 15 seconds
            time.sleep(15)
        except Exception as e:
            if not connection_error_shown:
                logging.error("[WEBSOCKET] Connection monitor error. Will continue retrying silently.")
                connection_error_shown = True
            time.sleep(15)

def start_websocket_client():
    """Start the WebSocket client in a background thread with its own event loop."""
    global websocket_client_started, websocket_client_lock, websocket_connected

    with websocket_client_lock:
        if websocket_client_started:
            return

        # Validate authentication token before starting WebSocket client
        is_valid, error_message = validate_auth_token()
        if not is_valid:
            logging.warning(f"[WEBSOCKET] {error_message}. WebSocket client will not start.")
            return

        try:
            with open(AUTH_TOKEN_FILE, 'r') as f:
                data = json.load(f)

            server_ip = data.get("server_ip")
            client_name = data.get("client_name")
            psk = data.get("psk")

            websocket_shutdown_event.clear()

            def run():
                global websocket_client_started
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                websocket_client_started = True
                try:
                    loop.run_until_complete(websocket_client_connect(server_ip, client_name, psk))
                finally:
                    websocket_client_started = False
                    loop.close()

            threading.Thread(target=run, daemon=True).start()

        except Exception as e:
            logging.error(f"[WEBSOCKET] Launch error: {e}")
            websocket_client_started = False

def detect_nat_and_set_connection_mode():
    """
    Detect if the client is behind NAT and set the appropriate connection mode.
    Returns True if WebSocket should be used, False if direct TCP is sufficient.
    """
    try:
        # Load auth token to get server details
        if not os.path.exists(AUTH_TOKEN_FILE):
            return False
            
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data.get("server_ip")
            
        if not server_ip:
            return False
        
        # Step 1: Try to establish a TCP connection to the server
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        
        try:
            test_socket.connect((server_ip, 5555))
            
            # Step 2: Get our local IP address from this connection
            local_ip, local_port = test_socket.getsockname()
            
            # Step 3: Ask the server what IP it sees for us
            handshake = json.dumps({"command": "get_client_ip"})
            test_socket.sendall(handshake.encode("utf-8"))
            
            response = test_socket.recv(1024).decode("utf-8")
            remote_view = json.loads(response)
            remote_ip = remote_view.get("client_ip")
            
            # Compare the IPs - if different, we're likely behind NAT
            is_natted = (local_ip != remote_ip)
            
            return is_natted
            
        except Exception as e:
            # If we can't connect, assume we need WebSocket for reliability
            return True
            
    except Exception as e:
        return True  # Default to WebSocket on error for reliability
    finally:
        if 'test_socket' in locals():
            test_socket.close()
            
async def poll_for_commands(client_name, websocket):
    """Poll the server for pending commands on a regular interval."""
    try:
        while True:
            try:
                # Send poll request
                await websocket.send(json.dumps({
                    "type": "poll_commands",
                    "client_name": client_name,
                    "timestamp": time.time()
                }))
            except Exception as e:
                logging.error(f"[COMMAND-POLL] Failed to send poll request: {e}")
                
            # Wait before next poll
            await asyncio.sleep(5)  # Poll every 5 seconds
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"[COMMAND-POLL] Error in polling task: {e}")
        import traceback
        logging.error(traceback.format_exc())
        
async def poll_for_commands_now(websocket):
    """Send an immediate request to poll for pending commands."""
    try:
        # Get client_name from auth token file
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            client_name = token_data.get("client_name")
            
        if not client_name:
            logging.error("[COMMAND-POLL] Cannot poll: client_name not found in auth token")
            return

        # Send poll request
        await websocket.send(json.dumps({
            "type": "poll_commands",
            "client_name": client_name,
            "timestamp": time.time()
        }))

    except Exception as e:
        logging.error(f"[COMMAND-POLL] Poll request error: {e}")
