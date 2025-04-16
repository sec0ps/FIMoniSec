# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution (Windows Version)
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
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
import win32file
import win32pipe
import win32con
import win32process
import win32security
import win32api
import win32event
import pywintypes
import ctypes
import re
from pathlib import Path
from client_crypt import encrypt_data, decrypt_data
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

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

def get_base_dir():
    """Get the base directory for the application based on script location"""
    return os.path.dirname(os.path.abspath(__file__))

# Define BASE_DIR statically for Windows
BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")

# Update LOG_FILES and LOG_FILE paths for Windows
LOG_FILES = [os.path.join(BASE_DIR, "logs\\file_monitor.json")]
LOG_FILE = os.path.join(BASE_DIR, "logs\\file_monitor.json")

# Update AUTH_TOKEN_FILE path for Windows
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
        logging.info(f"{error_message}. Running in local-only mode.")
        return False
        
    # Authentication token is valid, proceed with connection setup
    try:
        with open(AUTH_TOKEN_FILE, 'r') as f:
            auth_data = json.load(f)
            
        # Detect NAT status to decide on connection method
        use_websocket = detect_nat_and_set_connection_mode()
        
        # Log connection information
        logging.info(f"Authentication verified. Starting client connectivity to server {auth_data['server_ip']}...")
        
        if use_websocket:
            logging.info("[CONN] NAT detected or connection issue - using WebSocket as primary connection")
            
            # Start the WebSocket client in a thread
            websocket_thread = threading.Thread(target=start_websocket_client, daemon=True)
            websocket_thread.start()
            
            # Also try direct connection as backup
            listener_thread = threading.Thread(target=start_client_listener, daemon=True)
            listener_thread.start()
            
        else:
            logging.info("[CONN] Direct connectivity available - using TCP as primary connection")
            
            # Start the listener in a thread for direct commands
            listener_thread = threading.Thread(target=start_client_listener, daemon=True)
            listener_thread.start()
            
            # Also start WebSocket as a secondary channel
            websocket_thread = threading.Thread(target=start_websocket_client, daemon=True)
            websocket_thread.start()
        
        return True
        
    except Exception as e:
        logging.error(f"Error starting authorized listener: {e}")
        return False
        
def start_client_listener():
    """Starts a TCP server to receive and execute remote commands from monisec-server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
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
        # Windows-specific error handling for socket issues
        if e.winerror == 10048:  # Address already in use
            logging.error(f"Port {CLIENT_PORT} is already in use. Another instance may be running.")
        else:
            logging.error(f"Could not start listening service: {e}")
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
    
    # Set Windows file security to restrict access to Administrators and SYSTEM
    try:
        # Get a security descriptor for the file
        sd = win32security.GetFileSecurity(
            AUTH_TOKEN_FILE, 
            win32security.DACL_SECURITY_INFORMATION
        )
        
        # Create a new DACL (Discretionary Access Control List)
        dacl = win32security.ACL()
        
        # Add ACEs (Access Control Entries) for specific principals
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        # Grant full control to Administrators and SYSTEM
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
        
        # Set the new DACL
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            AUTH_TOKEN_FILE, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
    except Exception as e:
        logging.warning(f"Failed to set secure permissions on auth token file: {e}")

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

        # Send the initial JSON handshake with client_name
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

        # Windows TCP keepalive settings
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))

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

    except (socket.timeout, socket.error, OSError) as e:
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

def send_logs_to_server():
    """Continuously monitor log files and send new entries to the server."""
    RETRIES = 5
    DELAY = 3
    CHUNKING_THRESHOLD = 4000

    try:
        logging.info(f"[LOGS] Starting log transmission service with files: {LOG_FILES}")

        # Log file diagnostics
        for log_file in LOG_FILES:
            exists = os.path.exists(log_file)
            size = os.path.getsize(log_file) if exists else 0
            
            # Get Windows file permissions instead of Unix-style ones
            try:
                sd = win32security.GetFileSecurity(
                    log_file, 
                    win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
                ) if exists else None
                
                owner_sid = sd.GetSecurityDescriptorOwner() if sd else None
                owner_name = "Unknown"
                
                if owner_sid:
                    try:
                        domain, name, account_type = win32security.LookupAccountSid(None, owner_sid)
                        owner_name = f"{domain}\\{name}"
                    except:
                        owner_name = "SID: " + str(owner_sid)
                
                permissions = f"Owner: {owner_name}" if exists else "N/A"
            except Exception as e:
                permissions = f"Error getting permissions: {e}"
            
            logging.info(f"[LOGS] Log file: {log_file}, Exists: {exists}, Size: {size}, Permissions: {permissions}")

        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data["server_ip"]
            client_name = token_data["client_name"]
            psk = token_data["psk"]

        # NAT Detection
        try:
            logging.info("[NAT-DETECT] Connecting to server at {}:5555...".format(server_ip))
            sock_nat = socket.create_connection((server_ip, 5555), timeout=5)
            sock_nat.sendall(json.dumps({"command": "get_client_ip"}).encode("utf-8"))
            response = sock_nat.recv(1024)
            server_view = json.loads(response.decode("utf-8"))
            if "client_ip" in server_view:
                logging.info(f"[NAT-DETECT] Server sees us as: {server_view['client_ip']}")
            sock_nat.close()
        except Exception as e:
            logging.warning(f"[NAT-DETECT] NAT detection failed: {e}")

        sock = None
        for attempt in range(RETRIES):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((server_ip, 5555))

                # Use the same method that works in authenticate_with_server()
                # Send a JSON handshake instead of an HMAC handshake
                handshake_data = {
                    "client_name": client_name,
                    "timestamp": time.time()
                }
                handshake_json = json.dumps(handshake_data)
                sock.sendall(handshake_json.encode("utf-8"))

                sock.settimeout(5)
                response = sock.recv(1024)
                logging.info(f"[LOGS] Handshake response from server: {response}")

                if not response or response != b"OK":
                    logging.warning(f"[LOGS] Bad handshake response: {response}")
                    if attempt < RETRIES - 1:  # Don't raise on the last attempt to allow the outer loop to handle it
                        continue
                    raise ConnectionError("Bad handshake response")

                logging.info(f"[LOGS] Connected to server and authenticated. Attempt {attempt + 1}")
                break
            except Exception as e:
                logging.error(f"[LOGS] Connection attempt {attempt + 1} failed: {e}")
                if sock:
                    sock.close()
                    sock = None
                time.sleep(DELAY)
        else:
            logging.critical("[LOGS] Could not connect to server after multiple attempts.")
            return

        file_positions = {
            log_file: os.path.getsize(log_file) if os.path.exists(log_file) else 0
            for log_file in LOG_FILES
        }
        for log_file, pos in file_positions.items():
            logging.info(f"[LOGS] Initial position for {log_file}: {pos}")

        while True:
            logs_to_send = {}
            for log_file in LOG_FILES:
                if os.path.exists(log_file):
                    try:
                        current_size = os.path.getsize(log_file)
                        if current_size < file_positions[log_file]:
                            logging.warning(f"[LOGS] Log file {log_file} rotated/truncated. Resetting position.")
                            file_positions[log_file] = 0

                        if current_size <= file_positions[log_file]:
                            continue

                        with open(log_file, "r") as f:
                            f.seek(file_positions[log_file])
                            new_logs = f.read()
                            new_position = f.tell()

                            if new_logs:
                                entries = extract_valid_json_objects(new_logs)
                                logging.info(f"[LOGS] Extracted {len(entries)} entries from {log_file}")

                                if entries:
                                    sample = str(entries[0])[:100]
                                    logging.info(f"[LOGS] Sample entry: {sample}...")

                                    if log_file not in logs_to_send:
                                        logs_to_send[log_file] = {
                                            "entries": [],
                                            "new_position": new_position
                                        }

                                    for entry in entries:
                                        if isinstance(entry, dict):
                                            entry["client_name"] = client_name
                                            logs_to_send[log_file]["entries"].append(entry)
                    except Exception as e:
                        logging.error(f"[LOGS] Error reading {log_file}: {e}")

            if any(data["entries"] for data in logs_to_send.values()):
                try:
                    all_logs = []
                    for data in logs_to_send.values():
                        all_logs.extend(data["entries"])

                    message = json.dumps({
                        "logs": all_logs,
                        "client_name": client_name
                    })

                    logging.info(f"[LOGS] Sending {len(all_logs)} logs to server...")
                    # Import client_crypt here to avoid circular imports
                    from client_crypt import encrypt_data
                    encrypted = encrypt_data(message)
                    
                    if len(encrypted) > CHUNKING_THRESHOLD:
                        logging.info(f"[LOGS] Sending chunked data ({len(encrypted)} bytes)")
                        success = send_chunked_data(sock, encrypted)
                        if not success:
                            raise ConnectionError("Chunked data send failed")
                    else:
                        sock.sendall(encrypted)

                    sock.settimeout(5)
                    ack = sock.recv(1024)
                    if ack == b"ACK":
                        logging.info(f"[LOGS] Logs sent and ACK received.")
                        for log_file, data in logs_to_send.items():
                            file_positions[log_file] = data["new_position"]
                    else:
                        logging.warning(f"[LOGS] Unexpected server response: {ack}")
                        if not ack:
                            raise ConnectionError("No ACK, possible disconnect")

                except Exception as e:
                    logging.error(f"[LOGS] Send error: {e}")
                    try:
                        sock.close()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(10)
                        sock.connect((server_ip, 5555))

                        # Use the same JSON handshake method that works for reconnection
                        handshake_data = {
                            "client_name": client_name,
                            "timestamp": time.time()
                        }
                        handshake_json = json.dumps(handshake_data)
                        sock.sendall(handshake_json.encode("utf-8"))

                        sock.settimeout(5)
                        response = sock.recv(1024)
                        logging.info(f"[LOGS] Reconnected. Handshake response: {response}")
                        
                        if not response or response != b"OK":
                            logging.warning(f"[LOGS] Reconnection failed: {response}")
                            raise ConnectionError("Failed to authenticate after reconnection")
                    except Exception as reconnect_err:
                        logging.error(f"[LOGS] Failed to reconnect: {reconnect_err}")
                        break

            time.sleep(2)

    except Exception as e:
        logging.error(f"[LOGS] Fatal client error: {e}")
    finally:
        if sock:
            sock.close()
            logging.info("[LOGS] Connection to server closed.")

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

def check_auth_and_send_logs():
    """Checks if auth_token.json exists and starts log transmission if valid."""
    # Validate authentication token
    is_valid, error_message = validate_auth_token()
    if not is_valid:
        logging.info(f"{error_message}. Logging locally only.")
        return False

    try:
        # Authenticate with server and proceed if successful
        success = authenticate_with_server()
        if success:
            logging.info("Authentication successful. Starting real-time log transmission...")
            
            # Start regular log transmission thread
            log_thread = threading.Thread(target=send_logs_to_server, daemon=True)
            log_thread.start()
            
            # Start WebSocket client for command channel
            start_websocket_client()
            return True
        else:
            logging.warning("Authentication failed. Logging locally only.")
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
            
            logging.info(f"[COMMAND] Received command: {command} with params: {params}")
            
            # Process the command
            if command == "restart":
                result = handle_restart_command(params)
            elif command == "yara-scan":
                result = handle_yara_scan_command(params)
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

def handle_yara_scan_command(params):
    """Handle a YARA scan command."""
    target_path = params.get("target_path")
    rule_name = params.get("rule_name")
    
    if not target_path:
        return {"status": "error", "message": "Missing target_path parameter"}
    
    try:
        logging.info(f"[COMMAND] Running YARA scan on path: {target_path}")
        
        # Import the YARA manager
        from malscan_yara import YaraManager
        yara_manager = YaraManager()
        
        # Ensure YARA rules are loaded
        if not yara_manager.ensure_rules_exist():
            return {"status": "error", "message": "Failed to load YARA rules"}
            
        # Run the scan
        if rule_name:
            # Scan with a specific rule
            matches = yara_manager.scan_with_rule(target_path, rule_name)
        else:
            # Scan with all rules
            matches = yara_manager.scan_path(target_path)
        
        # Format results
        results = []
        for match in matches:
            results.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "file": match.file
            })
        
        return {
            "status": "success",
            "
