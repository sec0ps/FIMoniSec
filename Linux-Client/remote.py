# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
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
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

# Global flag to track if an IR shell is currently active
ir_shell_active = False

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
                logging.warning("[WARNING] Incomplete authentication token. Logging locally only.")
        except Exception as e:
            logging.error(f"[ERROR] Failed to read authentication token: {e}")
    else:
        logging.info("[INFO] No authentication token found. Logging locally only.")
        
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
            "message": f"YARA scan completed. Found {len(results)} matches.",
            "results": results
        }
    except Exception as e:
        logging.error(f"[ERROR] YARA scan failed: {e}")
        return {
            "status": "error",
            "message": f"YARA scan failed: {e}"
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
    """Execute a command in the IR shell with limited privileges."""
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
            result = subprocess.check_output(full_cmd, stderr=subprocess.STDOUT, shell=True, timeout=10)
            return result.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            return f"Command failed with code {e.returncode}:\n{e.output.decode('utf-8', errors='replace')}"
        except subprocess.TimeoutExpired:
            return "Command timed out after 10 seconds"
        except Exception as e:
            return f"Error executing command: {e}"
    
    # Check if the base command is allowed
    if cmd not in allowed_commands and not any(cmd_alias.startswith(cmd + " ") for cmd_alias in allowed_commands):
        return f"Command '{cmd}' not allowed in IR shell"
    
    # Handle command with arguments (checking for path traversal and other security issues)
    args = cmd_parts[1] if len(cmd_parts) > 1 else ""
    
    # Security check for arguments
    if ".." in args or args.startswith("/") or ";" in args or "|" in args or "&" in args or "`" in args or "$" in args:
        return f"Invalid argument (security restriction): {args}"
    
    # Whitelist approach for commands with arguments
    if cmd == "ls":
        # Allow only specific options for ls
        if args.startswith("-"):
            allowed_options = ["-l", "-a", "-la", "-al", "-lh", "-lah", "-alh"]
            option_part = args.split()[0] if args.split() else ""
            if option_part not in allowed_options:
                return f"Unsupported options for ls: {option_part}"
    elif cmd in ["cat", "head", "tail"]:
        # Only allow reading files from safe locations
        safe_paths = ["/proc", "/var/log", "/etc", "./logs", "~/"]
        if not any(args.startswith(path) for path in safe_paths) and not args.startswith("."):
            return f"Access to {args} is restricted. You can only access files in: {', '.join(safe_paths)}"
        
    # Execute the command with proper arguments
    try:
        # Use shell=True for commands like "ps aux" that use shell features
        result = subprocess.check_output(f"{cmd} {args}", stderr=subprocess.STDOUT, shell=True, timeout=10)
        return result.decode("utf-8", errors="replace")
    except subprocess.CalledProcessError as e:
        return f"Command failed with code {e.returncode}:\n{e.output.decode('utf-8', errors='replace')}"
    except subprocess.TimeoutExpired:
        return "Command timed out after 10 seconds"
    except Exception as e:
        return f"Error executing command: {e}"
