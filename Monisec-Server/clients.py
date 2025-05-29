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
import os
import sys
import json
import hmac
import hashlib
import logging
import select
import socket
import threading
import time
import server_siem
import server_crypt
from shared_state import websocket_lock, IPC_SOCKET_PATH

# Define a fixed base directory for the server
SERVER_BASE_DIR = "/opt/FIMoniSec/Monisec-Server"
PSK_STORE_FILE = "psk_store.json"
ENDPOINT_LOG_FILE = os.path.join(SERVER_BASE_DIR, "logs", "siem-forwarding.log")

# Configure logging
logging.basicConfig(
    filename="./logs/monisec-server.log",  # ✅ Server logs remain separate
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def load_psks():
    """Load stored PSKs from a JSON file as a structured list."""
    if not os.path.exists(PSK_STORE_FILE):
        return {}

    try:
        with open(PSK_STORE_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_psks(psks):
    """Save PSK store as a structured list."""
    with open(PSK_STORE_FILE, "w") as f:
        json.dump(psks, f, indent=4)

# Generate a new PSK
def generate_psk():
    """Generate a random 32-byte PSK."""
    return os.urandom(32).hex()

def get_next_agent_id(psks):
    """Find the next available Agent ID."""
    if not psks:
        return 0
    return max(int(agent["AgentID"]) for agent in psks.values()) + 1

def add_agent():
    """Prompts user for Agent Name and IP, assigns a unique Agent ID, and stores it in JSON."""
    psks = load_psks()

    # Prompt the user for input
    agent_name = input("Enter Agent Name: ").strip()
    if not agent_name:
        print("[ERROR] Agent name cannot be empty.")
        return

    # Ensure unique agent name
    for agent in psks.values():
        if agent["AgentName"] == agent_name:
            print(f"[ERROR] Agent '{agent_name}' already exists.")
            return

    agent_ip = input("Enter Agent IP Address: ").strip()
    if not agent_ip:
        print("[ERROR] Agent IP cannot be empty.")
        return

    # Assign next available Agent ID
    agent_id = get_next_agent_id(psks)
    new_psk = generate_psk()

    # Store the new agent information
    psks[str(agent_id)] = {
        "AgentID": str(agent_id),
        "AgentName": agent_name,
        "AgentPSK": new_psk,
        "AgentIP": agent_ip
    }

    save_psks(psks)
    print(f"[INFO] Agent '{agent_name}' added with Agent ID {agent_id}. IP: {agent_ip}, PSK: {new_psk}")

def remove_client(agent_id):
    """Removes a client from the PSK store using Agent ID."""
    psks = load_psks()

    if str(agent_id) in psks:
        removed_agent = psks.pop(str(agent_id))
        save_psks(psks)
        print(f"[INFO] Agent '{removed_agent['AgentName']}' (ID: {agent_id}, IP: {removed_agent['AgentIP']}) removed.")
        return True

    print(f"[ERROR] Agent ID {agent_id} not found.")
    return False

def list_agents():
    """Lists all registered clients with their Agent IDs, Names, and IPs."""
    psks = load_psks()
    if not psks:
        print("[INFO] No clients registered.")
        return

    print("[INFO] Registered Agents:")
    for agent_id, details in psks.items():
        print(f"  - Agent ID: {details['AgentID']}, Name: {details['AgentName']}, IP: {details['AgentIP']}")

def authenticate_client(client_socket):
    """Authenticates a client using stored PSK and IP."""
    try:
        # Receive authentication data from client
        auth_data = client_socket.recv(1024).decode("utf-8")

        if not auth_data:
            logging.warning("[ERROR] No authentication data received.")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Extract authentication parameters sent by the client
        try:
            client_name, nonce, client_hmac = auth_data.split(":")
        except ValueError:
            logging.warning("[ERROR] Malformed authentication data received.")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Load stored PSKs
        psks = load_psks()

        # Check if client name exists in PSKs
        matching_agent = None
        for agent_id, agent_data in psks.items():
            if agent_data["AgentName"] == client_name:
                matching_agent = agent_data
                break

        if not matching_agent:
            logging.warning("[ERROR] Unknown client attempted authentication.")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Retrieve stored PSK for the client
        client_psk = matching_agent["AgentPSK"]

        # Compute expected HMAC
        expected_hmac = hmac.new(client_psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()

        # Validate authentication
        if hmac.compare_digest(client_hmac, expected_hmac):
            client_socket.sendall(b"AUTH_SUCCESS")
            logging.info(f"[SUCCESS] Client {client_name} authenticated successfully.")
            return client_name
        else:
            logging.warning("[ERROR] Authentication failed.")
            client_socket.sendall(b"AUTH_FAILED")
            return None

    except Exception as e:
        logging.error(f"[ERROR] Unexpected authentication error: {e}")
        client_socket.sendall(b"AUTH_FAILED")
        return None

def receive_chunked_data(client_socket):
    """Receive data sent in chunks with length prefixes."""
    try:
        full_data = bytearray()
        
        while True:
            # Receive chunk size (4 bytes)
            size_bytes = b""
            bytes_received = 0
            
            # Ensure we get all 4 bytes of the size header
            while bytes_received < 4:
                try:
                    chunk = client_socket.recv(4 - bytes_received)
                    if not chunk:  # Connection closed
                        if bytes_received == 0:  # No data at all
                            return None
                        logging.error(f"[CHUNK] Connection closed while receiving size header. Got {bytes_received}/4 bytes")
                        return None
                    size_bytes += chunk
                    bytes_received += len(chunk)
                except Exception as e:
                    logging.error(f"[CHUNK] Error receiving chunk header: {e}")
                    return None
            
            # Convert size bytes to integer
            chunk_size = int.from_bytes(size_bytes, byteorder='big')
            
            # End of message marker
            if chunk_size == 0:
                break
            
            # Sanity check on chunk size
            if chunk_size > 10*1024*1024:  # >10MB is probably invalid
                logging.error(f"[CHUNK] Invalid chunk size: {chunk_size} bytes")
                return None
            
            # Receive the chunk data
            chunk_data = bytearray()
            bytes_received = 0
            
            while bytes_received < chunk_size:
                try:
                    buffer_size = min(4096, chunk_size - bytes_received)
                    buffer = client_socket.recv(buffer_size)
                    
                    if not buffer:  # Connection closed
                        logging.error(f"[CHUNK] Connection closed prematurely. Got {bytes_received}/{chunk_size} bytes")
                        return None
                    
                    chunk_data.extend(buffer)
                    bytes_received += len(buffer)
                    
                except Exception as e:
                    logging.error(f"[CHUNK] Error receiving chunk data: {e}")
                    return None
            
            # Add this chunk to our accumulated data
            full_data.extend(chunk_data)
        
        # Return the complete message
        logging.info(f"[CHUNK] Successfully received complete chunked message, total size: {len(full_data)} bytes")
        return bytes(full_data)
    
    except Exception as e:
        logging.error(f"[CHUNK] Error in receive_chunked_data: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return None
        
def is_chunked_message(client_socket):
    """Try to detect if the incoming message is using chunked protocol."""
    try:
        # Peek at the first 4 bytes without consuming them
        peek_data = client_socket.recv(4, socket.MSG_PEEK)
        
        # If we got less than 4 bytes, it's not enough to tell
        if len(peek_data) < 4:
            return False
            
        # Convert the first 4 bytes to an integer
        possible_size = int.from_bytes(peek_data, byteorder='big')
        
        # If the size is reasonable (less than 16MB but greater than 0),
        # it's likely a chunked message header
        return 0 < possible_size < 16 * 1024 * 1024
    except:
        return False

def handle_client(client_socket, client_address):
    """Handles encrypted log reception and NAT detection from authenticated client."""
    logging.info(f"New connection from {client_address[0]}:{client_address[1]}")

    try:
        raw = client_socket.recv(1024)

        if raw and (raw[0] < 32 or raw[0] > 126):
            pass  # Binary data detection - no logging needed

        try:
            try:
                payload = json.loads(raw.decode("utf-8"))

                if payload.get("command") == "get_client_ip":
                    client_ip = client_address[0]
                    response = json.dumps({"client_ip": client_ip})
                    client_socket.sendall(response.encode("utf-8"))
                    logging.info(f"[NAT-DETECT] Responded to IP check from {client_ip}")
                    return

                client_name = payload.get("client_name")
                if client_name:
                    logging.info(f"[AUTH] Client '{client_name}' connecting from {client_address[0]}")

                    try:
                        try:
                            psk = server_crypt.load_psks(client_name)
                        except ValueError as e:
                            logging.warning(f"[AUTH] Unknown client '{client_name}' from {client_address}: {e}")
                            client_socket.close()
                            return
                        except Exception as e:
                            logging.error(f"[AUTH] Error loading PSK for '{client_name}': {e}")
                            client_socket.close()
                            return

                        logging.info(f"[AUTH] Client '{client_name}' authenticated. Ready to receive logs.")
                        client_socket.sendall(b"OK")

                        # Retain PSK for log decryption
                        psk = server_crypt.load_psks(client_name)

                        while True:
                            readable, _, _ = select.select([client_socket], [], [], 0.5)
                            if not readable:
                                continue

                            try:
                                peek_bytes = client_socket.recv(4, socket.MSG_PEEK)
                                if len(peek_bytes) == 0:
                                    logging.info(f"[DISCONNECT] Client {client_name} disconnected (empty data)")
                                    break

                                if len(peek_bytes) == 4:
                                    potential_size = int.from_bytes(peek_bytes, byteorder='big')
                                    if 0 < potential_size < 8192:
                                        logging.info(f"[RECV] Preparing to receive chunked data of size ~{potential_size}")
                                        encrypted_data = receive_chunked_data(client_socket)
                                        if not encrypted_data:
                                            logging.info(f"[DISCONNECT] Client {client_name} disconnected during chunk receive")
                                            break
                                    else:
                                        logging.info(f"[RECV] Receiving standard block (non-chunked)")
                                        encrypted_data = client_socket.recv(4096)
                                        if not encrypted_data:
                                            logging.info(f"[DISCONNECT] Client {client_name} disconnected (standard receive)")
                                            break
                                else:
                                    logging.warning(f"[RECV] Peek data not 4 bytes: {len(peek_bytes)}")
                                    encrypted_data = client_socket.recv(4096)
                                    if not encrypted_data:
                                        logging.info(f"[DISCONNECT] Client {client_name} disconnected (fallback receive)")
                                        break
                            except Exception as e:
                                logging.warning(f"[RECV] Error peeking at data: {e}, falling back to standard receive")
                                encrypted_data = client_socket.recv(4096)
                                if not encrypted_data:
                                    logging.info(f"[DISCONNECT] Client {client_name} disconnected (fallback receive)")
                                    break

                            try:
                                if not psk:
                                    logging.error(f"[RECV] PSK not available for {client_name}")
                                    try:
                                        psk = server_crypt.load_psks(client_name)
                                        logging.info(f"[RECV] Reloaded PSK for {client_name}")
                                    except Exception as e:
                                        logging.error(f"[RECV] Failed to reload PSK: {e}")
                                        continue

                                logging.info(f"[RECV] Attempting decryption of {len(encrypted_data)} bytes from {client_name}")
                                log_data = server_crypt.decrypt_data_with_psk(psk, encrypted_data)

                                if not log_data:
                                    logging.warning(f"[RECV] Decryption failed or no logs in decrypted data from {client_name}")
                                    client_socket.sendall(b"ERROR")
                                    continue

                                # FIXED LOG PROCESSING SECTION
                                logs = []
                                
                                # Handle different data structures from client
                                if isinstance(log_data, dict):
                                    if "logs" in log_data:
                                        # Standard format: {"logs": [...], "client_name": "...", ...}
                                        logs = log_data["logs"]
                                        if isinstance(logs, dict):
                                            logs = [logs]  # Convert single dict to list
                                    else:
                                        # Single log entry format
                                        logs = [log_data]
                                elif isinstance(log_data, list):
                                    # Direct list of logs
                                    logs = log_data
                                else:
                                    logging.error(f"[RECV] Unexpected log_data type from {client_name}: {type(log_data)}")
                                    client_socket.sendall(b"ERROR")
                                    continue

                                # Validate logs structure
                                valid_logs = []
                                for i, log_entry in enumerate(logs):
                                    if log_entry is None:
                                        logging.warning(f"[RECV] Skipping None log entry {i+1} from {client_name}")
                                        continue
                                    
                                    if not isinstance(log_entry, dict):
                                        logging.warning(f"[RECV] Skipping non-dict log entry {i+1} from {client_name}: {type(log_entry)}")
                                        continue
                                    
                                    # Ensure required fields exist
                                    if not log_entry.get("log_type"):
                                        logging.warning(f"[RECV] Log entry {i+1} missing log_type, adding default")
                                        log_entry["log_type"] = "UNKNOWN"
                                    
                                    if not log_entry.get("timestamp"):
                                        log_entry["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                                    
                                    # Add client name to log entry
                                    log_entry["client_name"] = client_name
                                    valid_logs.append(log_entry)

                                if not valid_logs:
                                    logging.warning(f"[RECV] No valid log entries found from {client_name}")
                                    client_socket.sendall(b"ERROR")
                                    continue

                                log_count = len(valid_logs)
                                logging.info(f"[RECV] Successfully processed {log_count} valid logs from {client_name}")

                                # Write logs to file and forward to SIEM
                                for log_entry in valid_logs:
                                    try:
                                        with open(ENDPOINT_LOG_FILE, "a") as log_file:
                                            log_file.write(json.dumps(log_entry) + "\n")
                                    except Exception as e:
                                        logging.error(f"[ERROR] Failed to write client log: {e}")

                                    try:
                                        server_siem.forward_log_to_siem(log_entry, client_name)
                                    except Exception as e:
                                        logging.error(f"[ERROR] Failed to forward log to SIEM: {e}")

                                # Send ACK only after successful processing
                                client_socket.sendall(b"ACK")
                                logging.info(f"[RECV] Successfully processed and acknowledged {log_count} logs from {client_name}")

                            except Exception as e:
                                logging.error(f"[RECV] Unexpected processing error from {client_name}: {e}")
                                logging.error(f"[RECV] Error traceback: {traceback.format_exc()}")
                                try:
                                    client_socket.sendall(b"ERROR")
                                except Exception as send_err:
                                    logging.error(f"[SEND] Failed to send ERROR response: {send_err}")
                                    break

                    except Exception as e:
                        logging.error(f"[CLIENT] Exception handling client {client_name}: {e}")

            except json.JSONDecodeError:
                try:
                    parts = raw.decode("utf-8").split(":")
                    if len(parts) == 3:
                        client_name, nonce, client_hmac = parts
                        try:
                            psk = server_crypt.load_psks(client_name)
                        except Exception as e:
                            logging.warning(f"[AUTH] Unknown client in HMAC fallback: {e}")
                            client_socket.close()
                            return

                        expected_hmac = hmac.new(psk, nonce.encode(), hashlib.sha256).hexdigest()
                        if hmac.compare_digest(client_hmac, expected_hmac):
                            logging.info(f"[AUTH] HMAC authentication succeeded for {client_name}")
                            client_socket.sendall(b"AUTH_SUCCESS")
                        else:
                            logging.warning(f"[AUTH] Invalid HMAC from {client_address}")
                            client_socket.close()
                            return
                    else:
                        logging.warning("[AUTH] Invalid HMAC handshake format")
                        client_socket.close()
                        return
                except Exception as e:
                    logging.warning(f"[AUTH] Error parsing HMAC handshake: {e}")
                    client_socket.close()
                    return

        except UnicodeDecodeError:
            pass  # Non-UTF8 data - no logging needed

    except Exception as e:
        logging.error(f"[ERROR] Unexpected top-level error from {client_address}: {e}")
        logging.error(f"[ERROR] Traceback: {traceback.format_exc()}")
    finally:
        logging.info(f"[DISCONNECT] Client {client_address} disconnected.")
        client_socket.close()
        
def receive_chunked_data(client_socket):
    """Receive data sent in chunks with length prefixes."""
    try:
        full_data = bytearray()
        
        while True:
            # Receive chunk size (4 bytes)
            size_bytes = client_socket.recv(4)
            if not size_bytes or len(size_bytes) < 4:
                logging.error("Incomplete size header received")
                return None
                
            chunk_size = int.from_bytes(size_bytes, byteorder='big')
            
            # A zero-length chunk means end of message
            if chunk_size == 0:
                break
                
            # Receive the chunk data
            chunk = bytearray()
            bytes_received = 0
            
            # Keep receiving until we get all bytes for this chunk
            while bytes_received < chunk_size:
                remaining = chunk_size - bytes_received
                buffer = client_socket.recv(min(4096, remaining))
                
                if not buffer:
                    logging.error("Connection closed during chunk receive")
                    return None
                    
                chunk.extend(buffer)
                bytes_received += len(buffer)
            
            full_data.extend(chunk)
        
        return bytes(full_data)
    except Exception as e:
        logging.error(f"Error receiving chunked data: {e}")
        return None
        
def get_client_ip_by_name(client_name):
    """Retrieve a client's IP address with NAT awareness."""
    psks = load_psks()
    
    for agent_id, agent_data in psks.items():
        if agent_data["AgentName"] == client_name:
            # Check if there's a NAT-detected IP in the connections file
            from shared_state import get_active_connections
            connections = get_active_connections()
            
            if client_name in connections and "detected_ip" in connections[client_name]:
                detected_ip = connections[client_name]["detected_ip"]
                if detected_ip:
                    return detected_ip
                
            # Fall back to stored IP
            return agent_data["AgentIP"]
    
    return None

def send_command_to_client(client_name, command, params=None):
    """
    Send a command to a specific client.
    
    Args:
        client_name (str): The name of the client to send the command to
        command (str): Command type (restart, yara-scan, ir-shell)
        params (dict, optional): Additional parameters for the command
        
    Returns:
        dict: Result of the command execution
    """
    # Get client IP from name
    client_ip = get_client_ip_by_name(client_name)
    if not client_ip:
        logging.error(f"[ERROR] Unknown client: {client_name}")
        return {"status": "error", "message": f"Unknown client: {client_name}"}
    
    # Build command payload
    command_payload = {
        "command": command,
        "params": params or {}
    }
    
    try:
        # Load PSK for this client - FIX: use proper PSK loading method
        # Original line that causes the error:
        # psk = load_psks(client_name)
        
        # Fixed version - load all PSKs and then find the one for this client:
        psks = load_psks()
        client_psk = None
        
        for agent_data in psks.values():
            if agent_data["AgentName"] == client_name:
                client_psk = bytes.fromhex(agent_data["AgentPSK"])
                break
                
        if not client_psk:
            logging.error(f"[ERROR] No PSK found for client: {client_name}")
            return {"status": "error", "message": f"No PSK found for client: {client_name}"}
        
        # Connect to client's command port
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)  # 10 second timeout
        
        # Try to connect to the client's command port (6000)
        try:
            client_socket.connect((client_ip, 6000))
            logging.info(f"[COMMAND] Connected to client {client_name} at {client_ip}:6000")
        except Exception as e:
            logging.error(f"[ERROR] Failed to connect to client {client_name} at {client_ip}:6000: {e}")
            return {"status": "error", "message": f"Connection failed: {e}"}
        
        # Encrypt the command
        serialized_command = json.dumps(command_payload)
        encrypted_command = server_crypt.encrypt_data(client_psk, serialized_command)
        
        # Send the encrypted command
        client_socket.sendall(encrypted_command)
        logging.info(f"[COMMAND] Sent '{command}' to {client_name}")
        
        # Wait for response (with timeout)
        try:
            client_socket.settimeout(30)  # Longer timeout for response
            encrypted_response = client_socket.recv(8192)
            if not encrypted_response:
                return {"status": "error", "message": "Empty response from client"}
                
            response_data = server_crypt.decrypt_data_with_psk(client_psk, encrypted_response)
            logging.info(f"[COMMAND] Received response from {client_name}: {response_data.get('status', 'unknown')}")
            return response_data
        except socket.timeout:
            return {"status": "error", "message": "Response timeout"}
        
    except Exception as e:
        logging.error(f"[ERROR] Failed to send command to {client_name}: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        if 'client_socket' in locals():
            client_socket.close()

# Command-specific functions
def restart_client_service(client_name, service):
    """
    Restart a specific service on a client.
    
    Args:
        client_name (str): Client name
        service (str): Service to restart (monisec_client, fim_client, pim, lim)
        
    Returns:
        dict: Result of the restart operation
    """
    if service not in ["monisec_client", "fim_client", "pim", "lim"]:
        return {"status": "error", "message": f"Invalid service: {service}"}
        
    return send_command_to_client(client_name, "restart", {"service": service})

def run_yara_scan(client_name, target_path, rule_name=None):
    """
    Run a YARA scan on a client.
    
    Args:
        client_name (str): Client name
        target_path (str): Path to scan on the client
        rule_name (str, optional): Specific YARA rule to use
        
    Returns:
        dict: Scan results
    """
    params = {
        "target_path": target_path
    }
    
    if rule_name:
        params["rule_name"] = rule_name
        
    return send_command_to_client(client_name, "yara-scan", params)

# In clients.py

def spawn_ir_shell(client_name):
    """Initiate an interactive IR shell session with a client."""
    print(f"[INFO] Establishing IR shell with {client_name}...")
    
    # Get client IP address
    client_ip = get_client_ip_by_name(client_name)
    if not client_ip:
        print(f"[ERROR] Unknown client: {client_name}")
        return {"status": "error", "message": f"Unknown client: {client_name}"}
    
    # First try direct connection
    try:
        # Try to connect directly to the client on port 6000
        shell_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        shell_socket.settimeout(5)  # Short timeout for connection attempt
        
        print(f"[INFO] Attempting direct connection to {client_name} at {client_ip}:6000...")
        shell_socket.connect((client_ip, 6000))
        shell_socket.close()
        
        # If we get here, direct connection is possible
        direct_shell_successful = True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"[INFO] Direct connection failed: {e}")
        direct_shell_successful = False
    
    if direct_shell_successful:
        # Use direct connection for IR shell
        print(f"[INFO] Using direct connection for IR shell with {client_name}")
        result = direct_ir_shell(client_name)
        return result
    else:
        # Check if client has an active WebSocket connection
        from shared_state import is_client_connected
        
        if is_client_connected(client_name):
            from shared_state import get_active_connections
            connections = get_active_connections()
            conn_info = connections.get(client_name, {})
            last_seen = conn_info.get("timestamp", 0)
            
            # Format last_seen timestamp for display
            last_activity = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_seen))
            
            print(f"[INFO] Found active WebSocket connection for {client_name}")
            print(f"[INFO] Last activity: {last_activity}")
            
            # Run the virtual_shell_cli in the current event loop
            # This is a synchronous function that runs an event loop internally
            return run_async_shell(client_name)
        else:
            print(f"[INFO] No active WebSocket connection found for {client_name}")
            print("[INFO] Client must establish a connection first")
            return {"status": "error", "message": "Client not connected"}

def run_async_shell(client_name):
    """Run the asynchronous virtual shell in a synchronous context."""
    import asyncio
    from websocket_manager import virtual_shell_cli
    
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Run the async function in the event loop
        result = loop.run_until_complete(virtual_shell_cli(client_name))
        return result
    finally:
        # Clean up
        loop.close()
            
def run_interactive_shell(client_name):
    """
    Run an interactive IR shell session using the direct command channel.
    
    Args:
        client_name (str): Client name
        
    Returns:
        dict: Result of the shell session
    """
    print(f"[INFO] IR Shell session established with {client_name}")
    print("[INFO] Type 'exit' to end the session")
    print("[INFO] All commands are executed within the client's security context")
    print("="*60)
    
    try:
        # Interactive shell loop
        while True:
            command = input(f"{client_name}> ").strip()
            
            if command.lower() in ["exit", "quit"]:
                # Cleanly terminate the shell session
                send_command_to_client(client_name, "ir-shell-exit")
                print(f"[INFO] IR Shell session with {client_name} terminated")
                break
                
            if not command:
                continue
                
            # Send the command through the encrypted channel
            result = send_command_to_client(client_name, "ir-shell-command", {
                "command": command
            })
            
            if result.get("status") == "success":
                # Display command output
                output = result.get("output", "")
                print(output)
            else:
                print(f"[ERROR] Command failed: {result.get('message', 'Unknown error')}")
        
        return {"status": "success", "message": "IR Shell session completed"}
        
    except KeyboardInterrupt:
        print("\n[INFO] IR Shell session terminated by user")
        send_command_to_client(client_name, "ir-shell-exit")
        return {"status": "success", "message": "IR Shell session terminated by user"}
    except Exception as e:
        print(f"[ERROR] IR Shell error: {e}")
        return {"status": "error", "message": str(e)}

def original_spawn_ir_shell(client_name):
    """Original IR shell implementation for direct connections."""
    print(f"[INFO] IR Shell session established with {client_name}")
    print("[INFO] Type 'exit' to end the session")
    print("[INFO] All commands are executed within the client's security context")
    print("="*60)
    
    try:
        # Initialize the shell session
        result = send_command_to_client(client_name, "ir-shell-init")
        
        if result.get("status") != "success":
            print(f"[ERROR] Failed to initialize IR shell: {result.get('message')}")
            return result
        
        # Interactive shell loop
        while True:
            command = input(f"{client_name}> ").strip()
            
            if command.lower() in ["exit", "quit"]:
                # Cleanly terminate the shell session
                send_command_to_client(client_name, "ir-shell-exit")
                print(f"[INFO] IR Shell session with {client_name} terminated")
                break
                
            if not command:
                continue
                
            # Send the command through the encrypted channel
            result = send_command_to_client(client_name, "ir-shell-command", {
                "command": command
            })
            
            if result.get("status") == "success":
                # Display command output
                output = result.get("output", "")
                print(output)
            else:
                print(f"[ERROR] Command failed: {result.get('message', 'Unknown error')}")
        
        return {"status": "success", "message": "IR Shell session completed"}
        
    except KeyboardInterrupt:
        print("\n[INFO] IR Shell session terminated by user")
        send_command_to_client(client_name, "ir-shell-exit")
        return {"status": "success", "message": "IR Shell session terminated by user"}
    except Exception as e:
        print(f"[ERROR] IR Shell error: {e}")
        return {"status": "error", "message": str(e)}

def direct_ir_shell(client_name):
    """Run IR shell using direct TCP connection."""
    print(f"[INFO] IR Shell session established with {client_name}")
    print("[INFO] Type 'exit' to end the session")
    print("[INFO] All commands are executed within the client's security context")
    print("="*60)
    
    try:
        # Initialize the shell session
        result = send_command_to_client(client_name, "ir-shell-init")
        
        if result.get("status") != "success":
            print(f"[ERROR] Failed to initialize IR shell: {result.get('message')}")
            return result
        
        # Interactive shell loop
        while True:
            command = input(f"{client_name}> ").strip()
            
            if command.lower() in ["exit", "quit"]:
                # Cleanly terminate the shell session
                send_command_to_client(client_name, "ir-shell-exit")
                print(f"[INFO] IR Shell session with {client_name} terminated")
                break
                
            if not command:
                continue
                
            # Send the command through the encrypted channel
            result = send_command_to_client(client_name, "ir-shell-command", {
                "command": command
            })
            
            if result.get("status") == "success":
                # Display command output
                output = result.get("output", "")
                print(output)
            else:
                print(f"[ERROR] Command failed: {result.get('message', 'Unknown error')}")
        
        return {"status": "success", "message": "IR Shell session completed"}
        
    except KeyboardInterrupt:
        print("\n[INFO] IR Shell session terminated by user")
        send_command_to_client(client_name, "ir-shell-exit")
        return {"status": "success", "message": "IR Shell session terminated by user"}
    except Exception as e:
        print(f"[ERROR] IR Shell error: {e}")
        return {"status": "error", "message": str(e)}

def websocket_ir_shell(client_name):
    """
    Implement IR shell over WebSocket channel for NAT traversal.
    This function uses the virtual shell approach.
    """
    from shared_state import is_client_connected
    from websocket_manager import virtual_shell_cli
    
    # Check connection status first
    if not is_client_connected(client_name):
        print(f"[ERROR] Client {client_name} is not connected via active WebSocket")
        logging.error(f"[IR-SHELL] Failed to start shell - no active connection for {client_name}")
        return {"status": "error", "message": f"Client {client_name} is not connected via WebSocket"}
    
    # Launch the virtual shell CLI
    print(f"[INFO] Starting virtual WebSocket IR shell for {client_name}")
    logging.info(f"[IR-SHELL] Starting virtual WebSocket IR shell for {client_name}")
    
    # This will run the interactive shell
    return virtual_shell_cli(client_name)

def verify_websocket_connection(client_name):
    """Verify that a WebSocket connection is truly active before proceeding with IR shell."""
    logging.info(f"[CONN-CHECK] Verifying WebSocket connection to {client_name}...")
    
    # First check the connection file
    from shared_state import is_client_connected, get_active_connections
    
    if not is_client_connected(client_name):
        logging.error(f"[CONN-CHECK] No active connection record for {client_name}")
        return False
    
    # Get connection details for logging/debugging
    connections = get_active_connections()
    if client_name in connections:
        conn_info = connections[client_name]
        last_seen = conn_info.get("timestamp", 0)
        time_since = int(time.time() - last_seen)
        socket_id = conn_info.get("socket_id", "unknown")
        
        logging.info(f"[CONN-CHECK] Connection info for {client_name}: last seen {time_since}s ago, socket_id: {socket_id}")
        
        # IMPORTANT: Just check if the connection is recent enough (within last 30 seconds)
        # Don't try to get the actual WebSocket object since we're using a file-only approach
        if time_since < 30:
            logging.info(f"[CONN-CHECK] Connection to {client_name} verified (recent activity)")
            return True
        else:
            logging.warning(f"[CONN-CHECK] Connection to {client_name} is stale ({time_since}s old)")
            return False
    
    return False

def simple_ir_shell_cli(client_name):
    """Simple, direct IR shell CLI using file-based communication."""
    from shared_state import save_ir_cmd_request, get_ir_cmd_response, is_client_connected
    import os
    import time
    import uuid
    
    # Check if client is connected
    if not is_client_connected(client_name):
        print(f"[ERROR] Client {client_name} is not connected")
        return {"status": "error", "message": "Client not connected"}
        
    print(f"=== IR Shell Session for {client_name} ===")
    print("Commands will be sent to the client via WebSocket.")
    print("Type 'exit' to close the session.")
    print("="*50)
    
    # Initialize shell first
    init_cmd_id = f"cmd_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    # Save command request to file
    save_ir_cmd_request(client_name, "ir-shell-init", init_cmd_id)
    
    print("Initializing IR shell...")
    print(f"Command ID: {init_cmd_id}")
    
    # Wait for response
    start_time = time.time()
    init_success = False
    
    while time.time() - start_time < 30 and not init_success:
        # Check for response
        response = get_ir_cmd_response(init_cmd_id)
        if response:
            print(f"Response received: {response}")
            
            if response.get("status") == "success":
                init_success = True
                print("IR shell initialized successfully!")
            else:
                print(f"IR shell initialization failed: {response.get('message', 'Unknown error')}")
                return {"status": "error", "message": response.get('message', 'Unknown error')}
            break
            
        # Debug logging
        print(".", end="", flush=True)
        if (time.time() - start_time) % 5 < 0.2:  # Every ~5 seconds
            print("\nWaiting for response...")
            
        time.sleep(0.5)
    
    if not init_success:
        print("IR shell initialization timed out.")
        return {"status": "error", "message": "Initialization timeout"}
    
    # Main command loop
    shell_active = True
    while shell_active:
        try:
            # Prompt for command
            command = input(f"{client_name}> ").strip()
            
            if not command:
                continue
                
            if command.lower() in ["exit", "quit"]:
                print("Terminating IR shell session...")
                exit_cmd_id = f"cmd_{int(time.time())}_{uuid.uuid4().hex[:8]}"
                save_ir_cmd_request(client_name, "ir-shell-exit", exit_cmd_id)
                shell_active = False
                break
            
            # Generate command ID and save request
            cmd_id = f"cmd_{int(time.time())}_{uuid.uuid4().hex[:8]}"
            save_ir_cmd_request(client_name, command, cmd_id)
            print(f"Command sent (ID: {cmd_id})")
            
            # Wait for response
            start_time = time.time()
            response_received = False
            
            while time.time() - start_time < 30 and not response_received:
                # Check for response
                response = get_ir_cmd_response(cmd_id)
                if response:
                    response_received = True
                    
                    # Display response
                    if response.get("status") == "success":
                        output = response.get("output", "")
                        if output:
                            print(output)
                        else:
                            print("[No output]")
                    else:
                        error = response.get("message", "Unknown error")
                        print(f"[ERROR] {error}")
                    
                    break
                
                # Debug logging
                print(".", end="", flush=True)
                if (time.time() - start_time) % 5 < 0.2:  # Every ~5 seconds
                    print("\nWaiting for response...")
                
                time.sleep(0.5)
            
            if not response_received:
                print("Command timed out after 30 seconds")
                
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            shell_active = False
        except Exception as e:
            print(f"[ERROR] {e}")
    
    print("IR shell session ended.")
    return {"status": "success", "message": "IR shell session completed"}

def update_client(client_name):
    """
    Trigger a client update.
    
    Args:
        client_name (str): Client name
        
    Returns:
        dict: Update result
    """
    return send_command_to_client(client_name, "update")
