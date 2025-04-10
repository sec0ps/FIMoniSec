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
import json
import threading
import logging
import os
import time

# Path for the IPC socket
IPC_SOCKET_PATH = "/tmp/monisec-ipc.sock"
ipc_server_running = False

# Lock to protect file access - repurpose the existing lock
websocket_lock = threading.Lock()

SERVER_BASE_DIR = "/opt/FIMoniSec/Monisec-Server"
CONNECTIONS_FILE = os.path.join(SERVER_BASE_DIR, "active_connections.json")
COMMANDS_FILE = os.path.join(SERVER_BASE_DIR, "websocket_commands.json")
IR_SHELL_FILE = os.path.join(SERVER_BASE_DIR, "ir_shell_commands.json")

PSK_STORE_FILE = "psk_store.json" 

############# File Based Command Tracking - need to clean up the other functions to remove the dictionary tracking ####

def initialize_command_queue():
    """Ensure the commands file exists with proper structure."""
    with websocket_lock:
        try:
            if not os.path.exists(COMMANDS_FILE):
                with open(COMMANDS_FILE, 'w') as f:
                    json.dump({}, f)
                os.chmod(COMMANDS_FILE, 0o666)  # Ensure it's writable
                logging.info(f"[SHARED-STATE] Created command queue file at {COMMANDS_FILE}")
            return True
        except Exception as e:
            logging.error(f"[SHARED-STATE] Error initializing command queue file: {e}")
            return False

def queue_websocket_command(client_name, command):
    """Add a command to a client's queue with better locking and error checking."""
    with websocket_lock:
        try:
            # Create the file if it doesn't exist
            if not os.path.exists(COMMANDS_FILE):
                with open(COMMANDS_FILE, 'w') as f:
                    json.dump({}, f)
                os.chmod(COMMANDS_FILE, 0o666)
                
            # Read existing commands with better error handling
            all_commands = {}
            try:
                with open(COMMANDS_FILE, 'r') as f:
                    content = f.read().strip()
                    if content:
                        all_commands = json.loads(content)
                    else:
                        all_commands = {}
            except json.JSONDecodeError:
                logging.error("[SHARED-STATE] Invalid JSON in commands file, starting fresh")
                all_commands = {}

            # Initialize client's command list if needed
            if client_name not in all_commands:
                all_commands[client_name] = []

            # Add the new command
            all_commands[client_name].append(command)

            # Write back to file with temp file approach for atomicity
            temp_file = COMMANDS_FILE + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(all_commands, f)
            os.rename(temp_file, COMMANDS_FILE)

            # Set permissions to ensure it's writable
            os.chmod(COMMANDS_FILE, 0o666)
            
            # Log success with command count
            logging.info(f"[SHARED-STATE] Queued command for {client_name}: {command}")
            logging.info(f"[SHARED-STATE] Client {client_name} now has {len(all_commands[client_name])} pending commands")
            
            return True
        except Exception as e:
            logging.error(f"[SHARED-STATE] Error queuing command: {e}")
            import traceback
            logging.error(traceback.format_exc())
            return False

def get_next_command(client_name):
    """Get and remove the next command for a client from the commands file."""
    with websocket_lock:
        try:
            if not os.path.exists(COMMANDS_FILE):
                return None

            with open(COMMANDS_FILE, 'r') as f:
                try:
                    all_commands = json.load(f)
                except json.JSONDecodeError:
                    return None

            if client_name not in all_commands or not all_commands[client_name]:
                return None

            command = all_commands[client_name].pop(0)

            with open(COMMANDS_FILE, 'w') as f:
                json.dump(all_commands, f)

            logging.info(f"[SHARED-STATE] Retrieved command for {client_name}: {command}")
            return command
        except Exception as e:
            logging.error(f"[SHARED-STATE] Error getting next command: {e}")
            return None

def get_command_response(command_id):
    """Get a command response from the commands file."""
    with websocket_lock:
        try:
            if not os.path.exists(COMMANDS_FILE):
                return None
                
            with open(COMMANDS_FILE, 'r') as f:
                try:
                    all_data = json.load(f)
                    # Check if we have a responses section
                    if "responses" not in all_data:
                        return None
                        
                    responses = all_data["responses"]
                    if command_id in responses:
                        return responses[command_id]["response"]
                    return None
                except json.JSONDecodeError:
                    logging.error("[SHARED-STATE] Invalid JSON in commands file")
                    return None
        except Exception as e:
            logging.error(f"[SHARED-STATE] Error getting command response: {e}")
            return None

def clear_client_commands(client_name):
    """Clear all commands for a client from the commands file."""
    with websocket_lock:
        try:
            if not os.path.exists(COMMANDS_FILE):
                return

            with open(COMMANDS_FILE, 'r') as f:
                try:
                    all_commands = json.load(f)
                except json.JSONDecodeError:
                    return

            if client_name in all_commands:
                all_commands[client_name] = []

            with open(COMMANDS_FILE, 'w') as f:
                json.dump(all_commands, f)

            logging.info(f"[SHARED-STATE] Cleared commands for {client_name}")
        except Exception as e:
            logging.error(f"[SHARED-STATE] Error clearing commands: {e}")

def has_pending_commands(client_name):
    """Check if a client has pending commands in the commands file."""
    try:
        if not os.path.exists(COMMANDS_FILE):
            return False

        with open(COMMANDS_FILE, 'r') as f:
            try:
                all_commands = json.load(f)
            except json.JSONDecodeError:
                return False

        return client_name in all_commands and len(all_commands[client_name]) > 0
    except Exception as e:
        logging.error(f"[SHARED-STATE] Error checking pending commands: {e}")
        return False

def count_pending_commands(client_name):
    """Get the number of pending commands for a client."""
    try:
        if not os.path.exists(COMMANDS_FILE):
            return 0

        with open(COMMANDS_FILE, 'r') as f:
            try:
                all_commands = json.load(f)
            except json.JSONDecodeError:
                return 0

        if client_name in all_commands:
            return len(all_commands[client_name])
        return 0
    except Exception as e:
        logging.error(f"[SHARED-STATE] Error counting pending commands: {e}")
        return 0

def save_ir_shell_response(command_id, response):
    """Save an IR shell response to the file."""
    with websocket_lock:
        try:
            responses = {}
            if os.path.exists(IR_SHELL_RESPONSES_FILE):
                try:
                    with open(IR_SHELL_RESPONSES_FILE, 'r') as f:
                        responses = json.load(f)
                except json.JSONDecodeError:
                    logging.error("[IR-SHELL] Invalid JSON in responses file")
                    responses = {}
            
            # Add the response
            responses[command_id] = {
                "response": response,
                "timestamp": time.time()
            }
            
            # Write to file
            with open(IR_SHELL_RESPONSES_FILE, 'w') as f:
                json.dump(responses, f)
            
            # Set permissions
            os.chmod(IR_SHELL_RESPONSES_FILE, 0o666)
            
            logging.info(f"[IR-SHELL] Saved response for command ID: {command_id} to file")
            return True
        except Exception as e:
            logging.error(f"[IR-SHELL] Error saving response: {e}")
            return False

def get_ir_shell_response(command_id):
    """Get an IR shell response from the file."""
    try:
        if not os.path.exists(IR_SHELL_RESPONSES_FILE):
            return None
            
        with open(IR_SHELL_RESPONSES_FILE, 'r') as f:
            try:
                responses = json.load(f)
                if command_id in responses:
                    return responses[command_id]["response"]
                return None
            except json.JSONDecodeError:
                logging.error("[IR-SHELL] Invalid JSON in responses file")
                return None
    except Exception as e:
        logging.error(f"[IR-SHELL] Error reading response: {e}")
        return None
        
######################################################################################################################

def get_active_connections():
    """Get all active connections from the file."""
    try:
        if not os.path.exists(CONNECTIONS_FILE):
            return {}
            
        with open(CONNECTIONS_FILE, 'r') as f:
            try:
                connections = json.load(f)
                # Filter out expired connections
                current_time = time.time()
                active_connections = {}
                for client, details in connections.items():
                    # Consider connection valid if updated in the last 2 minutes
                    last_update = details.get("timestamp", 0)
                    if current_time - last_update < 120:  # 2 minutes timeout
                        active_connections[client] = details
                return active_connections
            except json.JSONDecodeError:
                logging.error("[CONN-FILE] Invalid JSON in connections file")
                return {}
    except Exception as e:
        logging.error(f"[CONN-FILE] Error reading connections file: {e}")
        return {}

def is_client_connected(client_name):
    """Check if a client is connected based on the file record."""
    connections = get_active_connections()
    
    # Check if client exists and hasn't timed out
    if client_name in connections:
        # Consider connection valid if updated in the last 2 minutes
        last_update = connections[client_name].get("timestamp", 0)
        current_time = time.time()
        
        # Calculate time difference for logging
        time_diff = current_time - last_update
        
        # Log detailed connection info at debug level
        logging.debug(f"[CONN-CHECK] Client {client_name} last seen {int(time_diff)} seconds ago")
        
        # Use a threshold of 120 seconds (2 minutes) for connection validity
        if time_diff > 120:
            logging.info(f"[CONN-CHECK] Client {client_name} connection is stale. " 
                        f"Last seen {int(time_diff)} seconds ago")
            return False
            
        # Connection is recent enough, consider it active
        logging.debug(f"[CONN-CHECK] Client {client_name} has active connection (last seen {int(time_diff)}s ago)")
        return True
    
    logging.info(f"[CONN-CHECK] No connection record found for client {client_name}")
    return False

def print_active_connections():
    """Print the current state of active connections."""
    connections = get_active_connections()
    connection_names = list(connections.keys())
    
    print(f"[CONN-FILE] Active connections: {connection_names}")
    logging.info(f"[CONN-FILE] Active connections: {connection_names}")
    
    return connection_names, id(connections)  # Return ID just for compatibility

def save_connection(client_name, connection_info):
    """Save or update a connection in the file."""
    with websocket_lock:  # Use lock for file access
        try:
            # Read existing connections
            connections = {}
            if os.path.exists(CONNECTIONS_FILE):
                with open(CONNECTIONS_FILE, 'r') as f:
                    try:
                        connections = json.load(f)
                    except json.JSONDecodeError:
                        logging.error("[CONN-FILE] Invalid JSON in connections file, starting fresh")
                        connections = {}
            
            # Update with new connection
            connections[client_name] = {
                "connected": True,
                "timestamp": time.time(),
                "socket_id": connection_info.get("socket_id", "unknown"),
                "nat_status": connection_info.get("nat_status", "unknown"),
                "detected_ip": connection_info.get("detected_ip", "")
            }
            
            # Write back
            with open(CONNECTIONS_FILE, 'w') as f:
                json.dump(connections, f)
            
            # Set permissions
            os.chmod(CONNECTIONS_FILE, 0o666)
            
            logging.info(f"[CONN-FILE] Saved connection for {client_name} to file")
            return True
        except Exception as e:
            logging.error(f"[CONN-FILE] Error saving connection to file: {e}")
            return False

def remove_connection(client_name):
    """Remove a client connection from the file."""
    with websocket_lock:  # Use lock for file access
        try:
            # Read existing connections
            if not os.path.exists(CONNECTIONS_FILE):
                return False
                
            with open(CONNECTIONS_FILE, 'r') as f:
                try:
                    connections = json.load(f)
                except json.JSONDecodeError:
                    return False
            
            # Remove client if exists
            if client_name in connections:
                del connections[client_name]
                
                # Write back
                with open(CONNECTIONS_FILE, 'w') as f:
                    json.dump(connections, f)
                    
                logging.info(f"[CONN-FILE] Removed connection for {client_name} from file")
                return True
            return False
        except Exception as e:
            logging.error(f"[CONN-FILE] Error removing connection from file: {e}")
            return False

def update_connection_timestamp(client_name):
    """Update the timestamp for a client connection."""
    with websocket_lock:  # Use lock for file access
        try:
            # Read existing connections
            if not os.path.exists(CONNECTIONS_FILE):
                return False
                
            with open(CONNECTIONS_FILE, 'r') as f:
                try:
                    connections = json.load(f)
                except json.JSONDecodeError:
                    return False
            
            # Update timestamp if client exists
            if client_name in connections:
                connections[client_name]["timestamp"] = time.time()
                
                # Write back
                with open(CONNECTIONS_FILE, 'w') as f:
                    json.dump(connections, f)
                    
                logging.debug(f"[CONN-FILE] Updated timestamp for {client_name}")
                return True
            return False
        except Exception as e:
            logging.error(f"[CONN-FILE] Error updating timestamp: {e}")
            return False

def get_active_websocket_clients():
    """
    Return a list of client names that are actively connected (from active_connections.json).
    """
    try:
        connections = get_active_connections()
        return list(connections.keys())
    except Exception as e:
        logging.error(f"[CONN-FILE] Error retrieving active WebSocket clients: {e}")
        return []

def purge_connections_file():
    """
    Purge the connections file only if no active WebSocket clients are still connected.
    """
    try:
        active_clients = get_active_websocket_clients()
        
        if active_clients:
            logging.warning(f"[CONN-FILE] Skipping purge: {len(active_clients)} active clients still connected: {active_clients}")
            return False

        if os.path.exists(CONNECTIONS_FILE):
            os.remove(CONNECTIONS_FILE)
            logging.info(f"[CONN-FILE] Purged connections file at {CONNECTIONS_FILE}")
            return True

        return False
    except Exception as e:
        logging.error(f"[CONN-FILE] Error during purge: {e}")
        return False

def reset_connection_tracking():
    """Reset all connection tracking by clearing the file."""
    return purge_connections_file()

def start_ipc_server():
    """Start an IPC socket server with improved error handling and response processing."""
    global ipc_server_running

    # Initialize the command queue file
    initialize_command_queue()
    
    if ipc_server_running:
        logging.info("[IPC] IPC server already running")
        return

    try:
        if os.path.exists(IPC_SOCKET_PATH):
            os.unlink(IPC_SOCKET_PATH)
            logging.info(f"[IPC] Removed existing socket at {IPC_SOCKET_PATH}")

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(IPC_SOCKET_PATH)
        server.listen(5)
        os.chmod(IPC_SOCKET_PATH, 0o777)  # Allow connections from CLI tools

        logging.info("[IPC] IPC server thread now actively listening")
        logging.info(f"[IPC] IPC socket is now available at {IPC_SOCKET_PATH}")
        ipc_server_running = True

        def handle_ipc_requests():
            logging.info("[IPC] IPC socket handler is ready")
            while ipc_server_running:
                try:
                    # Set a timeout on accept to allow clean shutdown
                    server.settimeout(1.0)
                    try:
                        client, _ = server.accept()
                    except socket.timeout:
                        continue
                    
                    client.settimeout(5.0)  # Set a timeout on client operations
                    request_data = client.recv(4096).decode('utf-8').strip()

                    if not request_data:
                        logging.warning("[IPC] Received empty request data — closing connection silently")
                        client.close()
                        continue

                    logging.debug(f"[IPC] Received request: {request_data}")

                    try:
                        request = json.loads(request_data)
                        command = request.get('command')

                        # Handle websocket_command with better verification
                        if command == 'websocket_command':
                            client_name = request.get('client_name')
                            shell_command = request.get('shell_command')
                            command_id = request.get('command_id')

                            logging.info(f"[IPC] Websocket command for {client_name}: {shell_command} (ID: {command_id})")

                            if not is_client_connected(client_name):
                                # Double-check connection with heartbeat
                                still_disconnected = True
                                
                                response = {
                                    'status': 'error',
                                    'message': f"Client {client_name} is not connected"
                                }
                            else:
                                # Use the file-based command queue
                                cmd = {
                                    'shell_command': shell_command,
                                    'command_id': command_id
                                }
                                
                                # Queue the command with retry logic
                                success = False
                                retry_count = 3
                                while retry_count > 0 and not success:
                                    success = queue_websocket_command(client_name, cmd)
                                    if not success:
                                        retry_count -= 1
                                        time.sleep(0.1)
                                
                                if success:
                                    # Log the pending command count
                                    cmd_count = count_pending_commands(client_name)
                                    logging.info(f"[IPC] Command queued for {client_name}: {shell_command} (ID: {command_id}). Now {cmd_count} pending commands.")
                                    
                                    response = {
                                        'status': 'success',
                                        'message': f"Command queued for client {client_name}"
                                    }
                                else:
                                    response = {
                                        'status': 'error',
                                        'message': f"Failed to queue command for client {client_name} after multiple attempts"
                                    }
                        # Process other commands...
                        else:
                            response = {'status': 'error', 'message': f"Unknown command: {command}"}

                    except json.JSONDecodeError:
                        response = {'status': 'error', 'message': 'Invalid JSON request'}
                    except Exception as e:
                        import traceback
                        logging.error(f"[IPC] Error processing request: {e}\n{traceback.format_exc()}")
                        response = {'status': 'error', 'message': f"Exception: {str(e)}"}

                    try:
                        client.sendall(json.dumps(response).encode('utf-8'))
                    except Exception as e:
                        logging.error(f"[IPC] Failed to send response: {e}")
                    finally:
                        client.close()

                except Exception as e:
                    logging.error(f"[IPC] Error handling IPC request: {e}")

            logging.info("[IPC] IPC server stopped")
            if os.path.exists(IPC_SOCKET_PATH):
                os.unlink(IPC_SOCKET_PATH)

        threading.Thread(target=handle_ipc_requests, daemon=True).start()

    except Exception as e:
        logging.error(f"[IPC] Failed to start IPC server: {e}")
        ipc_server_running = False

def ensure_ipc_socket_health():
    """Monitor and ensure IPC socket health."""

    active_clients = get_active_connections()
    if active_clients:
        logging.warning(f"[IPC] Active clients detected: {list(active_clients.keys())} — skipping IPC restart")
        return

    if not os.path.exists(IPC_SOCKET_PATH):
        logging.error(f"[IPC] Socket doesn't exist at {IPC_SOCKET_PATH}")
        try:
            stop_ipc_server()
            time.sleep(1)
            logging.info("[IPC] Attempting to restart IPC server due to missing socket...")
            start_ipc_server()
            logging.info("[IPC] IPC server restarted successfully after missing socket")
        except Exception as e:
            logging.error(f"[IPC] Failed to restart IPC server: {e}")
        return

    try:
        test_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        test_socket.settimeout(2)
        test_socket.connect(IPC_SOCKET_PATH)
        test_socket.close()
        logging.debug("[IPC] Socket health check passed")
    except Exception as e:
        logging.error(f"[IPC] Socket health check failed: {e}")
        try:
            stop_ipc_server()
            time.sleep(1)
            logging.info("[IPC] Attempting to restart IPC server after failed health check...")
            start_ipc_server()
            logging.info("[IPC] IPC server restarted after connectivity failure")
        except Exception as restart_err:
            logging.error(f"[IPC] Failed to restart IPC server: {restart_err}")

def wait_for_ipc_ready(timeout=10):
    """Wait until the IPC socket becomes available for connection."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        if os.path.exists(IPC_SOCKET_PATH):
            try:
                test_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_socket.settimeout(2)
                test_socket.connect(IPC_SOCKET_PATH)
                test_socket.close()
                logging.info("[IPC] IPC socket is now live and connectable")
                return True
            except Exception:
                pass
        time.sleep(0.5)

    logging.warning("[IPC] wait_for_ipc_ready() timed out")
    return False

def start_health_monitoring():
    """Start periodic health monitoring for connections and IPC."""
    def monitor_loop():
        while True:
            try:
                ensure_ipc_socket_health()
            except Exception as e:
                logging.error(f"[MONITOR] Health check error: {e}")
            time.sleep(30)  # Check every 30 seconds
    
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    logging.info("[MONITOR] Started system health monitoring")

def purge_connections_file():
    """
    Purge the connections file only if no active WebSocket clients are still connected.
    """
    try:
        active_clients = get_active_websocket_clients()
        
        if active_clients:
            logging.warning(f"[CONN-FILE] Skipping purge: {len(active_clients)} active clients still connected: {active_clients}")
            return False

        if os.path.exists(CONNECTIONS_FILE):
            os.remove(CONNECTIONS_FILE)
            logging.info(f"[CONN-FILE] Purged connections file at {CONNECTIONS_FILE}")
            return True

        return False
    except Exception as e:
        logging.error(f"[CONN-FILE] Error during purge: {e}")
        return False

def stop_ipc_server():
    global ipc_server_running
    ipc_server_running = False

    if os.path.exists(IPC_SOCKET_PATH):
        try:
            os.unlink(IPC_SOCKET_PATH)
            logging.info(f"[IPC] Removed socket at {IPC_SOCKET_PATH}")
        except Exception as e:
            logging.error(f"[IPC] Error removing socket: {e}")

    # This already triggers purge:
    purge_connections_file()

###################################### Virtual IR SHELL WORK ###############################

def save_ir_cmd_response(command_id, response):
    """Save an IR shell command response to a dedicated file."""
    with websocket_lock:
        try:
            data = {}
            if os.path.exists(IR_SHELL_FILE):
                try:
                    with open(IR_SHELL_FILE, 'r') as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    data = {"commands": {}, "responses": {}}
            else:
                data = {"commands": {}, "responses": {}}
            
            # Add the response
            data["responses"][command_id] = {
                "response": response,
                "timestamp": time.time()
            }
            
            # Write to file
            with open(IR_SHELL_FILE, 'w') as f:
                json.dump(data, f)
            
            # Set permissions
            os.chmod(IR_SHELL_FILE, 0o666)
            
            logging.info(f"[IR-SHELL-FILE] Saved response for command ID: {command_id}")
            return True
        except Exception as e:
            logging.error(f"[IR-SHELL-FILE] Error saving response: {e}")
            return False

def save_ir_cmd_request(client_name, command, command_id):
    """Save an IR shell command request to the file."""
    with websocket_lock:
        try:
            data = {}
            if os.path.exists(IR_SHELL_FILE):
                try:
                    with open(IR_SHELL_FILE, 'r') as f:
                        data = json.load(f)
                except json.JSONDecodeError:
                    data = {"commands": {}, "responses": {}}
            else:
                data = {"commands": {}, "responses": {}}
            
            # Initialize if needed
            if "commands" not in data:
                data["commands"] = {}
            if "responses" not in data:
                data["responses"] = {}
            
            # Add the command
            if client_name not in data["commands"]:
                data["commands"][client_name] = []
            
            # Use 'shell_command' field to match what the client expects
            data["commands"][client_name].append({
                "command_id": command_id,
                "shell_command": command,  # Changed from 'command' to 'shell_command'
                "timestamp": time.time(),
                "status": "pending"
            })
            
            # Write to file
            temp_file = IR_SHELL_FILE + ".tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f)
            os.rename(temp_file, IR_SHELL_FILE)
            
            # Set permissions
            os.chmod(IR_SHELL_FILE, 0o666)
            
            logging.info(f"[IR-SHELL-FILE] Saved command request for {client_name}: {command}")
            return True
        except Exception as e:
            logging.error(f"[IR-SHELL-FILE] Error saving command request: {e}")
            return False

def get_ir_cmd_response(command_id):
    """Get an IR shell command response from the dedicated file."""
    try:
        if not os.path.exists(IR_SHELL_FILE):
            return None
        
        with open(IR_SHELL_FILE, 'r') as f:
            try:
                data = json.load(f)
                if "responses" in data and command_id in data["responses"]:
                    return data["responses"][command_id]["response"]
                return None
            except json.JSONDecodeError:
                return None
    except Exception as e:
        logging.error(f"[IR-SHELL-FILE] Error getting response: {e}")
        return None

def get_ir_pending_commands(client_name):
    """Get pending IR shell commands for a client."""
    try:
        if not os.path.exists(IR_SHELL_FILE):
            return []
        
        with open(IR_SHELL_FILE, 'r') as f:
            try:
                data = json.load(f)
                if "commands" in data and client_name in data["commands"]:
                    # Only return commands with status="pending"
                    return [cmd for cmd in data["commands"][client_name] if cmd.get("status") == "pending"]
                return []
            except json.JSONDecodeError:
                return []
    except Exception as e:
        logging.error(f"[IR-SHELL-FILE] Error getting pending commands: {e}")
        return []

def mark_ir_cmd_sent(client_name, command_id):
    """Mark an IR shell command as sent."""
    with websocket_lock:
        try:
            if not os.path.exists(IR_SHELL_FILE):
                return False
            
            with open(IR_SHELL_FILE, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    return False
            
            # Find the command and mark it as sent
            if "commands" in data and client_name in data["commands"]:
                for cmd in data["commands"][client_name]:
                    if cmd.get("command_id") == command_id:
                        cmd["status"] = "sent"
                        cmd["sent_time"] = time.time()
                        break
            
            # Write back to file
            with open(IR_SHELL_FILE, 'w') as f:
                json.dump(data, f)
            
            return True
        except Exception as e:
            logging.error(f"[IR-SHELL-FILE] Error marking command sent: {e}")
            return False
