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
import json
import hmac
import time
import hashlib
import asyncio
import logging
import threading
import websockets
import server_siem
from clients import load_psks
from shared_state import (
    websocket_lock,
    COMMANDS_FILE,
    save_connection,
    remove_connection,
    update_connection_timestamp
)

LOG_DIR = "./logs"
ENDPOINT_LOG_FILE = os.path.join(LOG_DIR, "monisec-server.log")

async def authenticate_websocket_client(websocket):
    """Authenticate a WebSocket client using the PSK system and challenge-response."""
    try:
        # Step 1: Wait for handshake with client_name
        try:
            raw_message = await asyncio.wait_for(websocket.recv(), timeout=10)
            payload = json.loads(raw_message)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            await websocket.send(json.dumps({"status": "error", "message": "Invalid handshake or timeout"}))
            return None

        client_name = payload.get("client_name")
        if not client_name:
            await websocket.send(json.dumps({"status": "error", "message": "Missing client_name"}))
            return None

        # Step 2: Load PSK store
        psks = load_psks()
        client_psk = None

        for agent_data in psks.values():
            if agent_data["AgentName"] == client_name:
                client_psk = agent_data["AgentPSK"]
                break

        if not client_psk:
            await websocket.send(json.dumps({"status": "error", "message": "Unknown client"}))
            from shared_state import remove_connection
            remove_connection(client_name)
            return None

        # Step 3: Send challenge
        challenge = os.urandom(16).hex()
        await websocket.send(json.dumps({"status": "challenge", "challenge": challenge}))

        # Step 4: Wait for HMAC response
        try:
            response_json = await asyncio.wait_for(websocket.recv(), timeout=10)
            response_data = json.loads(response_json)
            client_hmac = response_data.get("hmac")
        except (asyncio.TimeoutError, json.JSONDecodeError):
            await websocket.send(json.dumps({"status": "error", "message": "Invalid HMAC response or timeout"}))
            from shared_state import remove_connection
            remove_connection(client_name)
            return None

        # Step 5: Validate HMAC
        expected_hmac = hmac.new(client_psk.encode(), challenge.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(client_hmac, expected_hmac):
            await websocket.send(json.dumps({"status": "error", "message": "Authentication failed"}))
            from shared_state import remove_connection
            remove_connection(client_name)
            return None

        await websocket.send(json.dumps({"status": "success", "message": "Authentication successful"}))
        return client_name

    except Exception as e:
        try:
            from shared_state import remove_connection
            remove_connection(client_name)
        except:
            pass  # Failsafe if client_name was never set
        return None

async def maintain_connection(websocket, client_name):
    """Keep the connection alive with periodic heartbeats."""
    try:
        while True:
            await asyncio.sleep(30)  # Send heartbeat every 30 seconds
            try:
                await websocket.send(json.dumps({"type": "heartbeat"}))
                
                # Update the timestamp in the connections file
                from shared_state import update_connection_timestamp
                update_connection_timestamp(client_name)
            except Exception as e:
                logging.error(f"[WEBSOCKET] Heartbeat to {client_name} failed: {e}")
                break
    except asyncio.CancelledError:
        pass  # Task was cancelled, exit gracefully
    except Exception as e:
        logging.error(f"[WEBSOCKET] Heartbeat task error for {client_name}: {e}")

async def monitor_active_connections():
    """Monitor the active connections dictionary periodically."""
    while True:
        await asyncio.sleep(60)  # Check every 60 seconds
        from shared_state import get_active_connections
        connections = get_active_connections()
        connection_list = list(connections.keys())
        logging.info(f"[WEBSOCKET] Active connections: {connection_list}")

async def process_websocket_message(websocket, client_name, message):
    """Process incoming WebSocket messages with improved logging and error handling."""
    try:
        logging.info(f"[WEBSOCKET] Received message from {client_name}: {message[:50]}..." if len(message) > 50 else f"[WEBSOCKET] Received message from {client_name}: {message}")
        
        data = json.loads(message)
        message_type = data.get("type")
        
        if message_type == "heartbeat":
            # Respond to heartbeat
            await websocket.send(json.dumps({"type": "heartbeat_ack", "timestamp": time.time()}))
            
            # Verify connection is registered by updating timestamp
            from shared_state import update_connection_timestamp
            update_connection_timestamp(client_name)
                    
        elif message_type == "ir_shell_response":
            # Handle IR shell response with file-based approach
            command_id = data.get("command_id")
            response = data.get("response")
            
            if command_id and response:
                logging.info(f"[WEBSOCKET] Received shell response from {client_name} - command_id: {command_id}")
                
                # Store response in file using the dedicated function
                from shared_state import save_ir_cmd_response
                save_ir_cmd_response(command_id, response)
                logging.info(f"[WEBSOCKET] Saved response to file: {command_id}")
                
            else:
                logging.warning(f"[WEBSOCKET] Incomplete response data from {client_name}: {data}")
                
        elif message_type == "poll_commands":
            # Handle command polling - log that a poll was received
            await handle_command_poll(websocket, client_name)
            
        else:
            logging.warning(f"[WEBSOCKET] Unknown message type from {client_name}: {message_type}")
            
    except json.JSONDecodeError:
        logging.error(f"[WEBSOCKET] Invalid JSON message from {client_name}: {message[:100]}")
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error processing message from {client_name}: {e}")
        import traceback
        logging.error(traceback.format_exc())
        
async def process_websocket_message(websocket, client_name, message):
    """Process incoming WebSocket messages with improved logging and error handling."""
    try:
        logging.info(f"[WEBSOCKET] Received message from {client_name}: {message[:50]}..." if len(message) > 50 else f"[WEBSOCKET] Received message from {client_name}: {message}")
        
        data = json.loads(message)
        message_type = data.get("type")
        
        if message_type == "heartbeat":
            # Respond to heartbeat
            await websocket.send(json.dumps({"type": "heartbeat_ack", "timestamp": time.time()}))
            
            # Verify connection is registered by updating timestamp
            from shared_state import update_connection_timestamp
            update_connection_timestamp(client_name)
                    
        elif message_type == "ir_shell_response":
            # Handle IR shell response with file-based approach
            command_id = data.get("command_id")
            response = data.get("response")
            
            if command_id and response:
                logging.info(f"[WEBSOCKET] Received shell response from {client_name} - command_id: {command_id}")
                
                # Store response in file using the correct function name
                from shared_state import save_ir_cmd_response
                save_ir_cmd_response(command_id, response)
                logging.info(f"[WEBSOCKET] Saved response to file: {command_id}")
            else:
                logging.warning(f"[WEBSOCKET] Incomplete response data from {client_name}: {data}")
                
        elif message_type == "poll_commands":
            # Handle command polling - log that a poll was received
            await handle_command_poll(websocket, client_name)
            
        else:
            logging.warning(f"[WEBSOCKET] Unknown message type from {client_name}: {message_type}")
            
    except json.JSONDecodeError:
        logging.error(f"[WEBSOCKET] Invalid JSON message from {client_name}: {message[:100]}")
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error processing message from {client_name}: {e}")
        import traceback
        logging.error(traceback.format_exc())

async def ir_shell_init(client_name):
    """Initialize an IR shell session for a client."""
    from shared_state import is_client_connected, save_ir_cmd_request, get_ir_cmd_response
    import uuid
    
    # Check if client is connected
    if not is_client_connected(client_name):
        return {
            "status": "error",
            "message": f"Client {client_name} is not connected"
        }
    
    # Create command ID for this session
    command_id = f"{client_name}_ir_init_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    # Use file-based approach to communicate with the WebSocket handler
    try:
        # Save command to the file for the websocket handler to pick up
        save_ir_cmd_request(client_name, "ir-shell-init", command_id)
        
        # Wait for response with timeout
        start_time = time.time()
        max_wait = 30  # seconds
        
        while time.time() - start_time < max_wait:
            # Check if response has been received
            response = get_ir_cmd_response(command_id)
            if response:
                return {
                    "status": "success",
                    "message": f"IR shell initialized for {client_name}"
                }
            await asyncio.sleep(0.5)
            
        # Timeout occurred
        return {
            "status": "error",
            "message": f"Timeout waiting for IR shell initialization from {client_name}"
        }
        
    except Exception as e:
        logging.error(f"[IR-SHELL] Error initializing shell: {e}")
        return {
            "status": "error",
            "message": f"Error initializing IR shell: {str(e)}"
        }

async def send_via_ipc(client_name, command, command_id=None):
    """Send a command via IPC to the WebSocket handler."""
    import socket
    from shared_state import IPC_SOCKET_PATH
    
    if command_id is None:
        command_id = f"{client_name}_{int(time.time())}_{os.urandom(4).hex()}"
    
    try:
        # Connect to the IPC socket
        ipc_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ipc_socket.settimeout(10)
        ipc_socket.connect(IPC_SOCKET_PATH)
        
        # Prepare request
        request = {
            "command": "websocket_command",
            "client_name": client_name,
            "shell_command": command,
            "command_id": command_id
        }
        
        # Send request
        ipc_socket.sendall(json.dumps(request).encode('utf-8'))
        
        # We don't need to wait for a response here, as we'll check
        # ir_shell_pending_responses asynchronously
        return True
    except Exception as e:
        logging.error(f"[IPC] Command error: {e}")
        return False
    finally:
        if 'ipc_socket' in locals():
            ipc_socket.close()

# In websocket_manager.py

async def ir_shell_execute(client_name, command):
    """
    Execute a command in an IR shell session.
    
    Args:
        client_name: Name of the client
        command: Command to execute
    
    Returns:
        dict: Command response
    """
    from shared_state import is_client_connected, save_ir_cmd_request, get_ir_cmd_response
    import uuid
    
    # Check if client is connected
    if not is_client_connected(client_name):
        return {
            "status": "error",
            "message": f"Client {client_name} is not connected"
        }
    
    # Create command ID
    command_id = f"{client_name}_ir_cmd_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    # Use file-based approach to communicate with the WebSocket handler
    try:
        # Save command to the file
        save_ir_cmd_request(client_name, command, command_id)
        
        # Wait for response with timeout
        start_time = time.time()
        max_wait = 30  # seconds
        
        while time.time() - start_time < max_wait:
            # Check if response has been received
            response = get_ir_cmd_response(command_id)
            if response:
                return response
            await asyncio.sleep(0.5)
            
        # Timeout occurred
        return {
            "status": "error",
            "message": f"Command timed out after {max_wait} seconds"
        }
        
    except Exception as e:
        logging.error(f"[IR-SHELL] Error executing command: {e}")
        return {
            "status": "error",
            "message": f"Error executing command: {str(e)}"
        }

async def ir_shell_exit(client_name):
    """
    Terminate an IR shell session.
    
    Args:
        client_name: Name of the client
    
    Returns:
        dict: Success or error message
    """
    from shared_state import is_client_connected
    
    # Check if client is connected
    if not is_client_connected(client_name):
        return {
            "status": "success",
            "message": f"Client {client_name} is not connected"
        }
    
    # Generate a command ID
    command_id = f"{client_name}_ir_exit_{int(time.time())}"
    
    try:
        # Send the exit command via IPC
        result = await send_via_ipc(client_name, "ir-shell-exit", command_id)
        
        # We don't need to wait for a response for exit commands
        return {
            "status": "success",
            "message": f"IR shell terminated for {client_name}"
        }
        
    except Exception as e:
        logging.error(f"[IR-SHELL] Error terminating shell: {e}")
        return {
            "status": "error",
            "message": f"Error terminating IR shell: {str(e)}"
        }

def debug_websocket_connections():
    """Print details about the current WebSocket connections dictionary."""
    from shared_state import get_active_connections
    connections = get_active_connections()
    connection_list = list(connections.keys())
    
    print(f"[WEBSOCKET-DEBUG] Active connections: {connection_list}")
    return connection_list

async def connect_client(client_name, websocket):
    """Forcefully register a client connection."""
    from shared_state import save_connection
    connection_info = {
        "socket_id": id(websocket),
        "nat_status": "unknown",
        "timestamp": time.time()
    }
    save_connection(client_name, connection_info)
    logging.info(f"[WEBSOCKET] Forcefully registered client {client_name}")
    
    # Get current connections for logging
    from shared_state import get_active_connections
    connections = get_active_connections()
    connection_list = list(connections.keys())
    
    logging.info(f"[WEBSOCKET] After forced register - active connections: {connection_list}")
    
    return True
    
async def websocket_handler(websocket, path):
    """Handles incoming WebSocket client connections and messages."""
    client_name = None
    
    try:
        # Authenticate client
        client_name = await authenticate_websocket_client(websocket)
        if not client_name:
            logging.warning("[WEBSOCKET] Authentication failed")
            await websocket.close()
            return

        # Save connection info
        socket_id = id(websocket)
        detected_ip = websocket.remote_address[0] if websocket.remote_address else "unknown"
        save_connection(client_name, {
            "socket_id": socket_id,
            "nat_status": "WebSocket",
            "detected_ip": detected_ip
        })

        logging.info(f"[WEBSOCKET] Client {client_name} connected from {detected_ip}")

        # Main loop to handle messages from the client
        while True:
            try:
                message = await websocket.recv()
                if not message:
                    logging.warning(f"[WEBSOCKET] Empty message from {client_name}")
                    continue

                # Process the message
                await process_websocket_message(websocket, client_name, message)

            except websockets.exceptions.ConnectionClosed:
                logging.info(f"[WEBSOCKET] Connection closed by {client_name}")
                break
            except Exception as e:
                logging.error(f"[WEBSOCKET] Error handling message: {e}")
                import traceback
                logging.error(traceback.format_exc())
                break

    except Exception as e:
        logging.error(f"[WEBSOCKET] Unexpected error: {e}")
        import traceback
        logging.error(traceback.format_exc())
    finally:
        if client_name:
            # Remove from active connections
            remove_connection(client_name)
            logging.info(f"[WEBSOCKET] Client {client_name} disconnected and removed")
        
        try:
            await websocket.close()
        except:
            pass

async def handle_command_poll(websocket, client_name):
    """Handle client polling for pending commands with IR shell support."""
    try:
        # Update connection timestamp
        from shared_state import update_connection_timestamp
        update_connection_timestamp(client_name)
        
        # Check for pending commands in the IR shell file
        from shared_state import get_ir_pending_commands, mark_ir_cmd_sent
        ir_pending_commands = get_ir_pending_commands(client_name)
        
        # Check for pending commands in the regular file
        regular_pending_commands = []
        with websocket_lock:
            if os.path.exists(COMMANDS_FILE):
                try:
                    with open(COMMANDS_FILE, 'r') as f:
                        content = f.read().strip()
                        if content:
                            all_commands = json.loads(content)
                            
                            if client_name in all_commands and all_commands[client_name]:
                                # Get all commands for this client
                                regular_pending_commands = all_commands[client_name]
                                
                                # Clear the commands for this client
                                all_commands[client_name] = []
                                
                                # Write back the updated command queue
                                with open(COMMANDS_FILE, 'w') as f:
                                    json.dump(all_commands, f)
                                    
                                logging.info(f"[WEBSOCKET] Retrieved {len(regular_pending_commands)} regular commands for {client_name}")
                except json.JSONDecodeError:
                    logging.error("[WEBSOCKET] Invalid JSON in commands file")
                except Exception as e:
                    logging.error(f"[WEBSOCKET] Error reading commands file: {e}")
        
        # Combine IR and regular commands
        all_pending_commands = ir_pending_commands + regular_pending_commands
        
        # Mark IR commands as sent
        for cmd in ir_pending_commands:
            mark_ir_cmd_sent(client_name, cmd.get("command_id"))
        
        # If we have pending commands, send them to the client
        if all_pending_commands:
            await websocket.send(json.dumps({
                "type": "pending_commands",
                "commands": all_pending_commands
            }))
            logging.info(f"[WEBSOCKET] Sent {len(all_pending_commands)} pending commands to {client_name}")
            
    except Exception as e:
        logging.error(f"[WEBSOCKET] Error handling command poll: {e}")

async def process_websocket_command(client_name, payload):
    """
    Processes a command received from a WebSocket client.

    Args:
        client_name (str): Name of the client sending the message.
        payload (dict): Parsed JSON payload from the WebSocket message.
    """
    try:
        if not isinstance(payload, dict):
            logging.warning(f"[WEBSOCKET-CMD] Payload from {client_name} is not a dict: {payload}")
            return

        command_type = payload.get("command")
        command_id = payload.get("command_id")

        if command_type == "ir-shell-response":
            if not command_id:
                logging.warning(f"[WEBSOCKET-CMD] Missing command_id in IR shell response from {client_name}")
                return

            # Store the response in the global shared state
            from shared_state import ir_shell_pending_responses
            ir_shell_pending_responses[command_id] = payload

        elif command_type == "status":
            status_msg = payload.get("message", "")

        elif command_type == "log":
            log_entry = payload.get("entry", "")

        else:
            logging.warning(f"[WEBSOCKET-CMD] Unknown command type from {client_name}: {command_type}")

    except Exception as e:
        logging.error(f"[WEBSOCKET-CMD] Exception processing command from {client_name}: {e}")
        import traceback
        logging.error(traceback.format_exc())

# In websocket_manager.py

def handle_client_reconnection(client_name, websocket):
    """Handle client reconnection with state recovery using file-based tracking."""
    
    try:
        # Update connection timestamp to ensure freshness
        from shared_state import update_connection_timestamp
        update_connection_timestamp(client_name)
        
        # Optionally send a notification to the client about reconnection
        asyncio.create_task(send_reconnection_notification(websocket, client_name))
    except Exception as e:
        logging.error(f"[RECONNECT] Error handling reconnection for {client_name}: {e}")

async def send_reconnection_notification(websocket, client_name):
    """Send a notification to the client that it has successfully reconnected."""
    try:
        await websocket.send(json.dumps({
            "type": "system_notification",
            "message": "Connection recovered",
            "reconnect": True
        }))
    except Exception as e:
        logging.error(f"[RECONNECT] Failed to send reconnection notification: {e}")

async def close_websocket_gracefully(websocket):
    """Close a websocket connection gracefully with a short delay."""
    try:
        await asyncio.sleep(0.5)  # Short delay before closing
        await websocket.close(1000, "Replaced by newer connection")
    except Exception as e:
        pass

async def handler_adaptor(websocket):
    # In newer websockets versions, use request_headers and path info
    # Extract path from URL if available
    path = ""
    if hasattr(websocket, "request_headers"):
        # Try to extract from request headers or URL
        try:
            path_info = websocket.request_headers.get("PATH_INFO", "")
            if not path_info and hasattr(websocket, "uri"):
                # Try extracting from URI
                uri = websocket.uri
                path = str(uri).split("//")[1].split("/", 1)[1] if "/" in str(uri).split("//")[1] else ""
            else:
                path = path_info
        except:
            path = ""
    
    # Call the handler with extracted path info
    await handle_websocket_client(websocket, path)


#################################### Virtual IR Shell Build #################################

async def virtual_shell_cli(client_name):
    """
    Provide an interactive IR shell CLI using WebSocket communication.
    
    Args:
        client_name (str): Name of the client to connect to
        
    Returns:
        dict: Result of the shell session
    """
    from shared_state import (
        save_ir_cmd_request, 
        get_ir_cmd_response, 
        is_client_connected
    )
    import uuid
    import time
    
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
    
    # Wait for response
    start_time = time.time()
    init_success = False
    
    while time.time() - start_time < 30 and not init_success:
        # Check for response
        response = get_ir_cmd_response(init_cmd_id)
        if response:
            if response.get("status") == "success":
                init_success = True
                print("IR shell initialized successfully!")
            else:
                print(f"IR shell initialization failed: {response.get('message', 'Unknown error')}")
                return {"status": "error", "message": response.get('message', 'Unknown error')}
            break
            
        time.sleep(0.5)
        print(".", end="", flush=True)
    
    if not init_success:
        print("\nIR shell initialization timed out.")
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
                
                time.sleep(0.5)
                print(".", end="", flush=True)
            
            if not response_received:
                print("\nCommand timed out after 30 seconds")
                
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            shell_active = False
        except Exception as e:
            print(f"[ERROR] {e}")
    
    print("IR shell session ended.")
    return {"status": "success", "message": "IR shell session completed"}
