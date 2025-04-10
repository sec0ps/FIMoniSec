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
import sys
import socket
import threading
import logging
import os
import hmac
import hashlib
import time
import json
import daemon
import daemon.pidfile
import signal
import asyncio
import websockets
import threading
import server_siem
import updater
from shared_state import websocket_lock, IPC_SOCKET_PATH
import websocket_manager
import clients


# Define a fixed base directory for the server
SERVER_BASE_DIR = "/opt/FIMoniSec/Monisec-Server"

# Define the config file path using the base directory
CONFIG_FILE = os.path.join(SERVER_BASE_DIR, "monisec-server.config")

server_socket = None  # Global reference to the server socket
shutdown_event = threading.Event()  # Event to signal shutdown

DEFAULT_CONFIG = {
    "HOST": "0.0.0.0",
    "PORT": 5555,
    "WEBSOCKET_PORT": 8765,
    "LOG_DIR": "./logs",
    "LOG_FILE": "monisec-server.log",
    "PSK_STORE_FILE": "psk_store.json",
    "MAX_CLIENTS": 10,
    "siem_settings": {
        "enabled": False,
        "siem_server": "",
        "siem_port": 0
    }
}

# List of valid modules for the restart command
VALID_MODULES = ["fim_client", "pim", "lim"]

# Function to create default config file if missing
def create_default_config():
    """Creates a default configuration file at the fixed location."""
    # Make sure the directory exists
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
    
    print(f"Default configuration created at {CONFIG_FILE}")

def load_config():
    """Load server configuration from the fixed config file path."""
    if not os.path.exists(CONFIG_FILE):
        print(f"monisec-server.config not found at {CONFIG_FILE}. Creating default configuration.")
        create_default_config()
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            
        # Ensure all required keys exist by merging with defaults
        for key, value in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value
                
        return config
    except json.JSONDecodeError:
        print(f"Error parsing {CONFIG_FILE}. Creating default configuration.")
        create_default_config()
        # Try loading again
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config

config = load_config()  # ✅ Load config first

# ✅ Use values from the config file dynamically
HOST = config["HOST"]
PORT = config["PORT"]
LOG_DIR = config["LOG_DIR"]
LOG_FILE = os.path.join(LOG_DIR, config["LOG_FILE"])
PSK_STORE_FILE = config["PSK_STORE_FILE"]
MAX_CLIENTS = config["MAX_CLIENTS"]
SIEM_CONFIG = config.get("siem_settings", {})
PID_FILE = os.path.join(LOG_DIR, "monisec-server.pid")

def handle_shutdown(signum, frame):
    logging.info("[INFO] Shutting down MoniSec Server...")
    shutdown_event.set()

    # Stop IPC server
    from shared_state import stop_ipc_server, IPC_SOCKET_PATH
    stop_ipc_server()

    # Double-check IPC socket is removed
    if os.path.exists(IPC_SOCKET_PATH):
        try:
            os.unlink(IPC_SOCKET_PATH)
            logging.info(f"[INFO] Removed IPC socket: {IPC_SOCKET_PATH}")
        except Exception as e:
            logging.warning(f"[WARNING] Failed to remove IPC socket: {e}")

    if server_socket:
        server_socket.close()

    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            logging.info(f"[INFO] Removed PID file: {PID_FILE}")
    except Exception as e:
        logging.warning(f"[WARNING] Failed to remove PID file: {e}")

    logging.info("[INFO] MoniSec Server stopped.")
    sys.exit(0)

# Register SIGINT (CTRL+C) and SIGTERM (kill command) for graceful shutdown
signal.signal(signal.SIGINT, handle_shutdown)
signal.signal(signal.SIGTERM, handle_shutdown)

def run_server():
    # First, reset all logging handlers to ensure we're not using closed file descriptors
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:  # Make a copy of the list for safe iteration
        root_logger.removeHandler(handler)
        try:
            handler.close()  # Close any open file descriptors
        except OSError as e:
            # Ignore "Bad file descriptor" errors when closing handlers
            if e.errno != 9:  # Only re-raise if it's not a "Bad file descriptor" error
                raise
    
    # Setup proper logging
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    
    # Now it's safe to log
    logging.info("[INIT] Starting run_server function...")
    
    siem_config = server_siem.load_siem_config()
    if siem_config:
        logging.info("[INFO] SIEM integration is enabled.")

    initialize_log_storage()

    # Verify PID file was created properly
    verify_pid_file()
    
    logging.info("Starting MoniSec Server...")
    logging.info(f"Server PID: {os.getpid()}")
    
    # Start WebSocket server in a background thread
    websocket_thread = threading.Thread(target=start_websocket_server, daemon=True)
    websocket_thread.start()
    logging.info(f"[INFO] WebSocket server thread started on port {config['WEBSOCKET_PORT']}")
    
    # Start IPC server for command-line tools with more detailed logging
    try:
        from shared_state import start_ipc_server, start_health_monitoring, IPC_SOCKET_PATH
        logging.info(f"[IPC] Imported IPC functions: {IPC_SOCKET_PATH}")
        
        # Check for and remove stale socket
        if os.path.exists(IPC_SOCKET_PATH):
            try:
                os.unlink(IPC_SOCKET_PATH)
                logging.info(f"[IPC] Removed stale socket at {IPC_SOCKET_PATH}")
            except Exception as e:
                logging.error(f"[IPC] Error removing stale socket: {e}")
        
        # Start the IPC server
        logging.info("[IPC] Calling start_ipc_server() function...")
        start_ipc_server()
        
        # Start health monitoring
        start_health_monitoring()
        logging.info("[IPC] Started IPC server health monitoring")
        
        # Verify IPC socket exists
        if not os.path.exists(IPC_SOCKET_PATH):
            logging.error(f"[IPC] ERROR: IPC socket not created at {IPC_SOCKET_PATH}")
            
            # Try emergency socket creation method
            logging.info("[IPC] Normal IPC initialization failed, trying emergency method...")
            if ensure_ipc_socket_exists():
                logging.info("[IPC] Emergency IPC socket creation successful")
            else:
                logging.error("[IPC] All IPC socket creation methods failed")
        else:
            logging.info(f"[IPC] IPC server started successfully at {IPC_SOCKET_PATH}")
            # Fix permissions if needed
            try:
                os.chmod(IPC_SOCKET_PATH, 0o777)
                logging.info(f"[IPC] Set socket permissions to 0o777")
            except Exception as e:
                logging.error(f"[IPC] Error setting socket permissions: {e}")
    except Exception as e:
        logging.error(f"[IPC] Error during IPC server initialization: {e}")
        import traceback
        logging.error(traceback.format_exc())
        
        # Try emergency method as last resort
        logging.info("[IPC] Trying emergency IPC socket creation after exception...")
        ensure_ipc_socket_exists()
    
    # Start the main TCP server
    logging.info("[INIT] Starting main TCP server...")
    start_server()

def start_server():
    # Your existing TCP server code
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(MAX_CLIENTS)
    logging.info(f"[INFO] MoniSec Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(target=clients.handle_client, args=(client_socket, client_address))
            client_thread.start()
    except Exception as e:
        logging.error(f"[ERROR] Server encountered an error: {e}")
    finally:
        logging.info("[INFO] Cleaning up server resources...")
        server.close()

def ensure_ipc_socket_exists():
    """Emergency function to ensure IPC socket exists."""
    try:
        # Import the IPC path
        from shared_state import IPC_SOCKET_PATH
        
        # Check if it already exists
        if os.path.exists(IPC_SOCKET_PATH):
            logging.info(f"[IPC-EMERGENCY] IPC socket already exists at {IPC_SOCKET_PATH}")
            return True
            
        # Create a basic socket file
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(IPC_SOCKET_PATH)
        server.listen(5)
        
        # Set permissions
        os.chmod(IPC_SOCKET_PATH, 0o777)
        
        logging.info(f"[IPC-EMERGENCY] Created IPC socket at {IPC_SOCKET_PATH}")
        
        # Start a simple handler thread
        def handle_connections():
            while True:
                try:
                    client, _ = server.accept()
                    response = json.dumps({"status": "emergency", "message": "Emergency IPC handler"})
                    client.sendall(response.encode('utf-8'))
                    client.close()
                except Exception as e:
                    logging.error(f"[IPC-EMERGENCY] Error: {e}")
                    break
                    
        thread = threading.Thread(target=handle_connections, daemon=True)
        thread.start()
        
        return True
    except Exception as e:
        logging.error(f"[IPC-EMERGENCY] Failed to create emergency socket: {e}")
        return False

def start_websocket_server():
    """Start the WebSocket server in a background thread with its own event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    ws_host = "0.0.0.0"
    ws_port = config["WEBSOCKET_PORT"]
    
    logging.info(f"[WEBSOCKET] Starting server on {ws_host}:{ws_port}")
    
    try:
        async def run_server():
            logging.info("[WEBSOCKET] Creating server")
            
            # Import the handler from websocket_manager
            from websocket_manager import websocket_handler
            
            # Create a wrapper function to pass the server_base_dir parameter
            async def handler_wrapper(websocket):
                await websocket_handler(websocket, SERVER_BASE_DIR)
            
            # Start the WebSocket server with the handler function
            server = await websockets.serve(
                handler_wrapper, 
                ws_host, 
                ws_port,
                ping_interval=60,  # Send ping every 60 seconds
                ping_timeout=30,   # Wait 30 seconds for pong
                close_timeout=10,  # Wait 10 seconds for close to complete
                max_size=10485760  # 10MB maximum message size
            )
            logging.info(f"[WEBSOCKET] Server started successfully on {ws_host}:{ws_port}")
            
            # Schedule periodic file checks
            async def check_connections_periodically():
                while True:
                    await asyncio.sleep(60)
                    try:
                        from shared_state import get_active_connections
                        connections = get_active_connections()
                        if connections:
                            logging.info(f"[WEBSOCKET-FILE] Active connections check: {list(connections.keys())}")
                    except Exception as e:
                        logging.error(f"[WEBSOCKET-FILE] Error checking connections: {e}")
            
            # Start connection monitoring
            monitor_task = asyncio.create_task(check_connections_periodically())
            
            # Run forever
            await asyncio.Future()
        
        loop.run_until_complete(run_server())
    except Exception as e:
        logging.error(f"[WEBSOCKET] Server startup error: {e}")
        import traceback
        logging.error(traceback.format_exc())
    finally:
        logging.info("[WEBSOCKET] Closing event loop")
        loop.close()

async def close_websocket_gracefully(websocket):
    """Close a websocket connection gracefully with a short delay."""
    try:
        await asyncio.sleep(0.5)  # Short delay before closing
        await websocket.close(1000, "Replaced by newer connection")
        logging.debug("[WEBSOCKET-DEBUG] Old connection closed gracefully")
    except Exception as e:
        logging.debug(f"[WEBSOCKET-DEBUG] Error during graceful close: {e}")
          
def initialize_log_storage():
    """Ensures necessary log directories and files exist with proper permissions."""
    try:
        # Ensure logs directory exists
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)

        # Ensure main MoniSec Server log file exists
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write("")  # Create an empty file
            os.chmod(LOG_FILE, 0o600)  # Secure permissions

        # Ensure SIEM log file exists
        SIEM_LOG_FILE = os.path.join(LOG_DIR, "siem-forwarding.log")
        if not os.path.exists(SIEM_LOG_FILE):
            with open(SIEM_LOG_FILE, "w") as f:
                f.write("")  # Create empty file
            os.chmod(SIEM_LOG_FILE, 0o600)  # Secure permissions

        logging.info(f"Log storage initialized. Logs directory: {LOG_DIR}")

    except Exception as e:
        logging.error(f"Failed to initialize log storage: {e}")

def ensure_directories():
    """Ensures necessary directories exist with proper permissions."""
    try:
        # Ensure logs directory exists
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        logging.info(f"Ensured logs directory exists: {LOG_DIR}")
    except Exception as e:
        print(f"[ERROR] Failed to create directories: {e}")
        sys.exit(1)

# Add this to the beginning of monisec-server.py

def setup_enhanced_logging():
    """Configure detailed logging to both file and console."""
    os.makedirs(LOG_DIR, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers to avoid duplication
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # File handler for all logs
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Console handler for info and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(levelname)s: %(message)s")
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Special WebSocket debug logger
    websocket_logger = logging.getLogger('websocket')
    websocket_logger.setLevel(logging.INFO)
    websocket_file_handler = logging.FileHandler(os.path.join(LOG_DIR, "websocket.log"))
    websocket_file_handler.setFormatter(file_formatter)
    websocket_logger.addHandler(websocket_file_handler)
    
    logging.info("Enhanced logging initialized")

# Call this function before the server starts
setup_enhanced_logging()

# Add this new function to your code
def verify_pid_file():
    """Verifies that PID file exists and contains the current process ID."""
    if not os.path.exists(PID_FILE):
        logging.error(f"[ERROR] PID file {PID_FILE} was not created properly")
        # Try to create it manually as a fallback
        try:
            with open(PID_FILE, "w") as f:
                f.write(str(os.getpid()))
            logging.info(f"[INFO] Created PID file manually: {PID_FILE}")
            os.chmod(PID_FILE, 0o644)  # Make sure it's readable
            return True
        except Exception as e:
            logging.error(f"[ERROR] Failed to create PID file manually: {e}")
            return False
    return True


async def websocket_server(host="0.0.0.0", port=8765):
    """Start a WebSocket server for IR shell fallback."""
    async def handle_websocket(websocket, path):
        client_name = None
        try:
            # Extract client name from the path (/ws/{client_name})
            path_parts = path.strip('/').split('/')
            if len(path_parts) >= 2 and path_parts[0] == 'ws':
                client_name = path_parts[1]
                
            # Authenticate the client
            auth_success = await authenticate_websocket_client(websocket, client_name)
            if not auth_success:
                logging.warning(f"[WEBSOCKET] Authentication failed for client: {client_name}")
                return
                
            # Store the connection
            with websocket_lock:
                active_websocket_connections[client_name] = websocket
                
            logging.info(f"[WEBSOCKET] Client {client_name} connected")
            
            # Keep connection alive and handle incoming messages
            async for message in websocket:
                await process_websocket_message(websocket, client_name, message)
                
        except Exception as e:
            logging.error(f"[WEBSOCKET] Error: {e}")
        finally:
            # Remove the connection when it closes
            if client_name:
                with websocket_lock:
                    if client_name in active_websocket_connections:
                        del active_websocket_connections[client_name]
                logging.info(f"[WEBSOCKET] Client {client_name} disconnected")
    
    server = await websockets.serve(handle_websocket, host, port)
    logging.info(f"[WEBSOCKET] Server started on {host}:{port}")
    return server

def print_help():
    """Prints the available command-line options for monisec-server.py"""
    print("""
Usage: python monisec-server.py [command] [options]

Management Commands:
  add-agent <agent_name>         Add a new client and generate a unique PSK.
  remove-agent <agent_name>      Remove an existing client.
  list-agents                    List all registered clients.
  configure-siem                 Configure SIEM settings for log forwarding.

Remote Commands:
  <module> [client_name]         Directly restart a module on all clients or a specific client.
                                 Example: python monisec-server.py fim_client server1
  restart <module> [client_name] Alternative syntax for restarting modules.
                                 Example: python monisec-server.py restart fim_client server1
  
  Valid modules: monisec_client, fim_client, pim, lim
  
  yara-scan <client> <path>      Run a YARA scan on a client.
  ir-shell <client>              Spawn an incident response shell on a client.
  update <client>                Trigger a client update.

Diagnostic Commands:
  debug-websocket [reset]        Debug WebSocket connections (with optional reset).
  websocket-status               Show detailed WebSocket and IPC connection status.

Server Control:
  -d                             Launch the MoniSec Server as a daemon.
  stop                           Stop the running MoniSec Server daemon.
  -h, --help                     Show this help message.

If no command is provided, the server will start normally.
""")

def restart_service(module, client_name=None):
    """Restart a service module on a client or all clients."""
    if module not in VALID_MODULES:
        print(f"[ERROR] Invalid module: {module}")
        print(f"Valid modules: {', '.join(VALID_MODULES)}")
        return False
    
    if client_name:
        # Restart module on a specific client
        print(f"[INFO] Sending restart command for {module} to client: {client_name}")
        result = clients.restart_client_service(client_name, module)
        
        if result.get("status") == "success":
            print(f"[SUCCESS] {module} restarted on {client_name}")
            return True
        else:
            print(f"[ERROR] Failed to restart {module} on {client_name}: {result.get('message')}")
            return False
    else:
        # Restart module on all clients
        print(f"[INFO] Sending restart command for {module} to all clients...")
        all_clients = clients.get_all_clients()
        success_count = 0
        
        for client in all_clients:
            print(f"[INFO] Restarting {module} on {client}...")
            result = clients.restart_client_service(client, module)
            
            if result.get("status") == "success":
                print(f"[SUCCESS] {module} restarted on {client}")
                success_count += 1
            else:
                print(f"[ERROR] Failed to restart {module} on {client}: {result.get('message')}")
        
        print(f"[INFO] Restart complete. Successful on {success_count}/{len(all_clients)} clients.")
        return success_count > 0

if __name__ == "__main__":
    should_run_updater = (len(sys.argv) == 1) or (len(sys.argv) > 1 and sys.argv[1] == "-d")

    if should_run_updater:
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")

    if len(sys.argv) > 1:
        action = sys.argv[1]

        if action in VALID_MODULES:
            module = action
            client_name = sys.argv[2] if len(sys.argv) > 2 else None
            print(f"[INFO] Running restart command for module: {module}")
            if restart_service(module, client_name):
                sys.exit(0)
            else:
                sys.exit(1)

        elif action in ["-h", "--help", "help"]:
            print_help()
            sys.exit(0)

        elif action == "list-agents":
            clients.list_clients()
            sys.exit(0)

        elif action == "add-agent":
            clients.add_client()
            sys.exit(0)

        elif action == "remove-agent":
            if len(sys.argv) < 3:
                print("[ERROR] Please specify an agent name to remove.")
                sys.exit(1)
            agent_name = sys.argv[2]
            clients.remove_client(agent_name)
            sys.exit(0)

        elif action == "configure-siem":
            server_siem.configure_siem()
            sys.exit(0)

        elif action == "restart":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py restart <module> [client_name]")
                print(f"Valid modules: {', '.join(VALID_MODULES)}")
                sys.exit(1)
            module = sys.argv[2]
            client_name = sys.argv[3] if len(sys.argv) > 3 else None
            if restart_service(module, client_name):
                sys.exit(0)
            else:
                sys.exit(1)

        elif action == "yara-scan":
            if len(sys.argv) < 4:
                print("[ERROR] Usage: python monisec-server.py yara-scan <client_name> <target_path> [rule_name]")
                sys.exit(1)
            client_name = sys.argv[2]
            target_path = sys.argv[3]
            rule_name = sys.argv[4] if len(sys.argv) > 4 else None
            print(f"[INFO] Triggering YARA scan on {client_name} for path {target_path}...")
            result = clients.run_yara_scan(client_name, target_path, rule_name)
            if result.get("status") == "success":
                print(f"[SUCCESS] YARA scan completed on {client_name}")
                scan_results = result.get("results", [])
                if scan_results:
                    print(f"Found {len(scan_results)} matches:")
                    for match in scan_results:
                        print(f"  - Rule: {match.get('rule')}")
                        print(f"    File: {match.get('file')}")
                        print(f"    Tags: {', '.join(match.get('tags', []))}")
                        print("")
                else:
                    print("No YARA matches found.")
            else:
                print(f"[ERROR] YARA scan failed on {client_name}: {result.get('message')}")
            sys.exit(0)

        elif action == "ir-shell":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py ir-shell <client_name>")
                sys.exit(1)
            client_name = sys.argv[2]
            print(f"[INFO] Establishing IR shell with {client_name}...")
            clients.spawn_ir_shell(client_name)
            sys.exit(0)

        elif action == "update":
            if len(sys.argv) < 3:
                print("[ERROR] Usage: python monisec-server.py update <client_name>")
                sys.exit(1)
            client_name = sys.argv[2]
            print(f"[INFO] Triggering update on {client_name}...")
            result = clients.update_client(client_name)
            if result.get("status") == "success":
                print(f"[SUCCESS] Update triggered on {client_name}")
                update_info = result.get("update_info", {})
                print(f"New version: {update_info.get('version', 'Unknown')}")
            else:
                print(f"[ERROR] Failed to update {client_name}: {result.get('message')}")
            sys.exit(0)

        elif action == "-d":
            print("[INFO] Daemonizing MoniSec Server...")
            os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
            from shared_state import IPC_SOCKET_PATH
            if os.path.exists(IPC_SOCKET_PATH):
                try:
                    os.unlink(IPC_SOCKET_PATH)
                    print(f"[INFO] Removed stale IPC socket at {IPC_SOCKET_PATH}")
                except Exception as e:
                    print(f"[WARNING] Error removing stale socket: {e}")
            with open(LOG_FILE, 'a+') as log_stream:
                with daemon.DaemonContext(
                    pidfile=daemon.pidfile.TimeoutPIDLockFile(PID_FILE),
                    stdout=log_stream,
                    stderr=log_stream,
                    working_directory=os.path.dirname(os.path.abspath(__file__)),
                    umask=0o022
                ):
                    run_server()
            sys.exit(0)

        elif action == "stop":
            if not os.path.exists(PID_FILE):
                print(f"[ERROR] PID file not found: {PID_FILE}")
                sys.exit(1)
            try:
                with open(PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                print(f"[INFO] Stopping MoniSec Server (PID: {pid})...")
                os.kill(pid, signal.SIGTERM)
                print("[INFO] SIGTERM signal sent.")
            except ProcessLookupError:
                print("[WARNING] Process not found. Removing stale PID file.")
                os.remove(PID_FILE)
            except Exception as e:
                print(f"[ERROR] Failed to stop daemon: {e}")
                sys.exit(1)
            sys.exit(0)

        elif action == "debug-websocket":
            print("[INFO] Debugging WebSocket connections...")
            from shared_state import get_active_connections, CONNECTIONS_FILE
            connections = get_active_connections()
            print("\n===== WEBSOCKET CONNECTION DIAGNOSTIC =====")
            print(f"Connections file: {CONNECTIONS_FILE}")
            print(f"Active connections: {list(connections.keys())}")
            print(f"Connection count: {len(connections)}")
            print("==========================================\n")
            if connections:
                print("Connection details:")
                for name, details in connections.items():
                    last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(details.get('timestamp', 0)))
                    print(f"  - {name}: Last seen at {last_seen}")
            if len(sys.argv) > 2 and sys.argv[2] == "reset":
                print("\n[INFO] Resetting WebSocket connection tracking...")
                from shared_state import reset_connection_tracking
                reset_connection_tracking()
                print(f"[INFO] Connection tracking reset complete.")
                print("[INFO] Please restart client connections.")
            sys.exit(0)

        elif action == "websocket-status":
            print("[INFO] Checking WebSocket connection status...")
            from shared_state import get_active_connections, CONNECTIONS_FILE, IPC_SOCKET_PATH
            connections = get_active_connections()
            print(f"[INFO] Server process PID: {os.getpid()}")
            print(f"[INFO] Connected clients: {list(connections.keys())}")
            if os.path.exists(CONNECTIONS_FILE):
                try:
                    for client, details in connections.items():
                        last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(details.get('timestamp', 0)))
                        print(f"  - {client}: Last seen at {last_seen}")
                except Exception as e:
                    print(f"[ERROR] Failed to read connections: {e}")
            else:
                print("[INFO] No connection store found")
            if os.path.exists(IPC_SOCKET_PATH):
                import stat
                socket_stat = os.stat(IPC_SOCKET_PATH)
                socket_perms = stat.filemode(socket_stat.st_mode)
                print(f"[INFO] IPC socket exists at {IPC_SOCKET_PATH} with permissions {socket_perms}")
            else:
                print(f"[WARNING] IPC socket not found at {IPC_SOCKET_PATH}")
            sys.exit(0)

    # Default path: start MoniSec server if no valid command was passed
    siem_config = server_siem.load_siem_config()
    if siem_config:
        logging.info("[INFO] SIEM integration is enabled.")
    initialize_log_storage()
    print("Starting MoniSec Server...")
    websocket_thread = threading.Thread(target=start_websocket_server, daemon=True)
    websocket_thread.start()
    print(f"WebSocket server thread started on port {config['WEBSOCKET_PORT']}")
    start_server()
