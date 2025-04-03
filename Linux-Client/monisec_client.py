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
import time
import psutil
import subprocess
import logging
import sys
import signal
import remote
import threading
import json
import updater
import yara
from pathlib import Path

def ensure_directories_and_files(base_dir):
    # Define the directory structure
    directories = [
        os.path.join(base_dir, "logs"),
        os.path.join(base_dir, "output")
    ]
    
    # Define log files
    log_files = [
        os.path.join(base_dir, "logs", "file_monitor.json"),
        os.path.join(base_dir, "logs", "monisec-endpoint.log"),
        os.path.join(base_dir, "logs", "process_monitor.log"),
        os.path.join(base_dir, "logs", "log_monitor.log")
    ]
    
    # Create directories if they don't exist
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
            logging.info(f"Created directory: {directory} with 700 permissions")
        else:
            # Ensure existing directories have correct permissions
            os.chmod(directory, 0o700)
    
    # Create files if they don't exist
    for log_file in log_files:
        if not os.path.exists(log_file):
            # Determine the appropriate initial content based on file type
            if log_file.endswith('.json'):
                initial_content = json.dumps({})
            else:
                initial_content = ""
                
            # Create the file with initial content
            with open(log_file, 'w') as f:
                f.write(initial_content)
                
            # Set permissions to 600
            os.chmod(log_file, 0o600)
            logging.info(f"Created file: {log_file} with 600 permissions")
        else:
            # Ensure existing files have correct permissions
            os.chmod(log_file, 0o600)

    return True
 
# Define the base directory function
def get_base_dir():
    """Get the base directory for the application based on script location"""
    return os.path.dirname(os.path.abspath(__file__))

# Set BASE_DIR
BASE_DIR = get_base_dir()

# Create directories and files before setting up logging
ensure_directories_and_files(BASE_DIR)

# Now set up logging properly with a single configuration
LOG_FILE = os.path.join(BASE_DIR, "logs", "monisec-endpoint.log")
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

# Clear any existing handlers to avoid duplication
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

# Add file handler
log_handler = logging.FileHandler(LOG_FILE)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.DEBUG)
root_logger.addHandler(log_handler)

# Only add console output if not running in daemon mode
if not (len(sys.argv) > 1 and sys.argv[1] == "-d"):
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)

# List of monitored processes
PROCESSES = {
    "fim_client": "python3 fim_client.py -d",
    "pim": "python3 pim.py -d",
    "lim": "python3 lim.py -d",
}

def create_default_config():
    """Create a default configuration file if it does not exist and set permissions."""
    default_config = {
        "scheduled_scan": {
            "directories": ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/var/www"],
            "scan_interval": 60
        },
        "real_time_monitoring": {
            "directories": ["/var/www"]
        },
        "exclusions": {
            "directories": ["/var/log"],
            "files": [
                "/etc/mnttab",
                "/etc/mtab",
                "/etc/hosts.deny",
                "/etc/mail/statistics",
                "/etc/random-seed",
                "/etc/adjtime",
                "/etc/httpd/logs",
                "/etc/utmpx",
                "/etc/wtmpx",
                "/etc/cups/certs",
                "/etc/dumpdates",
                "/etc/svc/volatile"
            ],
            "patterns": ["*.tmp", "*.log", "*.swp", "*~"],
            "extensions": [".bak", ".tmp", ".swp", ".cache"],
            "max_size": 1073741824  # 1GB
        },
        "performance": {
            "worker_threads": os.cpu_count() or 4,
            "chunk_size": 65536  # Default chunk size for hash calculation
        },
        "siem_settings": {
            "enabled": False,  # Default to disabled
            "siem_server": "",
            "siem_port": 0
        },
        "instructions": {
            "scheduled_scan": "Add directories to 'scheduled_scan -> directories' for periodic integrity checks. Adjust 'scan_interval' to control scan frequency (0 disables it).",
            "real_time_monitoring": "Add directories to 'real_time_monitoring -> directories' for instant event detection.",
            "exclusions": "Specify directories or files to be excluded from scanning and monitoring.",
            "performance": "Adjust performance settings based on system resources.",
            "siem_settings": "Set 'enabled' to true, and provide 'siem_server' and 'siem_port' for SIEM logging."
        }
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)
    os.chmod(CONFIG_FILE, 0o600)
    print(f"[INFO] Default configuration file created at {CONFIG_FILE}. Please update it as needed.")

def load_or_create_config():
    """
    Load the configuration file if it exists, otherwise create it with default settings.
    The configuration file is expected to be in the BASE_DIR.
    """
    base_dir = get_base_dir()
    config_path = os.path.join(base_dir, "fim.config")
    
    # Check if config file exists
    if os.path.isfile(config_path):
        # Load existing config
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                
            # Ensure BASE_DIR is set correctly in the loaded config
            if "general_settings" not in config:
                config["general_settings"] = {"BASE_DIR": base_dir, "log_level": "INFO"}
            else:
                config["general_settings"]["BASE_DIR"] = base_dir
                
            print(f"Loaded configuration from {config_path}")
            return config
            
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)
    else:
        # Config doesn't exist, create a new one
        default_config = create_default_config(base_dir)
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
                
            print(f"Created default configuration at {config_path}")
            return default_config
            
        except Exception as e:
            print(f"Failed to create default configuration file: {e}")
            sys.exit(1)

#create default config
config = load_or_create_config()

def start_process(name):
    if name in PROCESSES:
        if is_process_running(name):
            logging.info(f"{name} is already running.")
        else:
            logging.info(f"Starting {name}...")
            process = subprocess.Popen(PROCESSES[name].split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            time.sleep(2)  # Wait for process to start
            if is_process_running(name):
                logging.info(f"{name} started successfully with PID {process.pid}.")
            else:
                logging.error(f"Failed to start {name}.")

def stop_process(name):
    if name in PROCESSES:
        pid = is_process_running(name)
        if pid:
            logging.info(f"Stopping {name} with PID {pid}...")
            os.kill(pid, signal.SIGTERM)
        else:
            logging.info(f"{name} is not running.")
    else:
        logging.warning(f"[ERROR] Attempted to stop unknown process: {name}")

def restart_process(name):
    """
    Restart a process with verification and multiple attempts if needed.
    
    Args:
        name: Name of the process to restart
        
    Returns:
        bool: True if restart was successful, False otherwise
    """
    logging.info(f"Attempting to restart {name}...")
    
    # First, ensure the process is stopped
    stop_process(name)
    
    # Wait for process to fully terminate
    attempts = 0
    while is_process_running(name) and attempts < 5:
        logging.info(f"Waiting for {name} to terminate...")
        time.sleep(1)
        attempts += 1
    
    if is_process_running(name):
        logging.error(f"Could not terminate {name} gracefully, forcing...")
        force_stop_process(name)
        time.sleep(1)
    
    # Now start the process
    start_process(name)
    
    # Verify process started successfully
    time.sleep(2)  # Allow time for startup
    pid = is_process_running(name)
    
    if pid:
        logging.info(f"{name} successfully restarted with PID {pid}")
        return True
    else:
        # Try one more time
        logging.warning(f"First restart attempt for {name} failed, trying again...")
        start_process(name)
        time.sleep(3)  # Give a bit more time on second attempt
        
        pid = is_process_running(name)
        if pid:
            logging.info(f"{name} successfully restarted on second attempt with PID {pid}")
            return True
        else:
            logging.error(f"Failed to restart {name} after multiple attempts")
            return False

def is_process_running(name):
    """
    Check if a specific process is running by comparing executable name.
    Returns the PID if running, None otherwise.
    """
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:
            exe_name = proc.info['name']
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            # Match based on process type
            if exe_name == "python3" and any([
                # These patterns ensure we match the exact process
                f"{name}.py" in cmdline,
                f"/{name}.py" in cmdline,
                f"./{name}.py" in cmdline
            ]):
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None
    
def force_stop_process(name):
    """Force stop a process that won't terminate gracefully"""
    pid = is_process_running(name)
    if pid:
        try:
            logging.warning(f"Force stopping {name} with PID {pid}...")
            os.kill(pid, signal.SIGKILL)
            time.sleep(1)
            return not is_process_running(name)
        except Exception as e:
            logging.error(f"Error force stopping {name}: {e}")
            return False
    return True  # Already stopped

def monitor_processes():
    """
    Monitor all required processes and restart any that aren't running.
    Maintains a health check loop to ensure continuous operation.
    """
    logging.info("Starting process monitoring service")
    
    while True:
        all_running = True
        processes_checked = 0
        
        for name in PROCESSES:
            # Skip monisec_client as it shouldn't be self-monitored
            if name == "monisec_client":
                continue
                
            processes_checked += 1
            pid = is_process_running(name)
            
            if not pid:
                logging.warning(f"{name} is not running. Attempting restart...")
                start_process(name)
                time.sleep(2)  # Brief pause to let process initialize
                
                # Verify the process actually started
                new_pid = is_process_running(name)
                if new_pid:
                    logging.info(f"{name} successfully restarted with PID {new_pid}")
                else:
                    logging.error(f"Failed to restart {name} after multiple attempts")
                    all_running = False
            # Removed debug logging here
        
        # Adaptive sleep: shorter interval if there were issues, longer if stable
        if processes_checked > 0:  # Only sleep if we're monitoring at least one process
            sleep_time = 60 if all_running else 10
            # Removed debug logging here
            time.sleep(sleep_time)
        else:
            # If no processes to monitor, use a longer sleep
            time.sleep(300)

def stop_monisec_client_daemon():
    """Stop the MoniSec client running in daemon mode."""
    pidfile = "/tmp/monisec_client.pid"
    
    try:
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process is actually running
            try:
                os.kill(pid, 0)
                logging.info(f"Sending SIGTERM to MoniSec client daemon (PID: {pid})")
                os.kill(pid, signal.SIGTERM)
                
                # Wait for process to terminate
                for _ in range(10):  # 10-second timeout
                    try:
                        os.kill(pid, 0)
                        time.sleep(1)
                    except OSError:
                        logging.info("MoniSec client daemon stopped successfully.")
                        os.remove(pidfile)
                        return True
                
                # Force kill if not terminated
                os.kill(pid, signal.SIGKILL)
                os.remove(pidfile)
                logging.warning("MoniSec client daemon forcefully terminated.")
                return True
            
            except OSError:
                logging.warning("No running MoniSec client daemon found.")
                os.remove(pidfile)
                return False
        else:
            logging.warning("No PID file found. MoniSec client daemon might not be running.")
            return False
    
    except Exception as e:
        logging.error(f"Error stopping MoniSec client daemon: {e}")
        return False

def start_daemon():
    """Start MoniSec client in daemon mode with PID file tracking."""
    pidfile = "/tmp/monisec_client.pid"
    
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    os.umask(0)
    sys.stdin = open(os.devnull, 'r')

    # Write PID to file
    with open(pidfile, 'w') as f:
        f.write(str(os.getpid()))

    logging.info("MoniSec Endpoint Monitor started in daemon mode.")

    listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
    listener_thread.start()

    monitor_processes()
    
# Handle graceful shutdown on keyboard interrupt
def handle_exit(signum, frame):
    logging.info("Keyboard interrupt received. Stopping MoniSec client and all related processes...")

    # Prevent double SIGINT behavior
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    stop_process("fim_client")
    stop_process("pim")
    stop_process("lim")  # Add this line

    time.sleep(2)
    logging.info("MoniSec client shutdown complete.")
    sys.exit(0)

# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

if __name__ == "__main__":
    # Process commands first
    if len(sys.argv) > 1:
        action = sys.argv[1]

        # Commands that don't need YARA initialization
        if action == "import-psk":
            remote.import_psk()
            sys.exit(0)
            
        elif action == "auth":
            if len(sys.argv) > 2 and sys.argv[2] == "test":
                print("[INFO] Attempting authentication using stored credentials...")
                success = remote.authenticate_with_server()
                if success:
                    print("[SUCCESS] Authentication successful.")
                    sys.exit(0)
                else:
                    print("[ERROR] Authentication failed.")
                    sys.exit(1)
            else:
                print("[ERROR] Invalid command. Usage: monisec_client auth test")
                sys.exit(1)
        
        # All other commands will continue and may need YARA initialization
        
        # Initialize YARA if needed for other commands
        try:
            from malscan_yara import YaraManager
            # Create an instance of the YaraManager
            yara_manager = YaraManager()
            
            try:
                if not yara_manager.ensure_rules_exist():
                    logging.warning("Failed to download YARA rules. Some detection capabilities may be limited.")
            except Exception as e:
                logging.error(f"Error ensuring YARA rules: {e}")
        except ImportError:
            logging.error("Could not import malscan_yara module. YARA scanning will be unavailable.")

        # Check if we should run the updater
        should_run_updater = action == "-d"
        if should_run_updater:
            try:
                updater.check_for_updates()
            except Exception as e:
                logging.warning(f"Updater failed: {e}")

        # Command processing continues here
        if action == "restart":
            stop_monisec_client_daemon()
            time.sleep(2)
            start_process("monisec_client")

        elif action == "stop":
            stop_monisec_client_daemon()

        elif action in ["pim", "fim", "lim"]:
            if len(sys.argv) > 2 and sys.argv[2] in ["start", "stop", "restart"]:
                # Fix: Only append "_client" if the action is "fim"
                target_process = f"{action}_client" if action == "fim" else action
                if sys.argv[2] == "start":
                    start_process(target_process)
                elif sys.argv[2] == "stop":
                    stop_process(target_process)
                elif sys.argv[2] == "restart":
                    restart_process(target_process)
            else:
                print(f"[ERROR] Invalid command. Usage: monisec_client {action} start|stop|restart")
                sys.exit(1)
                
        # Update YARA rules command
        elif action == "update-yara":
            print("[INFO] Updating YARA rules from GitHub...")
            success = yara.update_rules()
            if success:
                print("[SUCCESS] YARA rules updated successfully.")
                sys.exit(0)
            else:
                print("[ERROR] Failed to update YARA rules.")
                sys.exit(1)
                
        # Test YARA scan on a file
        elif action == "yara-scan":
            if len(sys.argv) > 2:
                file_path = sys.argv[2]
                print(f"[INFO] Scanning file {file_path} with YARA rules...")
                
                # Ensure rules are compiled
                if not yara.compile_rules():
                    print("[ERROR] Failed to compile YARA rules.")
                    sys.exit(1)
                
                # Scan the file
                matches = yara.scan_file(file_path)
                
                if matches:
                    print(f"[ALERT] Found {len(matches)} YARA rule matches:")
                    for match in matches:
                        print(f"  - Rule: {match.rule}")
                        print(f"    Namespace: {match.namespace}")
                        print(f"    Tags: {', '.join(match.tags) if match.tags else 'None'}")
                        print(f"    Meta: {match.meta}")
                        print("")
                else:
                    print("[INFO] No YARA rule matches found.")
                
                sys.exit(0)
            else:
                print("[ERROR] Invalid command. Usage: monisec_client yara-scan <file_path>")
                sys.exit(1)
                
        # Daemon mode
        elif action == "-d":
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            os.setsid()
            os.umask(0)
            sys.stdin = open(os.devnull, 'r')
        
            # Write PID to file
            with open("/tmp/monisec_client.pid", 'w') as f:
                f.write(str(os.getpid()))
        
            logging.info("MoniSec Endpoint Monitor started in daemon mode.")
        
            # Add this line to start log transmission in daemon mode
            remote.check_auth_and_send_logs()
        
            listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
            listener_thread.start()
        
            monitor_processes()

        # Invalid command
        else:
            print(
                """Usage:
            monisec_client restart                  # Restart monisec_client
            monisec_client stop                     # Stop monisec_client daemon
            monisec_client pim start|stop|restart   # Control PIM process
            monisec_client fim start|stop|restart   # Control FIM process
            monisec_client lim start|stop|restart   # Control LIM process
            monisec_client import-psk               # Import PSK for authentication
            monisec_client auth test                # Test authentication, then exit
            monisec_client update-yara              # Update YARA rules from GitHub
            monisec_client yara-scan <file_path>    # Scan a file with YARA rules"""
            )
            sys.exit(1)

    else:
        # No command-line arguments, initialize YARA
        try:
            from malscan_yara import YaraManager
            # Create an instance of the YaraManager
            yara_manager = YaraManager()
            
            try:
                if not yara_manager.ensure_rules_exist():
                    logging.warning("Failed to download YARA rules. Some detection capabilities may be limited.")
            except Exception as e:
                logging.error(f"Error ensuring YARA rules: {e}")
        except ImportError:
            logging.error("Could not import malscan_yara module. YARA scanning will be unavailable.")

        # Run updater in foreground mode
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")

        logging.info("MoniSec Endpoint Monitor started in foreground.")

        listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
        listener_thread.start()

        remote.check_auth_and_send_logs()
        remote.start_listener_if_authorized()
        monitor_processes()
