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
import os
import time
import psutil
import subprocess
import logging
import sys
import threading
import json
import signal
import remote
import updater
import socket
import ctypes
import win32api
import win32con
import win32service
import win32serviceutil
import win32event
import win32security
import win32process
import servicemanager
import wmi
import winreg
from pathlib import Path
from win32com.client import GetObject
#import yara
#from malscan_yara import ensure_rules_exist, update_rules, compile_rules, yara_scan_file

# Define BASE_DIR as a static path for Windows
BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")

# Define CONFIG_FILE using the BASE_DIR
CONFIG_FILE = os.path.join(BASE_DIR, "fim.config")

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def ensure_directories_and_files(base_dir):
    """Create necessary directories and files with appropriate permissions"""
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
            os.makedirs(directory, exist_ok=True)
            logging.info(f"Created directory: {directory}")
            
            # Set Windows permissions (restricted to Administrators and SYSTEM)
            if is_admin():
                try:
                    # Create a security descriptor with tight permissions
                    sd = win32security.GetFileSecurity(
                        directory, 
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    dacl = win32security.ACL()
                    
                    # Add Admin and System full control
                    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
                    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
                    
                    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
                    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
                    
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        directory, 
                        win32security.DACL_SECURITY_INFORMATION, 
                        sd
                    )
                    logging.info(f"Set restricted permissions on directory: {directory}")
                except Exception as e:
                    logging.warning(f"Failed to set secure permissions on directory {directory}: {e}")
    
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
                
            logging.info(f"Created file: {log_file}")
            
            # Set restricted permissions similar to directories
            if is_admin():
                try:
                    sd = win32security.GetFileSecurity(
                        log_file, 
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    dacl = win32security.ACL()
                    
                    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
                    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
                    
                    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
                    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
                    
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        log_file, 
                        win32security.DACL_SECURITY_INFORMATION, 
                        sd
                    )
                    logging.info(f"Set restricted permissions on file: {log_file}")
                except Exception as e:
                    logging.warning(f"Failed to set secure permissions on file {log_file}: {e}")

    return True

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
logging.getLogger('websockets').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Only add console output if not running in service mode
if not (len(sys.argv) > 1 and sys.argv[1] == "--service"):
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)

# List of monitored processes (Windows-specific command paths)
PROCESSES = {
#    "fim_client": "python fim_client.py --service",
    "pim": "python pim.py --service",
#    "lim": "python lim.py --service",
}

def create_default_config():
    """Create a default Windows configuration file if it does not exist and set permissions."""
    default_config = {
        "client_settings": {
            "BASE_DIR": BASE_DIR
        },
        "scheduled_scan": {
            "directories": ["C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\inetpub"],
            "scan_interval": 60
        },
        "real_time_monitoring": {
            "directories": ["C:\\inetpub\\wwwroot"]
        },
        "exclusions": {
            "directories": [
                "C:\\Windows\\Temp",
                "C:\\Windows\\Logs"
            ],
            "files": [
                "C:\\pagefile.sys",
                "C:\\hiberfil.sys",
                "C:\\swapfile.sys"
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
        "enhanced_fim": {
            "enabled": True,
            "environment": "production",
            "performance": {
                "system_load_threshold": 75,
                "io_threshold": 80,
                "worker_threads": 4
            },
            "behavioral": {
                "training_samples": 100,
                "retraining_interval": 86400,
                "max_baseline_samples": 10000
            },
            "content_analysis": {
                "diff_threshold": 0.3,
                "max_file_size": 10485760
            },
            "detection": {
                "risk_multiplier": 1.5,
                "alert_threshold": 70
            }
        },
        "instructions": {
            "scheduled_scan": "Add directories to 'scheduled_scan -> directories' for periodic integrity checks. Adjust 'scan_interval' to control scan frequency (0 disables it).",
            "real_time_monitoring": "Add directories to 'real_time_monitoring -> directories' for instant event detection.",
            "exclusions": "Specify directories or files to be excluded from scanning and monitoring.",
            "performance": "Adjust performance settings based on system resources.",
            "siem_settings": "Set 'enabled' to true, and provide 'siem_server' and 'siem_port' for SIEM logging.",
            "enhanced_fim": "Configure enhanced file integrity monitoring capabilities including performance optimization, behavioral analysis, content analysis, and detection."
        }
    }
    
    with open(CONFIG_FILE, "w") as f:
        json.dump(default_config, f, indent=4)
    
    # Set restricted Windows file permissions
    if is_admin():
        try:
            sd = win32security.GetFileSecurity(
                CONFIG_FILE, 
                win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            
            admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
            
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
            
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                CONFIG_FILE, 
                win32security.DACL_SECURITY_INFORMATION, 
                sd
            )
        except Exception as e:
            logging.warning(f"Failed to set secure permissions on config file: {e}")
    
    print(f"[INFO] Default configuration file created at {CONFIG_FILE}. Please update it as needed.")
    return default_config

def load_or_create_config():
    """
    Load the configuration file if it exists, otherwise create it with default settings.
    The configuration file is expected to be in the BASE_DIR.
    """
    # Check if config file exists
    if os.path.isfile(CONFIG_FILE):
        # Load existing config
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                
            # Ensure BASE_DIR is set correctly in the loaded config
            if "client_settings" not in config:
                config["client_settings"] = {"BASE_DIR": BASE_DIR}
            else:
                config["client_settings"]["BASE_DIR"] = BASE_DIR
                
            print(f"Loaded configuration from {CONFIG_FILE}")
            return config
            
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)
    else:
        # Config doesn't exist, create a new one
        default_config = create_default_config()
        print(f"Created default configuration at {CONFIG_FILE}")
        return default_config

# Create default config
config = load_or_create_config()

def start_process(name):
    """Start a monitored process"""
    if name in PROCESSES:
        if is_process_running(name):
            logging.info(f"{name} is already running.")
        else:
            logging.info(f"Starting {name}...")
            # Use CREATE_NO_WINDOW flag to prevent console windows from appearing
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            process = subprocess.Popen(
                PROCESSES[name].split(), 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            time.sleep(2)  # Wait for process to start
            if is_process_running(name):
                logging.info(f"{name} started successfully with PID {process.pid}.")
            else:
                logging.error(f"Failed to start {name}.")

def stop_process(name):
    """Stop a monitored process"""
    if name in PROCESSES:
        pid = is_process_running(name)
        if pid:
            logging.info(f"Stopping {name} with PID {pid}...")
            try:
                # Try graceful termination first
                process = psutil.Process(pid)
                process.terminate()
                
                # Wait for process to terminate gracefully
                gone, alive = psutil.wait_procs([process], timeout=3)
                if process in alive:
                    # Force kill if not terminated gracefully
                    process.kill()
            except Exception as e:
                logging.error(f"Error stopping {name}: {e}")
        else:
            logging.info(f"{name} is not running.")
    else:
        logging.warning(f"[ERROR] Attempted to stop unknown process: {name}")

def restart_process(name):
    """Restart a process with verification and multiple attempts if needed."""
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
            exe_name = proc.info['name'].lower()
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            # Match based on process type
            if exe_name == "python.exe" and any([
                # These patterns ensure we match the exact process
                f"{name}.py" in cmdline,
                f"\\{name}.py" in cmdline
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
            
            # Use Windows-specific method to kill process
            handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, 0, pid)
            if handle:
                win32api.TerminateProcess(handle, 0)
                win32api.CloseHandle(handle)
                
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
        
        # Adaptive sleep: shorter interval if there were issues, longer if stable
        if processes_checked > 0:  # Only sleep if we're monitoring at least one process
            sleep_time = 60 if all_running else 10
            time.sleep(sleep_time)
        else:
            # If no processes to monitor, use a longer sleep
            time.sleep(300)

# Windows service implementation
class MoniSecService(win32serviceutil.ServiceFramework):
    _svc_name_ = "MoniSecService"
    _svc_display_name_ = "MoniSec Endpoint Monitoring Service"
    _svc_description_ = "Provides file integrity, process, and log monitoring for security purposes"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = False
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        """Stop the service"""
        logging.info("Service stop signal received")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.running = False
        
        # Stop all monitored processes
        for name in PROCESSES:
            stop_process(name)

    def SvcDoRun(self):
        """Run the service"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.running = True
        
        logging.info("MoniSec service started")
        
        # Initialize necessary modules
        try:
            from malscan_yara import YaraManager
            yara_manager = YaraManager()
            
            try:
                if not yara_manager.ensure_rules_exist():
                    logging.warning("Failed to download YARA rules. Some detection capabilities may be limited.")
            except Exception as e:
                logging.error(f"Error ensuring YARA rules: {e}")
        except ImportError:
            logging.error("Could not import malscan_yara module. YARA scanning will be unavailable.")
        
        # Run updater
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")
            
        # Start remote functionalities if authentication is valid
        remote.check_auth_and_send_logs()
        
        if remote.validate_auth_token()[0]:
            # Start connection monitoring
            connection_monitor = threading.Thread(target=remote.maintain_websocket_connection, daemon=True)
            connection_monitor.start()
            logging.info("[INIT] Started WebSocket connection monitoring")
            
            # Start listener
            remote.start_listener_if_authorized()
            
            # Start WebSocket client
            remote.start_websocket_client()
        
        # Run the process monitor in the main thread
        while self.running:
            try:
                monitor_processes()
            except Exception as e:
                logging.error(f"Error in process monitor: {e}")
                time.sleep(60)  # Sleep on error to prevent tight loop
                
            # Check if service stop was requested
            rc = win32event.WaitForSingleObject(self.stop_event, 5000)  # Wait 5 seconds
            if rc == win32event.WAIT_OBJECT_0:
                break

def stop_monisec_client_service():
    """Stop the MoniSec client Windows service"""
    try:
        win32serviceutil.StopService("MoniSecService")
        logging.info("MoniSec client service stopped successfully.")
        return True
    except Exception as e:
        logging.error(f"Error stopping MoniSec client service: {e}")
        return False

def start_service():
    """Start MoniSec client as a Windows service"""
    try:
        win32serviceutil.StartService("MoniSecService")
        logging.info("MoniSec client service started successfully.")
        return True
    except Exception as e:
        logging.error(f"Error starting MoniSec client service: {e}")
        return False

def handle_exit(signum, frame):
    """Handle graceful shutdown"""
    logging.info("Shutdown signal received. Stopping MoniSec client and all related processes...")

    # Stop all monitored processes
#    stop_process("fim_client")
    stop_process("pim")
#    stop_process("lim")

    time.sleep(2)
    logging.info("MoniSec client shutdown complete.")
    sys.exit(0)

# Register signal handlers for graceful shutdown
# Note: Windows doesn't fully support all signals, but we can still catch Ctrl+C
try:
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
except (AttributeError, ValueError):
    # Some signals might not be available on Windows
    pass

if __name__ == "__main__":
    # Check for administrator privileges
    if not is_admin():
        logging.warning("MoniSec client should be run with administrator privileges for full functionality.")
    
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
        
        # Windows service management commands
        elif action == "install":
            try:
                win32serviceutil.InstallService(
                    pythonClassString="monisec_client.MoniSecService",
                    serviceName="MoniSecService",
                    displayName="MoniSec Endpoint Monitoring Service",
                    description="Provides file integrity, process, and log monitoring for security purposes",
                    startType=win32service.SERVICE_AUTO_START
                )
                print("[SUCCESS] MoniSec service installed successfully.")
                sys.exit(0)
            except Exception as e:
                print(f"[ERROR] Failed to install service: {e}")
                sys.exit(1)
                
        elif action == "remove":
            try:
                win32serviceutil.RemoveService("MoniSecService")
                print("[SUCCESS] MoniSec service removed successfully.")
                sys.exit(0)
            except Exception as e:
                print(f"[ERROR] Failed to remove service: {e}")
                sys.exit(1)
                
        elif action == "start-service":
            if start_service():
                sys.exit(0)
            else:
                sys.exit(1)
                
        elif action == "stop-service":
            if stop_monisec_client_service():
                sys.exit(0)
            else:
                sys.exit(1)
                
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
        should_run_updater = action == "--service"
        if should_run_updater:
            try:
                updater.check_for_updates()
            except Exception as e:
                logging.warning(f"Updater failed: {e}")

        # Command processing continues here
        if action == "restart":
            stop_monisec_client_service()
            time.sleep(2)
            start_service()

        elif action == "stop":
            stop_monisec_client_service()

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
        #elif action == "update-yara":
        #    print("[INFO] Updating YARA rules from GitHub...")
        #    success = update_rules()
        #    if success:
        #        print("[SUCCESS] YARA rules updated successfully.")
        #        sys.exit(0)
        #    else:
        #        print("[ERROR] Failed to update YARA rules.")
        #        sys.exit(1)
        #        
        # Test YARA scan on a file
        #elif action == "yara-scan":
        #    if len(sys.argv) > 2:
        #        file_path = sys.argv[2]
        #        print(f"[INFO] Scanning file {file_path} with YARA rules...")
        #        
                # Ensure rules are compiled
        #        if not compile_rules():
        #            print("[ERROR] Failed to compile YARA rules.")
        #            sys.exit(1)
        #        
        #        # Scan the file
        #        matches = yara_scan_file(file_path)
        #        
        #        if matches:
        #            print(f"[ALERT] Found {len(matches)} YARA rule matches:")
        #            for match in matches:
        #                print(f"  - Rule: {match.rule}")
        #                print(f"    Namespace: {match.namespace}")
        #                print(f"    Tags: {', '.join(match.tags) if match.tags else 'None'}")
        #                print(f"    Meta: {match.meta}")
        #                print("")
        #        else:
        #            print("[INFO] No YARA rule matches found.")
        #        
        #        sys.exit(0)
        #    else:
        #        print("[ERROR] Invalid command. Usage: monisec_client yara-scan <file_path>")
        #        sys.exit(1)
                
        # Service mode - run as a Windows service
        elif action == "--service":
            # This command line argument is used when the service is starting the process
            logging.info("MoniSec client starting in service mode...")
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(MoniSecService)
            servicemanager.StartServiceCtrlDispatcher()

        # Invalid command
        else:
            print(
                """Usage:
            monisec_client install                  # Install MoniSec Windows service
            monisec_client remove                   # Remove MoniSec Windows service
            monisec_client start-service            # Start MoniSec service
            monisec_client stop-service             # Stop MoniSec service
            monisec_client restart                  # Restart MoniSec service
            monisec_client pim start|stop|restart   # Control PIM process
#            monisec_client fim start|stop|restart   # Control FIM process
#            monisec_client lim start|stop|restart   # Control LIM process
            monisec_client import-psk               # Import PSK for authentication
            monisec_client auth test                # Test authentication, then exit
#            monisec_client update-yara              # Update YARA rules from GitHub
#            monisec_client yara-scan <file_path>    # Scan a file with YARA rules"""
            )
            sys.exit(1)

    else:
        # No command-line arguments, initialize YARA
#        try:
#            from malscan_yara import YaraManager
            # Create an instance of the YaraManager
#            yara_manager = YaraManager()
#            
#            try:
#                if not yara_manager.ensure_rules_exist():
#                    logging.warning("Failed to download YARA rules. Some detection capabilities may be limited.")
#            except Exception as e:
#                logging.error(f"Error ensuring YARA rules: {e}")
#        except ImportError:
#            logging.error("Could not import malscan_yara module. YARA scanning will be unavailable.")

        # Run updater in foreground mode
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")

        logging.info("MoniSec Endpoint Monitor started in foreground.")

        # Check auth before attempting connections
        remote.check_auth_and_send_logs()
        
        # Start connection monitoring only if authentication is valid
        if remote.validate_auth_token()[0]:
            # Start the connection maintenance thread
            connection_monitor = threading.Thread(target=remote.maintain_websocket_connection, daemon=True)
            connection_monitor.start()
            logging.info("[INIT] Started WebSocket connection monitoring")
        else:
            logging.info("[INIT] WebSocket connection monitoring disabled - no valid authentication")
            
        # Only use start_listener_if_authorized to handle listener starting
        # This will internally check if auth token is valid
        remote.start_listener_if_authorized()
        
        # Only start WebSocket client if auth is valid
        if remote.validate_auth_token()[0]:
            # Start WebSocket client (after authentication)
            remote.start_websocket_client()
            
        monitor_processes()
