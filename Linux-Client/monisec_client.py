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
import threading
import atexit
import json
import remote
import updater
#import yara
#from malscan_yara import ensure_rules_exist, update_rules, compile_rules, yara_scan_file
from pathlib import Path
from utils.process_guardian import ProcessGuardian

# Define BASE_DIR as a static path
# In monisec_client.py
BASE_DIR = "/opt/FIMoniSec/Linux-Client"
UTILS_DIR = os.path.join(BASE_DIR, "utils")
sys.path.append(UTILS_DIR)

# Define CONFIG_FILE using the BASE_DIR
CONFIG_FILE = os.path.join(BASE_DIR, "fim.config")

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

# Define BASE_DIR as a static path
BASE_DIR = "/opt/FIMoniSec/Linux-Client"

# Define CONFIG_FILE using the BASE_DIR
CONFIG_FILE = os.path.join(BASE_DIR, "fim.config")

def create_default_config():
    """Create a default configuration file if it does not exist and set permissions."""
    default_config = {
        "client_settings": {
            "BASE_DIR": BASE_DIR
        },
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
    os.chmod(CONFIG_FILE, 0o600)
    print(f"[INFO] Default configuration file created at {CONFIG_FILE}. Please update it as needed.")
    return default_config

## Process Protection and Watchdog ###

# Initialize process guardian at the beginning of execution
def initialize_process_protection():
    """Initialize process protection mechanisms."""
    # Protected processes to monitor
    protected_processes = [
        "monisec_client.py",
        "fim.py",
        "lim.py",
        "pim.py"
    ]
    
    # Create and start the process guardian
    guardian = ProcessGuardian(
        process_names=protected_processes,
        pid_file=os.path.join(BASE_DIR, "output", "monisec_client.pid"),
        foreground_mode=True,
        install_signals=False
    )
    
    # Start monitoring for process termination
    guardian.start_monitoring()
    
    # Set higher process priority to make it harder to terminate
    guardian.set_process_priority(-10)
    
    # Prevent core dumps to avoid leaking sensitive information
    guardian.prevent_core_dumps()
    
    return guardian

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

#create default config
config = load_or_create_config()

def start_process(name):
    if name in PROCESSES:
        # Check if the process is already running and how many instances exist
        instances = is_process_running(name, count_instances=True)
        
        if instances > 0:
            pid = is_process_running(name)
            logging.info(f"{name} is already running with PID {pid}.")
            
            # If multiple instances are running, terminate the newer ones
            if instances > 1:
                logging.warning(f"Multiple {name} instances detected. Cleaning up duplicates...")
                cleanup_duplicate_processes(name)
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

def is_process_running(name, count_instances=False):
    """
    Check if a specific process is running by comparing executable name.
    By default returns the PID if running, None otherwise.
    If count_instances=True, returns the count of running instances instead.
    """
    instance_count = 0
    found_pids = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
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
                instance_count += 1
                found_pids.append(proc.info['pid'])
                
                # Log duplicate processes
                if instance_count > 1:
                    logging.warning(f"Duplicate {name} instance found with PID {proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    if count_instances:
        return instance_count
    
    if len(found_pids) > 1:
        # Get the oldest process (lower PID typically started earlier)
        return min(found_pids)
    elif found_pids:
        return found_pids[0]
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

def cleanup_duplicate_processes(name):
    """Terminate duplicate instances of a process, keeping only the oldest one."""
    process_list = []
    
    # Find all instances of the process
    for proc in psutil.process_iter(['pid', 'cmdline', 'create_time']):
        try:
            if proc.info['cmdline'] and any(f"{name}.py" in cmd for cmd in proc.info['cmdline']):
                process_list.append({
                    'pid': proc.pid,
                    'create_time': proc.create_time()
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Sort by creation time (oldest first)
    process_list.sort(key=lambda x: x['create_time'])
    
    # Keep the oldest process, terminate others
    if len(process_list) > 1:
        kept_pid = process_list[0]['pid']
        
        for proc in process_list[1:]:
            try:
                logging.warning(f"Terminating duplicate {name} process with PID {proc['pid']}")
                os.kill(proc['pid'], signal.SIGTERM)
            except Exception as e:
                logging.error(f"Failed to terminate process {proc['pid']}: {e}")
                
        logging.info(f"Kept oldest instance of {name} with PID {kept_pid}")

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
            # Removed debug logging here
            time.sleep(sleep_time)
        else:
            # If no processes to monitor, use a longer sleep
            time.sleep(300)

def stop_monisec_client_daemon():
    """Stop the MoniSec client running in daemon mode."""
    pidfile = os.path.join(BASE_DIR, "output", "monisec_client.pid")
    
    # Create control file to stop ProcessGuardian monitoring
    control_file = os.path.join(BASE_DIR, "output", "guardian_stop_monitoring")
    try:
        with open(control_file, 'w') as f:
            f.write(str(os.getpid()))
        logging.info("Signal sent to stop ProcessGuardian monitoring")
    except Exception as e:
        logging.error(f"Failed to create control file: {e}")
    
    # Allow a moment for ProcessGuardian to notice
    time.sleep(1)
    
    # Find and stop all child processes first
    for name in ["fim_client", "pim", "lim"]:
        pid = is_process_running(name)
        if pid:
            logging.info(f"Stopping {name} with PID {pid}...")
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as e:
                logging.error(f"Error stopping {name}: {e}")
                
    # Wait briefly for children to exit         
    time.sleep(1)
    
    try:
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process is actually running
            try:
                os.kill(pid, 0)  # Signal 0 doesn't kill but checks if process exists
                logging.info(f"Sending SIGTERM to MoniSec client daemon (PID: {pid})")
                os.kill(pid, signal.SIGTERM)
                
                # Wait for process to terminate
                for _ in range(10):  # 10-second timeout
                    try:
                        os.kill(pid, 0)
                        time.sleep(1)
                    except OSError:
                        logging.info("MoniSec client daemon stopped successfully.")
                        # Remove the control file
                        if os.path.exists(control_file):
                            os.remove(control_file)
                        if os.path.exists(pidfile):
                            os.remove(pidfile)
                        return True
                
                # Force kill if not terminated
                os.kill(pid, signal.SIGKILL)
                if os.path.exists(pidfile):
                    os.remove(pidfile)
                if os.path.exists(control_file):
                    os.remove(control_file)
                logging.warning("MoniSec client daemon forcefully terminated.")
                return True
            
            except OSError:
                logging.warning("No running MoniSec client daemon found.")
                if os.path.exists(pidfile):
                    os.remove(pidfile)
                if os.path.exists(control_file):
                    os.remove(control_file)
                return False
        else:
            logging.warning("No PID file found. MoniSec client daemon might not be running.")
            if os.path.exists(control_file):
                os.remove(control_file)
            return False
    
    except Exception as e:
        logging.error(f"Error stopping MoniSec client daemon: {e}")
        return False

def start_daemon():
    """Start MoniSec client in daemon mode with PID file tracking."""
    pidfile = os.path.join(BASE_DIR, "output", "monisec_client.pid")
    
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

def start_watchdog(delay=15):
    """
    Start the watchdog process as a separate process with a delay.
    
    Args:
        delay (int): Number of seconds to wait before starting the watchdog
    """
    watchdog_path = os.path.join(BASE_DIR, "utils", "watchdog.py")
    
    try:
        # Create a thread to handle the delayed execution
        def delayed_start():
            logging.info(f"Waiting {delay} seconds before starting watchdog...")
            time.sleep(delay)
            
            # Start the watchdog in daemon mode
            process = subprocess.Popen(
                ["python3", watchdog_path, "-d"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            logging.info(f"Started watchdog process after {delay} second delay with PID {process.pid}")
        
        # Start the delayed execution in a separate thread
        start_thread = threading.Thread(target=delayed_start, daemon=True)
        start_thread.start()
        logging.info(f"Scheduled watchdog to start with {delay} second delay")
        
    except Exception as e:
        logging.error(f"Failed to start watchdog process: {e}")

# Handle graceful shutdown on keyboard interrupt
def handle_exit(signum, frame):
    """Handle graceful shutdown on keyboard interrupt or termination signal."""
    logging.info(f"Signal {signum} received. Stopping MoniSec client and all related processes...")

    # Prevent double SIGINT behavior
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    
    # Create control file to stop ProcessGuardian monitoring
    control_file = os.path.join(BASE_DIR, "output", "guardian_stop_monitoring")
    monisec_manages_file = os.path.join(BASE_DIR, "output", "monisec_manages_processes")
    
    try:
        with open(control_file, 'w') as f:
            f.write(str(os.getpid()))
        logging.info("Signal sent to stop ProcessGuardian monitoring")
        
        # Remove the monisec manages file
        if os.path.exists(monisec_manages_file):
            os.remove(monisec_manages_file)
    except Exception as e:
        logging.error(f"Failed to create control file: {e}")
    
    # Give ProcessGuardian a moment to notice
    time.sleep(1)
    
    # Get a list of all child process PIDs to terminate
    child_processes = []
    for name in ["fim_client", "pim", "lim"]:
        pid = is_process_running(name)
        if pid:
            child_processes.append((name, pid))
            logging.info(f"Stopping {name} with PID {pid}...")
            try:
                # Send SIGTERM first for graceful shutdown
                os.kill(pid, signal.SIGTERM)
            except OSError as e:
                logging.error(f"Error stopping {name}: {e}")

    # Wait for processes to terminate gracefully
    max_wait = 5  # seconds
    start_time = time.time()
    while time.time() - start_time < max_wait and child_processes:
        for name, pid in list(child_processes):  # Use list() to allow modifying during iteration
            try:
                # Check if process still exists
                os.kill(pid, 0)  # Signal 0 doesn't kill but checks if process exists
                # Process still running, continue waiting
            except OSError:
                # Process no longer exists
                logging.info(f"{name} (PID {pid}) terminated.")
                child_processes.remove((name, pid))
        
        if child_processes:
            time.sleep(0.5)  # Short wait before checking again
    
    # Force kill any remaining processes
    for name, pid in child_processes:
        logging.warning(f"{name} (PID {pid}) did not terminate gracefully. Forcing...")
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass  # Process might already be gone
    
    # Make sure all child processes are terminated
    for name in ["fim_client", "pim", "lim"]:
        pid = is_process_running(name)
        if pid:
            logging.warning(f"Process {name} still running with PID {pid}. Force killing...")
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass  # Process might already be gone
    
    # Cleanup control file
    if os.path.exists(control_file):
        try:
            os.remove(control_file)
        except OSError:
            pass
    
    # Cleanup pid file
    pid_file = os.path.join(BASE_DIR, "output", "monisec_client.pid")
    if os.path.exists(pid_file):
        try:
            os.remove(pid_file)
            logging.info(f"Removed PID file: {pid_file}")
        except OSError:
            pass
    
    time.sleep(1)  # Brief pause to allow final cleanups
    
    logging.info("MoniSec client shutdown complete.")
    sys.exit(0)
    
# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# Add these functions to your existing monisec_client.py file

def manage_exclusions(command, exclusion_type, value=None):
    """
    Add or remove exclusions from the configuration.
    
    Args:
        command (str): 'add' or 'remove'
        exclusion_type (str): 'ip', 'user', 'file', 'directory', 'pattern', or 'extension'
        value (str): The value to add or remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    global config
    
    # Validate command
    if command not in ['add', 'remove']:
        print(f"[ERROR] Invalid command: {command}. Use 'add' or 'remove'.")
        return False
        
    # Validate exclusion type
    valid_types = ['ip', 'user', 'file', 'directory', 'pattern', 'extension']
    if exclusion_type not in valid_types:
        print(f"[ERROR] Invalid exclusion type: {exclusion_type}. Valid types: {', '.join(valid_types)}")
        return False
        
    # Validate value
    if not value:
        print(f"[ERROR] No value provided to {command}.")
        return False
    
    # Define mapping for exclusion types to their locations in the config
    config_paths = {
        'ip': ['log_integrity_monitor', 'excluded_ips'],
        'user': ['log_integrity_monitor', 'excluded_users'],
        'file': ['exclusions', 'files'],
        'directory': ['exclusions', 'directories'],
        'pattern': ['exclusions', 'patterns'],
        'extension': ['exclusions', 'extensions']
    }
    
    # Get the path to the exclusion list
    path = config_paths[exclusion_type]
    
    # Ensure all required sections exist in the config
    current = config
    for i, section in enumerate(path[:-1]):
        if section not in current:
            current[section] = {}
        current = current[section]
    
    # Ensure the final list exists
    final_key = path[-1]
    if final_key not in current:
        current[final_key] = []
    
    # Get the current list of exclusions
    exclusions = current[final_key]
    
    # Add or remove the value
    if command == 'add':
        if value in exclusions:
            print(f"[INFO] {value} is already in {exclusion_type} exclusions.")
            return True
        exclusions.append(value)
        print(f"[INFO] Added {value} to {exclusion_type} exclusions.")
    else:  # remove
        if value not in exclusions:
            print(f"[WARNING] {value} not found in {exclusion_type} exclusions.")
            return False
        exclusions.remove(value)
        print(f"[INFO] Removed {value} from {exclusion_type} exclusions.")
    
    # Save the updated configuration
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"[INFO] Configuration saved to {CONFIG_FILE}")
        
        # If we're working with file/directory exclusions, we may need to restart the FIM service
        if exclusion_type in ['file', 'directory', 'pattern', 'extension']:
            print("[INFO] File exclusions changed. Consider restarting the FIM service with: monisec_client fim restart")
        
        return True
    except Exception as e:
        print(f"[ERROR] Failed to save configuration: {e}")
        return False

def list_exclusions(exclusion_type=None):
    """
    List all exclusions of the specified type.
    
    Args:
        exclusion_type (str, optional): 'ip', 'user', 'file', 'directory', 'pattern', or 'extension'.
                                         If None, list all exclusions.
    """
    global config
    
    # Define mapping for exclusion types to their locations in the config
    config_paths = {
        'ip': ['log_integrity_monitor', 'excluded_ips'],
        'user': ['log_integrity_monitor', 'excluded_users'],
        'file': ['exclusions', 'files'],
        'directory': ['exclusions', 'directories'],
        'pattern': ['exclusions', 'patterns'],
        'extension': ['exclusions', 'extensions']
    }
    
    # If no specific type is provided, list all exclusions
    types_to_list = [exclusion_type] if exclusion_type else config_paths.keys()
    
    for current_type in types_to_list:
        if current_type not in config_paths:
            print(f"[ERROR] Invalid exclusion type: {current_type}")
            continue
            
        path = config_paths[current_type]
        
        # Navigate to the exclusion list in the config
        current = config
        found = True
        for section in path:
            if section not in current:
                found = False
                break
            current = current[section]
        
        # Print the exclusions
        if found:
            print(f"\n{current_type.upper()} EXCLUSIONS:")
            if isinstance(current, list) and current:
                for item in current:
                    print(f"  - {item}")
            elif isinstance(current, list):
                print("  None")
            else:
                print(f"  [ERROR] Expected a list but found {type(current)}")
        else:
            print(f"\n{current_type.upper()} EXCLUSIONS:")
            print("  None (section not found in configuration)")

if __name__ == "__main__":
    # Define flag to skip guardian initialization for stop/restart commands
    no_guardian = len(sys.argv) <= 1 or sys.argv[1] != "start"
    
    # Only initialize guardian if not stopping or restarting
    if not no_guardian:
        guardian = initialize_process_protection()
    
    # Process commands first
    if len(sys.argv) > 1:
        action = sys.argv[1]

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

        # Command processing continues here
        if action == "restart":
            stop_monisec_client_daemon()
            time.sleep(2)
            start_process("monisec_client")

        elif action == "stop":
            stop_monisec_client_daemon()
            sys.exit(0)  # Exit immediately after stopping

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
                
        # Daemon mode
        elif action == "-d":
            # Run updater in daemon mode
            try:
                updater.check_for_updates()
            except Exception as e:
                logging.warning(f"Updater failed: {e}")
            
            # Check if already running - with improved stale PID detection
            pid_file = os.path.join(BASE_DIR, "output", "monisec_client.pid")
            
            # Force remove any existing PID file regardless of content
            if os.path.exists(pid_file):
                try:
                    os.remove(pid_file)
                    logging.info(f"Removed existing PID file at startup")
                except Exception as e:
                    logging.error(f"Failed to remove existing PID file: {e}")
            
            # Scan for any potentially running processes
            running_monisec_processes = []
            for proc in psutil.process_iter(['pid', 'cmdline']):
                try:
                    cmdline = " ".join(proc.info['cmdline'] or [])
                    # Only count it if it's not our current process
                    if "monisec_client.py" in cmdline and "-d" in cmdline and proc.info['pid'] != os.getpid():
                        running_monisec_processes.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if running_monisec_processes:
                print(f"MoniSec client is already running with PID {running_monisec_processes[0]}")
                sys.exit(0)
            
            # Clean up any existing orphaned child processes
            for name in ["fim_client", "pim", "lim"]:
                instances = is_process_running(name, count_instances=True)
                if instances > 0:
                    logging.info(f"Found {instances} orphaned {name} processes. Cleaning up...")
                    cleanup_duplicate_processes(name)
            
            # Create output directory if it doesn't exist
            output_dir = os.path.join(BASE_DIR, "output")
            os.makedirs(output_dir, exist_ok=True)
            
            # Start the daemon process
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
            os.setsid()
            os.umask(0)
            sys.stdin = open(os.devnull, 'r')
        
            # Set path to PID file using absolute path
            pid_file = os.path.abspath(os.path.join(output_dir, "monisec_client.pid"))
            
            # Write PID to file with error handling
            try:
                with open(pid_file, 'w') as f:
                    f.write(str(os.getpid()))
                logging.info(f"Created PID file with PID {os.getpid()}")
            except Exception as e:
                logging.error(f"Failed to create PID file: {e}")
            
            # Create a flag file to tell ProcessGuardian not to manage these processes
            monisec_manages_file = os.path.join(output_dir, "monisec_manages_processes")
            with open(monisec_manages_file, 'w') as f:
                f.write("true")
                
            # Make sure the guardian stop monitoring file doesn't exist
            control_file = os.path.join(output_dir, "guardian_stop_monitoring")
            if os.path.exists(control_file):
                os.remove(control_file)
        
            logging.info("MoniSec Endpoint Monitor started in daemon mode.")
        
            # Start the watchdog BEFORE entering the monitoring loop
            start_watchdog(delay=15)
            
            # Check authentication first
            remote.check_auth_and_send_logs()
            
            # Let start_listener_if_authorized handle the listener starting
            remote.start_listener_if_authorized()
            
            # Register exit handler for the daemon process
            atexit.register(lambda: os.path.exists(monisec_manages_file) and os.remove(monisec_manages_file))
            
            # This is an infinite loop that never returns
            monitor_processes()
    
        elif action == "exclusion":
            if len(sys.argv) < 3:
                print("[ERROR] Invalid command. Usage: monisec_client exclusion add|remove|list [type] [value]")
                sys.exit(1)
                
            excl_action = sys.argv[2]
            
            if excl_action == "list":
                # List exclusions of a specific type or all if not specified
                exclusion_type = sys.argv[3] if len(sys.argv) > 3 else None
                if exclusion_type and exclusion_type not in ['ip', 'user', 'file', 'directory', 'pattern', 'extension']:
                    print(f"[ERROR] Invalid exclusion type: {exclusion_type}")
                    print("Valid types: ip, user, file, directory, pattern, extension")
                    sys.exit(1)
                list_exclusions(exclusion_type)
                sys.exit(0)
                
            elif excl_action in ["add", "remove"]:
                if len(sys.argv) < 5:
                    print(f"[ERROR] Invalid command. Usage: monisec_client exclusion {excl_action} <type> <value>")
                    print("Valid types: ip, user, file, directory, pattern, extension")
                    sys.exit(1)
                    
                exclusion_type = sys.argv[3]
                value = sys.argv[4]
                
                success = manage_exclusions(excl_action, exclusion_type, value)
                sys.exit(0 if success else 1)
            else:
                print("[ERROR] Invalid exclusion action. Use add, remove, or list")
                sys.exit(1)

        else:
            print(
                """Usage:
            monisec_client restart                                # Restart monisec_client
            monisec_client stop                                   # Stop monisec_client daemon
            monisec_client pim start|stop|restart                 # Control PIM process
            monisec_client fim start|stop|restart                 # Control FIM process
            monisec_client lim start|stop|restart                 # Control LIM process
            monisec_client import-psk                             # Import PSK for authentication
            monisec_client auth test                              # Test authentication, then exit
            monisec_client exclusion add <type> <value>           # Add an exclusion
            monisec_client exclusion remove <type> <value>        # Remove an exclusion
            monisec_client exclusion list [type]                  # List all exclusions or of a specific type
            
            Exclusion types: ip, user, file, directory, pattern, extension
        """
            )
            sys.exit(1)

    else:
        # Only initialize guardian for foreground mode
        if not no_guardian and 'guardian' not in locals():
            guardian = initialize_process_protection()

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
        
        # Only start WebSocket client if auth is valid - start_websocket_client 
        # will now internally validate auth token
        if remote.validate_auth_token()[0]:
            # Start WebSocket client (after authentication)
            remote.start_websocket_client()
            
        # Create the flag file for foreground mode too
        monisec_manages_file = os.path.join(BASE_DIR, "output", "monisec_manages_processes")
        with open(monisec_manages_file, 'w') as f:
            f.write("true")
            
        # Register cleanup on exit
        atexit.register(lambda: os.path.exists(monisec_manages_file) and os.remove(monisec_manages_file))
        
        # Start monitoring
        monitor_processes()
