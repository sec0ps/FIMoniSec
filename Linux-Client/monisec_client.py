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
# Purpose: This script is part of the FIMoniSec Tool, which provides enterprise-grade
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

# Ensure logs directory exists
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "monisec-endpoint.log")

# Set log file permissions to 600 (read/write for user only)
try:
    with open(LOG_FILE, 'a') as f:
        pass
    os.chmod(LOG_FILE, 0o600)
except Exception as e:
    print(f"Failed to set log file permissions: {e}")

# Configure logging to write to file and optionally to console
log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
log_handler = logging.FileHandler(LOG_FILE)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.DEBUG)
logging_handlers = [log_handler]

# Only add console output if not running in daemon mode
if not (len(sys.argv) > 1 and sys.argv[1] == "-d"):
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    console_handler.setLevel(logging.DEBUG)
    logging_handlers.append(console_handler)

logging.basicConfig(level=logging.DEBUG, handlers=logging_handlers)

# List of monitored processes
PROCESSES = {
    "fim_client": "python3 fim_client.py -d",
    "pim": "python3 pim.py -d",
}

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

# Function to restart a process
def restart_process(name):
    stop_process(name)
    time.sleep(2)
    start_process(name)

def is_process_running(name):
    """Check if a specific process is running by comparing executable name."""
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:
            exe_name = proc.info['name']
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

            # Only match exact script calls, avoid false positives like 'kate'
            if exe_name == "python3" and f"{name}.py" in cmdline:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None

def monitor_processes():
    while True:
        all_running = True
        for name in PROCESSES:
            if not is_process_running(name):
                logging.warning(f"{name} is not running. Restarting...")
                start_process(name)
                all_running = False  # Mark that at least one process was restarted

        time.sleep(10 if not all_running else 60)  # Increase interval if stable

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

    time.sleep(2)
    logging.info("MoniSec client shutdown complete.")
    sys.exit(0)

# Register signal handler for graceful shutdown
signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

if __name__ == "__main__":
    should_run_updater = (len(sys.argv) == 1) or (len(sys.argv) > 1 and sys.argv[1] == "-d")

    if should_run_updater:
        try:
            updater.check_for_updates()
        except Exception as e:
            logging.warning(f"Updater failed: {e}")

    if len(sys.argv) > 1:
        action = sys.argv[1]

        # Restart MoniSec Client
        if action == "restart":
            stop_monisec_client_daemon()
            time.sleep(2)
            start_process("monisec_client")

        # Stop MoniSec Client Daemon
        elif action == "stop":
            stop_monisec_client_daemon()

        # Start, Stop, Restart PIM or FIM
        elif action in ["pim", "fim"]:
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

        # Import PSK for authentication
        elif action == "import-psk":
            remote.import_psk()

        # Authenticate with server and exit
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
    monisec_client import-psk               # Import PSK for authentication
    monisec_client auth test                # Test authentication, then exit"""
            )
            sys.exit(1)

    else:
        logging.info("MoniSec Endpoint Monitor started in foreground.")

        listener_thread = threading.Thread(target=remote.start_client_listener, daemon=True)
        listener_thread.start()

        remote.check_auth_and_send_logs()
        monitor_processes()
