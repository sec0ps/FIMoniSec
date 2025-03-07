import os
import time
import psutil
import subprocess
import logging

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

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,  # Changed to DEBUG for troubleshooting
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# List of monitored processes
PROCESSES = {
    "python3 fim_client.py -d": "python3 fim_client.py -d",
    "python3 pim.py -d": "python3 pim.py -d"
}

# Function to check if a process is running more precisely
def is_process_running(full_command):
    logging.debug(f"Checking if {full_command} is running...")
    for proc in psutil.process_iter(attrs=['pid', 'cmdline']):
        try:
            if proc.info['cmdline'] and " ".join(proc.info['cmdline']) == full_command:
                logging.debug(f"Process {full_command} is running with PID {proc.info['pid']}.")
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    logging.debug(f"Process {full_command} is NOT running.")
    return False

# Function to restart a process
def restart_process(full_command):
    logging.warning(f"{full_command} is not running. Restarting...")
    try:
        process = subprocess.Popen(full_command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # Give time for process to start
        if is_process_running(full_command):
            logging.info(f"{full_command} restarted successfully with PID {process.pid}.")
        else:
            logging.error(f"Failed to restart {full_command}.")
    except Exception as e:
        logging.error(f"Error restarting {full_command}: {e}")

# Main monitoring loop
def monitor_processes():
    while True:
        logging.debug("Checking all monitored processes...")
        for full_command in PROCESSES.values():
            if not is_process_running(full_command):
                restart_process(full_command)
        logging.debug("Sleeping for 30 seconds before next check...")
        time.sleep(30)  # Check every 30 seconds

if __name__ == "__main__":
    logging.info("MoniSec Endpoint Monitor started.")
    monitor_processes()
