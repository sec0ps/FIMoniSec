import os
import time
import psutil
import subprocess
import logging

# Configure logging
logging.basicConfig(
    filename="monisec-endpoint.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# List of monitored processes
PROCESSES = {
    "fim.py": "python3 fim.py",
    "pim.py": "python3 pim.py"
}

# Function to check if a process is running
def is_process_running(process_name):
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:
            if proc.info['cmdline'] and process_name in proc.info['cmdline']:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

# Function to restart a process
def restart_process(process_name, command):
    logging.warning(f"{process_name} is not running. Restarting...")
    subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Give time for process to start
    if is_process_running(process_name):
        logging.info(f"{process_name} restarted successfully.")
    else:
        logging.error(f"Failed to restart {process_name}.")

# Main monitoring loop
def monitor_processes():
    while True:
        for process, command in PROCESSES.items():
            if not is_process_running(process):
                restart_process(process, command)
        time.sleep(30)  # Check every 30 seconds

if __name__ == "__main__":
    logging.info("MoniSec Endpoint Monitor started.")
    monitor_processes()
