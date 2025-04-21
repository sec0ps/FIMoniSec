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
import time
import signal
import logging
import subprocess
import psutil
import threading
import hashlib
import atexit
from datetime import datetime

BASE_DIR = "/opt/FIMoniSec/Linux-Client"
log_dir = os.path.join(BASE_DIR, "logs")
output_dir = os.path.join(BASE_DIR, "output")
utils_dir = os.path.join(BASE_DIR, "utils")
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

if os.path.exists(utils_dir) and utils_dir not in sys.path:
    sys.path.append(utils_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, "enhanced_watchdog.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("EnhancedWatchdog")

class EnhancedWatchdog:
    """
    Combined watchdog and process guardian for FIMoniSec processes.
    Provides process monitoring, auto-restart capabilities, and
    protection against termination attempts.
    """
    
    def __init__(self, daemon_mode=False):
        """Initialize the enhanced watchdog."""
        # Define the processes to monitor and protect
        self.processes = {
            "monisec_client": {
                "script": os.path.join(BASE_DIR, "monisec_client.py"),
                "args": ["-d"],
                "cwd": BASE_DIR,
                "expected_count": 1,
                "protected": True
            },
            "fim": {
                "script": os.path.join(BASE_DIR, "fim.py"),
                "args": ["-d"],
                "cwd": BASE_DIR,
                "expected_count": 1,
                "protected": True
            },
            "lim": {
                "script": os.path.join(BASE_DIR, "lim.py"),
                "args": ["-d"],
                "cwd": BASE_DIR,
                "expected_count": 1,
                "protected": True
            },
            "pim": {
                "script": os.path.join(BASE_DIR, "pim.py"),
                "args": ["-d"],
                "cwd": BASE_DIR,
                "expected_count": 1,
                "protected": True
            },
            "watchdog": {
                "script": os.path.join(BASE_DIR, "utils/watchdog.py"),
                "args": ["-d"],
                "cwd": BASE_DIR,
                "expected_count": 1,
                "protected": True
            }
        }
        
        # Internal state tracking
        self.termination_attempts = {}
        self.running = True
        self.monitor_thread = None
        self.integrity_thread = None
        self.main_pid = os.getpid()
        self.daemon_mode = daemon_mode
        self.pid_file = os.path.join(output_dir, "enhanced_watchdog.pid")
        self.process_hashes = {}
        
        # Set up signal handlers to intercept termination attempts
        self._setup_signal_handlers()
        
        # Create a PID file
        self._create_pid_file()
        atexit.register(self._cleanup_pid_file)
        
        # Initialize process binary hashes (for integrity monitoring)
        self._initialize_process_hashes()
        
        logger.info(f"Enhanced Watchdog initialized. Main PID: {self.main_pid}")
    
    def _setup_signal_handlers(self):
        """Set up handlers for various termination signals."""
        # SIGTERM - standard termination signal
        signal.signal(signal.SIGTERM, self._handle_termination_signal)
        # SIGINT - interrupt from keyboard (Ctrl+C)
        signal.signal(signal.SIGINT, self._handle_termination_signal)
        # SIGQUIT - quit from keyboard
        signal.signal(signal.SIGQUIT, self._handle_termination_signal)
        # SIGHUP - terminal line hangup
        signal.signal(signal.SIGHUP, self._handle_termination_signal)
        
        logger.info("Signal handlers installed")
    
    def _handle_termination_signal(self, signum, frame):
        """
        Handle termination signals by logging and optionally allowing termination.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_names = {
            signal.SIGTERM: "SIGTERM",
            signal.SIGINT: "SIGINT",
            signal.SIGQUIT: "SIGQUIT",
            signal.SIGHUP: "SIGHUP"
        }
        
        signal_name = signal_names.get(signum, f"Signal {signum}")
        
        # Get information about the sender of the signal
        sender_info = self._get_signal_sender()
        
        # Log the termination attempt
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.warning(f"SECURITY ALERT: Termination attempt detected! Signal: {signal_name}")
        logger.warning(f"Sender details: {sender_info}")
        
        # Record this attempt
        self.termination_attempts[timestamp] = {
            "signal": signal_name,
            "sender": sender_info
        }
        
        # Write to tamper evidence log
        self._log_tamper_attempt(signal_name, sender_info)
        
        # By default, we'll ignore most termination signals to keep the process alive
        # But we'll make an exception for repeated SIGTERM signals which might indicate
        # a legitimate shutdown request
        if signum == signal.SIGTERM:
            # Convert to datetime objects for proper comparison
            time_now = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            
            # Count recent attempts (within the last 60 seconds)
            recent_attempts = 0
            for ts in self.termination_attempts.keys():
                try:
                    time_past = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if (time_now - time_past).total_seconds() < 60:
                        recent_attempts += 1
                except ValueError:
                    continue
            
            if recent_attempts >= 3:
                logger.info("Multiple termination requests received. Allowing shutdown.")
                # Perform cleanup and exit
                self.running = False
                if self.monitor_thread and self.monitor_thread.is_alive():
                    self.monitor_thread.join(timeout=3)
                if self.integrity_thread and self.integrity_thread.is_alive():
                    self.integrity_thread.join(timeout=3)
                sys.exit(0)
        
        # Otherwise, ignore the signal and keep running
        logger.info(f"Ignored {signal_name} signal, continuing execution")
    
    def _get_signal_sender(self):
        """
        Attempt to identify the process that sent the termination signal.
        
        Returns:
            dict: Information about the sender, or empty dict if unknown
        """
        try:
            # Check the parent process, which might be the sender
            parent = psutil.Process(os.getppid())
            return {
                "pid": parent.pid,
                "name": parent.name(),
                "cmdline": " ".join(parent.cmdline()),
                "username": parent.username()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"info": "Unable to determine signal sender"}
    
    def _log_tamper_attempt(self, signal_name, sender_info):
        """
        Write tamper attempt to a dedicated tamper evidence log.
        
        Args:
            signal_name (str): Name of the signal received
            sender_info (dict): Information about the sender
        """
        tamper_log_path = os.path.join(log_dir, "tamper_evidence.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(tamper_log_path, "a") as f:
                f.write(f"{timestamp} - TAMPERING DETECTED - Signal: {signal_name}\n")
                f.write(f"{timestamp} - Sender: {sender_info}\n")
        except Exception as e:
            logger.error(f"Failed to write to tamper evidence log: {e}")
    
    def _create_pid_file(self):
        """Create a PID file for this process."""
        try:
            with open(self.pid_file, "w") as f:
                f.write(str(self.main_pid))
            logger.info(f"Created PID file: {self.pid_file}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {e}")
    
    def _cleanup_pid_file(self):
        """Remove the PID file on exit."""
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
                logger.info(f"Removed PID file: {self.pid_file}")
            except Exception as e:
                logger.error(f"Failed to remove PID file: {e}")
    
    def _initialize_process_hashes(self):
        """Initialize the known good hashes for monitored processes."""
        # Using BASE_DIR instead of hardcoded path
        
        # Define the main script files to monitor
        files_to_monitor = [
            "monisec_client.py",
            "fim.py",
            "lim.py",
            "pim.py"
        ]
        
        # Calculate hashes for each file
        for filename in files_to_monitor:
            file_path = os.path.join(BASE_DIR, filename)
            hash_value = self._calculate_file_hash(file_path)
            if hash_value:
                self.process_hashes[filename] = hash_value
                logger.info(f"Initialized integrity hash for {filename}: {hash_value}")
    
    def _calculate_file_hash(self, file_path):
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: SHA-256 hash of the file, or None if an error occurs
        """
        try:
            if not os.path.exists(file_path):
                logger.warning(f"Cannot calculate hash, file does not exist: {file_path}")
                return None
                
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return file_hash
        except Exception as e:
            logger.error(f"Error calculating file hash for {file_path}: {e}")
            return None
    
    def _integrity_check_thread(self):
        """Thread that periodically verifies the integrity of all monitored processes."""
        logger.info("Process integrity monitoring thread started")
        
        while self.running:
            try:
                for filename, original_hash in self.process_hashes.items():
                    file_path = os.path.join(BASE_DIR, filename)
                    current_hash = self._calculate_file_hash(file_path)
                    
                    if not current_hash:
                        logger.error(f"Failed to calculate current hash for {filename}")
                        continue
                        
                    if current_hash != original_hash:
                        logger.critical(f"SECURITY ALERT: Process binary integrity check failed for {filename}")
                        logger.critical(f"Expected hash: {original_hash}")
                        logger.critical(f"Current hash: {current_hash}")
                        
                        # Log the integrity violation as a security event
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        security_log_path = os.path.join(log_dir, "security_events.log")
                        
                        try:
                            with open(security_log_path, "a") as f:
                                f.write(f"{timestamp} - INTEGRITY VIOLATION - Process {filename} has been modified\n")
                                f.write(f"{timestamp} - Expected hash: {original_hash}\n")
                                f.write(f"{timestamp} - Current hash: {current_hash}\n")
                        except Exception as e:
                            logger.error(f"Failed to write to security events log: {e}")
                    else:
                        logger.debug(f"Integrity check passed for {filename}")
                
                # Sleep for 15 minutes before the next integrity check
                # This is a reasonable interval for integrity checks
                for _ in range(15 * 60):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in integrity check thread: {e}")
                time.sleep(60)  # Shorter sleep on error
    
    def check_processes(self):
        """
        Check if all monitored processes are running.
        
        Returns:
            list: Names of processes that are not running
        """
        missing_processes = []
        
        for proc_name, proc_config in self.processes.items():
            # Count how many instances of the process are running
            count = self._count_process_instances(proc_name)
            
            # If fewer than expected, add to missing list
            if count < proc_config["expected_count"]:
                logger.warning(f"Process {proc_name} has {count} instances running, expected {proc_config['expected_count']}")
                missing_processes.append(proc_name)
            else:
                logger.info(f"Process {proc_name} is running normally ({count} instances)")
        
        return missing_processes
    
    def _count_process_instances(self, proc_name):
        """
        Count how many instances of a process are running.
        
        Args:
            proc_name (str): Process name to count
            
        Returns:
            int: Number of instances running
        """
        count = 0
        current_pid = os.getpid()
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if process name matches
                if proc_name in proc.name():
                    count += 1
                    continue
                
                # Special handling for watchdog.py
                if proc_name == "watchdog":
                    if proc.info['cmdline'] and any("watchdog.py" in cmd for cmd in proc.info['cmdline']):
                        count += 1
                    continue
                    
                # Check if process script name matches in cmdline
                if proc.info['cmdline'] and any(f"{proc_name}.py" in cmd for cmd in proc.info['cmdline']):
                    count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return count
    
    def restart_process(self, proc_name):
        """
        Restart a missing process, with integrity verification.
        
        Args:
            proc_name (str): Process name to restart
            
        Returns:
            bool: True if restart was successful, False otherwise
        """
        proc_config = self.processes.get(proc_name)
        if not proc_config:
            logger.error(f"No configuration found for process {proc_name}")
            return False
        
        logger.warning(f"Attempting to restart {proc_name}")
        
        # Check integrity before restarting
        script_filename = os.path.basename(proc_config["script"])
        if script_filename in self.process_hashes:
            current_hash = self._calculate_file_hash(proc_config["script"])
            original_hash = self.process_hashes[script_filename]
            
            if current_hash != original_hash:
                logger.critical(f"SECURITY ALERT: Cannot restart {proc_name} - integrity check failed")
                self._log_security_event(f"Failed integrity check during restart attempt of {proc_name}")
                return False
        
        try:
            # Build the command
            cmd = ["python3", proc_config["script"]] + proc_config["args"]
            
            # Start the process
            process = subprocess.Popen(
                cmd,
                cwd=proc_config["cwd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True  # Detach from the parent process
            )
            
            # Wait a moment to make sure it starts
            time.sleep(2)
            
            # Check if it's running
            if process.poll() is None:
                logger.info(f"Successfully restarted {proc_name} with PID {process.pid}")
                self._log_process_restart(proc_name, process.pid)
                return True
            else:
                stderr = process.stderr.read().decode('utf-8', errors='ignore')
                logger.error(f"Process {proc_name} failed to start. Error: {stderr}")
                return False
            
        except Exception as e:
            logger.error(f"Failed to restart {proc_name}: {e}")
            return False
    
    def _log_process_restart(self, proc_name, new_pid):
        """
        Log process restart as a security event.
        
        Args:
            proc_name (str): Process name
            new_pid (int): New process PID
        """
        self._log_security_event(f"Process {proc_name} was restarted. New PID: {new_pid}")
    
    def _log_security_event(self, message):
        """
        Log a security event.
        
        Args:
            message (str): Security event message
        """
        security_log_path = os.path.join(log_dir, "security_events.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(security_log_path, "a") as f:
                f.write(f"{timestamp} - SECURITY EVENT - {message}\n")
        except Exception as e:
            logger.error(f"Failed to write to security events log: {e}")
    
    def set_process_priority(self, priority=10):
        """
        Set the process priority (nice value) to make it harder to terminate.
        Lower values have higher priority.
        
        Args:
            priority (int): Priority value (-20 to 19, lower is higher priority)
        """
        try:
            # Set the nice value
            os.nice(priority)
            logger.info(f"Set process priority to {priority}")
            return True
        except Exception as e:
            logger.warning(f"Failed to set process priority: {e}")
            logger.info("Continuing without priority adjustment")
            return False
    
    def prevent_core_dumps(self):
        """Prevent core dumps to avoid leaking sensitive information."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            logger.info("Prevented core dumps")
        except Exception as e:
            logger.error(f"Failed to prevent core dumps: {e}")
    
    def _monitor_thread(self):
        """
        Main monitoring thread that continuously checks processes
        and restarts any that are missing.
        """
        logger.info("Process monitoring thread starting with initial stabilization delay...")
        # Add additional stabilization delay to ensure all processes have fully started
        time.sleep(15)  # 15 second additional delay
        
        logger.info("Process monitoring thread now active")
        
        while self.running:
            try:
                # Check for missing processes
                missing_processes = self.check_processes()
                
                # Restart any missing processes
                for proc_name in missing_processes:
                    self.restart_process(proc_name)
                    
                # Adaptive sleep: shorter interval if there were issues, longer if stable
                sleep_time = 60 if not missing_processes else 10
                
                # Use time.sleep(1) in a loop so we can exit cleanly if needed
                for _ in range(sleep_time):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}")
                time.sleep(30)  # Sleep on error
                    
    def start(self):
        """Start the enhanced watchdog with all monitoring threads."""
        # Set process hardening measures
        self.set_process_priority()
        self.prevent_core_dumps()
        
        # Start the process monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_thread, daemon=True)
        self.monitor_thread.start()
        
        # Start the integrity check thread
        self.integrity_thread = threading.Thread(target=self._integrity_check_thread, daemon=True)
        self.integrity_thread.start()
        
        logger.info("Enhanced Watchdog started with all monitoring threads")
        
        # If running in daemon mode, just keep the process alive
        if self.daemon_mode:
            logger.info("Running in daemon mode")
            try:
                while self.running:
                    time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                logger.info("Received shutdown signal")
                self.running = False
        else:
            # Otherwise, run a single check and exit
            logger.info("Running in one-time check mode")
            missing_processes = self.check_processes()
            for proc_name in missing_processes:
                self.restart_process(proc_name)
            
            if missing_processes:
                logger.info(f"Restarted {len(missing_processes)} processes")
            else:
                logger.info("All FIMoniSec processes are running normally")


def start_daemon_mode():
    """Start the watchdog in daemon mode with proper forking."""
    pid = os.fork()
    if pid > 0:
        # Parent process exits
        sys.exit(0)
    
    # Child continues
    os.setsid()
    os.umask(0)
    
    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open(os.devnull, 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    
    log_file = os.path.join(log_dir, "enhanced_watchdog_daemon.log")
    with open(log_file, 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())
    
    # Start the watchdog
    watchdog = EnhancedWatchdog(daemon_mode=True)
    watchdog.start()


if __name__ == "__main__":
    # Create a temporary instance to check processes
    temp_watchdog = EnhancedWatchdog(daemon_mode=False)
    
    # Check if watchdog is already running
    watchdog_count = temp_watchdog._count_process_instances("watchdog")
    
    # Subtract 1 for current process
    if watchdog_count > 1:  # More than just the current instance
        print(f"Watchdog is already running. Found {watchdog_count-1} other instances. Exiting.")
        sys.exit(0)
    
    # Process command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        # Start in daemon mode
        logger.info("Starting Enhanced Watchdog in daemon mode...")
        
        # Now start the actual daemon
        start_daemon_mode()
    else:
        # Run a single check
        print("Running Enhanced Watchdog check...")
        watchdog = EnhancedWatchdog(daemon_mode=False)
        watchdog.start()
