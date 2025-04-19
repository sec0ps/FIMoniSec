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
import signal
import logging
import time
import subprocess
import psutil
import threading
import atexit
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/opt/FIMoniSec/logs/process_guardian.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("ProcessGuardian")

class ProcessGuardian:
    """
    Provides process protection and self-defense mechanisms for critical processes.
    Monitors processes, intercepts termination signals, and ensures persistence.
    """
    
    def __init__(self, process_names=None, pid_file=None):
        """
        Initialize the process guardian.
        
        Args:
            process_names (list): List of process names to protect (e.g., ["monisec_client.py"])
            pid_file (str): Path to PID file for this process
        """
        self.process_names = process_names or []
        self.pid_file = pid_file
        self.watched_processes = {}
        self.termination_attempts = {}
        self.running = True
        self.watch_thread = None
        self.main_pid = os.getpid()
        
        # Ensure logs directory exists
        os.makedirs("/opt/FIMoniSec/logs", exist_ok=True)
        
        # Set up signal handlers to intercept termination attempts
        self._setup_signal_handlers()
        
        # Create a PID file if specified
        if self.pid_file:
            self._create_pid_file()
            atexit.register(self._cleanup_pid_file)
        
        logger.info(f"Process Guardian initialized. Main PID: {self.main_pid}")
    
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
            # If we've received multiple SIGTERM signals in a short time, allow termination
            recent_attempts = [ts for ts in self.termination_attempts.keys() 
                              if timestamp.replace(' ', 'T') > ts.replace(' ', 'T') 
                              and (datetime.fromisoformat(timestamp.replace(' ', 'T')) - 
                                  datetime.fromisoformat(ts.replace(' ', 'T'))).total_seconds() < 60]
            
            if len(recent_attempts) >= 3:
                logger.info("Multiple termination requests received. Allowing shutdown.")
                # Perform cleanup and exit
                self.running = False
                if self.watch_thread and self.watch_thread.is_alive():
                    self.watch_thread.join(timeout=3)
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
        tamper_log_path = "/opt/FIMoniSec/logs/tamper_evidence.log"
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
    
    def start_monitoring(self):
        """Start the process monitoring thread."""
        self.watch_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.watch_thread.start()
        logger.info("Process monitoring started")
    
    def _monitor_processes(self):
        """
        Monitor the protected processes and restart them if they're terminated.
        """
        while self.running:
            try:
                # First, update our list of processes to watch
                self._update_watched_processes()
                
                # Check each watched process
                for proc_name, proc_info in list(self.watched_processes.items()):
                    # If we have a PID, check if it's still running
                    if proc_info["pid"]:
                        try:
                            proc = psutil.Process(proc_info["pid"])
                            # If process is not running or zombie, restart it
                            if proc.status() == psutil.STATUS_ZOMBIE:
                                logger.warning(f"Process {proc_name} (PID: {proc_info['pid']}) is zombie. Restarting...")
                                self._restart_process(proc_name, proc_info)
                        except psutil.NoSuchProcess:
                            logger.warning(f"Process {proc_name} (PID: {proc_info['pid']}) was terminated. Restarting...")
                            self._restart_process(proc_name, proc_info)
                
                # Sleep for a bit before checking again
                time.sleep(5)
            
            except Exception as e:
                logger.error(f"Error in process monitoring: {e}")
                time.sleep(10)  # Longer sleep on error
    
    def _update_watched_processes(self):
        """Update the list of processes to watch."""
        for proc_name in self.process_names:
            # If we're not already watching this process, add it
            if proc_name not in self.watched_processes:
                # Find the process by name
                pids = self._find_process_pids(proc_name)
                if pids:
                    self.watched_processes[proc_name] = {
                        "pid": pids[0],  # Just use the first one if multiple
                        "command": proc_name,
                        "restart_count": 0,
                        "last_restart": None
                    }
                    logger.info(f"Now watching process: {proc_name} (PID: {pids[0]})")
    
    def _find_process_pids(self, process_name):
        """
        Find PIDs of processes matching the given name.
        
        Args:
            process_name (str): Process name to find
            
        Returns:
            list: List of PIDs
        """
        pids = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Check if process name matches
                if proc.info['name'] and process_name in proc.info['name']:
                    pids.append(proc.info['pid'])
                    continue
                
                # Check if process cmdline contains the name
                if proc.info['cmdline'] and any(process_name in cmd for cmd in proc.info['cmdline']):
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return pids
    
    def _restart_process(self, proc_name, proc_info):
        """
        Restart a terminated process.
        
        Args:
            proc_name (str): Process name
            proc_info (dict): Process information
        """
        # Log the restart attempt
        logger.warning(f"Attempting to restart {proc_name}")
        
        # Determine the command to run based on the process name
        cmd = None
        cwd = None
        
        if "monisec_client.py" in proc_name:
            cmd = ["python3", "/opt/FIMoniSec/Linux-Client/monisec_client.py", "-d"]
            cwd = "/opt/FIMoniSec/Linux-Client"
        elif "fim.py" in proc_name:
            cmd = ["python3", "/opt/FIMoniSec/Linux-Client/fim.py"]
            cwd = "/opt/FIMoniSec/Linux-Client"
        elif "lim.py" in proc_name:
            cmd = ["python3", "/opt/FIMoniSec/Linux-Client/lim.py"]
            cwd = "/opt/FIMoniSec/Linux-Client"
        elif "pim.py" in proc_name:
            cmd = ["python3", "/opt/FIMoniSec/Linux-Client/pim.py"]
            cwd = "/opt/FIMoniSec/Linux-Client"
        
        if cmd and cwd:
            try:
                # Start the process
                process = subprocess.Popen(
                    cmd,
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True  # Detach from the parent process
                )
                
                # Update the process info
                proc_info["pid"] = process.pid
                proc_info["restart_count"] += 1
                proc_info["last_restart"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                logger.info(f"Successfully restarted {proc_name} with PID {process.pid}")
                
                # Log the restart as a security event
                self._log_process_restart(proc_name, process.pid)
            
            except Exception as e:
                logger.error(f"Failed to restart {proc_name}: {e}")
        else:
            logger.error(f"No restart command defined for {proc_name}")
    
    def _log_process_restart(self, proc_name, new_pid):
        """
        Log process restart as a security event.
        
        Args:
            proc_name (str): Process name
            new_pid (int): New process PID
        """
        security_log_path = "/opt/FIMoniSec/logs/security_events.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            with open(security_log_path, "a") as f:
                f.write(f"{timestamp} - SECURITY EVENT - Process {proc_name} was restarted\n")
                f.write(f"{timestamp} - New PID: {new_pid}\n")
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
        except Exception as e:
            logger.error(f"Failed to set process priority: {e}")

    def prevent_core_dumps(self):
        """Prevent core dumps to avoid leaking sensitive information."""
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            logger.info("Prevented core dumps")
        except Exception as e:
            logger.error(f"Failed to prevent core dumps: {e}")
