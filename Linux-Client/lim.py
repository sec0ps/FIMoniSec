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
import argparse
from multiprocessing import Process

# Import LIM components
from lim_utils.config import ConfigManager
from lim_utils.monitor import EnhancedLogMonitor  # Verify this class exists
from lim_utils.log_discovery import discover_and_classify_logs, identify_critical_logs
from lim_utils.log_detection_engine import LogDetectionEngine
from lim_utils.lim_ml import LogAnomalyDetector

BASE_DIR = "/opt/FIMoniSec/Linux-Client"

PID_FILE = "lim.pid"

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║ Log Integrity Management (LIM) Module     ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)

def start_monitor(foreground=True):
    """Start the LIM monitoring service"""
    # Ensure paths for PID and logs are correct
    pid_file = os.path.join(BASE_DIR, "output", PID_FILE)
    log_dir = os.path.join(BASE_DIR, "logs")
    
    # Create directories if they don't exist
    os.makedirs(os.path.join(BASE_DIR, "output"), exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    
    # Simply remove the PID file if it exists
    if os.path.exists(pid_file):
        print(f"Found existing PID file. Removing {pid_file} before starting.")
        os.remove(pid_file)

    if not foreground:
        # Proper daemonization using double-fork
        pid = os.fork()
        if pid > 0:
            # Exit parent
            print(f"LIM started in daemon mode with PID {pid}")
            with open(pid_file, 'w') as f:
                f.write(str(pid))
            sys.exit(0)

        # Decouple from parent environment
        os.setsid()
        os.umask(0)

        # Second fork to prevent reacquisition of terminal
        pid2 = os.fork()
        if pid2 > 0:
            with open(pid_file, 'w') as f:
                f.write(str(pid2))
            sys.exit(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        with open(os.path.join(log_dir, "lim_output.log"), 'a+') as out, \
             open(os.path.join(log_dir, "lim_error.log"), 'a+') as err:
            os.dup2(out.fileno(), sys.stdout.fileno())
            os.dup2(err.fileno(), sys.stderr.fileno())

        # In final daemon process
        run_monitor()
        return

    # Start in foreground mode
    try:
        run_monitor()
    except KeyboardInterrupt:
        print("\nLIM monitoring stopped by user.")

def run_monitor():
    """Run the actual monitoring process"""
    # Ensure we use the correct PID file path
    pid_file = os.path.join(BASE_DIR, "output", PID_FILE)
    
    config_manager = ConfigManager()
    monitor = EnhancedLogMonitor(config_manager)
    
    # Register signal handlers with correct PID file path
    def handle_signal(signum, frame):
        print("\nReceived signal to terminate. Shutting down LIM...")
        if os.path.exists(pid_file):
            os.remove(pid_file)
        sys.exit(0)
        
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    # Start monitoring
    monitor.start()

def stop_monitor():
    """Stop the LIM monitoring service"""
    pid_file = os.path.join(BASE_DIR, "output", PID_FILE)
    
    if not os.path.exists(pid_file):
        print("No LIM daemon is running.")
        return
        
    with open(pid_file, 'r') as f:
        try:
            pid = int(f.read().strip())
        except ValueError:
            print(f"Invalid PID in {pid_file}. Removing stale PID file.")
            os.remove(pid_file)
            return
            
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent termination signal to LIM process {pid}.")
        
        # Wait for process to terminate
        for _ in range(5):
            try:
                os.kill(pid, 0)  # Check if process exists
                time.sleep(1)
            except OSError:
                break
                
        if os.path.exists(pid_file):
            os.remove(pid_file)
            
    except ProcessLookupError:
        print(f"Process {pid} not found. Removing stale PID file.")
        os.remove(pid_file)
    except PermissionError:
        print(f"Permission denied when attempting to terminate process {pid}.")

def restart_monitor():
    """Restart the LIM monitoring service"""
    stop_monitor()
    time.sleep(2)
    start_monitor(foreground=False)

def scan_logs():
    """Scan and classify log files without starting the monitor"""
    print("Scanning system for log files...")
    logs = discover_and_classify_logs()
    
    print("\nLog files by category:")
    total_logs = 0
    for category, log_files in logs.items():
        print(f"\n{category.upper()} LOGS ({len(log_files)}):")
        for log_file in sorted(log_files):
            print(f"  - {log_file}")
        total_logs += len(log_files)
        
    print(f"\nTotal log files found: {total_logs}")
    
    # Identify critical logs
    critical_logs = identify_critical_logs(logs)
    print("\nCritical security logs:")
    for log_file in critical_logs[:10]:  # Show first 10
        print(f"  - {log_file}")
    if len(critical_logs) > 10:
        print(f"  ... and {len(critical_logs) - 10} more")
    
    return logs, critical_logs

def update_config():
    """Update the LIM configuration with the latest log files"""
    print("Updating LIM configuration...")
    
    # Get both regular and critical logs
    logs, critical_logs = scan_logs()
    
    config_manager = ConfigManager()
    
    # Update with regular logs
    config_manager.update_log_files(logs)
    
    # Add critical logs to the configuration separately
    lim_config = config_manager.get_lim_config()
    lim_config["critical_logs"] = critical_logs
    config_manager.update_config_value("log_integrity_monitor", lim_config)
    
    print("\nConfiguration updated successfully.")
    print(f"Regular logs updated: {sum(len(logs[category]) for category in logs)}")
    print(f"Critical logs identified: {len(critical_logs)}")

def main():
    """Main entry point with command-line argument parsing"""
    parser = argparse.ArgumentParser(description="Log Integrity Management (LIM) Module")
    
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('-s', '--start', action='store_true', help='Start LIM in foreground mode')
    command_group.add_argument('-d', '--daemon', action='store_true', help='Start LIM in daemon (background) mode')
    command_group.add_argument('-k', '--stop', action='store_true', help='Stop the LIM daemon')
    command_group.add_argument('-r', '--restart', action='store_true', help='Restart the LIM daemon')
    command_group.add_argument('-c', '--scan', action='store_true', help='Scan and classify log files without starting LIM')
    command_group.add_argument('-u', '--update', action='store_true', help='Update configuration with the latest log files')
    command_group.add_argument('-v', '--version', action='store_true', help='Show version information')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.start:
        start_monitor(foreground=True)
    elif args.daemon:
        start_monitor(foreground=False)
    elif args.stop:
        stop_monitor()
    elif args.restart:
        restart_monitor()
    elif args.scan:
        scan_logs()
    elif args.update:
        update_config()
    elif args.version:
        # Version is already shown in the banner
        pass
    else:
        # Default behavior: start in foreground
        start_monitor(foreground=True)

if __name__ == "__main__":
    main()
