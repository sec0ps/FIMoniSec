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
import re
import sys
import time
import json
import signal
import logging
import hashlib
import pyinotify
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Import LIM components
from lim_utils.log_parser import LogParser
from lim_utils.log_detection_engine import LogDetectionEngine
from lim_utils.lim_ml import LogAnomalyDetector
from lim_utils.log_discovery import discover_and_classify_logs, identify_critical_logs
from lim_utils.alert_manager import AlertManager

class EnhancedLogMonitor:
    """
    Enhanced log monitoring service with ML-based anomaly detection
    and signature-based detection
    """
    
    def __init__(self, config_manager):
        """
        Initialize the log monitor
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config_manager = config_manager
        self.config = config_manager.get_lim_config()
        
        # Set up logging
        self._setup_logging()
        
        # Initialize components
        self.log_parser = LogParser()
        self.alert_manager = AlertManager(self.config)
        
        # Initialize detection engines
        self._setup_detection_engines()
        
        # File position tracking
        self.file_positions = {}
        self.file_mtimes = {}
        
        # Monitoring state
        self.running = False
        self.monitored_files = set()
        self.watch_manager = None
        self.notifier = None
        
        # Performance tracking
        self.stats = {
            "start_time": time.time(),
            "logs_processed": 0,
            "alerts_generated": 0,
            "bytes_processed": 0,
            "processing_time": 0,
            "alerts_by_severity": defaultdict(int),
            "alerts_by_source": defaultdict(int)
        }
        
        # Circular buffer for recent alerts (max 1000)
        self.recent_alerts = deque(maxlen=1000)
        
        # Background scanners
        self.scanners = []
    
    def _setup_logging(self):
        """Configure logging for the monitor"""
        log_level = getattr(logging, self.config.get("log_level", "INFO").upper())
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=log_level, format=log_format)
        self.logger = logging.getLogger("lim")
        logging.getLogger("lim.detection").setLevel(logging.DEBUG)
    
    def _setup_detection_engines(self):
        """Initialize detection engines"""
        # Rule-based detection engine
        self.detection_engine = LogDetectionEngine(
            excluded_ips=self.config.get("excluded_ips", []),
            excluded_users=self.config.get("excluded_users", [])
        )
        
        # ML-based anomaly detection
        ml_config = self.config.get("ml_analysis", {})
        if ml_config.get("enabled", True):
            self.anomaly_detector = LogAnomalyDetector(ml_config)
        else:
            self.anomaly_detector = None
    
    def start(self):
        """Start the monitoring service"""
        self.running = True
        self.logger.info("Starting Log Integrity Management (LIM) service")
        
        # Load or discover log files
        self._initialize_log_files()
        
        # Set up real-time monitoring with pyinotify
        self._setup_file_monitoring()
        
        # Start background scanners
        self._start_background_scanners()
        
        try:
            # Process all monitored logs to establish baseline
            self._initial_log_scan()
            
            # Enter monitoring loop
            self.logger.info("Entering monitoring loop")
            if self.notifier:
                self.notifier.loop()
            else:
                # Fallback polling if inotify not available
                self._polling_loop()
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt. Stopping...")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the monitoring service"""
        self.running = False
        self.logger.info("Stopping Log Integrity Management (LIM) service")
        
        # Save file position checkpoints
        self._save_checkpoints()
        
        # Stop background scanners
        for scanner in self.scanners:
            if scanner.is_alive():
                scanner.join(timeout=2)
        
        # Stop notifier if running
        if self.notifier:
            self.notifier.stop()
        
        # Save final stats
        self._save_stats()
    
    def _initialize_log_files(self):
        """
        Enhanced version of _initialize_log_files with improved discovery
        """
        self.logger.info("Initializing log files for monitoring")
        
        # First try to use configured logs if available
        if self.config.get("monitored_logs"):
            self.logger.info(f"Using {len(self.config.get('monitored_logs'))} configured log files")
        else:
            self.logger.info("No monitored logs configured. Discovering logs...")
            
            # Check for common security-relevant logs that should exist on most systems
            common_security_logs = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/audit/audit.log"
            ]
            
            # Use these if available
            common_logs_found = []
            for log in common_security_logs:
                if os.path.exists(log) and os.access(log, os.R_OK):
                    common_logs_found.append(log)
            
            if common_logs_found:
                self.logger.info(f"Found {len(common_logs_found)} common security logs")
                self.config["monitored_logs"] = common_logs_found
                
                # Create a simple category structure
                self.config["log_categories"] = {"security": common_logs_found}
                self.config_manager.update_log_files({"security": common_logs_found})
            else:
                # Fall back to auto-discovery
                self.logger.info("No common security logs found. Running full discovery...")
                logs = discover_and_classify_logs()
                critical_logs = identify_critical_logs(logs)
                
                # Update configuration
                self.config["monitored_logs"] = critical_logs
                self.config["log_categories"] = logs
                self.config_manager.update_log_files(logs)
                
                self.logger.info(f"Discovered {len(critical_logs)} critical log files to monitor")
        
        # Filter to existing and readable logs
        valid_logs = []
        for log_file in self.config.get("monitored_logs", []):
            if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                valid_logs.append(log_file)
                self.logger.info(f"Monitoring log file: {log_file}")
            else:
                self.logger.warning(f"Log file not accessible: {log_file}")
        
        # Create test logs if no valid logs found (for testing only)
        if not valid_logs:
            self.logger.warning("No valid log files found. Creating test log for demonstration.")
            test_log = "test_security.log"
            with open(test_log, "w") as f:
                f.write("Apr 1 12:00:00 testhost sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2\n")
            valid_logs.append(test_log)
            self.logger.info(f"Created and monitoring test log file: {test_log}")
        
        self.monitored_files = set(valid_logs)
        self.logger.info(f"Monitoring {len(self.monitored_files)} log files")

    def _process_log_file(self, file_path, initial_scan=False, force_full=False):
        """
        Enhanced version of _process_log_file with improved error handling and debugging
        """
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            self.logger.warning(f"File {file_path} doesn't exist or isn't readable")
            return
        
        # Skip if not in monitored files
        if file_path not in self.monitored_files:
            self.logger.debug(f"File {file_path} not in monitored files, skipping")
            return
        
        self.logger.debug(f"Processing log file: {file_path}")
        start_time = time.time()
        
        try:
            # Get file information
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            mtime = file_stat.st_mtime
            
            # Update file mtime tracking
            self.file_mtimes[file_path] = mtime
            
            # Skip empty files
            if file_size == 0:
                self.logger.debug(f"File {file_path} is empty, skipping")
                return
            
            # Detect log format
            format_name, confidence = self.log_parser.detect_format(file_path)
            self.logger.debug(f"Detected format: {format_name} with confidence {confidence}")
            
            # Determine how much to read
            if force_full:
                # Process entire file
                position = 0
                self.logger.debug(f"Processing entire file (force_full=True)")
            elif initial_scan:
                # For initial scan, start at end minus a small amount
                position = max(0, file_size - 50000)  # Last ~50KB
                self.logger.debug(f"Initial scan - starting at position {position}")
            elif file_path not in self.file_positions:
                # For new files, start at end minus a small amount
                position = max(0, file_size - 10000)  # Last ~10KB
                self.logger.debug(f"New file - starting at position {position}")
            else:
                # Continue from last position
                position = self.file_positions[file_path]
                
                # If file got smaller (rotated), start from beginning
                if position > file_size:
                    self.logger.info(f"File {file_path} appears to have been rotated (size decreased)")
                    position = 0
            
            self.logger.debug(f"Reading from position {position} of {file_size} bytes")
            
            # Open and read the file
            with open(file_path, 'r', errors='ignore') as f:
                # Seek to the determined position
                f.seek(position)
                
                # Read new content
                lines = f.readlines()
                
                # Update position for next time
                new_position = f.tell()
                self.file_positions[file_path] = new_position
                
                self.logger.debug(f"Read {len(lines)} lines, new position: {new_position}")
            
            # Skip if no new content
            if not lines:
                self.logger.debug(f"No new content in {file_path}")
                return
            
            # Calculate source key (for ML)
            source_key = os.path.basename(file_path)
            
            # Process each line
            alerts_generated = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Update stats
                self.stats["logs_processed"] += 1
                self.stats["bytes_processed"] += len(line)
                
                # Parse log line
                parsed_log = self.log_parser.parse_line(line, format_name)
                if not parsed_log:
                    continue
                
                # Check for security events
                security_event = self.log_parser.extract_security_events(parsed_log)
                
                # Check for signature-based alerts
                signature_alert = self.detection_engine.analyze_line(line)
                
                # Check for ML-based anomalies
                anomaly_result = None
                if self.anomaly_detector:
                    anomaly_result = self.anomaly_detector.process_log(source_key, parsed_log)
                
                # Process security events
                if security_event:
                    self.logger.debug(f"Security event detected: {security_event.get('event_type')}")
                    self._handle_security_event(security_event, parsed_log, file_path)
                    alerts_generated += 1
                
                # Process signature-based alerts
                if signature_alert:
                    self.logger.debug(f"Signature alert detected with score {signature_alert.get('score')}")
                    self._handle_signature_alert(signature_alert, parsed_log, file_path)
                    alerts_generated += 1
                
                # Process ML-based anomalies
                if anomaly_result and anomaly_result.get("is_anomaly"):
                    self.logger.debug(f"ML anomaly detected with score {anomaly_result.get('anomaly_score')}")
                    self._handle_anomaly(anomaly_result, parsed_log, file_path)
                    alerts_generated += 1
            
            # Log summary
            processing_time = time.time() - start_time
            self.logger.info(
                f"Processed {len(lines)} lines from {file_path} in {processing_time:.2f} seconds. "
                f"Generated {alerts_generated} alerts."
            )
            
            # Update processing time stat
            self.stats["processing_time"] += processing_time
        
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {str(e)}", exc_info=True)
    
    def _setup_file_monitoring(self):
        """Set up real-time file monitoring with pyinotify"""
        try:
            self.watch_manager = pyinotify.WatchManager()
            mask = pyinotify.IN_MODIFY | pyinotify.IN_DELETE_SELF | pyinotify.IN_MOVE_SELF
            
            # Custom event handler that integrates with our monitor
            class LogEventHandler(pyinotify.ProcessEvent):
                def __init__(self, monitor):
                    self.monitor = monitor
                
                def process_IN_MODIFY(self, event):
                    self.monitor._process_log_file(event.pathname)
                    
                def process_IN_DELETE_SELF(self, event):
                    self.monitor._handle_file_deleted(event.pathname)
                    
                def process_IN_MOVE_SELF(self, event):
                    self.monitor._handle_file_moved(event.pathname)
            
            handler = LogEventHandler(self)
            self.notifier = pyinotify.Notifier(self.watch_manager, handler)
            
            # Add watches for all monitored logs
            for log_file in self.monitored_files:
                try:
                    self.watch_manager.add_watch(log_file, mask)
                except Exception as e:
                    self.logger.error(f"Error adding watch to {log_file}: {str(e)}")
            
            self.logger.info(f"Set up watches for {len(self.monitored_files)} log files")
        except Exception as e:
            self.logger.error(f"Error setting up inotify monitoring: {str(e)}")
            self.logger.warning("Falling back to polling-based monitoring")
            self.watch_manager = None
            self.notifier = None
    
    def _start_background_scanners(self):
        """Start background scanning threads"""
        # Log discovery scanner - periodically checks for new log files
        discovery_scanner = threading.Thread(
            target=self._log_discovery_scanner,
            name="LIM-LogDiscoveryScanner",
            daemon=True
        )
        discovery_scanner.start()
        self.scanners.append(discovery_scanner)
        
        # Periodic full scan - ensures we don't miss any log entries
        full_scan_thread = threading.Thread(
            target=self._periodic_full_scan,
            name="LIM-FullScanThread",
            daemon=True
        )
        full_scan_thread.start()
        self.scanners.append(full_scan_thread)
    
    def _initial_log_scan(self):
        """Perform initial scan of monitored log files"""
        self.logger.info("Performing initial scan of monitored log files")
    
        # Load previous checkpoints if they exist
        checkpoint_file = os.path.join("logs", "checkpoints", "file_positions.json")
        checkpoint_dir = os.path.dirname(checkpoint_file)
        
        # Create checkpoint directory if it doesn't exist
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Try to load previous checkpoints
        loaded_checkpoints = False
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, 'r') as f:
                    saved_positions = json.load(f)
                    # Filter to only include files that still exist
                    for file_path, position in saved_positions.items():
                        if os.path.exists(file_path):
                            self.file_positions[file_path] = position
                    loaded_checkpoints = True
                self.logger.info(f"Loaded checkpoints for {len(self.file_positions)} log files")
            except Exception as e:
                self.logger.warning(f"Failed to load checkpoints: {str(e)}")
        
        # For files without checkpoints, set position to end of file
        # so we only track new entries going forward
        if not loaded_checkpoints:
            self.logger.info("No previous checkpoints found. Will track logs from this point forward.")
            
        # Process critical logs first
        critical_logs = set(identify_critical_logs({"all": list(self.monitored_files)}))
        
        for log_file in sorted(self.monitored_files, 
                              key=lambda f: f in critical_logs, 
                              reverse=True):
            # If no saved position, set to end of file
            if log_file not in self.file_positions and os.path.exists(log_file):
                try:
                    self.file_positions[log_file] = os.path.getsize(log_file)
                    self.logger.debug(f"Set initial position to end of file for {log_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to get size of {log_file}: {str(e)}")
        
        # Save the initial positions
        self._save_checkpoints()
        
        self.logger.info(f"Initial scan complete. Will monitor new log entries going forward.")
    
    def _polling_loop(self):
        """Fallback polling loop for systems without inotify"""
        self.logger.info("Starting polling-based monitoring")
        
        while self.running:
            changed_files = []
            
            # Check each monitored file for changes
            for log_file in self.monitored_files:
                try:
                    # Skip if file doesn't exist or isn't readable
                    if not os.path.exists(log_file) or not os.access(log_file, os.R_OK):
                        continue
                        
                    # Check if file has been modified
                    mtime = os.path.getmtime(log_file)
                    if log_file not in self.file_mtimes or mtime > self.file_mtimes[log_file]:
                        changed_files.append(log_file)
                        self.file_mtimes[log_file] = mtime
                except Exception as e:
                    self.logger.debug(f"Error checking {log_file}: {str(e)}")
            
            # Process changed files
            for log_file in changed_files:
                self._process_log_file(log_file)
                
            # Short sleep to prevent high CPU usage
            time.sleep(1)
    
    def _log_discovery_scanner(self):
        """Background scanner to discover new log files"""
        scan_interval = 3600  # 1 hour
        
        while self.running:
            try:
                # Sleep first to prevent immediate re-scan after startup
                time.sleep(scan_interval)
                
                if not self.running:
                    break
                    
                self.logger.debug("Running periodic log discovery scan")
                
                # Discover logs
                logs = discover_and_classify_logs()
                all_logs = set()
                for category_logs in logs.values():
                    all_logs.update(category_logs)
                
                # Find new logs
                new_logs = all_logs - self.monitored_files
                
                if new_logs:
                    self.logger.info(f"Discovered {len(new_logs)} new log files")
                    
                    # Add to monitored files
                    self.monitored_files.update(new_logs)
                    
                    # Update configuration
                    self.config["monitored_logs"] = sorted(self.monitored_files)
                    self.config_manager.update_log_files(logs)
                    
                    # Add watches for new logs if using inotify
                    if self.watch_manager:
                        mask = pyinotify.IN_MODIFY | pyinotify.IN_DELETE_SELF | pyinotify.IN_MOVE_SELF
                        for log_file in new_logs:
                            try:
                                self.watch_manager.add_watch(log_file, mask)
                            except Exception as e:
                                self.logger.error(f"Error adding watch to {log_file}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error in log discovery scanner: {str(e)}")
    
    def _periodic_full_scan(self):
        """Periodically perform a full scan of all logs"""
        scan_interval = 86400  # 24 hours
        
        while self.running:
            try:
                # Sleep first to prevent immediate re-scan after startup
                time.sleep(scan_interval)
                
                if not self.running:
                    break
                    
                self.logger.info("Running periodic full scan of all logs")
                
                # Reset file positions to force full read
                self.file_positions = {}
                
                # Process all files
                for log_file in sorted(self.monitored_files):
                    if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                        self._process_log_file(log_file, force_full=True)
                        
                self.logger.info(f"Periodic full scan complete. Processed {self.stats['logs_processed']} log entries")
            except Exception as e:
                self.logger.error(f"Error in periodic full scan: {str(e)}")
    
    def _process_log_file(self, file_path, initial_scan=False, force_full=False):
        """
        Process a log file for analysis
    
        Args:
            file_path: Path to the log file
            initial_scan: Whether this is part of the initial scan
            force_full: Whether to force processing the entire file
        """
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            return
    
        # Skip if not in monitored files
        if file_path not in self.monitored_files:
            return
    
        start_time = time.time()
    
        try:
            # Get file information
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            mtime = file_stat.st_mtime
    
            # Update file mtime tracking
            self.file_mtimes[file_path] = mtime
    
            # Skip empty files
            if file_size == 0:
                return
    
            # Detect log format
            format_name, _ = self.log_parser.detect_format(file_path)
    
            # Determine how much to read
            if force_full:
                # Process entire file
                position = 0
            elif initial_scan:
                # For initial scan, start at end minus a small amount
                position = max(0, file_size - 50000)  # Last ~50KB
            elif file_path not in self.file_positions:
                # For new files, start at end minus a small amount
                position = max(0, file_size - 10000)  # Last ~10KB
            else:
                # Continue from last position
                position = self.file_positions[file_path]
    
                # If file got smaller (rotated), start from beginning
                if position > file_size:
                    position = 0
    
            # Open and read the file
            with open(file_path, 'r', errors='ignore') as f:
                # Seek to the determined position
                f.seek(position)
    
                # Read new content
                lines = f.readlines()
    
                # Update position for next time
                self.file_positions[file_path] = f.tell()
    
            # Skip if no new content
            if not lines:
                return
    
            # Calculate source key (for ML)
            source_key = os.path.basename(file_path)
    
            # Process each line
            for line in lines:
                line = line.strip()
                if not line:
                    continue
    
                # Update stats
                self.stats["logs_processed"] += 1
                self.stats["bytes_processed"] += len(line)
    
                # Parse log line
                parsed_log = self.log_parser.parse_line(line, format_name)
                if not parsed_log:
                    continue
    
                # Check for security events
                security_event = self.log_parser.extract_security_events(parsed_log)
    
                # ? FIXED: Pass raw line for accurate detection
                signature_alert = self.detection_engine.analyze_line(parsed_log.get("_raw", line))
    
                # Check for ML-based anomalies
                anomaly_result = None
                if self.anomaly_detector:
                    anomaly_result = self.anomaly_detector.process_log(source_key, parsed_log)
    
                # Process security events
                if security_event:
                    self._handle_security_event(security_event, parsed_log, file_path)
    
                # Process signature-based alerts
                if signature_alert:
                    self._handle_signature_alert(signature_alert, parsed_log, file_path)
    
                # Process ML-based anomalies
                if anomaly_result and anomaly_result.get("is_anomaly"):
                    self._handle_anomaly(anomaly_result, parsed_log, file_path)
    
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {str(e)}")
    
        # Update processing time stat
        processing_time = time.time() - start_time
        self.stats["processing_time"] += processing_time
    
    def _handle_security_event(self, event, parsed_log, file_path):
        """Handle a detected security event"""
        severity = event.get("severity", "medium")
        event_type = event.get("event_type", "security_event")
        
        # Create alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "security_event",
            "subtype": event_type,
            "severity": severity,
            "source_file": file_path,
            "source_log": parsed_log.get("_raw", ""),
            "details": event
        }
        
        # Generate alert message
        if event_type == "failed_login":
            message = f"Failed login detected for user '{event.get('user')}' from IP {event.get('ip')}"
        elif event_type == "privilege_escalation":
            message = f"Privilege escalation detected for user '{event.get('user')}'"
        elif event_type == "web_attack":
            message = f"Web attack detected: {event.get('attack_type')} from IP {event.get('ip')}"
        elif event_type == "firewall_block":
            message = f"Firewall blocked connection from {event.get('src_ip')}:{event.get('src_port')} to {event.get('dst_ip')}:{event.get('dst_port')}"
        else:
            message = f"Security event detected: {event_type}"
        
        alert["message"] = message
        
        # Send alert
        self._send_alert(alert)

    def _save_checkpoints(self):
        """Save file position checkpoints"""
        checkpoint_file = os.path.join("logs", "checkpoints", "file_positions.json")
        
        try:
            with open(checkpoint_file, 'w') as f:
                json.dump(self.file_positions, f)
            self.logger.debug("Saved file position checkpoints")
        except Exception as e:
            self.logger.error(f"Failed to save checkpoints: {str(e)}")

    def _handle_signature_alert(self, alert_data, parsed_log, file_path):
        """Handle a signature-based alert"""
        # Determine severity based on score
        score = alert_data.get("score", 0)
        if score >= 15:
            severity = "high"
        elif score >= 8:
            severity = "medium"
        else:
            severity = "low"
        
        # Create alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "signature_match",
            "subtype": "_".join(alert_data.get("tags", ["suspicious_activity"])),
            "severity": severity,
            "source_file": file_path,
            "source_log": alert_data.get("line", ""),
            "message": f"Suspicious activity detected from IP={alert_data.get('ip')} USER={alert_data.get('user')}: score={score}",
            "details": {
                "score": score,
                "tags": alert_data.get("tags", []),
                "reason": alert_data.get("reason", []),
                "ip": alert_data.get("ip"),
                "user": alert_data.get("user")
            }
        }
        
        # Send alert
        self._send_alert(alert)
    
    def _handle_anomaly(self, anomaly_result, parsed_log, file_path):
        """Handle an ML-detected anomaly"""
        # Calculate confidence percentage
        confidence = int(anomaly_result.get("anomaly_score", 0) * 100)
        
        # Determine severity based on confidence
        if confidence >= 90:
            severity = "high"
        elif confidence >= 75:
            severity = "medium"
        else:
            severity = "low"
        
        # Create alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "ml_anomaly",
            "subtype": "log_anomaly",
            "severity": severity,
            "source_file": file_path,
            "source_log": parsed_log.get("_raw", ""),
            "message": f"Anomalous log entry detected (confidence: {confidence}%)",
            "details": {
                "anomaly_score": anomaly_result.get("anomaly_score"),
                "confidence": confidence,
                "parsed_log": parsed_log
            }
        }
        
        # Send alert
        self._send_alert(alert)
    
    def _handle_file_deleted(self, file_path):
        """Handle a log file being deleted"""
        # Create alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "file_alert",
            "subtype": "file_deleted",
            "severity": "high",
            "source_file": file_path,
            "message": f"Monitored log file was deleted: {file_path}",
            "details": {
                "file_path": file_path,
                "event": "deleted"
            }
        }
        
        # Send alert
        self._send_alert(alert)
        
        # Remove from tracking
        if file_path in self.monitored_files:
            self.monitored_files.remove(file_path)
        if file_path in self.file_positions:
            del self.file_positions[file_path]
        if file_path in self.file_mtimes:
            del self.file_mtimes[file_path]
    
    def _handle_file_moved(self, file_path):
        """Handle a log file being moved or renamed"""
        # Create alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "file_alert",
            "subtype": "file_moved",
            "severity": "medium",
            "source_file": file_path,
            "message": f"Monitored log file was moved or renamed: {file_path}",
            "details": {
                "file_path": file_path,
                "event": "moved"
            }
        }
        
        # Send alert
        self._send_alert(alert)
        
        # Remove from tracking
        if file_path in self.monitored_files:
            self.monitored_files.remove(file_path)
        if file_path in self.file_positions:
            del self.file_positions[file_path]
        if file_path in self.file_mtimes:
            del self.file_mtimes[file_path]
    
    def _send_alert(self, alert):
        """Process and send an alert"""
        # Update stats
        self.stats["alerts_generated"] += 1
        self.stats["alerts_by_severity"][alert.get("severity")] += 1
        
        source_file = alert.get("source_file", "unknown")
        source_name = os.path.basename(source_file)
        self.stats["alerts_by_source"][source_name] += 1
        
        # Add to recent alerts buffer
        self.recent_alerts.append(alert)
        
        # Send to alert manager
        self.alert_manager.process_alert(alert)
    
    def _save_stats(self):
        """Save monitor statistics"""
        self.stats["end_time"] = time.time()
        self.stats["duration"] = self.stats["end_time"] - self.stats["start_time"]
        
        # Convert defaultdicts to regular dicts for serialization
        stats_copy = self.stats.copy()
        stats_copy["alerts_by_severity"] = dict(stats_copy["alerts_by_severity"])
        stats_copy["alerts_by_source"] = dict(stats_copy["alerts_by_source"])
        
        # Save to file
        stats_dir = os.path.join("logs", "stats")
        os.makedirs(stats_dir, exist_ok=True)
        
        stats_file = os.path.join(stats_dir, f"lim_stats_{int(time.time())}.json")
        try:
            with open(stats_file, "w") as f:
                json.dump(stats_copy, f, indent=2)
                
            self.logger.info(f"Monitor statistics saved to {stats_file}")
        except Exception as e:
            self.logger.error(f"Error saving stats: {str(e)}")
    
    def get_status(self):
        """Get the current status of the monitor"""
        uptime = time.time() - self.stats["start_time"]
        
        return {
            "status": "running" if self.running else "stopped",
            "uptime": uptime,
            "uptime_formatted": str(timedelta(seconds=int(uptime))),
            "monitored_files": len(self.monitored_files),
            "logs_processed": self.stats["logs_processed"],
            "alerts_generated": self.stats["alerts_generated"],
            "bytes_processed": self.stats["bytes_processed"],
            "bytes_processed_formatted": self._format_bytes(self.stats["bytes_processed"]),
            "alerts_by_severity": dict(self.stats["alerts_by_severity"]),
            "top_alert_sources": dict(sorted(
                self.stats["alerts_by_source"].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5])
        }
    
    def _format_bytes(self, size):
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024 or unit == 'TB':
                return f"{size:.2f} {unit}"
            size /= 1024
