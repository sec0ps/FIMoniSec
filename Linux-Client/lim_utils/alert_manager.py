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
import json
import time
import logging
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

def fix_alert_manager_paths():
    """
    Fix AlertManager path issues by using absolute paths
    """
    # Get current script directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define base directory (adjust as needed for your structure)
    base_dir = os.path.abspath(os.path.join(current_dir, ".."))
    
    # Log paths
    logging.info(f"Base directory: {base_dir}")
    logging.info(f"Script directory: {current_dir}")
    
    # Create absolute path directories
    alert_dir = os.path.join(base_dir, "logs", "alerts")
    alert_archive = os.path.join(base_dir, "logs", "archive")
    checkpoint_dir = os.path.join(base_dir, "logs", "checkpoints")
    
    # Ensure directories exist with proper permissions
    for directory in [alert_dir, alert_archive, checkpoint_dir]:
        try:
            os.makedirs(directory, exist_ok=True)
            logging.info(f"Created or verified directory: {directory}")
            
            # Test write permissions
            test_file = os.path.join(directory, "test_write.tmp")
            with open(test_file, "w") as f:
                f.write("Test write permission")
            os.remove(test_file)
            logging.info(f"Write permissions verified for: {directory}")
        except Exception as e:
            logging.error(f"Error with directory {directory}: {str(e)}")

    # Return the paths for use in AlertManager
    return base_dir, alert_dir, alert_archive

class AlertManager:
    """Manages alert processing, formatting, and output"""
    
    def __init__(self, config=None):
        """
        Initialize the alert manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        self.logger = logging.getLogger("lim.alerts")
        
        # Fix path issues
        base_dir, self.alert_dir, self.alert_archive = fix_alert_manager_paths()
        
        # Current day's alert file
        self.current_date = datetime.now().strftime("%Y-%m-%d")
        self.alert_file = os.path.join(self.alert_dir, f"alerts_{self.current_date}.log")
        
        # Alert suppression
        self.recent_alerts = {}
        self.suppression_window = self.config.get("alert_suppression_window", 60)  # 1 minute
        
        # Alert counter
        self.alert_count = defaultdict(int)
        
        # Alert retention
        self._cleanup_old_alerts()
    
    def process_alert(self, alert):
        """
        Process and store an alert
    
        Args:
            alert: Alert dictionary
    
        Returns:
            bool: True if alert was processed (not suppressed)
        """
        # Check if we need to rotate alert file
        current_date = datetime.now().strftime("%Y-%m-%d")
        if current_date != self.current_date:
            self.current_date = current_date
            self.alert_file = os.path.join(self.alert_dir, f"alerts_{self.current_date}.log")
    
        # Create alert ID and check for duplicates
        alert_id = self._create_alert_id(alert)
    
        # Check for suppression
        if self._should_suppress(alert_id, alert):
            self.logger.debug(f"[SUPPRESSED] Alert ID={alert_id} user={alert.get('user')} ip={alert.get('ip')} subtype={alert.get('subtype')}")
            return False
    
        # Add timestamp if not present
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.now().isoformat()
    
        # Add alert_id
        alert["alert_id"] = alert_id
    
        # STDOUT visibility
        print(f"\n[ALERT] {json.dumps(alert, indent=2)}\n")
    
        # Write to alert file
        try:
            with open(self.alert_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            self.logger.error(f"Error writing alert to file: {str(e)}")
    
        # Update alert count
        severity = alert.get("severity", "medium")
        self.alert_count[severity] += 1
    
        # Log to main logger by severity
        if severity == "high":
            self.logger.warning(f"HIGH SEVERITY ALERT: {alert.get('message')} [user={alert.get('user')} ip={alert.get('ip')}]")
        elif severity == "medium":
            self.logger.info(f"MEDIUM SEVERITY ALERT: {alert.get('message')} [user={alert.get('user')} ip={alert.get('ip')}]")
        else:
            self.logger.debug(f"LOW SEVERITY ALERT: {alert.get('message')} [user={alert.get('user')} ip={alert.get('ip')}]")
    
        return True
    
    def _create_alert_id(self, alert):
        """Create a unique ID for the alert based on its content"""
        # Extract key fields for ID generation
        type_str = alert.get("type", "unknown")
        subtype_str = alert.get("subtype", "unknown")
        source_file = alert.get("source_file", "unknown")
        source_log = alert.get("source_log", "")
        
        # Create a unique string
        unique_str = f"{type_str}:{subtype_str}:{source_file}:{source_log}"
        
        # Hash it
        return hashlib.md5(unique_str.encode()).hexdigest()
    
    def _should_suppress(self, alert_id, alert):
        """Check if an alert should be suppressed as a duplicate"""
        now = time.time()
    
        # Disable suppression entirely if configured (for testing)
        if self.suppression_window <= 0:
            self.logger.debug(f"[SUPPRESSION OFF] Alert not suppressed: {alert_id}")
            return False
    
        # Check if we've seen this alert recently
        if alert_id in self.recent_alerts:
            last_time, count = self.recent_alerts[alert_id]
    
            if now - last_time < self.suppression_window:
                self.logger.debug(
                    f"[SUPPRESSED] Duplicate alert: {alert_id} | "
                    f"user={alert.get('user')} ip={alert.get('ip')} subtype={alert.get('subtype')} "
                    f"count={count + 1}"
                )
                self.recent_alerts[alert_id] = (last_time, count + 1)
                return True
    
        # Not suppressed — record it
        self.recent_alerts[alert_id] = (now, 1)
        self.logger.debug(
            f"[ALERT PASSED] New or expired alert: {alert_id} "
            f"user={alert.get('user')} ip={alert.get('ip')} subtype={alert.get('subtype')}"
        )
    
        # Clean up old entries
        self._cleanup_recent_alerts(now)
    
        return False
    
    def _cleanup_recent_alerts(self, now):
        """Remove old entries from recent alerts tracking"""
        to_remove = []
        for alert_id, (timestamp, count) in self.recent_alerts.items():
            if now - timestamp > self.suppression_window * 2:
                to_remove.append(alert_id)
        
        for alert_id in to_remove:
            del self.recent_alerts[alert_id]
    
    def _cleanup_old_alerts(self):
        """Archive or delete old alert files based on retention policy"""
        retention_days = self.config.get("alert_retention_days", 30)
        archive_cutoff = datetime.now() - timedelta(days=retention_days)
        delete_cutoff = datetime.now() - timedelta(days=retention_days * 3)
        
        # Scan alert directory
        for filename in os.listdir(self.alert_dir):
            if not filename.startswith("alerts_") or not filename.endswith(".log"):
                continue
                
            try:
                # Extract date from filename
                date_str = filename.replace("alerts_", "").replace(".log", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                file_path = os.path.join(self.alert_dir, filename)
                
                # Archive old files
                if file_date < archive_cutoff:
                    archive_path = os.path.join(self.alert_archive, filename)
                    os.rename(file_path, archive_path)
                    self.logger.debug(f"Archived old alert file: {filename}")
            except Exception as e:
                self.logger.error(f"Error processing old alert file {filename}: {str(e)}")
        
        # Delete very old archived files
        for filename in os.listdir(self.alert_archive):
            if not filename.startswith("alerts_") or not filename.endswith(".log"):
                continue
                
            try:
                # Extract date from filename
                date_str = filename.replace("alerts_", "").replace(".log", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                file_path = os.path.join(self.alert_archive, filename)
                
                # Delete very old files
                if file_date < delete_cutoff:
                    os.remove(file_path)
                    self.logger.debug(f"Deleted expired alert file: {filename}")
            except Exception as e:
                self.logger.error(f"Error processing archive file {filename}: {str(e)}")
    
    def get_recent_alerts(self, count=50, severity=None, alert_type=None):
        """
        Get recent alerts with optional filtering
        
        Args:
            count: Maximum number of alerts to return
            severity: Filter by severity (high, medium, low)
            alert_type: Filter by alert type
            
        Returns:
            list: List of recent alerts
        """
        alerts = []
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        # Helper to check if an alert matches filters
        def matches_filters(alert):
            if severity and alert.get("severity") != severity:
                return False
            if alert_type and alert.get("type") != alert_type:
                return False
            return True
        
        # Check today's alerts first
        try:
            alert_file = os.path.join(self.alert_dir, f"alerts_{current_date}.log")
            if os.path.exists(alert_file):
                with open(alert_file, "r") as f:
                    for line in reversed(list(f)):
                        if line.strip():
                            try:
                                alert = json.loads(line)
                                if matches_filters(alert):
                                    alerts.append(alert)
                                    if len(alerts) >= count:
                                        return alerts
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            self.logger.error(f"Error reading current alert file: {str(e)}")
        
        # If we need more, look at recent days
        if len(alerts) < count:
            # Get list of alert files sorted by date (newest first)
            alert_files = []
            for filename in os.listdir(self.alert_dir):
                if filename.startswith("alerts_") and filename.endswith(".log"):
                    if filename != f"alerts_{current_date}.log":  # Skip today's file (already processed)
                        alert_files.append(filename)
            
            alert_files.sort(reverse=True)
            
            # Process each file until we have enough alerts
            for filename in alert_files:
                try:
                    with open(os.path.join(self.alert_dir, filename), "r") as f:
                        for line in reversed(list(f)):
                            if line.strip():
                                try:
                                    alert = json.loads(line)
                                    if matches_filters(alert):
                                        alerts.append(alert)
                                        if len(alerts) >= count:
                                            return alerts
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    self.logger.error(f"Error reading alert file {filename}: {str(e)}")
        
        return alerts
    
    def get_alert_stats(self):
        """
        Get alert statistics
        
        Returns:
            dict: Alert statistics
        """
        stats = {
            "total": sum(self.alert_count.values()),
            "by_severity": dict(self.alert_count),
            "suppressed": sum(count for _, count in self.recent_alerts.values()) - len(self.recent_alerts)
        }
        
        # Count alerts by day for the last week
        daily_counts = defaultdict(int)
        cutoff_date = datetime.now() - timedelta(days=7)
        
        # Process alert files for the past week
        for filename in os.listdir(self.alert_dir):
            if not filename.startswith("alerts_") or not filename.endswith(".log"):
                continue
                
            try:
                # Extract date from filename
                date_str = filename.replace("alerts_", "").replace(".log", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                # Skip if older than cutoff
                if file_date < cutoff_date:
                    continue
                    
                # Count alerts in file
                count = 0
                with open(os.path.join(self.alert_dir, filename), "r") as f:
                    for line in f:
                        if line.strip():
                            count += 1
                
                daily_counts[date_str] = count
            except Exception as e:
                self.logger.error(f"Error processing alert file {filename}: {str(e)}")
        
        stats["daily_counts"] = dict(daily_counts)
        
        return stats
