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
# Performance optimization module for FIM
import os
import psutil
import time
from threading import Thread
from collections import defaultdict

class AdaptiveScanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.system_load_threshold = self.config.get('system_load_threshold', 75)  # Default 75% CPU load
        self.io_threshold = self.config.get('io_threshold', 80)  # Default 80% I/O utilization
        self.scan_history = defaultdict(lambda: {'last_scan': 0, 'change_frequency': 0})
        self.critical_paths = self.config.get('critical_paths', ['/etc', '/bin', '/sbin', '/usr/bin'])
        self.is_paused = False
        self.backoff_multiplier = 1.0

    def get_system_load(self):
        """Get current system load metrics"""
        cpu_percent = psutil.cpu_percent(interval=0.5)
        io_counters = psutil.disk_io_counters()
        memory_percent = psutil.virtual_memory().percent
        
        return {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'io': io_counters
        }
    
    def should_throttle(self):
        """Determine if scanning should be throttled based on system load"""
        system_load = self.get_system_load()
        
        # Check if system is under heavy load
        if system_load['cpu'] > self.system_load_threshold:
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 10.0)
            return True
        else:
            self.backoff_multiplier = max(self.backoff_multiplier * 0.8, 1.0)
            return False
    
    def prioritize_scan_targets(self, directories):
        """Prioritize directories to scan based on criticality and change history"""
        prioritized = []
        
        # First tier: Critical system paths
        critical = [d for d in directories if any(d.startswith(cp) for cp in self.critical_paths)]
        
        # Second tier: Frequently changing directories
        current_time = time.time()
        change_frequency = {d: self.scan_history[d]['change_frequency'] for d in directories}
        sorted_by_frequency = sorted(
            [d for d in directories if d not in critical],
            key=lambda d: change_frequency.get(d, 0),
            reverse=True
        )
        
        # Third tier: Directories not scanned recently
        time_since_scan = {d: current_time - self.scan_history[d]['last_scan'] for d in directories}
        sorted_by_time = sorted(
            [d for d in directories if d not in critical and d not in sorted_by_frequency[:10]],
            key=lambda d: time_since_scan.get(d, float('inf')),
            reverse=True
        )
        
        # Combine tiers with appropriate scanning intensity
        return {
            'high_intensity': critical,
            'medium_intensity': sorted_by_frequency[:10],  # Top 10 frequently changing dirs
            'low_intensity': sorted_by_time  # Remaining dirs sorted by scan age
        }
    
    def differential_scan(self, directory, file_index):
        """Focus scanning on recently modified files"""
        # Get all files in directory with modification times
        current_files = {}
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                try:
                    mtime = os.path.getmtime(full_path)
                    current_files[full_path] = mtime
                except (OSError, IOError):
                    continue
        
        # Identify new and modified files since last scan
        if directory not in file_index:
            # First scan of this directory - all files are "new"
            file_index[directory] = current_files
            return list(current_files.keys()), []
        
        previous_files = file_index[directory]
        
        # Find new and modified files
        new_files = []
        modified_files = []
        
        for path, mtime in current_files.items():
            if path not in previous_files:
                new_files.append(path)
            elif mtime > previous_files[path]:
                modified_files.append(path)
        
        # Update the file index
        file_index[directory] = current_files
        
        return new_files, modified_files
    
    def update_scan_history(self, directory, changes_detected):
        """Update scan history and change frequency metrics"""
        current_time = time.time()
        
        # Get previous values
        previous = self.scan_history[directory]
        last_scan_time = previous['last_scan']
        change_frequency = previous['change_frequency']
        
        # Calculate time since last scan
        time_delta = current_time - last_scan_time if last_scan_time > 0 else 86400  # Default to 1 day
        
        # Exponential moving average for change frequency
        if changes_detected:
            # If changes were detected, increase the frequency score
            new_frequency = change_frequency * 0.7 + 0.3 * (1 / max(time_delta, 1))
        else:
            # If no changes, decay the frequency score
            new_frequency = change_frequency * 0.9
        
        # Update history
        self.scan_history[directory] = {
            'last_scan': current_time,
            'change_frequency': new_frequency
        }
    
    def adaptive_scan_scheduler(self, scheduled_directories, scan_callback):
        """Run scanning with adaptive scheduling based on system load and directory priority"""
        file_index = {}  # Track files and their modification times
        
        while True:
            # Check if scanning should be throttled
            if self.should_throttle():
                print(f"[INFO] System under load, throttling scans (backoff: {self.backoff_multiplier:.2f}x)")
                time.sleep(5 * self.backoff_multiplier)  # Adaptive backoff
                continue
            
            # Prioritize directories
            prioritized = self.prioritize_scan_targets(scheduled_directories)
            
            # Process high-priority directories first, with full scanning
            for directory in prioritized['high_intensity']:
                if self.should_throttle():
                    break  # Recheck system load between directories
                
                print(f"[INFO] High-intensity scanning of critical directory: {directory}")
                # For critical directories, do a full scan
                all_files = []
                for root, _, files in os.walk(directory):
                    for file in files:
                        all_files.append(os.path.join(root, file))
                
                changes = scan_callback(all_files, "critical")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Medium priority directories - scan frequently changed files
            for directory in prioritized['medium_intensity']:
                if self.should_throttle():
                    break
                
                print(f"[INFO] Medium-intensity scanning of frequently changing directory: {directory}")
                # Use differential scanning for these directories
                new_files, modified_files = self.differential_scan(directory, file_index)
                changes = scan_callback(new_files + modified_files, "standard")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Low priority directories - scan minimally
            for directory in prioritized['low_intensity']:
                if self.should_throttle():
                    break
                
                print(f"[INFO] Low-intensity scanning of infrequently changing directory: {directory}")
                # For low priority, only scan new files
                new_files, _ = self.differential_scan(directory, file_index)
                changes = scan_callback(new_files, "minimal")
                self.update_scan_history(directory, len(changes) > 0)
            
            # Sleep between full scan cycles, with adaptive timing
            sleep_time = 60 * self.backoff_multiplier  # Base: 1 minute, scales with load
            print(f"[INFO] Completed scan cycle, sleeping for {sleep_time:.1f} seconds")
            time.sleep(sleep_time)
