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

import re
import time
import hashlib
import logging
from collections import defaultdict, deque

# Original thresholds
# FAILED_LOGIN_THRESHOLD = 5
# SCORE_THRESHOLD = 10
# EVENT_WINDOW = 60  # seconds
# SESSION_WINDOW = 120  # seconds for tracking sequences

# New thresholds - more sensitive for testing
FAILED_LOGIN_THRESHOLD = 2  # Lowered from 5
SCORE_THRESHOLD = 5  # Lowered from 10
EVENT_WINDOW = 300  # Increased from 60 to 300 seconds
SESSION_WINDOW = 600  # Increased from 120 to 600 seconds

class LogDetectionEngine:
    """
    Enhanced rule-based detection engine for log analysis
    Based on the original implementation with additional capabilities
    """
    
    def __init__(self, excluded_ips=None, excluded_users=None):
        """
        Initialize the detection engine
        
        Args:
            excluded_ips: List of IPs to exclude from analysis
            excluded_users: List of users to exclude from analysis
        """
        self.failed_logins = defaultdict(lambda: deque())
        self.user_scores = defaultdict(int)
        self.last_activity = defaultdict(lambda: 0)
        self.session_log = defaultdict(lambda: deque())
        self.excluded_ips = set(excluded_ips) if excluded_ips is not None else set()
        self.excluded_users = set(excluded_users) if excluded_users is not None else set()
        
        # Add sequence detection
        self.sequence_patterns = self._initialize_sequence_patterns()
        
        # Alert deduplication
        self.recent_alerts = {}
        
        # Logger
        self.logger = logging.getLogger("lim.detection")
    
    def _initialize_sequence_patterns(self):
        """Initialize sequence patterns for advanced detection"""
        # Each pattern is a list of events that, when they occur in sequence,
        # indicate potentially malicious activity
        return [
            # Login followed quickly by privilege escalation and file access
            {
                "name": "privilege_escalation_sequence",
                "events": ["login_success", "escalation", "file_access"],
                "score": 10,
                "window": 120  # seconds
            },
            # Multiple failed logins followed by a successful login
            {
                "name": "brute_force_success",
                "events": ["failed_login", "failed_login", "failed_login", "login_success"],
                "score": 15,
                "window": 300  # seconds
            },
            # Network scan followed by exploit attempt
            {
                "name": "scan_exploit_sequence",
                "events": ["port_scan", "exploit_attempt"],
                "score": 12,
                "window": 180  # seconds
            },
            # File creation and then execution
            {
                "name": "file_execution_sequence",
                "events": ["file_creation", "file_execution"],
                "score": 8,
                "window": 60  # seconds
            }
        ]
    
    def _extract_context(self, line):
        """
        Extract IP and username from log line
        
        Args:
            line: Log line string
            
        Returns:
            tuple: (ip, user)
        """
        # Extract IP address
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        ip = ip_match.group(1) if ip_match else None
        
        # Enhanced username extraction patterns
        user_patterns = [
            r'user\s+(\w+)',
            r'User\s+(\w+)',
            r'username=(\w+)',
            r'invalid user\s+(\w+)',
            r'Accepted password for\s+(\w+)',
            r'authentication failure for\s+(\w+)',
            r'Failed password for\s+(\w+)',
            r'sudo:\s+(\w+)',
            r'su:\s+(\w+)',
            r'login:\s+USER=(\w+)',
            r'USER=(\w+)',
            r'user="?(\w+)"?'
        ]
        
        user = None
        for pattern in user_patterns:
            match = re.search(pattern, line)
            if match:
                user = match.group(1)
                break
        
        # Try additional method if still not found
        if user is None:
            # Look for common username prefixes and suffixes
            prefix_suffix_patterns = [
                r'(\w+)@',  # username@domain
                r'-(\w+)/'  # -username/
            ]
            
            for pattern in prefix_suffix_patterns:
                match = re.search(pattern, line)
                if match:
                    user = match.group(1)
                    break
        
        return ip, user
    
    def _log_session_event(self, ip, user, tag):
        """
        Log an event in the session tracking
        
        Args:
            ip: Source IP address
            user: Username
            tag: Event tag
        """
        key = (ip, user)
        now = time.time()
        self.session_log[key].append((tag, now))
        
        # Cleanup old session entries
        while self.session_log[key] and now - self.session_log[key][0][1] > SESSION_WINDOW:
            self.session_log[key].popleft()
        
        # Check for suspicious sequences
        self._check_sequences(key)
    
    def _check_sequences(self, key):
        """
        Check for suspicious event sequences
        
        Args:
            key: (ip, user) tuple
        """
        ip, user = key
        
        # Skip if no session data
        if key not in self.session_log or len(self.session_log[key]) < 2:
            return
        
        # Extract events and timestamps
        events = [(tag, ts) for tag, ts in self.session_log[key]]
        
        # Check each pattern
        for pattern in self.sequence_patterns:
            pattern_events = pattern["events"]
            window = pattern["window"]
            
            # Need at least as many events as in the pattern
            if len(events) < len(pattern_events):
                continue
            
            # Try to find the pattern in the events
            for i in range(len(events) - len(pattern_events) + 1):
                # Extract the slice of events to match
                event_slice = events[i:i+len(pattern_events)]
                
                # Check if events match pattern
                matches = True
                for j, (tag, _) in enumerate(event_slice):
                    if tag != pattern_events[j]:
                        matches = False
                        break
                
                # Check time window
                if matches:
                    start_time = event_slice[0][1]
                    end_time = event_slice[-1][1]
                    
                    if end_time - start_time <= window:
                        # Pattern matched within time window
                        self.user_scores[key] += pattern["score"]
                        self.logger.debug(
                            f"Sequence pattern '{pattern['name']}' matched for "
                            f"IP={ip} USER={user}, added {pattern['score']} points"
                        )
    
    def _score_event(self, ip, user, line):
        """
        Enhanced scoring function for the LogDetectionEngine
        Replace or patch the existing _score_event method
        """
        # Skip excluded IPs and users
        if ip in self.excluded_ips or user in self.excluded_users:
            return None
        
        # Debug logging to see what's happening
        self.logger.debug(f"Processing event: IP={ip} USER={user}")
        
        # Allow benign events without scoring
        benign = [
            "sudo: pam_unix(sudo:session): session closed",
            "Connection closed",
            "Disconnected from",
            "pam_unix(cron:session): session closed"
        ]
        if any(b in line for b in benign):
            return None
            
        key = (ip, user)
        line_id = hashlib.sha256(f"{ip}-{user}-{line.strip()}".encode()).hexdigest()
        now = time.time()
        
        # Deduplicate identical alerts within 60 seconds
        if not hasattr(self, "recent_alerts"):
            self.recent_alerts = {}
            
        if line_id in self.recent_alerts and now - self.recent_alerts[line_id] < 60:
            return None
        
        # Initialize scoring
        score = 0
        tags = []
        reasons = []
        
        # --- Authentication Events ---
        if "Failed password" in line or "authentication failure" in line or "Invalid user" in line:
            score += 3  # Increased from 2
            tags.append("failed_login")
            reasons.append("Failed login attempt")
            self.failed_logins[ip].append(now)
            self._log_session_event(ip, user, "failed_login")
            self.logger.debug(f"Failed login detected: IP={ip} USER={user}, Score +3")
        
        if "Accepted password for" in line or "session opened for user" in line:
            score += 2
            tags.append("successful_login")
            reasons.append("Successful login")
            self._log_session_event(ip, user, "login_success")
        
        # --- Privilege Escalation ---
        if "sudo:" in line or "su:" in line:
            score += 4  # Increased from 3
            tags.append("priv_escalation")
            reasons.append("Privilege escalation attempt")
            self._log_session_event(ip, user, "escalation")
        
        # --- File Access and Manipulation ---
        if any(s in line for s in ["open(", "access(", "unlink(", "rmdir("]):
            if any(s in line for s in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "authorized_keys"]):
                score += 6  # Increased from 5
                tags.append("sensitive_file_access")
                reasons.append("Access to sensitive system file")
                self._log_session_event(ip, user, "file_access")
        
        # --- Command Execution ---
        command_patterns = [r'COMMAND=([^,\s]+)', r'CMD="([^"]+)"', r'exec=([^,\s]+)']
        for pattern in command_patterns:
            cmd_match = re.search(pattern, line)
            if cmd_match:
                command = cmd_match.group(1)
                # Check for suspicious commands
                suspicious_cmds = ["wget", "curl", "nc", "netcat", "chmod 777", "chmod +x", 
                                  "base64", "python -c", "perl -e", "eval", "bash -i"]
                                  
                if any(s in command for s in suspicious_cmds):
                    score += 5  # Increased from 4
                    tags.append("suspicious_command")
                    reasons.append(f"Suspicious command execution: {command}")
                    self._log_session_event(ip, user, "command_execution")
        
        # --- Brute Force Detection ---
        if "failed_login" in tags:
            attempts = self.failed_logins[ip]
            # Clean up old attempts
            while attempts and now - attempts[0] > EVENT_WINDOW:
                attempts.popleft()
                
            if len(attempts) >= FAILED_LOGIN_THRESHOLD:
                score += 6  # Increased from 5
                tags.append("brute_force")
                reasons.append(f"{len(attempts)} failed logins within {EVENT_WINDOW} seconds")
                self.logger.debug(f"Brute force detected: IP={ip} USER={user}, {len(attempts)} attempts, Score +6")
        
        # --- Suspicious Session Patterns ---
        session_events = [tag for tag, ts in self.session_log.get(key, [])]
        
        # Login followed quickly by privilege escalation
        if "login_success" in session_events and "escalation" in session_events:
            login_time = None
            escalation_time = None
            
            # Find timestamps
            for tag, ts in self.session_log[key]:
                if tag == "login_success" and login_time is None:
                    login_time = ts
                elif tag == "escalation" and escalation_time is None:
                    escalation_time = ts
            
            # Check if privilege escalation happened quickly after login
            if login_time and escalation_time and escalation_time - login_time < 10:
                score += 4  # Increased from 3
                tags.append("rapid_privesc")
                reasons.append("Login immediately followed by privilege escalation")
        
        # --- High Frequency Actions ---
        if now - self.last_activity[key] < 5:
            score += 2  # Increased from 1
            tags.append("high_frequency")
            reasons.append("High-frequency actions")
        
        # --- Unknown Source ---
        if not ip and not user:
            tags.append("unknown_source")
            reasons.append("Activity with no identifiable user or IP")
        
        # Update last activity time
        self.last_activity[key] = now
        
        # Apply score if meaningful
        if score >= 2:  # Lowered from 3
            self.user_scores[key] += score
            self.logger.debug(f"Added score {score} for IP={ip} USER={user}, total={self.user_scores[key]}")
        
        # Check if threshold exceeded
        if self.user_scores[key] >= SCORE_THRESHOLD:
            final_score = self.user_scores[key]
            self.user_scores[key] = 0  # Reset score
            self.recent_alerts[line_id] = now  # Remember for deduplication
            
            self.logger.info(f"Alert triggered: IP={ip} USER={user}, Score={final_score}")
            
            return {
                "ip": ip,
                "user": user,
                "score": final_score,
                "tags": tags,
                "reason": reasons,
                "line": line.strip()
            }
        
        return None
    
    def analyze_line(self, line):
        """
        Analyze a log line for security events
        
        Args:
            line: Log line string
            
        Returns:
            dict: Alert data if suspicious, None otherwise
        """
        ip, user = self._extract_context(line)
        
        # Skip lines with no identifiable context
        if not ip and not user:
            return None
            
        return self._score_event(ip, user, line)
    
    def configure(self, config):
        """
        Update engine configuration
        
        Args:
            config: Configuration dictionary
        """
        # Update exclusion lists
        if "excluded_ips" in config:
            self.excluded_ips = set(config["excluded_ips"])
            
        if "excluded_users" in config:
            self.excluded_users = set(config["excluded_users"])
        
        # Update thresholds
        global FAILED_LOGIN_THRESHOLD, SCORE_THRESHOLD, EVENT_WINDOW, SESSION_WINDOW
        
        FAILED_LOGIN_THRESHOLD = config.get("failed_login_threshold", FAILED_LOGIN_THRESHOLD)
        SCORE_THRESHOLD = config.get("score_threshold", SCORE_THRESHOLD)
        EVENT_WINDOW = config.get("event_window", EVENT_WINDOW)
        SESSION_WINDOW = config.get("session_window", SESSION_WINDOW)
    
    def reset_state(self):
        """Reset all state for the detection engine"""
        self.failed_logins.clear()
        self.user_scores.clear()
        self.last_activity.clear()
        self.session_log.clear()
        self.recent_alerts.clear()
