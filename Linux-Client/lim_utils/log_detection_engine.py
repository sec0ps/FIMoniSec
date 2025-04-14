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

# =============================================================================
# Log Detection Engine with MITRE ATT&CK Mapping
# =============================================================================

import re
import time
import hashlib
import logging
import statistics
import ipaddress
from datetime import datetime
from collections import defaultdict, deque, Counter

# Enhanced thresholds (tunable)
FAILED_LOGIN_THRESHOLD = 3  # Number of failed logins to trigger alert
SCORE_THRESHOLD = 7         # Score threshold for alerts
EVENT_WINDOW = 300          # seconds for tracking events
SESSION_WINDOW = 600        # seconds for tracking sequences

class MitreAttackMapper:
    """Maps detected events to MITRE ATT&CK techniques"""
    
    def __init__(self):
        """Initialize the MITRE ATT&CK mapper"""
        # Initialize MITRE ATT&CK techniques mapping
        self.technique_mappings = {
            # Credential Access
            "failed_login": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may attempt to gain access to accounts by guessing passwords"
            },
            "brute_force": {
                "technique_id": "T1110.001",
                "technique_name": "Brute Force: Password Guessing",
                "tactic": "Credential Access",
                "description": "Adversaries may use a single or small list of commonly used passwords against many accounts"
            },
            
            # Privilege Escalation
            "privilege_escalation": {
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may exploit software vulnerabilities to gain higher privileges"
            },
            "rapid_privesc": {
                "technique_id": "T1548",
                "technique_name": "Abuse Elevation Control Mechanism",
                "tactic": "Privilege Escalation",
                "description": "Adversaries may abuse mechanisms designed to allow elevated execution"
            },
            
            # Execution
            "suspicious_command": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters to execute commands"
            },
            "command_execution": {
                "technique_id": "T1059.004",
                "technique_name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution",
                "description": "Adversaries may abuse Unix shell commands for execution"
            },
            
            # Defense Evasion
            "file_execution": {
                "technique_id": "T1036",
                "technique_name": "Masquerading",
                "tactic": "Defense Evasion",
                "description": "Adversaries may attempt to manipulate files to disguise executables"
            },
            
            # Initial Access
            "web_attack": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may attempt to exploit vulnerabilities in public-facing applications"
            },
            
            # Collection
            "sensitive_file_access": {
                "technique_id": "T1005",
                "technique_name": "Data from Local System",
                "tactic": "Collection",
                "description": "Adversaries may search for sensitive data stored on local systems"
            },
            
            # Discovery
            "port_scan": {
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to identify network services to target for exploitation"
            },
            
            # Defense Evasion
            "log_tampering": {
                "technique_id": "T1070",
                "technique_name": "Indicator Removal on Host",
                "tactic": "Defense Evasion",
                "description": "Adversaries may attempt to remove indicators of their presence on a system"
            },
            
            # Command and Control
            "dns_tunneling": {
                "technique_id": "T1071.004",
                "technique_name": "Application Layer Protocol: DNS",
                "tactic": "Command and Control",
                "description": "Adversaries may use DNS to communicate with systems under their control"
            },
            
            # Lateral Movement
            "lateral_movement": {
                "technique_id": "T1021",
                "technique_name": "Remote Services",
                "tactic": "Lateral Movement",
                "description": "Adversaries may use remote services to access other systems on a network"
            },
            
            # Persistence
            "cron_job_modification": {
                "technique_id": "T1053.003",
                "technique_name": "Scheduled Task/Job: Cron",
                "tactic": "Persistence, Privilege Escalation",
                "description": "Adversaries may abuse the cron utility to create persistence"
            },
            
            # Impact
            "data_destruction": {
                "technique_id": "T1485",
                "technique_name": "Data Destruction",
                "tactic": "Impact",
                "description": "Adversaries may destroy data and files on specific systems to interrupt availability"
            }
        }
    
    def get_technique_info(self, event_type):
        """
        Map an event type to a MITRE ATT&CK technique
        
        Args:
            event_type: The type of event detected
            
        Returns:
            dict: MITRE ATT&CK technique information or None if no mapping
        """
        # Check exact match
        if event_type in self.technique_mappings:
            return self.technique_mappings[event_type]
        
        # Check partial matches
        for key, value in self.technique_mappings.items():
            if key in event_type or event_type in key:
                return value
        
        # Default mapping for unknown events
        return {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "description": "Generic suspicious activity that may indicate account compromise"
        }

class DynamicPatternBuilder:
    """
    Builds detection patterns dynamically based on observed log patterns
    """
    
    def __init__(self, sample_size=1000, update_interval=3600):
        """
        Initialize the dynamic pattern builder
        
        Args:
            sample_size: Number of log entries to sample
            update_interval: How often to update patterns (seconds)
        """
        self.sample_size = sample_size
        self.update_interval = update_interval
        self.last_update = 0
        
        # Store samples
        self.log_samples = []
        
        # Generated patterns
        self.dynamic_patterns = {}
        
        # Initialize pattern statistics
        self.pattern_stats = defaultdict(int)
    
    def add_sample(self, log_entry):
        """
        Add a log sample for pattern building
        
        Args:
            log_entry: Parsed log entry
        """
        if len(self.log_samples) >= self.sample_size:
            # Remove oldest sample
            self.log_samples.pop(0)
        
        # Add new sample
        self.log_samples.append(log_entry)
        
        # Check if we should update patterns
        now = time.time()
        if now - self.last_update > self.update_interval and len(self.log_samples) >= self.sample_size:
            self._build_patterns()
            self.last_update = now
    
    def _build_patterns(self):
        """Build patterns from collected samples"""
        # Group logs by type
        grouped_logs = defaultdict(list)
        for log in self.log_samples:
            log_type = log.get("_format", "unknown")
            grouped_logs[log_type].append(log)
        
        # Build patterns for each log type
        for log_type, logs in grouped_logs.items():
            if log_type == "auth":
                self._build_auth_patterns(logs)
            elif log_type == "web_access":
                self._build_web_patterns(logs)
            # Add more specialized pattern builders as needed
    
    def _build_auth_patterns(self, logs):
        """Build auth log patterns"""
        # Extract users and IPs
        users = set()
        ips = set()
        
        for log in logs:
            user = log.get("user")
            ip = log.get("ip")
            
            if user:
                users.add(user)
            if ip:
                ips.add(ip)
        
        # Build IP frequency patterns
        ip_counts = Counter()
        for log in logs:
            ip = log.get("ip")
            if ip:
                ip_counts[ip] += 1
        
        # Identify potentially suspicious IPs (outliers in frequency)
        if ip_counts:
            mean_count = statistics.mean(ip_counts.values())
            std_dev = statistics.stdev(ip_counts.values()) if len(ip_counts) > 1 else 0
            
            suspicious_ips = []
            for ip, count in ip_counts.items():
                if count > mean_count + 2 * std_dev:
                    suspicious_ips.append(ip)
            
            if suspicious_ips:
                self.dynamic_patterns["suspicious_ips"] = suspicious_ips
    
    def _build_web_patterns(self, logs):
        """Build web log patterns"""
        # Extract paths and status codes
        path_counts = Counter()
        status_counts = defaultdict(lambda: defaultdict(int))
        
        for log in logs:
            path = log.get("path")
            status = log.get("status")
            ip = log.get("ip")
            
            if path and status:
                path_counts[path] += 1
                status_counts[path][status] += 1
        
        # Identify suspicious paths (high 4xx/5xx ratio)
        suspicious_paths = []
        for path, counts in status_counts.items():
            total = sum(counts.values())
            error_count = sum(counts[status] for status in counts if status >= 400)
            
            if total > 10 and error_count / total > 0.8:
                suspicious_paths.append(path)
        
        if suspicious_paths:
            self.dynamic_patterns["suspicious_paths"] = suspicious_paths
    
    def get_dynamic_patterns(self):
        """
        Get the dynamically generated patterns
        
        Returns:
            dict: Dynamic patterns
        """
        return self.dynamic_patterns

class LogDetectionEngine:
    """
    Rule-based detection engine for log analysis with MITRE ATT&CK mapping
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
        
        # Initialize MITRE ATT&CK mapper
        self.mitre_mapper = MitreAttackMapper()
        
        # Initialize dynamic pattern builder
        self.pattern_builder = DynamicPatternBuilder()
        
        # Add sequence detection
        self.sequence_patterns = self._initialize_sequence_patterns()
        
        # Initialize enhanced attack patterns
        self.attack_patterns = self._initialize_attack_patterns()
        
        # Alert deduplication
        self.recent_alerts = {}
        
        # Initialize user behavior profiles
        self.user_profiles = defaultdict(lambda: {
            "login_times": [],
            "login_ips": set(),
            "commands": set(),
            "last_seen": 0
        })
        
        # Initialize IP tracking for behavior analysis
        self.ip_tracking = defaultdict(lambda: {
            "first_seen": time.time(),
            "access_count": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "countries": set(),
            "users_accessed": set(),
            "paths_accessed": set(),
            "commands_executed": set()
        })
        
        # Logger
        self.logger = logging.getLogger("lim.detection")
        
        # Event counter
        self.event_counter = defaultdict(int)
    
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
                "window": 120,  # seconds
                "mitre_technique": "T1078"
            },
            # Multiple failed logins followed by a successful login
            {
                "name": "brute_force_success",
                "events": ["failed_login", "failed_login", "failed_login", "login_success"],
                "score": 15,
                "window": 300,  # seconds
                "mitre_technique": "T1110.001"
            },
            # Network scan followed by exploit attempt
            {
                "name": "scan_exploit_sequence",
                "events": ["port_scan", "exploit_attempt"],
                "score": 12,
                "window": 180,  # seconds
                "mitre_technique": "T1046"
            },
            # File creation and then execution
            {
                "name": "file_execution_sequence",
                "events": ["file_creation", "file_execution"],
                "score": 8,
                "window": 60,  # seconds
                "mitre_technique": "T1204"
            },
            # Account creation followed by privilege escalation
            {
                "name": "account_creation_privesc",
                "events": ["account_creation", "escalation"],
                "score": 18,
                "window": 300,  # seconds
                "mitre_technique": "T1136"
            },
            # SSH key creation followed by login
            {
                "name": "ssh_key_creation_login",
                "events": ["ssh_key_modification", "login_success"],
                "score": 10,
                "window": 600,  # seconds
                "mitre_technique": "T1098"
            },
            # Password change followed by lateral movement
            {
                "name": "password_change_lateral",
                "events": ["password_change", "lateral_movement"],
                "score": 12,
                "window": 300,  # seconds
                "mitre_technique": "T1021"
            },
            # Reconnaissance followed by data exfiltration
            {
                "name": "recon_exfiltration",
                "events": ["discovery", "data_collection", "data_exfiltration"],
                "score": 18,
                "window": 1800,  # seconds
                "mitre_technique": "T1048"
            }
        ]
    
    def _initialize_attack_patterns(self):
        """Initialize enhanced attack pattern detection"""
        return [
            # Format: (regex_pattern, tag, score, mitre_technique)
            
            # Credential access patterns
            (r'(?:passwd|password|pass).*(?:crack|brute|guess|dictionary)', "password_cracking", 8, "T1110"),
            (r'mimikatz|gsecdump|wce|lsadump|ntds\.dit|SAM', "credential_dumping", 10, "T1003"),
            (r'kerberos|krbtgt|TGT|TGS|golden\s+ticket|silver\s+ticket', "kerberos_attack", 10, "T1558"),
            
            # Privilege escalation patterns
            (r'sudo\s+\-u\s+root|sudo\s+\-s|sudo\s+bash|sudo\s+su', "sudo_abuse", 8, "T1548.003"),
            (r'chmod\s+(?:u\+s|4755|4777|a\+x|777)\s+(?:\/bin\/|\/etc\/|\/usr\/|\/tmp\/)', "setuid_modification", 10, "T1548.001"),
            (r'(?:kernel|linux).*exploit|CVE\-\d+\-\d+', "kernel_exploit", 12, "T1068"),
            
            # Defense evasion patterns
            (r'unset\s+HISTFILE|HISTSIZE\=0|HISTFILESIZE\=0|history\s+\-c', "history_clearing", 8, "T1070.003"),
            (r'(?:\/var\/log\/).*(?:rm|cat\s+\/dev\/null|\>|truncate)', "log_tampering", 10, "T1070.002"),
            (r'touch\s+\-[acdmr]|timestomp', "timestamp_modification", 8, "T1070.006"),
            (r'(?:base64|hex|rot13|xor)\s+(?:encode|decode)|\/\=[0-9a-f]{6,}', "encoding_obfuscation", 8, "T1027"),
            
            # Persistence patterns
            (r'crontab\s+\-e|\/etc\/cron|\/var\/spool\/cron', "cron_modification", 7, "T1053.003"),
            (r'(?:\/etc\/rc|init\.d|systemd|systemctl)', "service_persistence", 7, "T1543.002"),
            (r'(?:\/etc\/passwd|\+\+\+|authorized_keys|\.bashrc|\.profile|\.ssh\/)', "account_manipulation", 8, "T1098"),
            
            # Command and control patterns
            (r'(?:nc|netcat|ncat).{1,30}(?:\-e|\-c|bash|cmd|powershell|sh)', "reverse_shell", 12, "T1059.004"),
            (r'(?:\/dev\/tcp\/|socat|telnet|ssh)\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}', "network_connection", 8, "T1071"),
            (r'(?:dig|nslookup|host).{1,30}(?:ANY|TXT|MX|AAAA)\s+[a-zA-Z0-9\.\-]+', "dns_tunneling", 10, "T1071.004"),
            
            # Discovery patterns
            (r'(?:\/proc\/self\/|\/proc\/[0-9]+\/|\/proc\/net\/)', "process_discovery", 6, "T1057"),
            (r'(?:ifconfig|ip\s+a|\/sbin\/ip|\/bin\/ip|\/etc\/hosts)', "network_discovery", 5, "T1016"),
            (r'(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group|getent)', "account_discovery", 6, "T1087"),
            (r'(?:find|locate|grep|awk|sed).{1,30}(?:password|pass|pwd|key|secret|token)', "credential_discovery", 9, "T1552"),
            
            # Lateral movement patterns
            (r'(?:ssh|scp|sftp|rsync)\s+(?:\-i|\-l|\-P)', "remote_access", 7, "T1021.004"),
            (r'(?:smbclient|smb:|cifs:|mount\s+\-t\s+cifs|net\s+use)', "smb_access", 7, "T1021.002"),
            (r'(?:winexe|wmic|xfreerdp|rdesktop|mstsc)', "remote_service_access", 8, "T1021"),
            
            # Collection patterns
            (r'(?:tar|zip|rar|7z|gzip).{1,30}(?:\/etc\/|\/var\/|\/usr\/|\/home\/)', "archive_collection", 7, "T1560"),
            (r'(?:cp|scp|rsync|cat|tee).{1,30}(?:\/etc\/shadow|id_rsa|\.ssh\/|\.aws\/|authorized_keys)', "sensitive_file_collection", 9, "T1005"),
            (r'(?:mysqldump|pg_dump|sqlite3|mongodump)', "database_dump", 8, "T1005"),
            
            # Exfiltration patterns
            (r'(?:curl|wget|ftp|scp|sftp|ssh|nc).{1,30}(?:[0-9]{1,3}\.){3}[0-9]{1,3}.{0,20}(?:\/etc\/|\/var\/|passwd|shadow)', "data_exfiltration", 12, "T1048"),
            (r'(?:mail|sendmail|exim|postfix).{1,30}(?:\-a|\-s|\-f|\-t).{1,30}(?:\/etc\/|\/var\/|passwd|shadow)', "email_exfiltration", 11, "T1048.003"),
            
            # Impact patterns
            (r'(?:rm\s+\-rf|find.{1,30}\-delete|shred|wipe)', "data_destruction", 10, "T1485"),
            (r'(?:\/dev\/sd[a-z]|mkfs|dd\s+if|fdisk|sfdisk)', "disk_wipe", 12, "T1561"),
            (r'(?:kill\s+\-9|pkill|\/proc\/[0-9]+\/status)', "service_stop", 8, "T1489"),
            (r'(?:fork\s+bomb|\(\)\s*\{\s*\:\s*\|\s*\:\s*\&\s*\})', "resource_hijacking", 11, "T1496"),
            
            # Web specific patterns
            (r'(?:select|union|insert|update|delete|drop|alter).{1,30}(?:from|into|where|table|column|database)', "sql_injection", 9, "T1190"),
            (r'(?:\/\.\.\/|\.\.\\|\%2e\%2e\%2f|\%252e\%252e\%252f)', "path_traversal", 9, "T1083"),
            (r'(?:onload\=|onerror\=|onclick\=|script\>|javascript\:)', "cross_site_scripting", 8, "T1059.007"),
            (r'(?:whoami|id|uname|cat\s+\/etc|\\x[0-9a-f]{2})', "command_injection", 10, "T1059")
        ]
    
    def _extract_context(self, line):
        """
        Enhanced context extraction with additional pattern recognition
        
        Args:
            line: Log line string
            
        Returns:
            tuple: (ip, user, additional_context)
        """
        # Extract IP address with improved pattern recognition
        ip_patterns = [
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # Standard IPv4
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})',  # CIDR notation
            r'([0-9a-fA-F:]{2,})(%\w+)?',  # IPv6 (basic pattern)
            r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # Firewall notation
        ]
        
        ip = None
        for pattern in ip_patterns:
            ip_match = re.search(pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                break
        
        # Enhanced username extraction patterns with prioritization
        user_patterns = [
            # High confidence patterns (explicit username mention)
            (r'user[\s=]+\"?(\w+)\"?', 3),
            (r'User[\s=]+\"?(\w+)\"?', 3),
            (r'username=[\"\']?(\w+)[\"\']?', 3),
            (r'user\s+(\w+)', 3),
            
            # Medium confidence patterns (login context)
            (r'login[\s:]+user[\s=]+[\"\']?(\w+)[\"\']?', 2),
            (r'Accepted (?:password|publickey) for[\s]+(\w+)', 2),
            (r'Failed password for[\s]+(\w+)', 2),
            (r'invalid user[\s]+(\w+)', 2),
            (r'authentication failure[\s;]+(?:.*user=|.*USER=|ruser=|user=\"?)(\w+)', 2),
            
            # Lower confidence patterns (indirect references)
            (r'(?:sudo|su):[\s]+(\w+)', 1),
            (r'as (\w+) from', 1),
            (r'USER=(\w+)', 1),
            (r'(\w+):.*COMMAND=', 1),
            (r'owner=(\w+)', 1)
        ]
        
        # Find the highest confidence username match
        user = None
        highest_confidence = 0
        
        for pattern, confidence in user_patterns:
            match = re.search(pattern, line)
            if match and confidence >= highest_confidence:
                candidate = match.group(1)
                # Skip common false positives
                if candidate.lower() not in ['failed', 'invalid', 'user', 'root', 'system']:
                    user = candidate
                    highest_confidence = confidence
        
        # Extract additional context (commands, paths, services)
        additional_context = {}
        
        # Extract commands
        cmd_match = re.search(r'COMMAND=[\"\']?([^;\"\']+)[\"\']?', line)
        if cmd_match:
            additional_context['command'] = cmd_match.group(1)
            
        # Extract paths
        path_match = re.search(r'(?:\/[a-zA-Z0-9_\-\.]+)+\/?', line)
        if path_match:
            additional_context['path'] = path_match.group(0)
            
        # Extract service information
        service_match = re.search(r'(\w+)\[(\d+)\]:', line)
        if service_match:
            additional_context['service'] = service_match.group(1)
            additional_context['pid'] = service_match.group(2)
            
        # Extract potential attack indicators if present
        for pattern, tag, score, mitre_id in self.attack_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                additional_context['attack_indicator'] = {
                    'tag': tag,
                    'score': score,
                    'mitre_id': mitre_id
                }
                break
                
        return ip, user, additional_context
    
    def _log_session_event(self, ip, user, tag, additional_context=None):
        """
        Enhanced session event tracking with additional context
        
        Args:
            ip: Source IP address
            user: Username
            tag: Event tag
            additional_context: Additional context data
        """
        key = (ip, user)
        now = time.time()
        
        # Track event counter
        self.event_counter[tag] += 1
        
        # Add timestamp and context to event
        event_data = {
            'tag': tag,
            'timestamp': now,
            'context': additional_context or {}
        }
        
        self.session_log[key].append(event_data)
        
        # Cleanup old session entries
        while self.session_log[key] and now - self.session_log[key][0]['timestamp'] > SESSION_WINDOW:
            self.session_log[key].popleft()
        
        # Update user profile if applicable
        if user:
            profile = self.user_profiles[user]
            profile["last_seen"] = now
            if ip:
                profile["login_ips"].add(ip)
            if additional_context and "command" in additional_context:
                profile["commands"].add(additional_context["command"])
            if tag == "login_success":
                profile["login_times"].append(now)
                # Limit login times history
                if len(profile["login_times"]) > 20:
                    profile["login_times"].pop(0)
        
        # Update IP tracking
        if ip:
            ip_data = self.ip_tracking[ip]
            ip_data["access_count"] += 1
            if tag == "failed_login":
                ip_data["failed_logins"] += 1
            elif tag == "login_success":
                ip_data["successful_logins"] += 1
            if user:
                ip_data["users_accessed"].add(user)
            if additional_context:
                if "path" in additional_context:
                    ip_data["paths_accessed"].add(additional_context["path"])
                if "command" in additional_context:
                    ip_data["commands_executed"].add(additional_context["command"])
        
        # Check for suspicious sequences
        self._check_sequences(key)
    
    def _check_sequences(self, key):
        """
        Enhanced sequence detection with MITRE ATT&CK correlation
        
        Args:
            key: (ip, user) tuple
        """
        ip, user = key
        
        # Skip if no session data
        if key not in self.session_log or len(self.session_log[key]) < 2:
            return
        
        # Extract events
        events = [(e['tag'], e['timestamp'], e.get('context', {})) for e in self.session_log[key]]
        
        # Check each sequence pattern
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
                for j, (tag, _, _) in enumerate(event_slice):
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
                        
                        # Get MITRE technique
                        mitre_id = pattern.get("mitre_technique", "T1078")
                        
                        self.logger.info(
                            f"[MITRE: {mitre_id}] Sequence pattern '{pattern['name']}' matched for "
                            f"IP={ip} USER={user}, added {pattern['score']} points"
                        )
                        
                        # Check if this pushes user over the threshold
# Check if this pushes user over the threshold
                        if self.user_scores[key] >= SCORE_THRESHOLD:
                            return
    
    def _check_for_attack_indicators(self, line, additional_context):
        """
        Check for attack indicators in a log line
        
        Args:
            line: Log line
            additional_context: Additional extracted context
            
        Returns:
            dict: Attack indicator info if found, None otherwise
        """
        # Check if already found in context extraction
        if additional_context and 'attack_indicator' in additional_context:
            return additional_context['attack_indicator']
        
        # Check each pattern
        for pattern, tag, score, mitre_id in self.attack_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return {
                    'tag': tag,
                    'score': score,
                    'mitre_id': mitre_id
                }
                
        return None
    
    def _check_for_anomalous_behavior(self, ip, user, additional_context):
        """
        Check for anomalous behavior based on user/IP profiles
        
        Args:
            ip: Source IP address
            user: Username
            additional_context: Additional context data
            
        Returns:
            tuple: (is_anomalous, score, reason)
        """
        if not ip and not user:
            return False, 0, None
            
        anomaly_score = 0
        reasons = []
        
        # Check user profile for anomalies
        if user and user in self.user_profiles:
            profile = self.user_profiles[user]
            
            # Check if login from new IP
            if ip and profile["login_ips"] and ip not in profile["login_ips"]:
                anomaly_score += 3
                reasons.append(f"Login from new IP for user {user}")
                
            # Check for unusual login time (if we have enough history)
            if len(profile["login_times"]) >= 5:
                now = time.time()
                # Calculate average login hour
                login_hours = [datetime.fromtimestamp(t).hour for t in profile["login_times"]]
                avg_hour = sum(login_hours) / len(login_hours)
                current_hour = datetime.fromtimestamp(now).hour
                
                # Check if current login is more than 6 hours away from average
                if abs(current_hour - avg_hour) > 6:
                    anomaly_score += 4
                    reasons.append(f"Unusual login time for user {user}")
                    
            # Check for long absence
            if profile["last_seen"] > 0:
                days_since_last_seen = (time.time() - profile["last_seen"]) / (24 * 3600)
                if days_since_last_seen > 30:  # More than a month
                    anomaly_score += 3
                    reasons.append(f"First activity after {int(days_since_last_seen)} days for user {user}")
                    
            # Check for unusual command
            if additional_context and "command" in additional_context:
                if profile["commands"] and additional_context["command"] not in profile["commands"]:
                    anomaly_score += 2
                    reasons.append(f"Unusual command execution for user {user}")
        
        # Check IP profile for anomalies
        if ip and ip in self.ip_tracking:
            profile = self.ip_tracking[ip]
            
            # Check for high failed login ratio
            total_logins = profile["failed_logins"] + profile["successful_logins"]
            if total_logins > 5 and profile["failed_logins"] / total_logins > 0.7:
                anomaly_score += 5
                reasons.append(f"High failed login ratio from IP {ip}")
                
            # Check for accessing multiple user accounts
            if len(profile["users_accessed"]) > 3:
                anomaly_score += 3
                reasons.append(f"IP {ip} accessing multiple user accounts ({len(profile['users_accessed'])})")
                
            # Check for high number of commands
            if len(profile["commands_executed"]) > 20:
                anomaly_score += 2
                reasons.append(f"IP {ip} executing high number of distinct commands")
        
        is_anomalous = anomaly_score >= 5
        return is_anomalous, anomaly_score, reasons if reasons else None
    
    def _score_event(self, ip, user, line, additional_context=None):
        """
        Enhanced scoring function with MITRE ATT&CK mapping
        
        Args:
            ip: Source IP address
            user: Username
            line: Log line
            additional_context: Additional context dictionary
            
        Returns:
            dict: Alert data if suspicious, None otherwise
        """
        # Skip excluded IPs and users
        if ip in self.excluded_ips or user in self.excluded_users:
            return None
        
        # Debug logging
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
        if line_id in self.recent_alerts and now - self.recent_alerts[line_id] < 60:
            return None
        
        # Initialize scoring
        score = 0
        tags = []
        reasons = []
        mitre_techniques = set()
        
        # --- Check for known attack patterns ---
        attack_indicator = self._check_for_attack_indicators(line, additional_context)
        if attack_indicator:
            score += attack_indicator['score']
            tags.append(attack_indicator['tag'])
            reasons.append(f"Attack pattern detected: {attack_indicator['tag']}")
            mitre_techniques.add(attack_indicator['mitre_id'])
            self.logger.debug(f"Attack pattern {attack_indicator['tag']} detected, Score +{attack_indicator['score']}")
        
        # --- Check for dynamically generated patterns ---
        dynamic_patterns = self.pattern_builder.get_dynamic_patterns()
        
        # Check suspicious IPs
        if "suspicious_ips" in dynamic_patterns and ip in dynamic_patterns["suspicious_ips"]:
            score += 5
            tags.append("dynamically_detected_suspicious_ip")
            reasons.append("IP matches dynamically identified suspicious pattern")
            mitre_techniques.add("T1078")  # Valid Accounts
        
        # Check suspicious paths (for web logs)
        if additional_context and "path" in additional_context:
            path = additional_context["path"]
            if "suspicious_paths" in dynamic_patterns and path in dynamic_patterns["suspicious_paths"]:
                score += 5
                tags.append("dynamically_detected_suspicious_path")
                reasons.append("Path matches dynamically identified suspicious pattern")
                mitre_techniques.add("T1190")  # Exploit Public-Facing Application
        
        # --- Authentication Events ---
        if "Failed password" in line or "authentication failure" in line or "Invalid user" in line:
            score += 3
            tags.append("failed_login")
            reasons.append("Failed login attempt")
            self.failed_logins[ip].append(now)
            self._log_session_event(ip, user, "failed_login", additional_context)
            mitre_techniques.add("T1110")  # Brute Force
            self.logger.debug(f"Failed login detected: IP={ip} USER={user}, Score +3")
        
        if "Accepted password for" in line or "session opened for user" in line:
            score += 2
            tags.append("successful_login")
            reasons.append("Successful login")
            self._log_session_event(ip, user, "login_success", additional_context)
            mitre_techniques.add("T1078")  # Valid Accounts
        
        # --- Privilege Escalation ---
        if "sudo:" in line or "su:" in line:
            score += 4
            tags.append("privilege_escalation")
            reasons.append("Privilege escalation attempt")
            self._log_session_event(ip, user, "escalation", additional_context)
            mitre_techniques.add("T1548")  # Abuse Elevation Control Mechanism
        
        # --- File Access and Manipulation ---
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", 
            "authorized_keys", ".ssh/id_rsa", "/etc/hosts", 
            "/boot/grub", "/etc/crontab", "/etc/init.d", 
            "/etc/systemd", "/var/log"
        ]
        
        if any(s in line for s in ["open(", "access(", "unlink(", "rmdir(", "chmod", "chown", "rm "]):
            if any(s in line for s in sensitive_files):
                score += 6
                tags.append("sensitive_file_access")
                reasons.append("Access to sensitive system file")
                self._log_session_event(ip, user, "file_access", additional_context)
                mitre_techniques.add("T1005")  # Data from Local System
        
        # --- Command Execution ---
        if additional_context and 'command' in additional_context:
            command = additional_context['command']
            
            # Check for suspicious commands
            suspicious_cmds = [
                "wget", "curl", "nc", "netcat", "chmod 777", "chmod +x", 
                "base64", "python -c", "perl -e", "eval", "bash -i",
                "nmap", "tcpdump", "dd if", "shred", "dump", "strings"
            ]
                              
            if any(s in command for s in suspicious_cmds):
                score += 5
                tags.append("suspicious_command")
                reasons.append(f"Suspicious command execution: {command}")
                self._log_session_event(ip, user, "command_execution", additional_context)
                mitre_techniques.add("T1059")  # Command and Scripting Interpreter
        
        # --- Brute Force Detection ---
        if "failed_login" in tags:
            attempts = self.failed_logins[ip]
            # Clean up old attempts
            while attempts and now - attempts[0] > EVENT_WINDOW:
                attempts.popleft()
                
            if len(attempts) >= FAILED_LOGIN_THRESHOLD:
                score += 6
                tags.append("brute_force")
                reasons.append(f"{len(attempts)} failed logins within {EVENT_WINDOW} seconds")
                mitre_techniques.add("T1110.001")  # Brute Force: Password Guessing
                self.logger.debug(f"Brute force detected: IP={ip} USER={user}, {len(attempts)} attempts, Score +6")
        
        # --- Suspicious Session Patterns ---
        session_events = [e['tag'] for e in self.session_log.get(key, [])]
        
        # Login followed quickly by privilege escalation
        if "login_success" in session_events and "escalation" in session_events:
            login_time = None
            escalation_time = None
            
            # Find timestamps
            for event in self.session_log[key]:
                if event['tag'] == "login_success" and login_time is None:
                    login_time = event['timestamp']
                elif event['tag'] == "escalation" and escalation_time is None:
                    escalation_time = event['timestamp']
            
            # Check if privilege escalation happened quickly after login
            if login_time and escalation_time and escalation_time - login_time < 10:
                score += 4
                tags.append("rapid_privesc")
                reasons.append("Login immediately followed by privilege escalation")
                mitre_techniques.add("T1548")  # Abuse Elevation Control Mechanism
        
        # --- High Frequency Actions ---
        if now - self.last_activity[key] < 5:
            score += 2
            tags.append("high_frequency")
            reasons.append("High-frequency actions")
            mitre_techniques.add("T1059")  # Command and Scripting Interpreter
        
        # --- Unknown Source ---
        if not ip and not user:
            tags.append("unknown_source")
            reasons.append("Activity with no identifiable user or IP")
        
        # --- Check for Behavioral Anomalies ---
        is_anomalous, anomaly_score, anomaly_reasons = self._check_for_anomalous_behavior(ip, user, additional_context)
        if is_anomalous:
            score += anomaly_score
            tags.append("behavioral_anomaly")
            if anomaly_reasons:
                reasons.extend(anomaly_reasons)
            else:
                reasons.append("Anomalous behavior detected")
            mitre_techniques.add("T1078")  # Valid Accounts
        
        # Update last activity time
        self.last_activity[key] = now
        
        # Apply score if meaningful
        if score >= 2:  # Lowered threshold for better sensitivity
            self.user_scores[key] += score
            self.logger.debug(f"Added score {score} for IP={ip} USER={user}, total={self.user_scores[key]}")
        
        # Check if threshold exceeded
        if self.user_scores[key] >= SCORE_THRESHOLD:
            final_score = self.user_scores[key]
            self.user_scores[key] = 0  # Reset score
            self.recent_alerts[line_id] = now  # Remember for deduplication
            
            # Get MITRE ATT&CK information for primary technique
            primary_mitre = None
            if mitre_techniques:
                primary_technique = next(iter(mitre_techniques))
                primary_mitre = self.mitre_mapper.get_technique_info(primary_technique)
                self.logger.info(f"Primary MITRE technique: {primary_technique} ({primary_mitre['technique_name'] if primary_mitre else 'Unknown'})")
            
            self.logger.info(f"Alert triggered: IP={ip} USER={user}, Score={final_score}")
            
            return {
                "ip": ip,
                "user": user,
                "score": final_score,
                "tags": tags,
                "reasons": reasons,
                "line": line.strip(),
                "mitre": {
                    "techniques": list(mitre_techniques),
                    "primary_technique": primary_mitre
                }
            }
        
        return None
    
    def analyze_line(self, line):
        """
        Analyze a log line for security events with MITRE ATT&CK mapping
        
        Args:
            line: Log line string
            
        Returns:
            dict: Alert data if suspicious, None otherwise
        """
        # Extract context with enhanced patterns
        ip, user, additional_context = self._extract_context(line)
        
        # Add this sample to the dynamic pattern builder
        self.pattern_builder.add_sample({
            "raw": line,
            "ip": ip,
            "user": user,
            "context": additional_context
        })
            
        return self._score_event(ip, user, line, additional_context)
    
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
        self.user_profiles.clear()
        self.ip_tracking.clear()
        self.event_counter.clear()
    
    def get_stats(self):
        """
        Get engine statistics
        
        Returns:
            dict: Statistics for the detection engine
        """
        return {
            "events_processed": sum(self.event_counter.values()),
            "events_by_type": dict(self.event_counter),
            "users_tracked": len(self.user_profiles),
            "ips_tracked": len(self.ip_tracking),
            "active_sessions": len(self.session_log)
        }
    
    def get_ip_report(self, ip):
        """
        Get detailed report for an IP address
        
        Args:
            ip: IP address
            
        Returns:
            dict: IP activity report
        """
        if ip not in self.ip_tracking:
            return {"ip": ip, "status": "unknown"}
            
        data = self.ip_tracking[ip]
        
        # Calculate risk score
        risk_score = 0
        
        # Base score on various factors
        if data["failed_logins"] > 5:
            risk_score += min(10, data["failed_logins"] // 2)
            
        if len(data["users_accessed"]) > 3:
            risk_score += len(data["users_accessed"])
            
        if len(data["commands_executed"]) > 10:
            risk_score += min(10, len(data["commands_executed"]) // 2)
            
        return {
            "ip": ip,
            "status": "active" if time.time() - data["first_seen"] < 3600 else "inactive",
            "first_seen": datetime.fromtimestamp(data["first_seen"]).isoformat(),
            "access_count": data["access_count"],
            "failed_logins": data["failed_logins"],
            "successful_logins": data["successful_logins"],
            "users_accessed": list(data["users_accessed"]),
            "commands_executed": list(data["commands_executed"]),
            "risk_score": risk_score,
            "risk_level": "high" if risk_score > 15 else "medium" if risk_score > 7 else "low"
        }
    
    def get_user_report(self, user):
        """
        Get detailed report for a user
        
        Args:
            user: Username
            
        Returns:
            dict: User activity report
        """
        if user not in self.user_profiles:
            return {"user": user, "status": "unknown"}
            
        data = self.user_profiles[user]
        
        # Calculate risk score
        risk_score = 0
        
        # Base score on various factors
        if len(data["login_ips"]) > 3:
            risk_score += len(data["login_ips"])
            
        if len(data["commands"]) > 10:
            risk_score += min(5, len(data["commands"]) // 3)
            
        # Check login time variance if we have enough data
        if len(data["login_times"]) >= 5:
            login_hours = [datetime.fromtimestamp(t).hour for t in data["login_times"]]
            min_hour = min(login_hours)
            max_hour = max(login_hours)
            
            # Wide range of login hours can indicate account sharing or compromise
            if max_hour - min_hour > 12:
                risk_score += 5
        
        return {
            "user": user,
            "status": "active" if time.time() - data["last_seen"] < 86400 else "inactive",
            "last_seen": datetime.fromtimestamp(data["last_seen"]).isoformat() if data["last_seen"] > 0 else None,
            "login_ips": list(data["login_ips"]),
            "login_times": [datetime.fromtimestamp(t).isoformat() for t in data["login_times"][-5:]],  # Last 5 logins
            "commands": list(data["commands"]),
            "risk_score": risk_score,
            "risk_level": "high" if risk_score > 15 else "medium" if risk_score > 7 else "low"
        }
