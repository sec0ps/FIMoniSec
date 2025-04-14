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
# Log Parser with Optimized Pattern Matching and Attack Detection
# =============================================================================

import re
import json
import logging
import os
from datetime import datetime
from collections import defaultdict, Counter

class OptimizedPatternMatcher:
    """
    Provides optimized pattern matching for log analysis
    """
    
    def __init__(self):
        """Initialize the optimized pattern matcher"""
        # Initialize pattern caches
        self.pattern_cache = {}
        self.parsed_results_cache = {}
        self.cache_size = 10000  # Maximum cache size
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Precompile common regex patterns
        self._precompile_common_patterns()
    
    def _precompile_common_patterns(self):
        """Precompile frequently used regex patterns"""
        self.common_patterns = {
            # IP addresses
            "ipv4": re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
            "ipv6": re.compile(r'([0-9a-fA-F:]{2,})(%\w+)?'),
            
            # Timestamps
            "syslog_timestamp": re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
            "iso_timestamp": re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)'),
            
            # Common fields
            "hostname": re.compile(r'\s+(\S+)\s+[^\[:\s]+(?:\[\d+\])?:'),
            "process": re.compile(r'\s+([^\[:\s]+)(?:\[(\d+)\])?:'),
            
            # User identification
            "username": re.compile(r'(?:user|User|USER)[= :"\']+([^"\':\s]+)'),
            "user_context": re.compile(r'(?:for|as|by)[= :"\']+([^"\':\s]+)'),
            
            # File paths
            "unix_path": re.compile(r'(?:\/[a-zA-Z0-9_\-\.]+)+\/?'),
            "windows_path": re.compile(r'(?:[A-Za-z]:\\[a-zA-Z0-9_\-\.\\]+)'),
            
            # Commands
            "command": re.compile(r'COMMAND=[\"\']?([^;\"\']+)[\"\']?'),
            "sudo_command": re.compile(r'sudo:.*COMMAND=[\"\']?([^;\"\']+)[\"\']?'),
            
            # Web specific
            "http_method": re.compile(r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+'),
            "http_status": re.compile(r'\s+(\d{3})\s+'),
            "user_agent": re.compile(r'\"([^\"]+Mozilla[^\"]+)\"')
        }
    
    def match(self, line, pattern_name=None, pattern=None):
        """
        Match a line with a cached pattern
        
        Args:
            line: Log line string
            pattern_name: Name of predefined pattern
            pattern: Custom regex pattern string
            
        Returns:
            Match object or None
        """
        # Check if the line is in the parsed results cache
        cache_key = f"{pattern_name or pattern}:{line}"
        if cache_key in self.parsed_results_cache:
            self.cache_hits += 1
            return self.parsed_results_cache[cache_key]
            
        self.cache_misses += 1
        
        # Use predefined pattern if provided
        if pattern_name and pattern_name in self.common_patterns:
            result = self.common_patterns[pattern_name].search(line)
        
        # Use or compile custom pattern
        elif pattern:
            if pattern not in self.pattern_cache:
                # Limit cache size
                if len(self.pattern_cache) >= self.cache_size:
                    # Remove a random pattern (future: LRU implementation)
                    self.pattern_cache.pop(next(iter(self.pattern_cache)))
                
                # Compile and cache
                self.pattern_cache[pattern] = re.compile(pattern)
                
            # Use cached pattern
            result = self.pattern_cache[pattern].search(line)
        else:
            return None
            
        # Cache result
        if len(self.parsed_results_cache) >= self.cache_size:
            # Remove a random result (future: LRU implementation)
            self.parsed_results_cache.pop(next(iter(self.parsed_results_cache)))
            
        self.parsed_results_cache[cache_key] = result
        return result
    
    def match_all(self, line, pattern_name=None, pattern=None):
        """
        Match all occurrences in a line with a cached pattern
        
        Args:
            line: Log line string
            pattern_name: Name of predefined pattern
            pattern: Custom regex pattern string
            
        Returns:
            List of match objects
        """
        # Use predefined pattern if provided
        if pattern_name and pattern_name in self.common_patterns:
            return list(self.common_patterns[pattern_name].finditer(line))
        
        # Use or compile custom pattern
        elif pattern:
            if pattern not in self.pattern_cache:
                # Limit cache size
                if len(self.pattern_cache) >= self.cache_size:
                    # Remove a random pattern (future: LRU implementation)
                    self.pattern_cache.pop(next(iter(self.pattern_cache)))
                
                # Compile and cache
                self.pattern_cache[pattern] = re.compile(pattern)
                
            # Use cached pattern
            return list(self.pattern_cache[pattern].finditer(line))
        else:
            return []
    
    def get_stats(self):
        """Get pattern matcher statistics"""
        return {
            "pattern_cache_size": len(self.pattern_cache),
            "result_cache_size": len(self.parsed_results_cache),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_ratio": self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0
        }

class LogParser:
    """Log parser with optimized pattern matching and attack detection"""
    
    def __init__(self):
        """Initialize the log parser"""
        # Initialize pattern matcher
        self.pattern_matcher = OptimizedPatternMatcher()
        
        # Initialize format patterns
        self._init_format_patterns()
        
        # Cache for detected log formats
        self.file_formats = {}
        
        # Statistics for parser usage
        self.stats = defaultdict(int)
        
        # Initialize attack patterns
        self._init_attack_patterns()
        
        # Set up logging
        self.logger = logging.getLogger("lim.parser")
    
    def _init_format_patterns(self):
        """Initialize log format detection patterns with MITRE mapping"""
        self.format_patterns = {
            # Standard syslog format: Jan 23 10:30:45 hostname process[pid]: message
            "syslog": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Alternate syslog with ISO dates: 2023-01-23T10:30:45+00:00 hostname process[pid]: message
            "syslog_iso": r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z))\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Common auth log format: Jan 23 10:30:45 hostname sshd[pid]: message
            "auth": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\-]+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Apache/Nginx access logs: client - user [time] "request" status bytes "referer" "user-agent"
            "web_access": r'^(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
            
            # Apache/Nginx error logs: [time] [level] [client IP] message
            "web_error": r'^\[(.*?)\] \[(\w+)\](?: \[client (\S+)\])? (.*)$',
            
            # Auditd logs: type=TYPE msg=audit(timestamp:id): message
            "audit": r'^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s+(.*)$',
            
            # JSON formatted logs
            "json": r'^(\{.*\})$',
            
            # Key-value format: key1=value1 key2="value with spaces" key3=value3
            "key_value": r'^([A-Za-z0-9_\-]+)=("([^"]+)"|([^ ]+))(\s+[A-Za-z0-9_\-]+=("([^"]+)"|([^ ]+)))*$',
            
            # Simple line with timestamp prefix: [2023-01-23 10:30:45] message
            "simple_timestamp": r'^\[([\d\-:/ ]+)\]\s+(.*)$',
            
            # Firewall logs (iptables): Jan 23 10:30:45 hostname kernel: iptables message
            "firewall": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(IP|iptables|UFW|firewall).*?$',
            
            # Windows event logs
            "windows_event": r'^\s*Log Name:\s+(.*?)$',
            
            # Rsyslog format
            "rsyslog": r'^(?:<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$',
            
# ModSecurity audit logs
            "modsecurity": r'--([a-fA-F0-9]+)-([A-Z])--$',
            
            # Suricata/Snort IDS logs
            "ids": r'^(\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]',
            
            # Kubernetes logs
            "kubernetes": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Cloud provider logs (generic)
            "cloud": r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z))\s+(\S+)\s+(.+)$'
        }
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.format_patterns.items()
        }
    
    def _init_attack_patterns(self):
        """Initialize attack pattern detection with MITRE ATT&CK mapping"""
        # Format: (pattern, attack_name, mitre_id, severity)
        self.attack_patterns = [
            # Credential Access (TA0006)
            (r'(?:password|passwd)\s+cracking|john\s+the\s+ripper|hashcat', "password_cracking", "T1110", "medium"),
            (r'mimikatz|gsecdump|wce|lsadump|ntds\.dit|SAM', "credential_dumping", "T1003", "high"),
            (r'kerberos|krbtgt|TGT|TGS|golden\s+ticket|silver\s+ticket', "kerberos_attack", "T1558", "high"),
            
            # Privilege Escalation (TA0004)
            (r'kernel\s+exploit|CVE\-\d+\-\d+', "kernel_exploit", "T1068", "high"),
            (r'sudo\s+\-u\s+root|sudo\s+\-s|sudo\s+su\s*$', "sudo_misuse", "T1548.003", "medium"),
            (r'chmod\s+(?:u\+s|4755|4777|a\+x|777)\s+(?:\/bin\/|\/etc\/|\/usr\/)', "setuid_modification", "T1548.001", "high"),
            
            # Defense Evasion (TA0005)
            (r'unset\s+HISTFILE|HISTSIZE\=0|HISTFILESIZE\=0|history\s+\-c', "history_clearing", "T1070.003", "medium"),
            (r'(?:\/var\/log\/).*(?:rm|cat\s+\/dev\/null|\>|truncate)', "log_tampering", "T1070.002", "high"),
            (r'touch\s+\-[acdmr]|timestomp', "timestamp_modification", "T1070.006", "medium"),
            
            # Persistence (TA0003)
            (r'crontab\s+\-e|\/etc\/cron|\/var\/spool\/cron', "cron_modification", "T1053.003", "medium"),
            (r'(?:\/etc\/rc|init\.d|systemd|systemctl)', "service_modification", "T1543.002", "medium"),
            (r'(?:\/etc\/passwd|\+\+\+|authorized_keys|\.bashrc|\.profile|\.ssh\/)', "account_manipulation", "T1098", "high"),
            
            # Command and Control (TA0011)
            (r'(?:nc|netcat|ncat).{1,30}(?:\-e|\-c|bash|cmd|powershell|sh)', "reverse_shell", "T1071.001", "high"),
            (r'(?:\/dev\/tcp\/|socat|telnet|ssh)\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}', "network_connection", "T1071", "medium"),
            (r'dns\s+exfiltration|(?:dig|nslookup|host).{1,30}(?:ANY|TXT|MX|AAAA)', "dns_tunneling", "T1071.004", "high"),
            
            # Discovery (TA0007)
            (r'nmap|\-sS|\-sV|\-sT|\-A|\-p\s*\d+|--open', "port_scanning", "T1046", "medium"),
            (r'(?:\/proc\/self\/|\/proc\/[0-9]+\/|\/proc\/net\/)', "process_discovery", "T1057", "low"),
            (r'(?:ifconfig|ip\s+a|\/sbin\/ip|\/bin\/ip|\/etc\/hosts)', "network_discovery", "T1016", "low"),
            
            # Lateral Movement (TA0008)
            (r'(?:ssh|scp|sftp|rsync)\s+(?:\-i|\-l|\-P)', "remote_access", "T1021.004", "medium"),
            (r'(?:smbclient|smb:|cifs:|mount\s+\-t\s+cifs|net\s+use)', "smb_access", "T1021.002", "medium"),
            (r'(?:winexe|wmic|xfreerdp|rdesktop|mstsc)', "remote_service", "T1021", "medium"),
            
            # Collection (TA0009)
            (r'(?:tar|zip|rar|7z|gzip).{1,30}(?:\/etc\/|\/var\/|\/usr\/|\/home\/)', "data_archive", "T1560", "medium"),
            (r'(?:cp|scp|rsync|cat|tee).{1,30}(?:\/etc\/shadow|id_rsa|\.ssh\/)', "data_collection", "T1005", "high"),
            (r'(?:mysqldump|pg_dump|sqlite3|mongodump)', "database_dump", "T1005", "medium"),
            
            # Exfiltration (TA0010)
            (r'(?:curl|wget|ftp|scp|sftp|ssh).{1,30}(?:[0-9]{1,3}\.){3}[0-9]{1,3}.{0,20}(?:\/etc\/|\/var\/|passwd|shadow)', "data_exfiltration", "T1048", "high"),
            (r'(?:mail|sendmail|exim|postfix).{1,30}(?:\-a|\-s|\-f|\-t).{1,30}(?:\/etc\/|\/var\/|passwd|shadow)', "email_exfiltration", "T1048.003", "high"),
            
            # Impact (TA0040)
            (r'(?:rm\s+\-rf|find.{1,30}\-delete|shred|wipe)', "data_destruction", "T1485", "high"),
            (r'(?:\/dev\/sd[a-z]|mkfs|dd\s+if|fdisk|sfdisk)', "disk_wipe", "T1561", "high"),
            (r'(?:kill\s+\-9|pkill|\/proc\/[0-9]+\/status)', "service_stop", "T1489", "medium"),
            
            # Web specific attacks
            (r'(?:select.*from|union.*select|insert.*into|update.*set|delete.*from)', "sql_injection", "T1190", "high"),
            (r'(?:\/\.\.\/|\.\.\\|\%2e\%2e\%2f|\%252e\%252e\%252f)', "path_traversal", "T1083", "high"),
            (r'(?:onload\=|onerror\=|onclick\=|script\>|javascript\:)', "cross_site_scripting", "T1059.007", "medium"),
            (r'<!\[CDATA|<%.*%>|\{\{.*\}\}|\$\{.*\}', "template_injection", "T1059", "high")
        ]
        
        # Precompile attack patterns
        self.compiled_attack_patterns = [
            (re.compile(pattern, re.IGNORECASE), attack_name, mitre_id, severity) 
            for pattern, attack_name, mitre_id, severity in self.attack_patterns
        ]
        
    def detect_format(self, file_path, sample_size=20):
        """
        Detect the log format of a file by sampling lines
        
        Args:
            file_path: Path to the log file
            sample_size: Number of lines to sample
            
        Returns:
            tuple: (format_name, confidence)
                format_name: Name of the detected format
                confidence: Confidence score (0-1)
        """
        # Return cached result if available
        if file_path in self.file_formats:
            return self.file_formats[file_path]
        
        format_counts = defaultdict(int)
        total_lines = 0
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                # Skip empty or very short files
                if f.seek(0, 2) < 10:  # Go to end and check file size
                    self.file_formats[file_path] = ("unknown", 0)
                    return "unknown", 0
                
                # Reset to beginning of file
                f.seek(0)
                
                # Sample lines from the file
                lines = []
                for i, line in enumerate(f):
                    if i >= sample_size:
                        break
                    if line.strip():  # Skip blank lines
                        lines.append(line.strip())
                
                total_lines = len(lines)
                if total_lines == 0:
                    self.file_formats[file_path] = ("unknown", 0)
                    return "unknown", 0
                
                # Test each format against the lines
                for line in lines:
                    for format_name, pattern in self.compiled_patterns.items():
                        if pattern.match(line):
                            format_counts[format_name] += 1
                            break
            
            # Determine best format
            if not format_counts:
                best_format = "unknown"
                confidence = 0
            else:
                best_format = max(format_counts.items(), key=lambda x: x[1])
                format_name = best_format[0]
                match_count = best_format[1]
                confidence = match_count / total_lines
                best_format = format_name
            
            # Cache the result
            self.file_formats[file_path] = (best_format, confidence)
            return best_format, confidence
            
        except Exception as e:
            self.logger.error(f"Error detecting format for {file_path}: {str(e)}")
            self.file_formats[file_path] = ("unknown", 0)
            return "unknown", 0

    def parse_line(self, line, format_name=None):
        """
        Parse a log line into structured data with attack detection
        
        Args:
            line: Log line string
            format_name: Format name (if known)
        
        Returns:
            dict: Parsed log entry with attack detection
        """
        if not line or not line.strip():
            return None
    
        line = line.strip()
        self.stats["total_lines_parsed"] += 1
    
        # Auto-detect format if not provided
        if not format_name or format_name == "unknown":
            for name, pattern in self.compiled_patterns.items():
                if pattern.match(line):
                    format_name = name
                    self.logger.debug(f"[FORMAT DETECTED] {format_name} => {line}")
                    break
    
        # Parse based on detected format
        parser_method = getattr(self, f"_parse_{format_name}", None)
        if parser_method:
            try:
                result = parser_method(line)
                if result:
                    self.stats[f"{format_name}_parsed"] += 1
                    
                    # Add raw line and format info
                    result["_raw"] = line
                    result["_format"] = format_name
                    
                    # Check for attack patterns
                    attack_info = self._check_attack_patterns(line, result)
                    if attack_info:
                        result["attack_info"] = attack_info
                        
                    return result
            except Exception as e:
                self.logger.debug(f"Error parsing as {format_name}: {str(e)}")
    
        # Fallback: log unmatched lines for debugging
        self.logger.debug(f"[NO MATCH] {line}")
        self.stats["basic_parsed"] += 1
        
        # Basic parsing for unknown format
        result = {
            "timestamp": None,
            "message": line,
            "_raw": line,
            "_format": "unknown"
        }
        
        # Still check for attack patterns even in unknown formats
        attack_info = self._check_attack_patterns(line, result)
        if attack_info:
            result["attack_info"] = attack_info
            
        return result
    
    def _check_attack_patterns(self, line, parsed_log):
        """
        Check a log line for attack patterns
        
        Args:
            line: Raw log line
            parsed_log: Parsed log data
            
        Returns:
            dict: Attack information if detected, None otherwise
        """
        line_lower = line.lower()
        message = parsed_log.get("message", "")
        if isinstance(message, str):
            message_lower = message.lower()
        else:
            message_lower = ""
            
        # Check against each attack pattern
        for pattern, attack_name, mitre_id, severity in self.compiled_attack_patterns:
            # Check both raw line and message field if available
            if pattern.search(line_lower) or (message_lower and pattern.search(message_lower)):
                return {
                    "attack_type": attack_name,
                    "mitre_technique": mitre_id,
                    "severity": severity,
                    "confidence": 0.8  # Default confidence
                }
        
        return None
        
    def _parse_syslog(self, line):
        """Parse standard syslog format with optimized pattern matching"""
        # Use our cached pattern matching
        match = self.pattern_matcher.match(None, pattern=self.format_patterns["syslog"])
        if not match:
            match = self.compiled_patterns["syslog"].match(line)
            
        if not match:
            return None
            
        timestamp, hostname, process, pid, message = match.groups()
        
        # Convert timestamp to ISO format
        try:
            # Add current year since syslog doesn't include it
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            # Handle December logs in January
            if dt > datetime.now():
                dt = datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
        
        # Extract IP addresses from message if present
        ip_addresses = []
        ip_matches = self.pattern_matcher.match_all(message, "ipv4")
        if ip_matches:
            ip_addresses = [m.group(0) for m in ip_matches]
            
        # Extract potential usernames
        username = None
        username_match = self.pattern_matcher.match(message, "username")
        if username_match:
            username = username_match.group(1)
            
        # Extract file paths if present
        paths = []
        path_matches = self.pattern_matcher.match_all(message, "unix_path")
        if path_matches:
            paths = [m.group(0) for m in path_matches]
        
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message,
            "ip_addresses": ip_addresses if ip_addresses else None,
            "username": username,
            "paths": paths if paths else None
        }
    
    def _parse_syslog_iso(self, line):
        """Parse syslog with ISO timestamps using optimized pattern matching"""
        match = self.compiled_patterns["syslog_iso"].match(line)
        if not match:
            return None
            
        timestamp, hostname, process, pid, message = match.groups()
        
        # Extract IP addresses from message if present
        ip_addresses = []
        ip_matches = self.pattern_matcher.match_all(message, "ipv4")
        if ip_matches:
            ip_addresses = [m.group(0) for m in ip_matches]
            
        # Extract potential usernames
        username = None
        username_match = self.pattern_matcher.match(message, "username")
        if username_match:
            username = username_match.group(1)
            
        # Extract file paths if present
        paths = []
        path_matches = self.pattern_matcher.match_all(message, "unix_path")
        if path_matches:
            paths = [m.group(0) for m in path_matches]
        
        return {
            "timestamp": timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message,
            "ip_addresses": ip_addresses if ip_addresses else None,
            "username": username,
            "paths": paths if paths else None
        }
    
    def _parse_auth(self, line):
        """Parse authentication log format with enhanced threat detection"""
        match = self.compiled_patterns["auth"].match(line)
        if not match:
            return None
            
        timestamp, hostname, service, pid, message = match.groups()
        
        # Extract common auth patterns
        user = None
        ip = None
        action = None
        
        # Extract IP address if present - optimized pattern matching
        ip_match = self.pattern_matcher.match(message, "ipv4")
        if ip_match:
            ip = ip_match.group(0)
            
        # Extract username with improved detection
        username_match = self.pattern_matcher.match(message, "username")
        if username_match:
            user = username_match.group(1)
        else:
            # Try alternative patterns
            user_patterns = [
                r'for\s+(\w+)',
                r'for invalid user\s+(\w+)',
                r'user\s+(\w+)\s+from'
            ]
            
            for pattern in user_patterns:
                user_match = re.search(pattern, message)
                if user_match:
                    user = user_match.group(1)
                    break
                    
        # Determine authentication action with enhanced detection
        if 'Failed password' in message or 'authentication failure' in message or 'Invalid user' in message:
            action = 'failed_login'
        elif 'Accepted' in message and ('password' in message or 'publickey' in message or 'keyboard-interactive' in message):
            action = 'successful_login'
        elif 'session opened' in message:
            action = 'session_start'
        elif 'session closed' in message:
            action = 'session_end'
        elif 'TTY=' in message and service.lower() == 'sudo':
            action = 'privilege_escalation'
        elif 'new user' in message.lower() or 'adding user' in message.lower():
            action = 'user_creation'
        elif 'delete user' in message.lower() or 'removing user' in message.lower():
            action = 'user_deletion'
        elif 'password changed' in message.lower():
            action = 'password_change'
        elif 'group' in message.lower() and ('add' in message.lower() or 'new' in message.lower()):
            action = 'group_modification'
            
        # Extract SSH key information if present
        ssh_key_info = None
        if 'ssh' in service.lower() and ('publickey' in message or 'authorized_keys' in message):
            key_match = re.search(r'([a-zA-Z0-9+/]{10,})', message)
            if key_match:
                ssh_key_info = {
                    'partial_key': key_match.group(1)[:20] + '...',
                    'key_type': 'rsa' if 'rsa' in message.lower() else 
                               'dsa' if 'dsa' in message.lower() else 
                               'ecdsa' if 'ecdsa' in message.lower() else 
                               'ed25519' if 'ed25519' in message.lower() else 'unknown'
                }
            
        # Convert timestamp to ISO format
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
            
        # Extract command if present (for sudo logs)
        command = None
        if service.lower() == 'sudo':
            cmd_match = self.pattern_matcher.match(message, "sudo_command")
            if cmd_match:
                command = cmd_match.group(1)
        
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "pid": pid,
            "message": message,
            "user": user,
            "ip": ip,
            "action": action,
            "command": command,
            "ssh_key_info": ssh_key_info
        }
    
    def extract_security_events(self, parsed_log):
        """
        Extract security-relevant events from parsed log entries with MITRE ATT&CK mapping
        
        Args:
            parsed_log: Dictionary of parsed log data
        
        Returns:
            dict: Security event data or None if not a security event
        """
        if not parsed_log:
            return None
        
        format_type = parsed_log.get("_format", "unknown")
        
        # Check if attack info was already detected during parsing
        if "attack_info" in parsed_log:
            attack_info = parsed_log["attack_info"]
            return {
                "event_type": attack_info["attack_type"],
                "severity": attack_info["severity"],
                "mitre_technique": attack_info["mitre_technique"],
                "confidence": attack_info["confidence"],
                "timestamp": parsed_log.get("timestamp"),
                "details": parsed_log
            }
        
        # Authentication-related events
        if format_type == "auth":
            action = parsed_log.get("action")
            message = parsed_log.get("message", "").lower()
            
            # Fallback detection if action is missing
            if not action:
                if "failed password" in message or "authentication failure" in message:
                    action = "failed_login"
                elif "invalid user" in message:
                    action = "failed_login"  # treat invalid user as failed login
                elif "accepted password" in message or "accepted publickey" in message:
                    action = "successful_login"
                elif "sudo" in message:
                    action = "privilege_escalation"
            
            if action in ["failed_login", "successful_login", "privilege_escalation"]:
                # Map to MITRE ATT&CK
                mitre_map = {
                    "failed_login": "T1110",  # Brute Force
                    "successful_login": "T1078",  # Valid Accounts
                    "privilege_escalation": "T1548"  # Abuse Elevation Control Mechanism
                }
                
                severity_map = {
                    "failed_login": "medium",
                    "successful_login": "low",
                    "privilege_escalation": "high"
                }
                
                return {
                    "event_type": action,
                    "severity": severity_map.get(action, "medium"),
                    "mitre_technique": mitre_map.get(action),
                    "user": parsed_log.get("user"),
                    "ip": parsed_log.get("ip"),
                    "timestamp": parsed_log.get("timestamp"),
                    "command": parsed_log.get("command"),
                    "details": parsed_log
                }
                
        # Web server security events
        elif format_type == "web_access":
            status = parsed_log.get("status")
            path = parsed_log.get("path", "")
            suspicious = parsed_log.get("suspicious", {})
            
            # Check for suspicious paths or user agents
            if suspicious.get("path"):
                return {
                    "event_type": "web_attack",
                    "attack_type": suspicious.get("path_reason", "suspicious_path"),
                    "severity": "high",
                    "mitre_technique": "T1190",  # Exploit Public-Facing Application
                    "ip": parsed_log.get("ip"),
                    "timestamp": parsed_log.get("timestamp"),
                    "path": path,
                    "status": status,
                    "details": parsed_log
                }
            
            # Detect authentication failures or unauthorized access
            if status in [401, 403, 407]:
                return {
                    "event_type": "web_auth_failure",
                    "severity": "medium",
                    "mitre_technique": "T1078",  # Valid Accounts
                    "ip": parsed_log.get("ip"),
                    "timestamp": parsed_log.get("timestamp"),
                    "path": path,
                    "status": status,
                    "details": parsed_log
                }
                
        # Firewall events
        elif format_type == "firewall":
            action = parsed_log.get("action")
            suspicious = parsed_log.get("suspicious", {})
            
            if action in ["drop", "reject", "block"]:
                # Map to appropriate MITRE technique
                mitre_technique = "T1046"  # Network Scanning
                
                # Check if this is a common service (potentially more serious)
                if parsed_log.get("service"):
                    if parsed_log["service"] in ["SSH", "RDP", "VNC", "SMB"]:
                        mitre_technique = "T1021"  # Remote Services
                    elif parsed_log["service"] in ["HTTP", "HTTPS"]:
                        mitre_technique = "T1190"  # Exploit Public-Facing Application
                
                return {
                    "event_type": "firewall_block",
                    "severity": "medium",
                    "mitre_technique": mitre_technique,
                    "src_ip": parsed_log.get("src_ip"),
                    "dst_ip": parsed_log.get("dst_ip"),
                    "src_port": parsed_log.get("src_port"),
                    "dst_port": parsed_log.get("dst_port"),
                    "protocol": parsed_log.get("protocol"),
                    "service": parsed_log.get("service"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
            
            # Check for suspicious activity even if not blocked
            if suspicious.get("is_suspicious"):
                return {
                    "event_type": "suspicious_network_activity",
                    "severity": "medium",
                    "mitre_technique": "T1046",  # Network Scanning
                    "reasons": suspicious.get("reasons"),
                    "src_ip": parsed_log.get("src_ip"),
                    "dst_ip": parsed_log.get("dst_ip"),
                    "src_port": parsed_log.get("src_port"),
                    "dst_port": parsed_log.get("dst_port"),
                    "protocol": parsed_log.get("protocol"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
        # Audit log security events
        elif format_type == "audit":
            audit_type = parsed_log.get("audit_type")
            content = parsed_log.get("content", {})
            security_context = parsed_log.get("security_context")
            mitre_technique = parsed_log.get("mitre_technique")
            
            # Use security context if available
            if security_context:
                # Map severity based on context
                severity = "medium"
                if security_context in ["privilege_escalation", "credential_management"]:
                    severity = "high"
                elif security_context in ["system_event", "session_management"]:
                    severity = "low"
                    
                return {
                    "event_type": f"audit_{security_context}",
                    "severity": severity,
                    "mitre_technique": mitre_technique,
                    "user": parsed_log.get("user"),
                    "command": parsed_log.get("command"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
            
            # Check for relevant audit types
            if audit_type in ["USER_AUTH", "USER_LOGIN", "USER_CMD", "USER_ACCT"]:
                return {
                    "event_type": f"audit_{audit_type.lower()}",
                    "severity": "medium",
                    "mitre_technique": "T1078",  # Valid Accounts
                    "user": content.get("acct") or content.get("user"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
            # Check for privilege escalation
            elif audit_type in ["USER_CMD"] and content.get("cmd", "").startswith("sudo"):
                return {
                    "event_type": "privilege_escalation",
                    "severity": "high",
                    "mitre_technique": "T1548",  # Abuse Elevation Control Mechanism
                    "user": content.get("acct") or content.get("user"),
                    "command": content.get("cmd"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
            # Check for system changes
            elif audit_type in ["SYSCALL", "CONFIG_CHANGE", "USER_ROLE_CHANGE"]:
                return {
                    "event_type": "system_change",
                    "severity": "medium",
                    "mitre_technique": "T1098",  # Account Manipulation
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
        
        # Check for common security keywords in any log type
        message = parsed_log.get("message", "")
        if not message and isinstance(parsed_log.get("_raw"), str):
            message = parsed_log.get("_raw")
            
        if isinstance(message, str):
            message = message.lower()
            
            # Security-related keywords with MITRE mapping
            security_keywords = {
                "attack": {"event": "possible_attack", "mitre": "T1190"},
                "intrusion": {"event": "possible_intrusion", "mitre": "T1190"},
                "malware": {"event": "possible_malware", "mitre": "T1047"},
"virus": {"event": "possible_malware", "mitre": "T1047"},
                "trojan": {"event": "possible_malware", "mitre": "T1047"},
                "rootkit": {"event": "possible_rootkit", "mitre": "T1014"},
                "backdoor": {"event": "possible_backdoor", "mitre": "T1133"},
                "exploit": {"event": "possible_exploit", "mitre": "T1190"},
                "vulnerability": {"event": "possible_vulnerability", "mitre": "T1190"},
                "breach": {"event": "possible_breach", "mitre": "T1078"},
                "command injection": {"event": "possible_injection", "mitre": "T1059"},
                "sql injection": {"event": "possible_injection", "mitre": "T1190"},
                "xss": {"event": "possible_xss", "mitre": "T1059.007"},
                "cross site": {"event": "possible_xss", "mitre": "T1059.007"},
                "csrf": {"event": "possible_csrf", "mitre": "T1565"},
                "overflow": {"event": "possible_overflow", "mitre": "T1190"},
                "denial of service": {"event": "possible_dos", "mitre": "T1498"},
                "ddos": {"event": "possible_ddos", "mitre": "T1498"}
            }
            
            for keyword, info in security_keywords.items():
                if keyword in message:
                    return {
                        "event_type": info["event"],
                        "severity": "high",
                        "timestamp": parsed_log.get("timestamp"),
                        "mitre_technique": info["mitre"],
                        "keyword": keyword,
                        "message": message,
                        "details": parsed_log
                    }
        
        # Not a security event
        return None
    
    def parse_file(self, file_path, max_lines=None):
        """
        Parse a log file and return structured data with security event extraction
        
        Args:
            file_path: Path to the log file
            max_lines: Maximum number of lines to parse (None for all)
            
        Returns:
            tuple: (parsed_logs, security_events)
                parsed_logs: List of all parsed log entries
                security_events: List of detected security events
        """
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            self.logger.error(f"File {file_path} does not exist or is not readable")
            return [], []
            
        # Detect format
        format_name, _ = self.detect_format(file_path)
        
        parsed_logs = []
        security_events = []
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines is not None and i >= max_lines:
                        break
                        
                    if line.strip():
                        parsed = self.parse_line(line, format_name)
                        if parsed:
                            parsed_logs.append(parsed)
                            
                            # Check for security events
                            security_event = self.extract_security_events(parsed)
                            if security_event:
                                security_events.append(security_event)
        except Exception as e:
            self.logger.error(f"Error parsing file {file_path}: {str(e)}")
            
        return parsed_logs, security_events
    
    def get_stats(self):
        """Get parser statistics"""
        return {
            "parser_stats": dict(self.stats),
            "pattern_matcher_stats": self.pattern_matcher.get_stats(),
            "attack_patterns": len(self.compiled_attack_patterns),
            "format_patterns": len(self.compiled_patterns)
        }
