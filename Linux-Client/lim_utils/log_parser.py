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

import re
import json
import logging
import os
from datetime import datetime
from collections import defaultdict

class LogParser:
    """Intelligent log parser with format detection and security event extraction"""
    
    def __init__(self):
        """Initialize the log parser"""
        # Initialize format patterns
        self._init_format_patterns()
        
        # Cache for detected log formats
        self.file_formats = {}
        
        # Statistics for parser usage
        self.stats = defaultdict(int)
        
        # Set up logging
        self.logger = logging.getLogger("lim.parser")
    
    def _init_format_patterns(self):
        """Initialize log format detection patterns"""
        self.format_patterns = {
            # Standard syslog format: Jan 23 10:30:45 hostname process[pid]: message
            "syslog": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Alternate syslog with ISO dates: 2023-01-23T10:30:45+00:00 hostname process[pid]: message
            "syslog_iso": r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z))\s+(\S+)\s+([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)$',
            
            # Common auth log format: Jan 23 10:30:45 hostname sshd[pid]: message
            #"auth": r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(sshd|su|sudo|systemd-logind|login)(?:\[(\d+)\])?:\s+(.*)$',
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
            "rsyslog": r'^(?:<\d+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$'
        }
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.format_patterns.items()
        }
    
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
        Parse a log line into structured data
    
        Args:
            line: Log line string
            format_name: Format name (if known)
    
        Returns:
            dict: Parsed log entry
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
                    return result
            except Exception as e:
                self.logger.debug(f"Error parsing as {format_name}: {str(e)}")
    
        # Fallback: log unmatched lines for debugging
        self.logger.debug(f"[NO MATCH] {line}")
        self.stats["basic_parsed"] += 1
        return {
            "timestamp": None,
            "message": line,
            "_raw": line,
            "_format": "unknown"
        }
    
    def _parse_syslog(self, line):
        """Parse standard syslog format"""
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
        
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message
        }
    
    def _parse_syslog_iso(self, line):
        """Parse syslog with ISO timestamps"""
        match = self.compiled_patterns["syslog_iso"].match(line)
        if not match:
            return None
            
        timestamp, hostname, process, pid, message = match.groups()
        
        return {
            "timestamp": timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message
        }
    
    def _parse_auth(self, line):
        """Parse authentication log format"""
        match = self.compiled_patterns["auth"].match(line)
        if not match:
            return None
            
        timestamp, hostname, service, pid, message = match.groups()
        
        # Extract common auth patterns
        user = None
        ip = None
        action = None
        
        # Extract IP address if present
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        if ip_match:
            ip = ip_match.group(1)
            
        # Extract username if present
        user_patterns = [
            r'user\s+(\w+)',
            r'for\s+(\w+)',
            r'for invalid user\s+(\w+)',
            r'user\s+(\w+)\s+from'
        ]
        
        for pattern in user_patterns:
            user_match = re.search(pattern, message)
            if user_match:
                user = user_match.group(1)
                break
                
        # Determine authentication action
        if 'Failed password' in message or 'authentication failure' in message:
            action = 'failed_login'
        elif 'Accepted password' in message or 'session opened' in message:
            action = 'successful_login'
        elif 'session closed' in message:
            action = 'logout'
        elif 'TTY=tty' in message and service == 'sudo':
            action = 'privilege_escalation'
            
        # Convert timestamp to ISO format
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
            
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "pid": pid,
            "message": message,
            "user": user,
            "ip": ip,
            "action": action
        }
    
    def _parse_web_access(self, line):
        """Parse web server access log format"""
        match = self.compiled_patterns["web_access"].match(line)
        if not match:
            return None
            
        ip, _, user, timestamp, request, status, bytes_sent, referer, user_agent = match.groups()
        
        # Parse request parts
        request_parts = request.split()
        method = request_parts[0] if len(request_parts) > 0 else None
        path = request_parts[1] if len(request_parts) > 1 else None
        http_version = request_parts[2] if len(request_parts) > 2 else None
        
        # Convert timestamp to ISO format
        try:
            # Example: 10/Oct/2023:13:55:36 +0000
            dt = datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
            
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "ip": ip,
            "user": user if user != "-" else None,
            "method": method,
            "path": path,
            "http_version": http_version,
            "status": int(status) if status.isdigit() else status,
            "bytes_sent": int(bytes_sent) if bytes_sent.isdigit() else bytes_sent,
            "referer": referer if referer != "-" else None,
            "user_agent": user_agent if user_agent != "-" else None
        }
    
    def _parse_web_error(self, line):
        """Parse web server error log format"""
        match = self.compiled_patterns["web_error"].match(line)
        if not match:
            return None
            
        timestamp, level, client, message = match.groups()
        
        return {
            "timestamp": timestamp,
            "level": level,
            "client": client,
            "message": message
        }
    
    def _parse_audit(self, line):
        """Parse audit log format"""
        match = self.compiled_patterns["audit"].match(line)
        if not match:
            return None
            
        audit_type, timestamp, audit_id, content = match.groups()
        
        # Parse key-value pairs in content
        parsed_content = {}
        for kv_pair in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', content):
            k, v1, v2 = kv_pair.groups()
            parsed_content[k] = v1 if v1 is not None else v2
            
        return {
            "timestamp": timestamp,
            "audit_type": audit_type,
            "audit_id": audit_id,
            "content": parsed_content,
            "raw_content": content
        }
    
    def _parse_json(self, line):
        """Parse JSON formatted log"""
        try:
            data = json.loads(line)
            
            # Extract timestamp if available in common fields
            timestamp = None
            for ts_field in ['timestamp', 'time', '@timestamp', 'eventTime', 'date']:
                if ts_field in data:
                    timestamp = data[ts_field]
                    break
                    
            return {
                "timestamp": timestamp,
                "data": data
            }
        except json.JSONDecodeError:
            return None
    
    def _parse_key_value(self, line):
        """Parse key-value formatted log"""
        result = {}
        
        for kv_pair in re.finditer(r'([A-Za-z0-9_\-]+)=(?:"([^"]*)"|([^ ]+))', line):
            k, v1, v2 = kv_pair.groups()
            result[k] = v1 if v1 is not None else v2
            
        # Extract timestamp if available
        timestamp = None
        for ts_field in ['timestamp', 'time', 'date']:
            if ts_field in result:
                timestamp = result[ts_field]
                break
                
        return {
            "timestamp": timestamp,
            "data": result
        }
    
    def _parse_simple_timestamp(self, line):
        """Parse simple timestamp format"""
        match = self.compiled_patterns["simple_timestamp"].match(line)
        if not match:
            return None
            
        timestamp, message = match.groups()
        
        return {
            "timestamp": timestamp,
            "message": message
        }
    
    def _parse_firewall(self, line):
        """Parse firewall log format"""
        match = self.compiled_patterns["firewall"].match(line)
        if not match:
            return None
            
        timestamp, hostname, fw_type = match.groups()
        
        # Extract common firewall log components
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = None
        action = None
        
        # Source IP
        src_match = re.search(r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if src_match:
            src_ip = src_match.group(1)
            
        # Destination IP
        dst_match = re.search(r'DST=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
        if dst_match:
            dst_ip = dst_match.group(1)
            
        # Source port
        sport_match = re.search(r'SPT=(\d+)', line)
        if sport_match:
            src_port = int(sport_match.group(1))
            
        # Destination port
        dport_match = re.search(r'DPT=(\d+)', line)
        if dport_match:
            dst_port = int(dport_match.group(1))
            
        # Protocol
        proto_match = re.search(r'PROTO=(\w+)', line)
        if proto_match:
            protocol = proto_match.group(1)
            
        # Action (ACCEPT, DROP, REJECT)
        for act in ['ACCEPT', 'DROP', 'REJECT', 'BLOCK']:
            if act in line:
                action = act.lower()
                break
                
        # Convert timestamp to ISO format
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
            
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "firewall_type": fw_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "message": line
        }
    
    def _parse_windows_event(self, line):
        """Parse Windows event log format"""
        # This is a basic implementation since Windows events span multiple lines
        # In a real implementation, you'd need to handle multi-line parsing
        match = self.compiled_patterns["windows_event"].match(line)
        if not match:
            return None
            
        log_name = match.group(1)
        
        # Try to extract other common fields
        timestamp = None
        event_id = None
        level = None
        
        time_match = re.search(r'Date:\s+(.*?)$', line)
        if time_match:
            timestamp = time_match.group(1)
            
        id_match = re.search(r'Event ID:\s+(\d+)', line)
        if id_match:
            event_id = id_match.group(1)
            
        level_match = re.search(r'Level:\s+(\w+)', line)
        if level_match:
            level = level_match.group(1)
            
        return {
            "log_name": log_name,
            "timestamp": timestamp,
            "event_id": event_id,
            "level": level,
            "message": line
        }
    
    def _parse_rsyslog(self, line):
        """Parse rsyslog format"""
        match = self.compiled_patterns["rsyslog"].match(line)
        if not match:
            return None
            
        timestamp, hostname, message = match.groups()
        
        # Try to extract process name and pid
        process = None
        pid = None
        
        process_match = re.search(r'^([^\[:\s]+)(?:\[(\d+)\])?:\s+(.*)', message)
        if process_match:
            process, pid, message = process_match.groups()
            
        # Convert timestamp to ISO format
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            if dt > datetime.now():
                dt = datetime.strptime(f"{current_year-1} {timestamp}", "%Y %b %d %H:%M:%S")
            iso_timestamp = dt.isoformat()
        except Exception:
            iso_timestamp = None
            
        return {
            "timestamp": iso_timestamp,
            "original_timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message
        }
    
    def extract_security_events(self, parsed_log):
        """
        Extract security-relevant events from parsed log entries
    
        Args:
            parsed_log: Dictionary of parsed log data
    
        Returns:
            dict: Security event data or None if not a security event
        """
        if not parsed_log:
            return None
    
        format_type = parsed_log.get("_format", "unknown")
    
        # Authentication-related events
        if format_type == "auth":
            action = parsed_log.get("action")
            message = parsed_log.get("message", "").lower()
    
            # Fallback detection if action is missing
            if not action:
                if "failed password" in message:
                    action = "failed_login"
                elif "invalid user" in message:
                    action = "failed_login"  # treat invalid user as failed login
                elif "accepted password" in message:
                    action = "successful_login"
                elif "sudo" in message:
                    action = "privilege_escalation"
    
            if action in ["failed_login", "successful_login", "privilege_escalation"]:
                return {
                    "event_type": action,
                    "severity": "high" if action in ["failed_login", "privilege_escalation"] else "medium",
                    "user": parsed_log.get("user"),
                    "ip": parsed_log.get("ip"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
        # Web server security events
        elif format_type == "web_access":
            status = parsed_log.get("status")
            path = parsed_log.get("path", "")
            
            # Detect potential attacks in URL
            attack_patterns = [
                (r'(?:\.\./|\.\.\\)', "path_traversal"),
                (r'(?:select.*from|union.*select|insert.*into|update.*set|delete.*from)', "sql_injection"),
                (r'(?:eval\(|exec\(|system\()', "code_injection"),
                (r'(?:script>|javascript:|<iframe)', "xss"),
                (r'(?:etc/passwd|/etc/shadow|/proc/self)', "sensitive_file_access")
            ]
            
            for pattern, attack_type in attack_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return {
                        "event_type": "web_attack",
                        "attack_type": attack_type,
                        "severity": "high",
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
                    "ip": parsed_log.get("ip"),
                    "timestamp": parsed_log.get("timestamp"),
                    "path": path,
                    "status": status,
                    "details": parsed_log
                }
                
        # Firewall events
        elif format_type == "firewall":
            action = parsed_log.get("action")
            if action in ["drop", "reject", "block"]:
                return {
                    "event_type": "firewall_block",
                    "severity": "medium",
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
            
            # Check for relevant audit types
            if audit_type in ["USER_AUTH", "USER_LOGIN", "USER_CMD", "USER_ACCT"]:
                return {
                    "event_type": "audit_" + audit_type.lower(),
                    "severity": "medium",
                    "user": content.get("acct") or content.get("user"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
            # Check for privilege escalation
            elif audit_type in ["USER_CMD"] and "sudo" in content.get("cmd", ""):
                return {
                    "event_type": "privilege_escalation",
                    "severity": "high",
                    "user": content.get("acct") or content.get("user"),
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
                
            # Check for system changes
            elif audit_type in ["SYSCALL", "CONFIG_CHANGE", "USER_ROLE_CHANGE"]:
                return {
                    "event_type": "system_change",
                    "severity": "medium",
                    "timestamp": parsed_log.get("timestamp"),
                    "details": parsed_log
                }
        
        # Check for common security keywords in any log type
        message = parsed_log.get("message", "")
        if not message and isinstance(parsed_log.get("_raw"), str):
            message = parsed_log.get("_raw")
            
        if isinstance(message, str):
            message = message.lower()
            
            # Security-related keywords
            security_keywords = {
                "attack": "possible_attack",
                "intrusion": "possible_intrusion",
                "malware": "possible_malware",
                "virus": "possible_malware",
                "trojan": "possible_malware",
                "rootkit": "possible_rootkit",
                "backdoor": "possible_backdoor",
                "exploit": "possible_exploit",
                "vulnerability": "possible_vulnerability",
                "breach": "possible_breach",
                "command injection": "possible_injection",
                "sql injection": "possible_injection",
                "xss": "possible_xss",
                "cross site": "possible_xss",
                "csrf": "possible_csrf",
                "overflow": "possible_overflow",
                "denial of service": "possible_dos",
                "ddos": "possible_ddos"
            }
            
            for keyword, event_type in security_keywords.items():
                if keyword in message:
                    return {
                        "event_type": event_type,
                        "severity": "high",
                        "timestamp": parsed_log.get("timestamp"),
                        "keyword": keyword,
                        "message": message,
                        "details": parsed_log
                    }
        
        # Not a security event
        return None
    
    def parse_file(self, file_path, max_lines=None):
        """
        Parse a log file and return structured data
        
        Args:
            file_path: Path to the log file
            max_lines: Maximum number of lines to parse (None for all)
            
        Returns:
            list: List of parsed log entries
        """
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            self.logger.error(f"File {file_path} does not exist or is not readable")
            return []
            
        # Detect format
        format_name, _ = self.detect_format(file_path)
        
        results = []
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines is not None and i >= max_lines:
                        break
                        
                    if line.strip():
                        parsed = self.parse_line(line, format_name)
                        if parsed:
                            results.append(parsed)
        except Exception as e:
            self.logger.error(f"Error parsing file {file_path}: {str(e)}")
            
        return results
    
    def get_stats(self):
        """Get parser statistics"""
        return dict(self.stats)
    
    def reset_stats(self):
        """Reset parser statistics"""
        self.stats = defaultdict(int)
