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
import logging
from pathlib import Path
from collections import defaultdict

# Common log directories to scan
DEFAULT_LOG_DIRS = [
    "/var/log",
    "/var/adm",
    "/var/messages",
    "/usr/local/apache/logs",
    "/usr/local/nginx/logs",
    "/var/spool/mail",
    "/var/spool/mqueue",
]

# Patterns for log classification
LOG_PATTERNS = {
    "auth": [
        r'auth\.log$',
        r'secure$',
        r'sshd\.log$',
        r'lastlog$',
        r'authlog$',
        r'pam.*\.log$',
        r'login\.log$'
    ],
    "system": [
        r'syslog$',
        r'messages$',
        r'dmesg$',
        r'kern\.log$',
        r'daemon\.log$',
        r'cron\.log$',
        r'boot\.log$'
    ],
    "application": [
        r'app\.log$',
        r'application\.log$',
        r'debug\.log$',
        r'error\.log$'
    ],
    "network": [
        r'ufw\.log$',
        r'firewall\.log$',
        r'iptables\.log$',
        r'pf\.log$',
        r'nftables\.log$',
        r'dhcp.*\.log$',
        r'traffic\.log$'
    ],
    "audit": [
        r'audit\.log$',
        r'auditd\.log$',
        r'compliance\.log$',
        r'lynis.*\.log$',
        r'aide.*\.log$'
    ],
    "web": [
        r'(apache2|httpd|nginx)/access\.log$',
        r'(apache2|httpd|nginx)/error\.log$',
        r'httpd/.*\.log$',
        r'nginx/.*\.log$',
        r'lighttpd/.*\.log$',
        r'access_log$',
        r'error_log$'
    ],
    "database": [
        r'mysql.*\.log$',
        r'postgresql.*\.log$',
        r'mongodb.*\.log$',
        r'mariadb.*\.log$',
        r'oracle.*\.log$',
        r'sqlite.*\.log$'
    ],
    "mail": [
        r'mail\.log$',
        r'maillog$',
        r'dovecot\.log$',
        r'postfix\.log$',
        r'sendmail\.log$',
        r'exim.*\.log$'
    ],
    "ssh": [
        r'ssh.*\.log$',
        r'sftp.*\.log$'
    ],
    "ftp": [
        r'ftp\.log$',
        r'vsftpd\.log$',
        r'proftpd.*\.log$'
    ]
}

def discover_and_classify_logs(base_dirs=None, include_all=False):
    """
    Discover and classify log files across the system
    
    Args:
        base_dirs: List of directories to scan (defaults to common log directories)
        include_all: Whether to include all .log files or only known types
        
    Returns:
        Dictionary of categorized log files
    """
    if base_dirs is None:
        base_dirs = [d for d in DEFAULT_LOG_DIRS if os.path.exists(d)]
        
    if not base_dirs:
        logging.warning("No valid log directories found to scan")
        return {}
        
    # Initialize categories
    log_categories = defaultdict(list)
    
    # Precompile all patterns for efficiency
    compiled_patterns = {}
    for category, patterns in LOG_PATTERNS.items():
        compiled_patterns[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    # Track files already classified
    classified_files = set()
    
    # Scan all directories
    for base_dir in base_dirs:
        logging.info(f"Scanning {base_dir} for log files")
        try:
            for root, dirs, files in os.walk(base_dir):
                for filename in files:
                    # Skip files that don't look like logs
                    if not is_log_file(filename):
                        continue
                        
                    full_path = os.path.join(root, filename)
                    
                    # Skip if not readable
                    if not os.access(full_path, os.R_OK):
                        logging.warning(f"Skipping {full_path} - not readable")
                        continue
                        
                    # Skip if too large (>100MB)
                    try:
                        if os.path.getsize(full_path) > 100 * 1024 * 1024:
                            logging.warning(f"Skipping {full_path} - file too large")
                            continue
                    except OSError:
                        logging.warning(f"Could not get size for {full_path}")
                        continue
                        
                    # Categorize the log file
                    categorized = False
                    for category, patterns in compiled_patterns.items():
                        if any(pattern.search(full_path) for pattern in patterns):
                            log_categories[category].append(full_path)
                            classified_files.add(full_path)
                            categorized = True
                            break
                            
                    # Add to "other" if not categorized but include_all is True
                    if not categorized and include_all:
                        log_categories["other"].append(full_path)
                        classified_files.add(full_path)
        except PermissionError:
            logging.warning(f"Permission denied when scanning {base_dir}")
        except Exception as e:
            logging.error(f"Error scanning {base_dir}: {str(e)}")
    
    # Sort each category
    for category in log_categories:
        log_categories[category] = sorted(log_categories[category])
    
    logging.info(f"Discovered {sum(len(logs) for logs in log_categories.values())} log files across {len(log_categories)} categories")
    return dict(log_categories)

def is_log_file(filename):
    """Check if a file is likely a log file based on extension and patterns"""
    # Standard log extensions
    if filename.endswith('.log'):
        return True
        
    # Common log file names without extensions
    if filename in ['syslog', 'messages', 'secure', 'lastlog', 'wtmp', 'btmp', 'dmesg']:
        return True
        
    # Log files with rotation numbers
    if re.match(r'.*\.log\.\d+$', filename) and not filename.endswith('.gz'):
        return True
        
    return False

def identify_critical_logs(log_categories):
    """
    Identify critical security logs that should be prioritized for monitoring
    
    Args:
        log_categories: Dictionary of categorized log files
        
    Returns:
        List of critical log files
    """
    critical_logs = []
    
    # High-priority categories and specific log files
    high_priority = {
        "auth": 10,      # Highest priority - authentication logs
        "audit": 9,      # Audit logs
        "ssh": 8,        # SSH-specific logs
        "system": 7,     # System logs
        "network": 6,    # Network/firewall logs 
        "web": 5,        # Web server logs
        "database": 4,   # Database logs
        "mail": 3,       # Mail server logs
        "ftp": 2,        # FTP logs
        "application": 1 # Application logs
    }
    
    # Critical log patterns (specific files that are always important)
    critical_patterns = [
        r'/var/log/auth\.log$',
        r'/var/log/secure$',
        r'/var/log/audit/audit\.log$',
        r'/var/log/syslog$',
        r'/var/log/messages$',
        r'/var/log/kern\.log$',
        r'/var/log/apache2/access\.log$',
        r'/var/log/nginx/access\.log$',
        r'/var/log/httpd/access_log$',
        r'/var/log/apache2/error\.log$',
        r'/var/log/nginx/error\.log$',
        r'/var/log/httpd/error_log$',
        r'/var/log/mysql/mysql\.log$',
        r'/var/log/postgresql/postgresql\.log$',
        r'/var/log/ufw\.log$',
        r'/var/log/firewall\.log$',
        r'/var/log/iptables\.log$'
    ]
    
    # First add known critical logs
    for pattern in critical_patterns:
        pattern_re = re.compile(pattern)
        for category, logs in log_categories.items():
            for log_file in logs:
                if pattern_re.search(log_file) and log_file not in critical_logs:
                    critical_logs.append(log_file)
    
    # Then add by category priority
    for category, priority in sorted(high_priority.items(), key=lambda x: x[1], reverse=True):
        if category in log_categories:
            for log_file in log_categories[category]:
                if log_file not in critical_logs:
                    critical_logs.append(log_file)
    
    return critical_logs

def estimate_log_importance(log_file):
    """
    Estimate the security importance of a log file based on content sampling
    
    Args:
        log_file: Path to log file
        
    Returns:
        importance_score: 0-10 score of estimated security importance
        tags: List of tags indicating the type of content found
    """
    importance_score = 0
    tags = []
    
    # Check filename/path first (quick check before opening file)
    path_lower = log_file.lower()
    
    # Security-related keywords in path
    security_path_keywords = [
        'auth', 'secure', 'ssh', 'audit', 'security', 'fail', 
        'firewall', 'iptables', 'ufw', 'access', 'login'
    ]
    
    for keyword in security_path_keywords:
        if keyword in path_lower:
            importance_score += 1
            tags.append(f"path_contains_{keyword}")
    
    # Security-related content keywords
    security_content_keywords = {
        'authentication failure': 3,
        'failed password': 3,
        'invalid user': 3,
        'permission denied': 2,
        'unauthorized': 2,
        'security alert': 3,
        'intrusion': 3,
        'attack': 2,
        'exploit': 3,
        'malicious': 2,
        'violation': 2,
        'suspicious': 2,
        'blocked': 1,
        'rejected': 1,
        'denied': 1
    }
    
    # Sample the file content
    try:
        # Read at most 100 lines or 50KB
        sample_size = 0
        sample_lines = []
        
        with open(log_file, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 100 or sample_size > 50 * 1024:
                    break
                sample_lines.append(line)
                sample_size += len(line)
        
        # Check content
        for line in sample_lines:
            line_lower = line.lower()
            for keyword, score in security_content_keywords.items():
                if keyword in line_lower:
                    importance_score += score
                    tags.append(f"content_contains_{keyword.replace(' ', '_')}")
        
        # Cap the score at 10
        importance_score = min(10, importance_score)
        
    except Exception as e:
        logging.warning(f"Error sampling {log_file}: {str(e)}")
    
    return importance_score, list(set(tags))  # Remove duplicate tags

if __name__ == "__main__":
    # Set up logging for standalone use
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Discover and print log files
    logs = discover_and_classify_logs()
    
    print("\nDiscovered log files by category:")
    for category, log_files in logs.items():
        print(f"\n{category.upper()} LOGS ({len(log_files)}):")
        for log_file in log_files:
            print(f"  - {log_file}")
    
    # Identify critical logs
    critical = identify_critical_logs(logs)
    
    print("\nCritical security logs:")
    for log_file in critical[:20]:  # Show top 20
        print(f"  - {log_file}")
        
    if len(critical) > 20:
        print(f"  ... and {len(critical) - 20} more")
