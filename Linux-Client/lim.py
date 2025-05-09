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
#!/usr/bin/env python3

import argparse
import datetime
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import hashlib
from collections import defaultdict
import threading
import daemon
from daemon import pidfile
import numpy as np
from sklearn.ensemble import IsolationForest

BASE_DIR="/opt/FIMoniSec/Linux-Client"

class LogIntegrityMonitor:
    def __init__(self, config_file=None, base_dir=None):
        # Setup base directory and paths - use parameter or default to constant
        self.base_dir = base_dir or BASE_DIR
        os.makedirs(self.base_dir, exist_ok=True)
        
        self.output_dir = os.path.join(self.base_dir, "output")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Config initialization - create the config attribute first to avoid the error
        self.config = {}
        self.config_file = config_file or os.path.join(self.base_dir, "fim.config")
        self.config = self.load_config()
        
        # Initialize log positions tracking
        self.log_positions = {}
        self.positions_file = os.path.join(self.output_dir, "log_positions.json")
        self.load_log_positions()
        
        # State flags
        self.running = False
        self.ml_models = {}
        
        # Initialize attack patterns
        self.initialize_attack_patterns()
        
        # PID file for daemon mode - moved to output directory
        self.pid_file = os.path.join(self.output_dir, "lim.pid")

    def setup_logging(self):
        """Setup logging configuration with log files in the logs directory"""
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(self.base_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        # Set log file path inside logs directory
        log_file = os.path.join(logs_dir, "lim.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("LIM")
        self.logger.info("Log Integrity Monitor initializing...")

    def load_config(self):
        """Load or create configuration file while preserving existing structure"""
        DEFAULT_CONFIG = {
            "log_integrity_monitor": {
                "enabled": True,
                "monitored_logs": [],
                "log_categories": {},
                "excluded_ips": [],
                "excluded_users": [],
                "ml_analysis": {
                    "enabled": True,
                    "training_period": 3600,  # 1 hour in seconds
                    "anomaly_threshold": 0.8,
                    "min_training_samples": 1000
                },
                "retention": {
                    "alert_retention_days": 30,
                    "model_retention_days": 90
                },
                "alert_suppression_window": 60,  # seconds
                "log_level": "INFO"
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.logger.info(f"Configuration loaded from {self.config_file}")
                    
                    # Preserve existing config and add required sections if missing
                    if "log_integrity_monitor" not in config:
                        self.logger.warning("Missing 'log_integrity_monitor' section in config, adding default")
                        config["log_integrity_monitor"] = DEFAULT_CONFIG["log_integrity_monitor"]
                        
                    # Ensure all required sub-keys exist
                    lim_config = config["log_integrity_monitor"]
                    needs_update = False
                    
                    # Check for and add missing sub-keys
                    for key, default_value in DEFAULT_CONFIG["log_integrity_monitor"].items():
                        if key not in lim_config:
                            lim_config[key] = default_value
                            self.logger.warning(f"Added missing '{key}' to config")
                            needs_update = True
                    
                    # Check if log scan is needed to populate config
                    needs_scan = False
                    if not lim_config.get("monitored_logs"):
                        self.logger.warning("Empty 'monitored_logs' in config, will scan for logs")
                        needs_scan = True
                    
                    if not lim_config.get("log_categories"):
                        self.logger.warning("Empty 'log_categories' in config, will categorize logs")
                        needs_scan = True
                    
                    # Save updated config if needed
                    if needs_update:
                        with open(self.config_file, 'w') as f:
                            json.dump(config, f, indent=4)
                        self.logger.info("Updated configuration with missing keys")
                    
                    # Return the config now - scan_logs will be called after initialization
                    return config
                    
            except Exception as e:
                self.logger.error(f"Error loading config: {str(e)}")
                self.logger.info("Using default configuration")
                return DEFAULT_CONFIG
        else:
            self.logger.info(f"Config file not found, creating default at {self.config_file}")
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            return DEFAULT_CONFIG

    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving config: {str(e)}")
    
    def load_log_positions(self):
        """Load log file positions from saved state"""
        if os.path.exists(self.positions_file):
            try:
                with open(self.positions_file, 'r') as f:
                    self.log_positions = json.load(f)
                self.logger.info(f"Log positions loaded from {self.positions_file}")
            except Exception as e:
                self.logger.error(f"Error loading log positions: {str(e)}")
                self.log_positions = {}
        else:
            self.log_positions = {}
            self.logger.info("No saved log positions found, will start from current position")
    
    def save_log_positions(self):
        """Save current log file positions to state file"""
        try:
            with open(self.positions_file, 'w') as f:
                json.dump(self.log_positions, f, indent=4)
            self.logger.debug(f"Log positions saved to {self.positions_file}")
        except Exception as e:
            self.logger.error(f"Error saving log positions: {str(e)}")
    
    def initialize_attack_patterns(self):
        """Initialize attack pattern detection with MITRE ATT&CK mapping and tuned patterns to reduce false positives"""
        # Create lookup lists of known system processes and services to exclude from detection
        self.known_system_services = [
            "systemd", "dbus", "NetworkManager", "rsyslogd", "crond", "ntpd", "chronyd", 
            "snapd", "apt", "dpkg", "yum", "dnf", "logrotate", "accounts-daemon", 
            "udev", "polkit", "avahi", "cups", "sshd", "gdm", "lightdm", "apache2", 
            "nginx", "mysql", "mariadb", "postgresql", "cron", "atd", "ntp", "ssh",
            "kernel", "systemd-udevd", "systemd-journald", "systemd-logind", "udisksd"
        ]
    
        self.benign_systemd_actions = [
            "Started", "Stopped", "Reloaded", "Condition check", "Reached target",
            "Listening on", "Created slice", "Removed slice", "Starting", "Stopping",
            "Startup finished", "Session", "Closed", "Received", "Mounted", "Unmounted"
        ]
    
        # Format: (pattern, attack_name, mitre_id, severity)
        self.attack_patterns = [
            # Credential Access (TA0006)
            (r'\b(?:password|passwd)\s+cracking\b|\bjohn\s+the\s+ripper\b|\bhashcat\b', "password_cracking", "T1110", "medium"),
            (r'\bmimikatz\b|\bgsecdump\b|\bwce\b|\blsadump\b|\bntds\.dit\b|\bSAM\b', "credential_dumping", "T1003", "high"),
            (r'\bkerberos\s+ticket|\bkrbtgt\b|\bTGT\b|\bTGS\b|\bgolden\s+ticket\b|\bsilver\s+ticket\b', "kerberos_attack", "T1558", "high"),
            (r'cat\s+\/etc\/shadow\b|cat\s+\/etc\/passwd\b|\bunshadow\b', "credential_dumping", "T1003.008", "high"),
            (r'memory\s+\.dump\b|\bmemdump\b|\/proc\/kcore\b|\/dev\/mem\b', "memory_dump", "T1003.001", "high"),
            (r'(?:chmod|chown|rm|mv|cat)\s+.*(?:\/var\/log\/auth\.log|\/var\/log\/secure|\/var\/log\/audit)', "auth_log_tampering", "T1070.002", "high"),
            
            # Privilege Escalation (TA0004)
            (r'\bkernel\s+exploit\b|exploit\s+CVE\-\d+\-\d+', "kernel_exploit", "T1068", "high"),
            (r'\bsudo\s+\-u\s+root\b|\bsudo\s+\-s\b|\bsudo\s+su\b\s*$|\bsudo\s+\/bin\/bash\b', "sudo_misuse", "T1548.003", "medium"),
            (r'chmod\s+(?:u\+s|4755|4777|a\+x|777)\s+(?:\/bin\/|\/etc\/|\/usr\/|\/sbin\/)', "setuid_modification", "T1548.001", "high"),
            (r'\bpolkit\b|\bpkexec\b.*\b\-\-user\s+root\b|\bdbus-send\b.*\bPolicyKit', "polkit_exploit", "T1068", "high"),
            (r'export\s+LD_PRELOAD=|\bexport\s+LD_LIBRARY_PATH=', "dynamic_linker_hijacking", "T1574.006", "high"),
            (r'(?:\binsmod\b|\bmodprobe\b)\s+(?!.*nvidia|.*bluetooth|.*wifi|.*sound).*\.ko\b', "kernel_module_loading", "T1547.006", "high"),
            (r'\binit_module\(|\bfinit_module\(|\bcreate_module\(', "kernel_module_syscalls", "T1547.006", "high"),
            
            # Defense Evasion (TA0005)
            (r'\bunset\s+HISTFILE\b|\bHISTSIZE\=0\b|\bHISTFILESIZE\=0\b|\bhistory\s+\-c\b', "history_clearing", "T1070.003", "medium"),
            (r'(?:\brm\b|\bshred\b|\bwipe\b|\bcat\s+\/dev\/null\s+>\b|\b>\s+|\btruncate\b)\s+(?:\/var\/log\/|\/var\/audit\/)', "log_tampering", "T1070.002", "high"),
            (r'\btouch\s+\-[acdmr]\b.*|\btimestomp\b', "timestamp_modification", "T1070.006", "medium"),
            (r'\brmmod\s+\b|\bmodprobe\s+\-r\b', "unload_kernel_module", "T1070.002", "high"),
            (r'\biptables\s+\-F\b|\bufw\s+disable\b|\bfirewalld\s+stop\b|\bsystemctl\s+stop\s+firewalld\b', "firewall_disable", "T1562.004", "high"),
            (r'\bauditd\s+stop\b|\bsystemctl\s+stop\s+auditd\b|\bservice\s+auditd\s+stop\b|\bkill\s+\-9\s+.*\bauditd\b', "audit_disable", "T1562.006", "high"),
            (r'echo\s+[0-9]\s+>\s+\/proc\/sys\/kernel\/yama\/', "yama_disable", "T1562.003", "high"),
            (r'echo\s+[0-9]\s+>\s+\/proc\/sys\/kernel\/kptr_restrict\b|\/etc\/sysctl\.conf.*kptr_restrict\=0\b', "kptr_restrict_disable", "T1562.001", "high"),
            (r'(?:chmod|touch)\s+.*\/dev\/shm\/.*\.(?:sh|elf|bin|so)\b|(?:chmod|touch)\s+.*\/tmp\/.*\.(?:sh|elf|bin|so)\b|\/run\/shm\/.*\.(?:sh|elf|bin|so)\b', "fileless_execution", "T1559", "high"),
            (r'\bmemfd_create\b|\bmemfd:\b', "fileless_execution", "T1559", "high"),
            (r'\bftrace\s+\-p\b|\bkprobe\s+attach\b|\bio_uring_setup\b', "advanced_rootkit_technique", "T1014", "critical"),
            
            # Persistence (TA0003) - REFINED TO REDUCE FALSE POSITIVES
            (r'\bcrontab\s+\-e\b|\becho\s+.*\s+>>\s+\/etc\/cron|\becho\s+.*\s+>>\s+\/var\/spool\/cron\/', "cron_modification", "T1053.003", "medium"),
            # Modified systemd detection to exclude normal notifications - look for service creation/modification
            (r'(?:systemctl\s+enable|systemctl\s+unmask|systemd-run\s+\-\-unit|systemctl\s+edit|systemctl\s+set-property)|(?:\btouch\b|\bvi\b|\bvim\b|\bnano\b|\becho\b)\s+.*\.service', "service_modification", "T1543.002", "medium"),
            # Modified to look for account manipulation with more specificity
            (r'(?:usermod\s+\-G\s+(?:sudo|wheel|admin)|useradd\s+\-G\s+(?:sudo|wheel|admin)|userdel\s+\-r|userdel\s+\-f|\bvipw\b|echo\s+.*\s+>>\s+\/etc\/passwd|echo\s+.*\s+>>\s+\/etc\/shadow|\bchage\s+\-d|echo\s+.*\s+>>\s+\/etc\/sudoers)', "account_manipulation", "T1098", "high"),
            (r'(?:echo\s+.*\s+>>\s+.*\.ssh\/authorized_keys|ssh-copy-id\s+\-i|echo\s+.*\s+>>\s+\/etc\/ssh\/sshd_config)', "ssh_key_manipulation", "T1098", "high"),
            # Refined shell startup files to look for modification
            (r'(?:\becho\b|\bcat\b|\btouch\b|\bvi\b|\bvim\b|\bnano\b)\s+.*(?:\.bash_profile|\.bashrc|\.profile|\.zshrc)', "shell_startup_files", "T1546.004", "medium"),
            (r'(?:\btouch\b|\becho\b|\bcat\b|\bvi\b|\bvim\b|\bnano\b)\s+.*\/etc\/ld\.so\.preload\b', "ld_preload", "T1574.006", "high"),
            (r'(?:\btouch\b|\becho\b|\bcat\b|\bvi\b|\bvim\b|\bnano\b)\s+.*(?:\/etc\/xdg\/autostart\/|\.config\/autostart\/)', "desktop_autostart", "T1547.013", "medium"),
            (r'(?:insmod\s+|modprobe\s+)(?!.*nvidia|.*bluetooth|.*wifi|.*audio)', "kernel_module_persistence", "T1547.006", "high"),
            
            # Command and Control (TA0011)
            (r'(?:\bnc\b|\bnetcat\b|\bncat\b).{1,30}(?:\-e\b|\-c\b|\bbash\b|\bcmd\b|\bpowershell\b|\bsh\b)', "reverse_shell", "T1071.001", "high"),
            (r'(?:\/dev\/tcp\/|\bsocat\b|\btelnet\b).*\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}\:[0-9]+', "network_connection", "T1071", "medium"),
            (r'\bdns\s+exfiltration\b|(?:\bdig\b|\bnslookup\b|\bhost\b)\s+.*(?:\bANY\b|\bTXT\b|\bMX\b|\bAAAA\b)\s+.*\.(?:xyz|tk|ml|ga|cf|gq)', "dns_tunneling", "T1071.004", "high"),
            (r'\bbeacon\b|\bimplant\b|\bc2\b|\bcommand\s+and\s+control\b|\bcallback\b', "c2_communication", "T1095", "high"),
            (r'\bcurl\s+\-s\b|\bwget\s+\-q\b|\bfetch\s+\-q\b', "quiet_download", "T1105", "medium"),
            (r'\biodine\b|\bdnscat\b|\bptunnel\b|\budptunnel\b', "protocol_tunneling", "T1572", "high"),
            (r'\bchisel\b|\bngrok\b|\bpagekite\b|\bserveo\b', "proxy_tunneling", "T1090", "high"),
            
            # Discovery (TA0007)
            (r'\bnmap\s+|\b\-sS\b|\b\-sV\b|\b\-sT\b|\b\-A\b|\b\-p\s*\d+\b|\b\-\-open\b', "port_scanning", "T1046", "medium"),
            (r'for\s+pid\s+in\s+\/proc\/[0-9]', "process_discovery", "T1057", "low"),
            (r'for\s+ip\s+in\s+(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}', "network_discovery", "T1016", "low"),
            # Modified to avoid matching web requests and database logs
            (r'\bid\s+\-u\b|\bwho\s+am\s+i\b|\bgroups\b\s+|\bw\b\s+|\busers\b\s+|\bwhoami\b', "user_discovery", "T1033", "low"),
            (r'\buname\s+\-a\b|\bcat\s+\/etc\/\*release\b|\blsb_release\b', "system_info_discovery", "T1082", "low"),
            (r'\bfind\s+\/\s+\-perm\b|\bfind\s+\/\s+\-user\s+root\b|\bfind\s+\/home\s+\-type\s+f\b|\bfind\s+\/\s+\-name\s+\.ssh\b', "file_discovery", "T1083", "low"),
            (r'\bss\s+\-tuln\b|\bnetstat\s+\-antp\b|\blsof\s+\-i\b', "network_service_discovery", "T1046", "low"),
            (r'\bjournalctl\s+\-f\b|\bausearch\s+\-ts\b|\bgrep\s+\-r\s+.*\/var\/log\b', "log_discovery", "T1082", "low"),
            
            # Lateral Movement (TA0008)
            (r'(?:\bssh\b|\bscp\b).{1,30}\-i\s+.*\.key', "remote_access", "T1021.004", "medium"),
            (r'(?:\bsmbclient\b|\bsmb:\b|\bcifs:\b|\bmount\s+\-t\s+cifs\b|\bnet\s+use\b)', "smb_access", "T1021.002", "medium"),
            (r'(?:\bwinexe\b|\bwmic\b|\bxfreerdp\b|\brdesktop\b|\bmstsc\b)', "remote_service", "T1021", "medium"),
            (r'\bpsexec\b|\bxfreerdp\b|\bvncviewer\b|\brdesktop\b', "remote_services", "T1021", "medium"),
            (r'\bssh-keygen\b|\bssh-copy-id\b|\becho\s+.*\s+>>\s+.*authorized_keys\b', "ssh_key_manipulation", "T1098", "medium"),
            (r'\bexpect\s+script\b|\bsshpass\s+\-p\b', "password_in_command", "T1552.001", "medium"),
            
            # Collection (TA0009)
            (r'(?:\btar\s+\-[cz]|\bzip\b|\brar\b|\b7z\b|\bgzip\b)\s+.*(?:\/etc\/|\/var\/|\/usr\/|\/home\/|\.ssh\/)', "data_archive", "T1560", "medium"),
            (r'(?:\bcp\b|\bscp\b|\brsync\b|\bcat\b|\btee\b).*(?:\/etc\/shadow\b|\/etc\/passwd\b|\bid_rsa\b|\.ssh\/|\bknown_hosts\b)', "data_collection", "T1005", "high"),
            (r'(?:\bmysqldump\b|\bpg_dump\b|\bsqlite3\b|\bmongodump\b)', "database_dump", "T1005", "medium"),
            (r'\btshark\b|\btcpdump\b|\bwireshark\b|\bethereal\b', "packet_capture", "T1040", "medium"),
            (r'\bpstree\b\s+\-a|\bps\s+aux\s+\|\s+grep\b|\bps\s+\-ef\s+\|\s+grep\b|\btop\s+\-\b', "process_discovery", "T1057", "low"),
            (r'\bscreenshot\b|\bimlib2\b|\bxwd\b|\bimport\s+\-window\b', "screen_capture", "T1113", "medium"),
            (r'for\s+fd\s+in\s+\/proc\/self\/fd\b|cat\s+\/proc\/self\/environ\b|ls\s+\-la\s+\/dev\/pts\b', "process_discovery", "T1057", "medium"),
            
            # Exfiltration (TA0010)
            (r'(?:\bcurl\b|\bwget\b|\bftp\b|\bscp\b|\bsftp\b|\bssh\b).*(?:[0-9]{1,3}\.){3}[0-9]{1,3}.*(?:\/etc\/passwd\b|\/etc\/shadow\b|\.ssh\/|id_rsa|\/var\/log\/)', "data_exfiltration", "T1048", "high"),
            (r'(?:\bmail\b|\bsendmail\b|\bexim\b|\bpostfix\b).*\-s\s+.*(?:\/etc\/passwd\b|\/etc\/shadow\b|\.ssh\/|id_rsa|\/var\/log\/)', "email_exfiltration", "T1048.003", "high"),
            (r'\bbase64\s+.*\|\s*curl\b|\bbase64\s+.*\|\s*nc\b', "data_encoding", "T1132.001", "medium"),
            (r'\bxxd\s+\-p\b|\bhexdump\b\s+\-C|\bod\s+\-t\s+x1\b', "data_encoding", "T1132", "medium"),
            (r'\bsteghide\b|\boutguess\b|\bsteganography\b|\bsteganographic\b', "steganography", "T1027", "high"),
            (r'\bcryptcat\b|\bopenssl\s+enc\b', "encrypted_channel", "T1573", "high"),
            
            # Impact (TA0040)
            (r'(?:\brm\s+\-rf\s+\/\b|\brm\s+\-rf\s+\/home\b|\bfind\s+\/\s+.*\-delete\b|\bshred\s+\-z\b|\bwipe\s+\-r\b)', "data_destruction", "T1485", "high"),
            
            # Disk Wipe - SPECIFICALLY REFINED to avoid false positives on normal system operations
            (r'(?:dd\s+if=\/dev\/(?:zero|urandom|random)\s+of=\/dev\/sd[a-z]|'  # dd writing zeros/random data
             r'mkfs\.(?:ext[234]|xfs|btrfs|ntfs|fat|vfat)\s+\/dev\/sd[a-z]|'    # explicit formatting with filesystem
             r'cryptsetup\s+luksFormat\s+\/dev\/sd[a-z]|'                       # encrypting a disk (which wipes it)
             r'shred\s+(?:\-\-iterations|\-n|\-z|\-v|\-f|\-u)\s+\/dev\/sd[a-z]|' # shred with options on disk device 
             r'wipe\s+(?:\-r|\-q|\-f)\s+\/dev\/sd[a-z]|'                         # wipe command on disk device
             r'scrub\s+(?:\-p|\-r|\-f)\s+\/dev\/sd[a-z]|'                        # scrub command on disk device
             r'badblocks\s+\-w\s+\/dev\/sd[a-z]|'                                # badblocks write-mode test
             r'fdisk\s+\-\-wipe\s+.*\/dev\/sd[a-z]|'                             # fdisk with explicit wipe option
             r'wipefs\s+(?:\-a|\-\-all|\-\-force)\s+\/dev\/sd[a-z])'             # wipefs with all option
            , "disk_wipe", "T1561", "high"),
            
            (r'(?:\bkill\s+\-9\s+[0-9]+\b|\bpkill\s+\-9\b|\bpkill\s+\-f\b)', "service_stop", "T1489", "medium"),
            (r'\bbadblocks\s+\-c\b|\bshred\s+\-z\b|\bscrub\s+\-p\b|\bsecure-delete\s+\-v\b', "disk_wipe", "T1561", "high"),
            (r':\(\)\{\s+:\|\:;\s+\}\s*;:', "resource_hijacking", "T1496", "high"),
            (r'\bstress\-ng\s+\-\-cpu\b|\bstress\s+\-c\b|\bdd\s+if=\/dev\/zero\s+of=\/dev\/null\b|\byes\s+>\s+\/dev\/null\b', "resource_hijacking", "T1496", "high"),
            (r'\biptables\s+\-A\s+INPUT\s+\-j\s+DROP\b|\biptables\s+\-P\s+INPUT\s+DROP\b', "network_denial_of_service", "T1498", "high"),
            
            # Web specific attacks
            (r'(?:select.*from.*where|union.*select|insert.*into.*values|update.*set.*where|delete.*from.*where)', "sql_injection", "T1190", "high"),
            (r'(?:\/\.\.\/|\.\.\\|\%2e\%2e\%2f|\%252e\%252e\%252f)', "path_traversal", "T1083", "high"),
            (r'(?:script>|javascript:|onload=|onerror=|onclick=)', "cross_site_scripting", "T1059.007", "medium"),
            (r'<!\[CDATA|<%.*%>|\{\{.*\}\}|\$\{.*\}', "template_injection", "T1059", "high"),
            
            # Linux SSH Brute Force and User Enumeration - updated patterns
            (r'Failed password for (?:invalid user )?\w+ from (?:[0-9]{1,3}\.){3}[0-9]{1,3} port [0-9]+ ssh2\b', "credential_brute_force", "T1110.001", "medium"),
            (r'Connection closed by invalid user \w+ (?:[0-9]{1,3}\.){3}[0-9]{1,3} port [0-9]+\b', "user_enumeration", "T1110.001", "low"),
            (r'Failed password for invalid user \w+ from (?:[0-9]{1,3}\.){3}[0-9]{1,3} port [0-9]+ ssh2\b', "password_spray", "T1110.003", "medium"),
            
            # Database-specific patterns
            (r'invalid length of startup packet', "database_probe", "T1190", "medium"),
            (r'connection request from IP', "database_connection_attempt", "T1190", "low"),
            (r'password authentication failed for user', "database_auth_failure", "T1110", "medium"),
            
            # Web server probes and attacks
            (r'Invalid method in request \w+', "web_probe", "T1190", "medium"),
            (r'(?:PROPFIND|CONNECT|OPTIONS|TRACE|PUT|DELETE) \/.*HTTP\/[0-9.]+', "web_method_probe", "T1190", "medium"),
            
            # Advanced Rootkit Techniques (Recent 2024-2025)
            (r'(?:insmod|modprobe)\s+.*kmod_hiding', "module_signing_bypass", "T1014", "critical"),
            (r'\bcommit_creds\(|prepare_kernel_cred\(|cred_alloc_blank\(', "kernel_credential_theft", "T1003.008", "critical"),
            (r'\bio_uring_setup\(|\bio_uring_register\(|\bio_uring_enter\(', "io_uring_rootkit", "T1014", "critical"),
            (r'register_ftrace_function\(|ftrace_setup_regs\(', "ftrace_hook_rootkit", "T1014", "critical"),
            (r'register_kprobe\(|unregister_kprobe\(|kprobe_register\(', "kprobe_rootkit", "T1014", "critical"),
            (r'mount\s+\-t\s+debugfs|mount\s+\-t\s+tracefs|mount\s+\-t\s+securityfs', "debug_filesystem_abuse", "T1562.001", "high"),
            (r'\bSNOWLIGHT\b|\bVShell\b|\bReptile\b|\bMedusa\b|\bPumakit\b', "known_rootkit_malware", "T1014", "critical"),
            (r'modify_ldt\(|get_ldt\(|set_ldt\(', "processor_descriptor_table", "T1014", "critical"),
            
            # Supply Chain Attacks (2024-2025)
            (r'npm\s+install\s+\-\-registry|pip\s+install\s+\-\-extra\-index\-url|pip\s+install\s+\-\-index\-url', "package_manager_compromise", "T1195.001", "critical"),
            (r'preinstall|postinstall|prepublish|postpublish', "package_hook_exploitation", "T1195.001", "high"),
            (r'curl\s+.*\|\s*(?:bash|sh)|wget\s+.*\|\s*(?:bash|sh)', "piped_shell_execution", "T1059.004", "high"),
            
            # Container & Cloud-specific attacks
            (r'docker\.sock|docker\s+exec\s+\-it|docker\s+run\s+\-\-privileged', "container_escape", "T1610", "critical"), 
            (r'kubectl\s+exec\s+\-it|kubectl\s+port-forward\s+pod|kubeconfig', "kubernetes_attack", "T1552.007", "high"),
            (r'aws\s+configure\s+set\s+aws_access|aws\s+sts\s+get-session-token|aws\s+s3\s+cp\s+s3:|aws\s+ec2\s+run-instances', "cloud_credential_access", "T1552.005", "high"),
            (r'AWSAccessKeyId=[A-Z0-9]{20}|AWSSecretKey=[A-Za-z0-9/+=]{40}|AKIA[0-9A-Z]{16}', "aws_key_leak", "T1552.005", "critical")
        ]
        
        # Compile regex patterns for performance
        for i, (pattern, name, mitre_id, severity) in enumerate(self.attack_patterns):
            self.attack_patterns[i] = (re.compile(pattern, re.IGNORECASE), name, mitre_id, severity)
        
        # Create a subset of critical and high severity patterns for faster initial checking
        self.critical_attack_patterns = [
            pattern_tuple for pattern_tuple in self.attack_patterns 
            if pattern_tuple[3] in ("critical", "high")
        ]
        
        # Initialize attack correlation tracking
        self.attack_correlation = {}
        
        # Create regex patterns for filtering out benign system messages
        self.benign_message_patterns = [
            re.compile(r'Reached target', re.IGNORECASE),
            re.compile(r'Condition check resulted in', re.IGNORECASE),
            re.compile(r'Startup finished', re.IGNORECASE),
            re.compile(r'Listening on', re.IGNORECASE),
            re.compile(r'Started Session', re.IGNORECASE),
            re.compile(r'Started User Manager', re.IGNORECASE),
            re.compile(r'Created slice', re.IGNORECASE),
            re.compile(r'Removed slice', re.IGNORECASE),
            re.compile(r'Stopping', re.IGNORECASE),
            re.compile(r'Starting', re.IGNORECASE),
            re.compile(r'Closed', re.IGNORECASE),
            re.compile(r'Received connection', re.IGNORECASE),
            re.compile(r'Received SIGTERM', re.IGNORECASE),
            re.compile(r'Received SIGINT', re.IGNORECASE),
            re.compile(r'Stopped', re.IGNORECASE),
            re.compile(r'Succeeded', re.IGNORECASE),
            re.compile(r'Using default', re.IGNORECASE),
            re.compile(r'Main PID', re.IGNORECASE),
            re.compile(r'Status', re.IGNORECASE),
            re.compile(r'Unit .* has finished', re.IGNORECASE),
            re.compile(r'Unit .* has begun', re.IGNORECASE),
            re.compile(r'Job .* has begun', re.IGNORECASE),
            re.compile(r'Unit .* entered the .* state', re.IGNORECASE),
            # Specific benign disk operations
            re.compile(r'Adding .* swap on', re.IGNORECASE),
            re.compile(r'attached SCSI', re.IGNORECASE),
            re.compile(r'mounted.*filesystem', re.IGNORECASE),
            re.compile(r'Found valid superblock', re.IGNORECASE),
            re.compile(r'I\/O scheduler', re.IGNORECASE),
            re.compile(r'partition.*detected', re.IGNORECASE),
            re.compile(r'sectors of.*memory', re.IGNORECASE),
            re.compile(r'skip.* device', re.IGNORECASE),
            re.compile(r'snap auto-import', re.IGNORECASE),
            re.compile(r'device nodes', re.IGNORECASE),
            re.compile(r'Media change', re.IGNORECASE),
            re.compile(r'Process .* failed with exit code', re.IGNORECASE),
            re.compile(r'failed with result', re.IGNORECASE)
        ]
        
        # Lists to identify benign disk operations
        self.benign_disk_operations = [
            "adding swap", "swap on", "swap device", "mounted on", 
            "detected capacity change", "partition table", "found valid superblock", 
            "mounted filesystem", "snap auto-import", "media change", 
            "failed with exit code", "process failed", "priority", "across"
        ]
    
    def find_log_files(self):
        """Scan system for common security audit log files excluding archives"""
        log_files = []
        
        # Common log file locations
        log_dirs = [
            "/var/log",
            "/var/log/audit",
            "/var/log/apache2",
            "/var/log/nginx",
            "/var/log/httpd",
            "/var/log/syslog",
            "/var/log/secure",
            "/var/log/auth.log",
            "/var/log/messages"
        ]
        
        # Use find command (which is in NOPASSWD list)
        for log_dir in log_dirs:
            try:
                # Check if directory exists first
                check_cmd = ["sudo", "find", log_dir, "-maxdepth", "0", "-type", "d"]
                check_result = subprocess.run(check_cmd, capture_output=True, text=True)
                
                if check_result.returncode != 0:
                    # Skip directories that don't exist or can't be accessed
                    continue
                    
                # Use find to get all regular files
                find_cmd = ["sudo", "find", log_dir, "-type", "f"]
                find_result = subprocess.run(find_cmd, capture_output=True, text=True)
                
                if find_result.returncode == 0 and find_result.stdout:
                    found_files = find_result.stdout.strip().split('\n')
                    
                    # Filter for common log files
                    for file_path in found_files:
                        # Check filename against common log patterns
                        file_name = os.path.basename(file_path)
                        if (file_name.endswith(".log") or 
                            any(name in file_name for name in ["syslog", "auth", "secure", "audit", "messages", 
                                                             "access", "error", "mail", "kern", "dmesg"])):
                            # Skip archive files
                            if not re.search(r'\.(gz|zip|bz2|\d+)$', file_path):
                                log_files.append(file_path)
                                
            except Exception as e:
                self.logger.error(f"Error finding logs in {log_dir}: {str(e)}")
        
        # Deduplicate and sort
        log_files = sorted(list(set(log_files)))
        self.logger.info(f"Found {len(log_files)} log files (excluding archives)")
        return log_files
    
    def categorize_log_file(self, log_file):
        """Determine category of log file based on content and path"""
        # Create a mapping of patterns to categories for efficient lookup
        category_patterns = {
            "auth": ["auth.log", "secure", "login", "lastlog", "faillog", "pam"],
            "syslog": ["syslog", "messages", "kern.log", "daemon.log", "debug", "system.log"],
            "audit": ["audit", "auditd", "ausearch", "audit.log"],
            "web": ["apache", "nginx", "httpd", "access.log", "error.log", "modsec"],
            "app": ["app", "application", "daemon", "service"],
            "mail": ["mail", "maillog", "exim", "postfix", "dovecot", "smtpd"],
            "ssh": ["ssh", "sshd", "sftp", "authorized_keys"],
            "cron": ["cron", "anacron", "at"],
            "firewall": ["ufw", "iptables", "firewall", "pf.log", "ipfw", "ipchains", "fwsnort", "shorewall"],
            "database": ["mysql", "mariadb", "postgresql", "mongo", "oracle", "db2", "sqlite"],
            "proxy": ["squid", "haproxy", "nginx", "proxy"],
            "vpn": ["openvpn", "wireguard", "ipsec", "strongswan", "vpn"],
            "dhcp": ["dhcp", "dhcpd", "isc-dhcp"],
            "dns": ["bind", "named", "dns", "named.log", "resolver"],
            "ntp": ["ntp", "chrony", "timesyncd"],
            "sudo": ["sudo", "sudoers"],
            "kernel": ["dmesg", "kern.log", "kernel"],
            "container": ["docker", "k8s", "kubernetes", "podman", "lxc"],
            "journal": ["journal", "systemd"],
            "security": ["suricata", "snort", "wazuh", "ossec", "aide", "fail2ban"]
        }
        
        # Check filename and path against categories
        file_base = os.path.basename(log_file).lower()
        file_path = log_file.lower()
        
        # Use any() for more efficient pattern matching
        for category, patterns in category_patterns.items():
            if any(pattern in file_base or pattern in file_path for pattern in patterns):
                return category
        
        # If no match by filename/path, check content
        try:
            # Use head command which is in the NOPASSWD list
            head_cmd = ["sudo", "head", "-c", "2000", log_file]
            result = subprocess.run(head_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise PermissionError(result.stderr.strip())
            
            head = result.stdout.lower()  # Convert to lowercase once for efficient comparison
            
            # Check content signatures with a more efficient approach
            content_signatures = [
                ("auth", ["authentication", "auth", "pam", "session opened"]),
                ("web", ["apache", "nginx", "get ", "post ", "http/"]),
                ("audit", ["audit", "ausearch"]),
                ("cron", ["cron", "anacron"]),
                ("mail", ["postfix", "exim", "mail", "dovecot"]),
                ("ssh", ["sshd", "ssh", "connection from"]),
                ("firewall", ["iptables", "firewall", "ufw", "blocked"]),
                ("sudo", ["sudo", "command"]),
                ("kernel", ["kernel", "cpu", "memory", "device"]),
                ("container", ["docker", "container", "pod"]),
                ("database", ["mysqld", "postgres", "mongodb"]),
                ("dhcp", ["dhcpd", "dhcp", "lease"]),
                ("dns", ["named", "dns", "zone"]),
                ("ntp", ["ntpd", "chrony", "time sync"]),
                ("journal", ["systemd", "journald"]),
                ("security", ["snort", "suricata", "ossec", "wazuh"])
            ]
            
            for category, signatures in content_signatures:
                if any(sig in head for sig in signatures):
                    return category
            
        except Exception as e:
            self.logger.warning(f"Could not read {log_file} for categorization: {str(e)}")
        
        # Default category if no match found
        return "other"
    
    def update_config_with_logs(self, log_files):
        """Update config with found log files and their categories"""
        log_categories = defaultdict(list)
        
        # Categorize logs and update
        for log_file in log_files:
            category = self.categorize_log_file(log_file)
            log_categories[category].append(log_file)
        
        # Update config
        self.config["log_integrity_monitor"]["monitored_logs"] = log_files
        self.config["log_integrity_monitor"]["log_categories"] = dict(log_categories)
        
        # Save updated config
        self.save_config()
        self.logger.info(f"Config updated with {len(log_files)} log files in {len(log_categories)} categories")

    def get_log_position(self, log_file):
        """Get current position to start reading from log file"""
        if log_file in self.log_positions:
            return self.log_positions[log_file]["position"]
        
        # For new logs that don't have a saved position, start from the end
        # to avoid processing the entire log history on first run
        try:
            # Check if we can access the file
            try:
                # Use head to check if file is accessible
                check_cmd = ["sudo", "head", "-c", "1", log_file]
                check_result = subprocess.run(check_cmd, capture_output=True)
                
                if check_result.returncode != 0:
                    self.logger.warning(f"Cannot access {log_file}: {check_result.stderr}")
                    return 0
            except Exception:
                self.logger.warning(f"Cannot access {log_file}")
                return 0
                
            # For new files, start from end (don't analyze existing logs on first run)
            # Get approximate file size using tail with a large value
            size_cmd = ["sudo", "tail", "-c", "1", log_file]
            size_result = subprocess.run(size_cmd, capture_output=True)
            if size_result.returncode != 0:
                self.logger.warning(f"Cannot get file size for {log_file}")
                size = 0
            else:
                # Efficient way to get file size using cat and wc
                try:
                    # Use a more efficient approach to get file size
                    # We pipe the entire file through wc to count bytes
                    wc_cmd = f"sudo cat '{log_file}' | wc -c"
                    size_result = subprocess.run(wc_cmd, shell=True, capture_output=True, text=True)
                    if size_result.returncode == 0:
                        size = int(size_result.stdout.strip())
                    else:
                        # Alternative: use tail to get an approximate size
                        self.logger.warning(f"Using alternative size method for {log_file}")
                        size_cmd = ["sudo", "tail", "-c", "524288000", log_file]  # Try to read up to 500MB
                        proc = subprocess.Popen(size_cmd, stdout=subprocess.PIPE)
                        size = 0
                        while True:
                            chunk = proc.stdout.read(65536)  # Read in 64KB chunks
                            if not chunk:
                                break
                            size += len(chunk)
                        proc.terminate()
                        proc.wait()
                except Exception as e:
                    self.logger.warning(f"Error calculating file size: {str(e)}")
                    # If we can't determine size, start from position 0
                    size = 0
            
            # Store the position
            self.log_positions[log_file] = {
                "position": size,
                "last_read": datetime.datetime.now().isoformat(),
                "first_seen": True  # Mark this as first time seeing this file
            }
            self.logger.info(f"New log file {log_file}, starting from position {size}")
            return size
        except Exception as e:
            self.logger.error(f"Error getting file size for {log_file}: {str(e)}")
            # Start from position 0 on error
            self.log_positions[log_file] = {
                "position": 0,
                "last_read": datetime.datetime.now().isoformat(),
                "first_seen": True  # Mark this as first time seeing this file
            }
            return 0
    
    def update_log_position(self, log_file, position):
        """Update saved position for log file"""
        self.log_positions[log_file] = {
            "position": position,
            "last_read": datetime.datetime.now().isoformat()
        }

    def correlate_attack(self, parsed_data, attack_name, mitre_id, severity, log_file, log_category):
        """Track attack patterns for correlation and escalation"""
        # Get current time for timestamp comparison
        now = datetime.datetime.now()
        
        # Extract source IP if available
        src_ip = None
        if "ip_addresses" in parsed_data and parsed_data["ip_addresses"]:
            src_ip = parsed_data["ip_addresses"][0]
        
        # Skip correlation if no source IP
        if not src_ip:
            return
        
        # Initialize correlation data structure if needed
        if src_ip not in self.attack_correlation:
            self.attack_correlation[src_ip] = {
                "first_seen": now,
                "last_seen": now,
                "attack_types": {},
                "mitre_ids": set(),
                "usernames": set(),
                "user_enum_count": 0,
                "failed_auth_count": 0,
                "web_probes_count": 0,
                "db_probes_count": 0
            }
        
        # Update correlation tracking
        corr_data = self.attack_correlation[src_ip]
        corr_data["last_seen"] = now
        
        # Increment attack type counter
        if attack_name not in corr_data["attack_types"]:
            corr_data["attack_types"][attack_name] = 0
        corr_data["attack_types"][attack_name] += 1
        
        # Add MITRE ID to set
        corr_data["mitre_ids"].add(mitre_id)
        
        # Track attempted usernames for auth attacks
        if "username" in parsed_data:
            corr_data["usernames"].add(parsed_data["username"])
        
        # Update specific counters based on attack type
        if attack_name == "user_enumeration" or attack_name == "credential_brute_force":
            corr_data["user_enum_count"] += 1
            if "username" in parsed_data:
                corr_data["usernames"].add(parsed_data["username"])
        
        if "auth_result" in parsed_data and parsed_data["auth_result"] == "failure":
            corr_data["failed_auth_count"] += 1
        
        if attack_name == "web_probe" or attack_name == "web_method_probe":
            corr_data["web_probes_count"] += 1
        
        if attack_name == "database_probe":
            corr_data["db_probes_count"] += 1
        
        # Clean up old entries (older than 1 hour)
        cleanup_time = now - datetime.timedelta(hours=1)
        ips_to_remove = []
        
        for ip, data in self.attack_correlation.items():
            if data["last_seen"] < cleanup_time:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.attack_correlation[ip]
        
        if ips_to_remove:
            self.logger.debug(f"Cleaned up correlation data for {len(ips_to_remove)} IPs")
    
    def check_attack_escalation(self, parsed_data, attack_name, mitre_id, severity):
        """Check if an attack should be escalated based on correlation patterns"""
        # Default is to return the original values
        escalated_severity = severity
        escalated_attack_name = attack_name
        
        # Extract source IP if available
        src_ip = None
        if "ip_addresses" in parsed_data and parsed_data["ip_addresses"]:
            src_ip = parsed_data["ip_addresses"][0]
        
        # Skip escalation if no source IP or correlation data
        if not src_ip or src_ip not in self.attack_correlation:
            return severity, attack_name
        
        corr_data = self.attack_correlation[src_ip]
        
        # Escalation rules
        
        # 1. User enumeration -> Password spray
        if attack_name == "user_enumeration" and corr_data["user_enum_count"] >= 3:
            if len(corr_data["usernames"]) >= 3:
                # Multiple different usernames = password spray
                escalated_attack_name = "password_spray"
                escalated_severity = "medium"
                self.logger.info(f"Escalated user enumeration to password spray for {src_ip} ({len(corr_data['usernames'])} usernames)")
            else:
                # Same username multiple times = brute force
                escalated_attack_name = "credential_brute_force"
                escalated_severity = "medium"
                self.logger.info(f"Escalated user enumeration to brute force for {src_ip}")
        
        # 2. Credential brute force volume-based escalation
        if attack_name == "credential_brute_force" and corr_data["failed_auth_count"] > 10:
            escalated_severity = "high"
            self.logger.info(f"Escalated brute force severity to high for {src_ip} ({corr_data['failed_auth_count']} attempts)")
        
        # 3. Password spray escalation
        if attack_name == "password_spray" and len(corr_data["usernames"]) > 10:
            escalated_severity = "high"
            self.logger.info(f"Escalated password spray severity to high for {src_ip} ({len(corr_data['usernames'])} usernames)")
        
        # 4. Web probes escalation
        if (attack_name == "web_probe" or attack_name == "web_method_probe") and corr_data["web_probes_count"] > 5:
            escalated_attack_name = "web_scanning"
            escalated_severity = "medium"
            self.logger.info(f"Escalated web probes to web scanning for {src_ip}")
        
        # 5. Database probes escalation
        if attack_name == "database_probe" and corr_data["db_probes_count"] > 3:
            escalated_attack_name = "database_scanning"
            escalated_severity = "medium"
            self.logger.info(f"Escalated database probes to database scanning for {src_ip}")
        
        # 6. Cross-technique escalation (multiple MITRE IDs)
        if len(corr_data["mitre_ids"]) >= 3 and severity != "critical":
            # Attacker using multiple techniques
            if severity == "low":
                escalated_severity = "medium"
            elif severity == "medium":
                escalated_severity = "high"
            
            self.logger.info(f"Escalated severity due to multiple techniques ({len(corr_data['mitre_ids'])}) for {src_ip}")
        
        # 7. Rapid succession escalation
        time_window = (corr_data["last_seen"] - corr_data["first_seen"]).total_seconds()
        attack_count = sum(corr_data["attack_types"].values())
        
        if time_window < 60 and attack_count > 10 and severity != "critical":
            # High velocity attacks in short time window
            if severity == "low":
                escalated_severity = "medium"
            elif severity == "medium":
                escalated_severity = "high"
            
            self.logger.info(f"Escalated severity due to attack velocity ({attack_count} in {time_window:.1f}s) for {src_ip}")
        
        return escalated_severity, escalated_attack_name
    
    def ml_analyze(self, entries, parsed_data, log_file, log_category):
        """Enhanced ML analysis that references attack patterns for anomaly classification"""
        alerts = []
        
        # Skip ML analysis if too few entries
        if len(entries) < 5:
            return alerts
        
        # Extract features for ML
        features = self.extract_log_features(entries, parsed_data, log_category)
        
        # Use a global model key for unified analysis
        model_key = "global_ml_model"
        
        if model_key not in self.ml_models:
            self.ml_models[model_key] = {
                "model": IsolationForest(contamination=0.1, random_state=42),
                "trained": False,
                "training_data": []
            }
        
        ml_config = self.config["log_integrity_monitor"]["ml_analysis"]
        model_data = self.ml_models[model_key]
        
        # If in training mode, collect data
        if not model_data["trained"]:
            model_data["training_data"].extend(features)
            self.logger.debug(f"Collected {len(features)} samples for ML training, total: {len(model_data['training_data'])}")
            
            # Train model when enough data collected
            if len(model_data["training_data"]) >= ml_config["min_training_samples"]:
                try:
                    X = np.array(model_data["training_data"])
                    model_data["model"].fit(X)
                    model_data["trained"] = True
                    self.logger.info(f"ML model trained on global data with {len(model_data['training_data'])} samples")
                except Exception as e:
                    self.logger.error(f"Error training ML model: {str(e)}")
        
        # If model trained, perform anomaly detection
        elif model_data["trained"]:
            X = np.array(features)
            if X.size > 0:  # Ensure we have features to analyze
                try:
                    # Predict anomalies
                    scores = model_data["model"].decision_function(X)
                    predictions = model_data["model"].predict(X)
                    
                    # Process anomalies and check against attack patterns
                    for i, (score, pred) in enumerate(zip(scores, predictions)):
                        if pred == -1 and score < -ml_config["anomaly_threshold"]:
                            # Anomaly detected - check against attack patterns
                            entry = entries[i] if i < len(entries) else ""
                            parsed = parsed_data[i] if i < len(parsed_data) else {}
                            
                            # Check if this anomaly matches any attack patterns
                            attack_matched = False
                            for pattern, attack_name, mitre_id, severity in self.attack_patterns:
                                if pattern.search(entry):
                                    # Found a match - create an alert with higher confidence
                                    alert = {
                                        "timestamp": datetime.datetime.now().isoformat(),
                                        "log_file": log_file,
                                        "log_category": log_category,
                                        "entry": entry,
                                        "parsed": parsed,
                                        "attack_name": attack_name,
                                        "mitre_id": mitre_id,
                                        "severity": severity,  # Use pattern's severity
                                        "detection_type": "ml_correlation",
                                        "anomaly_score": float(score)
                                    }
                                    alerts.append(alert)
                                    self.logger.warning(f"ML Alert: {attack_name} (MITRE {mitre_id}) detected in {log_file} (score: {score:.2f})")
                                    attack_matched = True
                                    break
                            
                            # If no pattern matched, still alert as generic anomaly
                            if not attack_matched:
                                alert = {
                                    "timestamp": datetime.datetime.now().isoformat(),
                                    "log_file": log_file,
                                    "log_category": log_category,
                                    "entry": entry,
                                    "parsed": parsed,
                                    "attack_name": "anomalous_log_pattern",
                                    "mitre_id": "T1562",  # Impair Defenses
                                    "severity": "medium",
                                    "detection_type": "ml",
                                    "anomaly_score": float(score)
                                }
                                alerts.append(alert)
                                self.logger.warning(f"ML Alert: Anomalous pattern detected in {log_file} (score: {score:.2f})")
                except Exception as e:
                    self.logger.error(f"Error in ML prediction: {str(e)}")
        
        return alerts
    
    def extract_log_features(self, entries, parsed_data, log_category):
        """Extract numeric features from log entries for ML analysis with improved features"""
        features = []
        
        # Define a standard feature vector length to match what the model expects
        STANDARD_VECTOR_LENGTH = 16
        
        # Precompile regex patterns for better performance
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        
        for i, entry in enumerate(entries):
            if not entry.strip():
                continue
            
            # Get parsed data if available
            parsed = parsed_data[i] if i < len(parsed_data) else {}
            
            # Cache some calculations to avoid repeated work
            entry_len = len(entry)
            entry_lower = entry.lower()  # Convert once for case-insensitive checks
            
            # Base features that apply to all log types
            feature_vector = [
                entry_len,                                            # Length of entry
                len(entry.split()),                                   # Word count
                sum(c.isdigit() for c in entry) / max(1, entry_len),  # Digit ratio
                sum(c.isupper() for c in entry) / max(1, entry_len),  # Uppercase ratio
                sum(not c.isalnum() for c in entry) / max(1, entry_len),  # Special char ratio
                entry.count('/'),                                     # Path separator count
                entry.count('='),                                     # Assignment count
                len(ip_pattern.findall(entry))                        # IP address count
            ]
            
            # Add category-specific features - we have 8 base features, so we need 8 more
            # to match the expected 16 features
            category_features = [0] * 8  # Initialize with zeros
            
            # Only compute features for specific categories we care about
            if log_category == "auth" or log_category == "ssh":
                # Authentication logs features
                category_features[0] = 1 if "failure" in entry_lower or "failed" in entry_lower else 0
                category_features[1] = 1 if "success" in entry_lower or "accepted" in entry_lower else 0
                category_features[2] = 1 if "root" in entry_lower else 0
                category_features[3] = 1 if "sudo" in entry_lower else 0
                category_features[4] = 1 if "invalid user" in entry_lower else 0
                category_features[5] = 1 if "password" in entry_lower else 0
                category_features[6] = 1 if "publickey" in entry_lower or "public key" in entry_lower else 0
                
                # Add feature for unusual usernames
                if "username" in parsed:
                    username = parsed["username"].lower()
                    category_features[7] = 1 if (username in ["admin", "administrator", "root", "system"] or
                                             len(username) < 3 or len(username) > 16 or
                                             bool(re.search(r'[^a-zA-Z0-9_-]', username))) else 0
                        
            elif log_category == "web":
                # Web server logs features
                category_features[0] = 1 if "GET" in entry else 0
                category_features[1] = 1 if "POST" in entry else 0
                category_features[2] = 1 if "PUT" in entry or "DELETE" in entry else 0
                category_features[3] = 1 if re.search(r'\s+[45]\d\d\s+', entry) else 0
                category_features[4] = 1 if re.search(r'\s+2\d\d\s+', entry) else 0
                category_features[5] = 1 if re.search(r'\.(php|asp|jsp|cgi|pl)\b', entry_lower) else 0
                category_features[6] = 1 if re.search(r'\.(jpg|jpeg|png|gif|css|js)\b', entry_lower) else 0
                category_features[7] = entry.count("?") + entry.count("&")
                        
            elif log_category == "firewall":
                # Firewall logs features
                category_features[0] = 1 if "ACCEPT" in entry else 0
                category_features[1] = 1 if any(x in entry for x in ["DROP", "REJECT", "BLOCK", "DENY"]) else 0
                category_features[2] = 1 if "PROTO=TCP" in entry else 0
                category_features[3] = 1 if "PROTO=UDP" in entry else 0
                category_features[4] = 1 if "PROTO=ICMP" in entry else 0
                category_features[5] = 1 if re.search(r'DPT=(80|443|8080|8443)\b', entry) else 0
                category_features[6] = 1 if re.search(r'DPT=(20|21|22|23|25|53|110|143|993|995|3389)\b', entry) else 0
                        
            elif log_category == "audit":
                # Audit logs features
                category_features[0] = 1 if "type=USER_" in entry else 0
                category_features[1] = 1 if "type=CRED_" in entry else 0
                category_features[2] = 1 if "type=SYSCALL" in entry else 0
                category_features[3] = 1 if "success=yes" in entry else 0
                category_features[4] = 1 if "success=no" in entry else 0
                category_features[5] = 1 if "uid=0" in entry else 0
                category_features[6] = 1 if re.search(r'cmd=([^"]*(?:sh|bash|dash|ksh|zsh|csh)[^"]*")', entry) else 0
                
            elif log_category == "database":
                # Database logs features
                category_features[0] = 1 if "error" in entry_lower else 0
                category_features[1] = 1 if "warning" in entry_lower else 0
                category_features[2] = 1 if "select" in entry_lower else 0
                category_features[3] = 1 if "insert" in entry_lower else 0
                category_features[4] = 1 if "update" in entry_lower else 0
                category_features[5] = 1 if "delete" in entry_lower else 0
                category_features[6] = 1 if "transaction" in entry_lower else 0
                category_features[7] = 1 if "connection" in entry_lower or "timeout" in entry_lower else 0
                
            # Final check to ensure consistent vector length
            feature_vector.extend(category_features)
            if len(feature_vector) != STANDARD_VECTOR_LENGTH:
                # Normalize vector length to expected size
                if len(feature_vector) < STANDARD_VECTOR_LENGTH:
                    feature_vector.extend([0] * (STANDARD_VECTOR_LENGTH - len(feature_vector)))
                else:
                    feature_vector = feature_vector[:STANDARD_VECTOR_LENGTH]
            
            features.append(feature_vector)
        
        return features
    
    def read_log_file(self, log_file, log_category):
        """Read and analyze log file from last position using sudo for access"""
        try:
            # Get starting position
            position = self.get_log_position(log_file)
            
            # Skip files with extensions indicating they are archived
            if re.search(r'\.(gz|zip|bz2|\d+)$', log_file):
                self.logger.debug(f"Skipping fs log file: {log_file}")
                return []
            
            # Try to get the file size using sudo head
            try:
                # Use sudo head to peek at the file
                head_cmd = ["sudo", "head", "-c", "1", log_file]
                head_result = subprocess.run(head_cmd, capture_output=True)
                
                if head_result.returncode != 0:
                    self.logger.warning(f"Cannot access {log_file}: {head_result.stderr}")
                    return []
                
                # If we can access the file, get its size with a large head command
                # 500MB should be enough for most logs
                size_cmd = ["sudo", "head", "-c", "524288000", log_file]
                size_proc = subprocess.Popen(size_cmd, stdout=subprocess.PIPE)
                
                # Count bytes as they come through
                current_size = 0
                while True:
                    chunk = size_proc.stdout.read(1024 * 1024)  # Read 1MB chunks
                    if not chunk:
                        break
                    current_size += len(chunk)
                
                # Clean up process
                size_proc.terminate()
                size_proc.wait()
                
            except Exception as e:
                self.logger.warning(f"Error getting file size for {log_file}: {str(e)}")
                # If we can't get the file size, use a safer approach
                # Either start from the beginning (0) or keep the last position
                if position == 0:
                    current_size = 0
                else:
                    # If we had a previous position, assume file hasn't changed
                    current_size = position
            
            # Handle file truncation (file smaller than last position)
            if current_size < position:
                self.logger.info(f"File {log_file} appears to have been truncated, resetting position")
                position = 0
            
            # If no new content, skip file
            if current_size <= position and current_size > 0:
                self.logger.debug(f"No new content in {log_file}, skipping")
                return []
            
            # Read new content using tail or cat (both in NOPASSWD list)
            try:
                if position > 0:
                    # Only read from last position to end
                    cmd = ["sudo", "tail", "-c", f"+{position+1}", log_file]
                else:
                    # Read whole file
                    cmd = ["sudo", "cat", log_file]
                    
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.warning(f"Error reading {log_file}: {result.stderr}")
                    return []
                    
                new_content = result.stdout
                
                # Update position to current size
                self.update_log_position(log_file, current_size)
                
                # If no new content, return empty list
                if not new_content:
                    return []
                
                # Split into entries and analyze
                entries = new_content.split('\n')
                alerts = self.analyze_log_entries(entries, log_file, log_category)
                
                return alerts
            except Exception as e:
                self.logger.warning(f"Error reading content from {log_file}: {str(e)}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error processing log file {log_file}: {str(e)}")
            return []

    def analyze_log_entries(self, entries, log_file, log_category):
        """Analyze log entries for security patterns with correlation capabilities"""
        alerts = []
        parsed_data = []
        
        # Compile frequently used regex patterns once
        syslog_pattern = re.compile(
            r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})\s+(\S+)\s+([^\[\:]+)(?:\[(\d+)\])?\:?\s+(.*)'
        )
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        
        # Process each log entry
        for entry in entries:
            # Skip empty lines
            entry = entry.strip()
            if not entry:
                continue
            
            # Filter out benign system messages - especially for systemd
            # Check if this is a systemd log entry and if it matches benign patterns
            is_benign = False
            if "systemd" in entry.lower():
                # Check against benign patterns
                for pattern in self.benign_message_patterns:
                    if pattern.search(entry):
                        is_benign = True
                        break
                
                # Skip benign entries
                if is_benign:
                    continue
            
            # Common log format parsing
            parsed = {"raw": entry}
            
            # Extract standard syslog components
            syslog_match = syslog_pattern.match(entry)
            
            if syslog_match:
                parsed["timestamp"] = syslog_match.group(1)
                parsed["system_name"] = syslog_match.group(2)
                parsed["service"] = syslog_match.group(3).strip()
                parsed["pid"] = syslog_match.group(4) if syslog_match.group(4) else None
                parsed["message"] = syslog_match.group(5)
                
                # Skip entries that are just routine service status messages
                # Look for patterns like "Started X", "Stopped Y", etc. from systemd
                if parsed.get("service") == "systemd" and any(action in parsed.get("message", "") 
                                                             for action in self.benign_systemd_actions):
                    # Check if this is actually a privileged action - username/root/etc.
                    if not any(keyword in parsed.get("message", "").lower() 
                              for keyword in ["root", "admin", "sudo", "wheel", "privilege"]):
                        # Skip benign systemd messages
                        continue
            
            # Extract IP addresses from the log entry
            ip_matches = ip_pattern.findall(entry)
            if ip_matches:
                parsed["ip_addresses"] = ip_matches
            
            # Category-specific parsing - only perform if necessary based on log category
            if log_category in ("auth", "ssh"):
                service = parsed.get("service", "")
                
                if "sudo" in service:
                    # Extract sudo user
                    sudo_user_match = re.search(r'sudo:\s+(\S+)', entry)
                    if sudo_user_match:
                        parsed["sudo_user"] = sudo_user_match.group(1)
                    
                    # Extract TTY
                    tty_match = re.search(r'TTY=([^;]+)', entry)
                    if tty_match:
                        parsed["tty"] = tty_match.group(1).strip()
                    
                    # Extract PWD
                    pwd_match = re.search(r'PWD=([^;]+)', entry)
                    if pwd_match:
                        parsed["pwd"] = pwd_match.group(1).strip()
                    
                    # Extract USER (the user being switched to)
                    user_match = re.search(r'USER=([^;]+)', entry)
                    if user_match:
                        parsed["target_user"] = user_match.group(1).strip()
                    
                    # Extract COMMAND
                    command_match = re.search(r'COMMAND=([^;]+)$', entry)
                    if command_match:
                        parsed["command"] = command_match.group(1).strip()
                        
                        # Check if command indicates a sensitive operation
                        sensitive_commands = ["vi", "vim", "nano", "cat", "echo", "cp", "mv", "rm", "chmod", 
                                             "chown", "systemctl", "mount", "umount", "dd"]
                        command = parsed.get("command", "").lower()
                        sensitive_targets = ["/etc/", "/boot/", "/bin/", "/sbin/", "/usr/bin/", 
                                            "passwd", "shadow", "sudoers", ".service", "systemd"]
                        
                        # Skip harmless sudo commands that don't target sensitive paths
                        if not any(cmd in command for cmd in sensitive_commands) or \
                           not any(target in command for target in sensitive_targets):
                            # This is likely a routine sudo command, not a security concern
                            continue
                
                elif "sshd" in service:
                    # Extract username for SSH logs
                    username_match = re.search(r'(?:user|invalid user) (\w+)', entry)
                    if username_match:
                        parsed["username"] = username_match.group(1)
                    
                    # Extract auth result
                    if re.search(r'accepted|success|authenticated', entry, re.IGNORECASE):
                        parsed["auth_result"] = "success"
                    elif re.search(r'failed|failure|invalid|closed|error', entry, re.IGNORECASE):
                        parsed["auth_result"] = "failure"
                    
                    # Extract authentication method if present
                    auth_method_match = re.search(r'(?:publickey|password|keyboard-interactive|gssapi)', entry, re.IGNORECASE)
                    if auth_method_match:
                        parsed["auth_method"] = auth_method_match.group(0).lower()
                    
                    # Extract port information
                    port_match = re.search(r'port (\d+)', entry)
                    if port_match:
                        parsed["port"] = port_match.group(1)
            
            elif log_category == "syslog" and parsed.get("service") == "systemd":
                # Parse systemd service status messages more carefully
                service_match = re.search(r'(Started|Stopped|Reloaded|Failed) (.+?)(?:\.|\:)', parsed.get("message", ""))
                if service_match:
                    parsed["systemd_action"] = service_match.group(1)
                    parsed["systemd_unit"] = service_match.group(2)
                    
                    # Check if this is a routine systemd message
                    if service_match.group(1) in ["Started", "Stopped"] and \
                       not any(keyword in service_match.group(2).lower() 
                              for keyword in ["sudo", "root", "admin", "firewall", "network", "security"]):
                        # Skip routine service starts/stops
                        continue
            
            # Store the parsed data
            parsed_data.append(parsed)
            
            # Apply exclusion logic for our own operations
            skip_analysis = False
            
            # Exclude our own operations - sudo commands from our base directory
            if parsed.get("service") == "sudo" and parsed.get("target_user") == "root":
                pwd = parsed.get("pwd", "")
                if pwd == self.base_dir or "/opt/FIMoniSec/Linux-Client" in pwd:
                    self.logger.debug(f"Excluded log entry from analysis (USER=root in base_dir): {entry[:100]}...")
                    skip_analysis = True
            
            # Skip pattern matching if excluded
            if skip_analysis:
                continue
            
            # First check critical and high severity patterns for early detection
            attack_matched = False
            
            # Check critical patterns first (optimization)
            for pattern, attack_name, mitre_id, severity in self.critical_attack_patterns:
                if pattern.search(entry):
                    # Before creating an alert, do a final check for potential false positives
                    # Skip benign actions from known system services
                    if (parsed.get("service", "") in self.known_system_services and 
                        not any(keyword in entry.lower() for keyword in [
                            "failed", "error", "warning", "critical", "denied", "unauthorized",
                            "invalid", "exploit", "attack", "hack", "malicious", "suspicious"
                        ])):
                        # Likely a false positive from normal system service
                        continue
                    
                    # Track for correlation
                    self.correlate_attack(parsed, attack_name, mitre_id, severity, log_file, log_category)
                    
                    # Check if this alert should be escalated based on correlation
                    escalated_severity, escalated_attack_name = self.check_attack_escalation(parsed, attack_name, mitre_id, severity)
                    
                    # Create the alert with potentially escalated severity
                    alert = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "log_file": log_file,
                        "log_category": log_category,
                        "entry": entry,
                        "parsed": parsed,
                        "attack_name": escalated_attack_name,
                        "mitre_id": mitre_id,
                        "severity": escalated_severity,
                        "detection_type": "signature"
                    }
                    alerts.append(alert)
                    
                    if escalated_severity != severity:
                        self.logger.warning(f"Escalated Alert: {escalated_attack_name} (MITRE {mitre_id}) detected in {log_file}")
                    else:
                        self.logger.warning(f"Alert: {attack_name} (MITRE {mitre_id}) detected in {log_file}")
                        
                    attack_matched = True
                    break
                    
            # If no critical match, check the remaining patterns
            if not attack_matched:
                # Only check non-critical patterns if no match was found in critical ones
                for pattern, attack_name, mitre_id, severity in self.attack_patterns:
                    # Skip patterns already checked in critical_attack_patterns
                    if severity in ("critical", "high"):
                        continue
                        
                    if pattern.search(entry):
                        # Before creating an alert, do a final check for potential false positives
                        # Skip benign actions from known system services
                        if (parsed.get("service", "") in self.known_system_services and 
                            not any(keyword in entry.lower() for keyword in [
                                "failed", "error", "warning", "critical", "denied", "unauthorized",
                                "invalid", "exploit", "attack", "hack", "malicious", "suspicious"
                            ])):
                            # Likely a false positive from normal system service
                            continue
                        
                        # Track for correlation
                        self.correlate_attack(parsed, attack_name, mitre_id, severity, log_file, log_category)
                        
                        # Check if this alert should be escalated based on correlation
                        escalated_severity, escalated_attack_name = self.check_attack_escalation(parsed, attack_name, mitre_id, severity)
                        
                        # Create the alert with potentially escalated severity
                        alert = {
                            "timestamp": datetime.datetime.now().isoformat(),
                            "log_file": log_file,
                            "log_category": log_category,
                            "entry": entry,
                            "parsed": parsed,
                            "attack_name": escalated_attack_name,
                            "mitre_id": mitre_id,
                            "severity": escalated_severity,
                            "detection_type": "signature"
                        }
                        alerts.append(alert)
                        
                        if escalated_severity != severity:
                            self.logger.warning(f"Escalated Alert: {escalated_attack_name} (MITRE {mitre_id}) detected in {log_file}")
                        else:
                            self.logger.warning(f"Alert: {attack_name} (MITRE {mitre_id}) detected in {log_file}")
                            
                        break
        
        # ML analysis is performed only if enabled and there are enough entries
        if self.config["log_integrity_monitor"]["ml_analysis"]["enabled"] and len(entries) >= 5:
            ml_alerts = self.ml_analyze(entries, parsed_data, log_file, log_category)
            if ml_alerts:
                # Filter ML alerts to remove potential false positives
                filtered_ml_alerts = []
                for alert in ml_alerts:
                    # Skip generic "anomalous_log_pattern" alerts for benign system services
                    if (alert["attack_name"] == "anomalous_log_pattern" and
                        alert["parsed"].get("service", "") in self.known_system_services and
                        not any(keyword in alert["entry"].lower() for keyword in [
                            "failed", "error", "warning", "critical", "denied", "unauthorized",
                            "invalid", "exploit", "attack", "hack", "malicious", "suspicious"
                        ])):
                        # Likely a false positive - skip
                        continue
                    
                    # Skip ML alerts on benign systemd messages
                    if "systemd" in alert["entry"].lower():
                        is_benign = False
                        for pattern in self.benign_message_patterns:
                            if pattern.search(alert["entry"]):
                                is_benign = True
                                break
                        
                        if is_benign:
                            continue
                    
                    # Keep legitimate alerts
                    filtered_ml_alerts.append(alert)
                
                alerts.extend(filtered_ml_alerts)
        
        return alerts

    def process_monitored_logs(self):
        """Process all monitored log files"""
        alerts = []
        
        # Get monitored logs from config
        monitored_logs = self.config["log_integrity_monitor"]["monitored_logs"]
        log_categories = self.config["log_integrity_monitor"]["log_categories"]
        
        # Reverse mapping from log file to category
        file_to_category = {}
        for category, files in log_categories.items():
            for file in files:
                file_to_category[file] = category
        
        # Process each log file
        for log_file in monitored_logs:
            log_category = file_to_category.get(log_file, "other")
            log_alerts = self.read_log_file(log_file, log_category)
            alerts.extend(log_alerts)
        
        return alerts
    
    def write_alerts(self, alerts):
        """Write alerts to output file in JSON format"""
        if not alerts:
            return
        
        logs_dir = os.path.join(self.base_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        output_file = os.path.join(logs_dir, "lim.json")

        # Read existing alerts if file exists
        existing_alerts = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    existing_alerts = json.load(f)
            except Exception as e:
                self.logger.error(f"Error reading existing alerts: {str(e)}")
        
        # Combine alerts and write back
        combined_alerts = existing_alerts + alerts
        
        # Apply retention policy
        retention_days = self.config["log_integrity_monitor"]["retention"]["alert_retention_days"]
        if retention_days > 0:
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=retention_days)).isoformat()
            combined_alerts = [alert for alert in combined_alerts if alert.get("timestamp", "") >= cutoff_date]
        
        try:
            with open(output_file, 'w') as f:
                json.dump(combined_alerts, f, indent=4)
            self.logger.info(f"Wrote {len(alerts)} new alerts to {output_file}, total: {len(combined_alerts)}")
        except Exception as e:
            self.logger.error(f"Error writing alerts: {str(e)}")
    
    def scan_logs(self):
        """Scan log files, update config, and analyze current state"""
        self.logger.info("Starting log scan")
        
        # Find log files
        log_files = self.find_log_files()
        
        # Update config with found logs
        self.update_config_with_logs(log_files)
        
        # Analyze all logs
        alerts = self.process_monitored_logs()
        
        # Write alerts
        self.write_alerts(alerts)
        
        # Save log positions
        self.save_log_positions()
        
        self.logger.info(f"Log scan completed, {len(alerts)} alerts generated")
        return len(alerts)
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        self.logger.info("Starting monitoring loop")
        self.running = True
        
        try:
            while self.running:
                # Process logs
                alerts = self.process_monitored_logs()
                
                # Write alerts
                self.write_alerts(alerts)
                
                # Save log positions periodically
                self.save_log_positions()
                
                # Sleep
                time.sleep(10)  # Check logs every 10 seconds
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {str(e)}")
        finally:
            self.running = False
            self.logger.info("Monitoring loop stopped")
    
    def start(self):
        """Start monitoring in foreground"""
        # Initial scan
        self.scan_logs()
        
        # Start monitoring
        self.monitoring_loop()

    @staticmethod
    def stop_daemon(pid_file=None):
        """Stop daemon if running without loading config"""
        if pid_file is None:
            # Use the module-level BASE_DIR constant
            base_dir = BASE_DIR
            output_dir = os.path.join(base_dir, "output")
            pid_file = os.path.join(output_dir, "lim.pid")
        
        try:
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                # Try to terminate process
                os.kill(pid, signal.SIGTERM)
                print(f"Sent SIGTERM to process {pid}")
                
                # Wait for process to terminate
                max_wait = 10  # seconds
                while max_wait > 0:
                    try:
                        os.kill(pid, 0)  # Check if process exists
                        time.sleep(1)
                        max_wait -= 1
                    except OSError:
                        # Process terminated
                        break
                
                # Force kill if still running
                if max_wait == 0:
                    os.kill(pid, signal.SIGKILL)
                    print(f"Process {pid} did not terminate, sent SIGKILL")
                
                # Remove PID file
                if os.path.exists(pid_file):
                    os.remove(pid_file)
                
                return True
            else:
                print("No PID file found, daemon not running?")
                return False
        except Exception as e:
            print(f"Error stopping daemon: {e}")
            return False
          
    def start_daemon(self):
        """Start monitoring in background daemon mode"""
        self.logger.info("Starting daemon mode")
        
        # Ensure pid directory exists
        os.makedirs(os.path.dirname(self.pid_file), exist_ok=True)
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.handle_sigterm)
        
        # Configure daemon context
        daemon_context = daemon.DaemonContext(
            working_directory=self.base_dir,
            umask=0o022,
            pidfile=pidfile.TimeoutPIDLockFile(self.pid_file),
            detach_process=True,
            signal_map={
                signal.SIGTERM: self.handle_sigterm,
                signal.SIGINT: self.handle_sigterm
            }
        )
        
        # Start daemon
        try:
            with daemon_context:
                self.logger.info("Daemon started")
                
                # Initial scan
                self.scan_logs()
                
                # Start monitoring loop
                self.monitoring_loop()
        except Exception as e:
            self.logger.error(f"Error starting daemon: {str(e)}")          
  
    def handle_sigterm(self, signum, frame):
        """Handle termination signals"""
        self.logger.info(f"Received signal {signum}, stopping")
        self.running = False

def display_help():
    """Display a visually appealing help menu"""
    help_text = """
Log Integrity Monitor (LIM) - Help Menu
Usage:
  python lim.py              Start the LIM monitoring service in foreground mode
  python lim.py start        Start the LIM monitoring service in foreground mode
  python lim.py stop/-k      Stop the LIM service if running in background mode
  python lim.py daemon/-d    Run LIM in background (daemon) mode
  python lim.py scan         Scan logs and update configuration
  python lim.py help/-h      Show this help message

Description:
  The Log Integrity Monitor continuously monitors system log files for:
    - Malicious activity patterns and signatures mapped to MITRE ATT&CK framework
    - Suspicious command executions and privilege escalation attempts
    - Unauthorized access attempts and user enumeration
    - Anomalous log patterns detected via machine learning analysis
    - Correlation of related events to identify sophisticated attack patterns
  
  It uses logging and alerting to flag any security anomalies and supports 
  integration with SIEM tools.

Options:
  --base-dir    Base directory (default: /opt/FIMoniSec/Linux-Client)
  --config      Custom config file path

Note:
  Use the 'daemon/-d' option to run LIM in background mode. This is recommended
  for long-term monitoring.
"""
    print(help_text)

def main():
    """Main entry point with improved help text"""
    # First, do a simple check for help flags before any other processing
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h" or sys.argv[1] == "help":
            display_help()
            return  # Exit immediately after showing help
    
    parser = argparse.ArgumentParser(description="Log Integrity Monitor (LIM)", add_help=False)
    
    # Command line arguments with more descriptive help
    parser.add_argument("action", nargs="?",
                      choices=["start", "daemon", "stop", "scan", "help", "-s", "-d", "-k", "-h"],
                      default="start",
                      help="Action to perform (default: start)")
    
    # Parse arguments
    args, unknown = parser.parse_known_args()
    
    # Map short options to full action names
    action_map = {
        "-s": "start",
        "-d": "daemon",
        "-k": "stop",
        "-h": "help"
    }
    action = action_map.get(args.action, args.action)
    
    # Log before taking action for debugging
    print(f"Selected action: {action}")
    
    # Special case for stop - don't need to initialize the full object
    if action == "stop":
        # Use the class's static method
        LogIntegrityMonitor.stop_daemon()
        return
    
    # Initialize LIM with default configuration
    lim = LogIntegrityMonitor()
    
    # Execute requested action
    if action == "start":
        lim.logger.info("Starting LIM in foreground mode")
        lim.start()
    elif action == "daemon":
        lim.logger.info("Starting LIM in daemon mode")
        lim.start_daemon()
    elif action == "scan":
        lim.logger.info("Running one-time log scan")
        alert_count = lim.scan_logs()
        print(f"Scan completed. {alert_count} alerts generated.")

if __name__ == "__main__":
    main()
