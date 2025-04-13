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
# Context-aware detection engineering
import json
import os
import re
import time
from collections import deque, defaultdict

class ContextAwareDetection:
    def __init__(self, config=None):
        self.config = config or {}
        self.event_history = deque(maxlen=1000)  # Keep last 1000 events
        self.attack_chains = defaultdict(list)
        self.environment = self.config.get('environment', 'production')
        self.ip_blocklist = set()
        self.suspicious_processes = set()
        self.mitre_techniques = self.load_mitre_techniques()
        
        # Environment-specific settings
        self.thresholds = {
            'production': {'risk_multiplier': 1.5, 'alert_threshold': 70},
            'staging': {'risk_multiplier': 1.2, 'alert_threshold': 75},
            'development': {'risk_multiplier': 1.0, 'alert_threshold': 80}
        }
        
        # Load critical file mappings
        self.file_criticality = self.load_file_criticality()
    
    def load_mitre_techniques(self):
        """Load detailed MITRE ATT&CK technique information"""
        # This would typically load from a JSON file containing full technique details
        # Simplified example included here
        techniques = {
            "T1222": {
                "name": "File and Directory Permissions Modification",
                "tactic": "Defense Evasion",
                "severity": 70,
                "detection_difficulty": "Medium",
                "related_techniques": ["T1222.001", "T1222.002", "T1574"],
                "common_tools": ["chmod", "chown", "icacls", "attrib"]
            },
            "T1565": {
                "name": "Data Manipulation",
                "tactic": "Impact",
                "severity": 75,
                "detection_difficulty": "High",
                "related_techniques": ["T1565.001", "T1565.002", "T1565.003"],
                "common_tools": ["hex editor", "sed", "awk", "vim"]
            },
            # Add more techniques as needed
        }
        return techniques
    
    def load_file_criticality(self):
        """Load file criticality mappings based on environment"""
        # This would typically load from a configuration file
        # Simplified example included here
        base_criticality = {
            "/etc/passwd": 95,
            "/etc/shadow": 95,
            "/etc/sudoers": 90,
            "/etc/ssh/sshd_config": 85,
            "/etc/hosts": 80,
            "/var/www/html": 75,
            "/bin": 70,
            "/sbin": 70,
            "/usr/bin": 70,
            "/usr/sbin": 70,
            "/boot": 90,
            "/lib": 70,
            "/etc/crontab": 85,
            "/etc/cron.d": 85,
            "/.ssh/authorized_keys": 90
        }
        
        # Adjust criticality based on environment
        if self.environment == 'development':
            return {k: max(v * 0.7, 50) for k, v in base_criticality.items()}
        elif self.environment == 'staging':
            return {k: max(v * 0.9, 60) for k, v in base_criticality.items()}
        else:  # production
            return base_criticality
    
    def calculate_file_criticality(self, file_path):
        """Calculate criticality score for a file based on path and content"""
        # Direct match for known critical files
        for critical_path, score in self.file_criticality.items():
            if file_path.startswith(critical_path):
                return score
        
        # Criticality based on file type and location
        if file_path.startswith('/etc/'):
            return 70
        elif file_path.startswith(('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/')):
            return 65
        elif '/www/' in file_path:
            if any(ext in file_path.lower() for ext in ['.php', '.asp', '.jsp']):
                return 75  # Web executable content
            return 60
        elif '.ssh/' in file_path:
            return 85
        elif any(file_path.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb']):
            return 60  # Scripts
        elif any(file_path.endswith(ext) for ext in ['.conf', '.cfg', '.ini', '.json']):
            return 65  # Config files
        
        # Default criticality
        return 50
    
    def correlate_attack_chain(self, event):
        """Identify potential attack chains by correlating multiple events"""
        # Extract key information
        event_type = event.get('event_type')
        file_path = event.get('file_path')
        timestamp = event.get('timestamp')
        technique_id = event.get('mitre_mapping', {}).get('technique_id', 'unknown')
        process_info = event.get('process_correlation', {}).get('related_process', {})
        
        # Create event identifier for grouping
        host_id = event.get('host_id', 'localhost')
        user_id = process_info.get('user', 'unknown')
        process_name = process_info.get('process_name', 'unknown')
        
        # Group identifier to track related events
        group_key = f"{host_id}_{user_id}_{process_name}"
        
        # Add to event history
        self.event_history.append(event)
        
        # Add to potential attack chain
        self.attack_chains[group_key].append({
            'timestamp': timestamp,
            'event_type': event_type,
            'file_path': file_path,
            'technique_id': technique_id,
            'process_pid': process_info.get('pid', 'unknown')
        })
        
        # Prune old events from attack chains (events older than 30 minutes)
        if timestamp:
            try:
                event_time = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                event_time = time.mktime(event_time)
                
                # Remove events older than 30 minutes
                cutoff_time = event_time - (30 * 60)
                self.attack_chains[group_key] = [
                    e for e in self.attack_chains[group_key] 
                    if time.mktime(time.strptime(e['timestamp'], "%Y-%m-%d %H:%M:%S")) >= cutoff_time
                ]
                
                # Remove empty chains
                if not self.attack_chains[group_key]:
                    del self.attack_chains[group_key]
            except (ValueError, TypeError):
                pass  # Skip time-based pruning if timestamp format is invalid
        
        # Check for attack patterns in this chain
        return self.detect_attack_patterns(group_key)
    
    def detect_attack_patterns(self, group_key):
        """Detect known attack patterns in event chains"""
        if group_key not in self.attack_chains:
            return None
        
        chain = self.attack_chains[group_key]
        if len(chain) < 2:
            return None  # Need at least 2 events for a chain
        
        # Common attack patterns to check for
        patterns = [
            {
                'name': 'Reconnaissance and Data Theft',
                'severity': 85,
                'techniques': ['T1083', 'T1005', 'T1039', 'T1020'],
                'min_match': 2
            },
            {
                'name': 'Credential Access',
                'severity': 90,
                'techniques': ['T1003', 'T1552', 'T1555', 'T1212'],
                'min_match': 1
            },
            {
                'name': 'Defense Evasion',
                'severity': 85,
                'techniques': ['T1222', 'T1562', 'T1070', 'T1036', 'T1027'],
                'min_match': 2
            },
            {
                'name': 'Persistence',
                'severity': 80,
                'techniques': ['T1053', 'T1543', 'T1546', 'T1098', 'T1136'],
                'min_match': 1
            }
        ]
        
        # Check each pattern against our chain
        chain_techniques = [event['technique_id'] for event in chain]
        detected_patterns = []
        
        for pattern in patterns:
            matches = [tech for tech in chain_techniques if any(tech.startswith(pt) for pt in pattern['techniques'])]
            if len(matches) >= pattern['min_match']:
                detected_patterns.append({
                    'pattern': pattern['name'],
                    'severity': pattern['severity'],
                    'matched_techniques': matches,
                    'events': chain
                })
        
        return detected_patterns if detected_patterns else None
    
    def calculate_risk_score(self, event):
        """Calculate risk score based on multiple factors including file criticality"""
        # Base score starts from file criticality
        file_path = event.get('file_path', '')
        base_score = self.calculate_file_criticality(file_path)
        
        # Adjust for MITRE technique severity
        mitre_mapping = event.get('mitre_mapping', {})
        technique_id = mitre_mapping.get('technique_id', '')
        
        technique_severity = 50  # Default value
        if technique_id in self.mitre_techniques:
            technique_severity = self.mitre_techniques[technique_id].get('severity', 50)
        
        # Adjust for anomaly detection results
        anomaly_data = event.get('anomaly_detection', {})
        anomaly_score = anomaly_data.get('anomaly_score', 0) if anomaly_data else 0
        
        # Consider process correlation
        process_correlation = event.get('process_correlation', {})
        process_factor = 1.0  # Default neutral factor
        
        if process_correlation:
            process = process_correlation.get('related_process', {})
            
            # Check for suspicious processes
            process_name = process.get('process_name', '').lower()
            if process_name in self.suspicious_processes:
                process_factor = 1.5
            
            # Check for unusual execution paths
            cmd_line = process.get('cmdline', '').lower()
            if cmd_line and ('/tmp/' in cmd_line or '/dev/shm/' in cmd_line):
                process_factor = 1.4
        
        # Calculate final risk score
        risk_multiplier = self.thresholds[self.environment]['risk_multiplier']
        
        # Combine all factors: base criticality, technique severity, anomaly score, and process factor
        risk_score = (
            (base_score * 0.3) +                      # 30% from file criticality
            (technique_severity * 0.3) +              # 30% from MITRE technique severity
            (anomaly_score * 50 * 0.2) +              # 20% from anomaly score (scaled from [-1,1] to [0,100])
            (base_score * process_factor * 0.2)       # 20% from process context
        ) * risk_multiplier
        
        # Cap at 100
        risk_score = min(max(risk_score, 0), 100)
        
        return {
            'score': risk_score,
            'components': {
                'file_criticality': base_score,
                'technique_severity': technique_severity,
                'anomaly_factor': anomaly_score * 50,
                'process_factor': process_factor,
                'environment_multiplier': risk_multiplier
            },
            'is_alert': risk_score >= self.thresholds[self.environment]['alert_threshold']
        }
