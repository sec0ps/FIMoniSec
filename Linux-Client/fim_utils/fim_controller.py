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
# Main controller for enhanced FIM system
import os
import time
import json
import threading
import queue
from collections import defaultdict

from fim_utils.fim_perf import AdaptiveScanner
from fim_utils.fim_context import ContextAwareDetection
from fim_utils.fim_behavioral import EnhancedBehavioralBaselining
from fim_utils.adv_analysis import AdvancedFileContentAnalysis

class EnhancedFIM:
    def __init__(self, config=None):
        self.config = config or {}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_dir = os.path.join(self.base_dir, "output")
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize components
        self.adaptive_scanner = AdaptiveScanner(self.config.get('performance', {}))
        self.context_detection = ContextAwareDetection(self.config.get('detection', {}))
        self.behavioral_baselining = EnhancedBehavioralBaselining(self.config.get('behavioral', {}))
        self.content_analysis = AdvancedFileContentAnalysis(self.config.get('content_analysis', {}))
        
        # Event processing queue
        self.event_queue = queue.Queue()
        self.processing_thread = None
        self.running = False
        
        # Correlation storage
        self.correlated_events = defaultdict(list)
        self.attack_chains = {}
        
        # Initialize environment
        self.environment = self.config.get('environment', 'production')
        
    def start(self):
        """Start the enhanced FIM system"""
        if self.running:
            print("[INFO] Enhanced FIM system already running")
            return
            
        self.running = True
        
        # Start event processing thread
        self.processing_thread = threading.Thread(target=self.process_events, daemon=True)
        self.processing_thread.start()
        
        print(f"[INFO] Enhanced FIM system started in {self.environment} environment")
        
    def stop(self):
        """Stop the enhanced FIM system"""
        if not self.running:
            return
            
        self.running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        print("[INFO] Enhanced FIM system stopped")
    
    def handle_file_event(self, event):
        """Handle file events from the base FIM system"""
        # Enqueue for processing
        self.event_queue.put(event)
        
        # Return initial fast-path result
        return {
            "event_received": True,
            "queued_for_analysis": True,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def process_events(self):
        """Process events in the background"""
        while self.running:
            try:
                # Get next event with timeout
                try:
                    event = self.event_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process the event
                processed_event = self.analyze_event(event)
                
                # Log the enhanced event
                self.log_enhanced_event(processed_event)
                
                # Trigger alerts if needed
                if self.should_alert(processed_event):
                    self.trigger_alert(processed_event)
                
                # Update behavioral baseline
                self.behavioral_baselining.update_baseline(event)
                
                # Mark as done
                self.event_queue.task_done()
                
            except Exception as e:
                print(f"[ERROR] Event processing error: {e}")
    
    def analyze_event(self, event):
        """Apply all enhanced analysis to an event"""
        enhanced_event = event.copy()
        
        # Extract basic information
        file_path = event.get('file_path', '')
        event_type = event.get('event_type', '')
        previous_hash = event.get('previous_hash', '')
        new_hash = event.get('new_hash', '')
        previous_metadata = event.get('previous_metadata', {})
        new_metadata = event.get('new_metadata', {})
        
        # 1. Behavioral anomaly detection
        anomaly_result = self.behavioral_baselining.detect_anomalies(event)
        if anomaly_result:
            enhanced_event['enhanced_anomaly_detection'] = anomaly_result
        
        # 2. Context-aware detection
        risk_score = self.context_detection.calculate_risk_score(event)
        enhanced_event['risk_assessment'] = risk_score
        
        # 3. Attack chain correlation
        attack_chains = self.context_detection.correlate_attack_chain(event)
        if attack_chains:
            enhanced_event['attack_chains'] = attack_chains
        
        # 4. Advanced file content analysis (for modifications)
        if event_type == 'MODIFIED' and os.path.exists(file_path):
            content_analysis = self.content_analysis.analyze_file_changes(
                file_path, previous_hash, new_hash
            )
            enhanced_event['content_analysis'] = content_analysis
            
            # Add malware indicators check
            malware_check = self.content_analysis.check_malware_indicators(file_path, new_hash)
            enhanced_event['malware_indicators'] = malware_check
        
        # 5. Time series analysis on related events
        host_id = event.get('host_id', 'localhost')
        if host_id in self.correlated_events:
            time_series = self.behavioral_baselining.analyze_time_series(
                self.correlated_events[host_id][-50:]  # Analyze last 50 events
            )
            if time_series:
                enhanced_event['time_series_analysis'] = time_series
        
        # Add to correlated events
        self.correlated_events[host_id].append(event)
        if len(self.correlated_events[host_id]) > 1000:
            self.correlated_events[host_id] = self.correlated_events[host_id][-1000:]
        
        return enhanced_event
    
    def log_enhanced_event(self, event):
        """Log the enhanced event for further analysis"""
        log_path = os.path.join(self.output_dir, "enhanced_events.json")
        
        try:
            with open(log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to log enhanced event: {e}")
    
    def should_alert(self, event):
        """Determine if an event should trigger an alert"""
        # Check risk score
        risk_assessment = event.get('risk_assessment', {})
        if risk_assessment.get('is_alert', False):
            return True
        
        # Check anomaly detection
        anomaly = event.get('enhanced_anomaly_detection', {})
        if anomaly and anomaly.get('is_anomaly', False) and anomaly.get('anomaly_score', 0) < -0.7:
            return True
            
        # Check attack chains
        attack_chains = event.get('attack_chains', [])
        if attack_chains:
            return True
            
        # Check malware indicators
        indicators = event.get('malware_indicators', {})
        if indicators and indicators.get('high_entropy', False):
            return True
            
        # Check content analysis criticality
        content = event.get('content_analysis', {})
        if content and content.get('criticality', 'low') == 'high':
            return True
            
        return False
    
    def trigger_alert(self, event):
        """Trigger an alert for a high-risk event"""
        alert_file = os.path.join(self.output_dir, "fim_alerts.json")
        
        # Create alert object
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": event.get("uuid", str(time.time())),
            "file_path": event.get("file_path", ""),
            "event_type": event.get("event_type", ""),
            "risk_score": event.get("risk_assessment", {}).get("score", 0),
            "anomaly_score": event.get("enhanced_anomaly_detection", {}).get("anomaly_score", 0),
            "alert_reasons": self.get_alert_reasons(event),
            "suggested_actions": self.get_suggested_actions(event),
            "raw_event": event
        }
        
        # Write alert to file
        try:
            with open(alert_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to write alert: {e}")
            
        # Print alert to console
        print(f"\n[ALERT] High-risk file integrity event detected!")
        print(f"[ALERT] File: {alert['file_path']}")
        print(f"[ALERT] Event: {alert['event_type']}")
        print(f"[ALERT] Risk Score: {alert['risk_score']:.2f}")
        print(f"[ALERT] Reasons: {', '.join(alert['alert_reasons'])}")
        print(f"[ALERT] Suggested Actions: {', '.join(alert['suggested_actions'])}")
    
    def get_alert_reasons(self, event):
        """Get human-readable reasons for an alert"""
        reasons = []
        
        # Risk score reason
        risk = event.get('risk_assessment', {})
        if risk.get('is_alert', False):
            reasons.append(f"High risk score ({risk.get('score', 0):.2f})")
            
            # Add risk components
            components = risk.get('components', {})
            if components.get('file_criticality', 0) > 80:
                reasons.append("Critical file modified")
            if components.get('technique_severity', 0) > 80:
                reasons.append("Severe MITRE technique detected")
            if components.get('process_factor', 1.0) > 1.2:
                reasons.append("Suspicious process involvement")
        
        # Anomaly reasons
        anomaly = event.get('enhanced_anomaly_detection', {})
        if anomaly and anomaly.get('is_anomaly', False):
            reasons.append(f"Behavioral anomaly ({anomaly.get('anomaly_score', 0):.2f})")
            
            # Add model-specific reasons
            for model, result in anomaly.get('model_scores', {}).items():
                if result.get('is_anomaly', False):
                    features = result.get('contributing_features', [])
                    if features:
                        reasons.append(f"Unusual {model} pattern: {', '.join(features)}")
        
        # Attack chain reasons
        attack_chains = event.get('attack_chains', [])
        if attack_chains:
            for chain in attack_chains:
                reasons.append(f"Part of attack pattern: {chain.get('pattern', 'Unknown')}")
        
        # Content analysis reasons
        content = event.get('content_analysis', {})
        if content:
            if content.get('criticality', 'low') == 'high':
                reasons.append("Critical content changes detected")
                
            # Add specific content reasons
            if content.get('type_specific', {}).get('suspicious_patterns', {}):
                patterns = content.get('type_specific', {}).get('suspicious_patterns', {})
                for category in patterns:
                    reasons.append(f"Suspicious {category} found in content")
        
        # Malware indicators
        indicators = event.get('malware_indicators', {})
        if indicators and indicators.get('high_entropy', False):
            reasons.append(f"High entropy content ({indicators.get('entropy', 0):.2f})")
            
        return reasons
    
    def get_suggested_actions(self, event):
        """Get suggested actions based on the event"""
        actions = []
        risk_score = event.get('risk_assessment', {}).get('score', 0)
        event_type = event.get('event_type', '')
        file_path = event.get('file_path', '')
        
        # Basic actions based on risk
        if risk_score > 90:
            actions.append("Isolate host immediately")
            actions.append("Initiate incident response procedure")
        elif risk_score > 80:
            actions.append("Terminate suspicious processes")
            actions.append("Take file backup for forensic analysis")
        elif risk_score > 70:
            actions.append("Increase monitoring on this host")
            
        # Content-specific actions
        content = event.get('content_analysis', {})
        if content:
            if content.get('type_specific', {}).get('format', '') == 'config':
                actions.append("Review configuration changes")
                
            if content.get('type_specific', {}).get('format', '') == 'script':
                suspicious = content.get('type_specific', {}).get('suspicious_patterns', {})
                if suspicious:
                    actions.append("Review script for malicious code")
        
        # File-specific actions
        if event_type == 'NEW FILE' and 'bin' in file_path:
            actions.append("Verify executable authenticity")
        
        if event_type == 'MODIFIED' and any(ext in file_path for ext in ['.conf', '.cfg', '.ini']):
            actions.append("Verify configuration changes with admin")
            
        # Malware indicators
        indicators = event.get('malware_indicators', {})
        if indicators and indicators.get('high_entropy', False):
            actions.append("Scan file with anti-virus")
            
        # Minimal default action
        if not actions:
            actions.append("Investigate file changes")
            
        return actions
