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
# Enhanced behavioral baselining and anomaly detection
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import os
import time
import json
from collections import defaultdict

class EnhancedBehavioralBaselining:
    def __init__(self, config=None):
        self.config = config or {}
        self.models = {}
        self.feature_scalers = {}
        self.baseline_data = defaultdict(list)
        self.model_dir = self.config.get('model_dir', os.path.join(os.getcwd(), 'ml_models'))
        self.training_samples_required = self.config.get('training_samples', 100)
        self.retraining_interval = self.config.get('retraining_interval', 86400)  # 24 hours
        self.last_training_time = 0
        self.feature_importance = {}
        
        # Ensure model directory exists
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Load existing models if available
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models if available"""
        model_types = ['temporal', 'contextual', 'content']
        
        for model_type in model_types:
            model_path = os.path.join(self.model_dir, f"{model_type}_model.joblib")
            scaler_path = os.path.join(self.model_dir, f"{model_type}_scaler.joblib")
            
            if os.path.exists(model_path) and os.path.exists(scaler_path):
                try:
                    self.models[model_type] = joblib.load(model_path)
                    self.feature_scalers[model_type] = joblib.load(scaler_path)
                    print(f"[INFO] Loaded {model_type} model and scaler")
                except Exception as e:
                    print(f"[ERROR] Failed to load {model_type} model: {e}")
    
    def extract_temporal_features(self, event):
        """Extract time-based features from event data"""
        # Parse timestamp
        timestamp = event.get('timestamp', '')
        try:
            if timestamp:
                dt = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                hour = dt.tm_hour
                minute = dt.tm_min
                weekday = dt.tm_wday  # 0-6, Monday is 0
                is_weekend = 1 if weekday >= 5 else 0
                is_business_hours = 1 if (8 <= hour <= 18 and weekday < 5) else 0
                is_night = 1 if (hour < 6 or hour >= 22) else 0
            else:
                # Default values if timestamp is missing
                hour, minute, weekday = 12, 0, 0
                is_weekend, is_business_hours, is_night = 0, 1, 0
        except ValueError:
            # Default values if timestamp format is invalid
            hour, minute, weekday = 12, 0, 0
            is_weekend, is_business_hours, is_night = 0, 1, 0
        
        # Event type encoding
        event_type_map = {
            'NEW FILE': 1,
            'MODIFIED': 2,
            'DELETED': 3,
            'METADATA_CHANGED': 4
        }
        event_type_code = event_type_map.get(event.get('event_type', ''), 0)
        
        # Extract features
        features = {
            'hour': hour,
            'minute': minute,
            'weekday': weekday,
            'is_weekend': is_weekend,
            'is_business_hours': is_business_hours,
            'is_night': is_night,
            'event_type_code': event_type_code
        }
        
        return features
    
    def extract_contextual_features(self, event):
        """Extract context-related features from event data"""
        # File path features
        file_path = event.get('file_path', '')
        is_system_file = 1 if any(file_path.startswith(d) for d in ['/bin', '/sbin', '/lib', '/etc', '/usr/bin', '/usr/sbin', '/usr/lib']) else 0
        is_home_file = 1 if '/home/' in file_path else 0
        is_temp_file = 1 if any(t in file_path for t in ['/tmp/', '/var/tmp/', '/dev/shm/']) else 0
        is_config_file = 1 if any(file_path.endswith(ext) for ext in ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml']) else 0
        is_executable = 1 if any(file_path.endswith(ext) for ext in ['', '.sh', '.py', '.rb', '.pl']) and (is_system_file or '/bin/' in file_path) else 0
        
        # Process correlation features
        process_correlation = event.get('process_correlation', {})
        has_process_correlation = 1 if process_correlation and process_correlation != 'N/A' else 0
        
        process_info = {}
        if has_process_correlation:
            related_process = process_correlation.get('related_process', {})
            process_info = {
                'pid': related_process.get('pid', 0),
                'process_name': related_process.get('process_name', ''),
                'user': related_process.get('user', '')
            }
        
        is_root_process = 1 if process_info.get('user') == 'root' else 0
        is_system_process = 1 if process_info.get('process_name') in ['systemd', 'init', 'cron', 'sshd'] else 0
        
        # File metadata features
        new_metadata = event.get('new_metadata', {})
        if isinstance(new_metadata, str):
            new_metadata = {}
        
        file_size = 0
        try:
            file_size = int(new_metadata.get('size', 0))
        except (ValueError, TypeError):
            pass
        
        features = {
            'is_system_file': is_system_file,
            'is_home_file': is_home_file,
            'is_temp_file': is_temp_file,
            'is_config_file': is_config_file,
            'is_executable': is_executable,
            'has_process_correlation': has_process_correlation,
            'is_root_process': is_root_process,
            'is_system_process': is_system_process,
            'file_size': file_size
        }
        
        return features
    
    def extract_content_features(self, event):
        """Extract content-related features from file changes"""
        # Check for hash changes
        previous_hash = event.get('previous_hash', '')
        new_hash = event.get('new_hash', '')
        hash_changed = 1 if previous_hash and new_hash and previous_hash != new_hash else 0
        
        # Check for metadata changes
        changes = event.get('changes', {})
        if isinstance(changes, str):
            changes = {}
        
        permission_changed = 1 if 'Permissions changed' in changes else 0
        ownership_changed = 1 if 'Ownership changed' in changes else 0
        size_changed = 1 if 'Size changed' in changes else 0
        timestamp_changed = 1 if 'Last modified timestamp changed' in changes else 0
        
        # Metadata details
        new_metadata = event.get('new_metadata', {})
        if isinstance(new_metadata, str):
            new_metadata = {}
            
        previous_metadata = event.get('previous_metadata', {})
        if isinstance(previous_metadata, str):
            previous_metadata = {}
        
        size_delta = 0
        try:
            new_size = int(new_metadata.get('size', 0))
            prev_size = int(previous_metadata.get('size', 0))
            size_delta = new_size - prev_size
        except (ValueError, TypeError):
            pass
        
        features = {
            'hash_changed': hash_changed,
            'permission_changed': permission_changed,
            'ownership_changed': ownership_changed,
            'size_changed': size_changed,
            'timestamp_changed': timestamp_changed,
            'size_delta': size_delta
        }
        
        return features
    
    def combine_features(self, event):
        """Combine all feature types for comprehensive analysis"""
        temporal = self.extract_temporal_features(event)
        contextual = self.extract_contextual_features(event)
        content = self.extract_content_features(event)
        
        # Combine all features
        features = {}
        features.update(temporal)
        features.update(contextual)
        features.update(content)
        
        return features
    
    def train_models(self, events):
        """Train or update anomaly detection models based on collected events"""
        if len(events) < self.training_samples_required:
            print(f"[INFO] Not enough samples for training. Have {len(events)}, need {self.training_samples_required}")
            return False
        
        print(f"[INFO] Training anomaly detection models with {len(events)} events")
        
        # Extract all feature types
        all_features = []
        for event in events:
            features = self.combine_features(event)
            all_features.append(features)
        
        # Convert to DataFrame
        df = pd.DataFrame(all_features)
        
        # Replace NaN values with 0
        df.fillna(0, inplace=True)
        
        # Train different models for different feature types
        model_configs = {
            'temporal': {
                'features': [col for col in df.columns if col in self.extract_temporal_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            },
            'contextual': {
                'features': [col for col in df.columns if col in self.extract_contextual_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            },
            'content': {
                'features': [col for col in df.columns if col in self.extract_content_features({})],
                'model': IsolationForest(contamination=0.05, random_state=42)
            }
        }
        
        # Train each model
        for model_name, config in model_configs.items():
            feature_cols = config['features']
            if not feature_cols:
                continue  # Skip if no features available
            
            # Get feature subset
            X = df[feature_cols]
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Train model
            model = config['model']
            model.fit(X_scaled)
            
            # Save model and scaler
            self.models[model_name] = model
            self.feature_scalers[model_name] = scaler
            
            # Save to disk
# Save feature scaler
            joblib.dump(scaler, os.path.join(self.model_dir, f"{model_name}_scaler.joblib"))
            
            # Calculate feature importance for interpretability (for RandomForest only)
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                self.feature_importance[model_name] = dict(zip(feature_cols, importances))
        
        self.last_training_time = time.time()
        return True
    
    def detect_anomalies(self, event):
        """Detect anomalies using all trained models"""
        if not self.models:
            return None  # No trained models available
        
        # Extract and combine features
        features = self.combine_features(event)
        
        # Run detection for each model
        anomaly_results = {}
        for model_name, model in self.models.items():
            # Get relevant features for this model
            if model_name == 'temporal':
                model_features = self.extract_temporal_features(event)
            elif model_name == 'contextual':
                model_features = self.extract_contextual_features(event)
            elif model_name == 'content':
                model_features = self.extract_content_features(event)
            else:
                continue
            
            # Create feature vector
            feature_names = list(model_features.keys())
            feature_values = list(model_features.values())
            
            # Skip if no features available
            if not feature_names:
                continue
            
            # Scale features
            scaler = self.feature_scalers.get(model_name)
            if not scaler:
                continue
                
            X = np.array(feature_values).reshape(1, -1)
            X_scaled = scaler.transform(X)
            
            # Predict anomaly
            prediction = model.predict(X_scaled)[0]
            anomaly_score = model.decision_function(X_scaled)[0]
            
            # Score interpretation:
            # Isolation Forest: negative = anomaly, positive = normal
            # Convert to standard range [-1, 1] where -1 is most anomalous
            norm_score = anomaly_score
            
            anomaly_results[model_name] = {
                'is_anomaly': prediction == -1,
                'score': norm_score,
                'contributing_features': self.get_contributing_features(model_name, X_scaled[0], feature_names)
            }
        
        # Combine results for final decision
        if anomaly_results:
            combined_score = np.mean([r['score'] for r in anomaly_results.values()])
            is_anomaly = any(r['is_anomaly'] for r in anomaly_results.values())
            
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': combined_score,
                'model_scores': anomaly_results,
                'summary': f"Anomaly detected with score {combined_score:.4f}" if is_anomaly else "Normal activity"
            }
        
        return None
    
    def get_contributing_features(self, model_name, features_scaled, feature_names):
        """Identify which features contributed most to the anomaly score"""
        if model_name not in self.feature_importance or not self.feature_importance[model_name]:
            return []
            
        # Get feature importance
        importance = self.feature_importance[model_name]
        
        # Find features with highest deviation from norm, weighted by importance
        contributors = []
        for i, feature in enumerate(feature_names):
            if feature in importance:
                # Calculate contribution: absolute scaled value * feature importance
                contrib = abs(features_scaled[i]) * importance[feature]
                contributors.append((feature, contrib))
        
        # Sort by contribution and return top 3
        return [f for f, _ in sorted(contributors, key=lambda x: x[1], reverse=True)[:3]]
    
    def update_baseline(self, event):
        """Update baseline with new event data"""
        # Add to baseline data
        self.baseline_data['events'].append(event)
        
        # Limit size of baseline data
        max_samples = self.config.get('max_baseline_samples', 10000)
        if len(self.baseline_data['events']) > max_samples:
            self.baseline_data['events'] = self.baseline_data['events'][-max_samples:]
        
        # Check if retraining is needed
        current_time = time.time()
        if current_time - self.last_training_time > self.retraining_interval:
            # Retrain models with updated data
            print("[INFO] Retraining anomaly detection models with updated baseline data")
            self.train_models(self.baseline_data['events'])
    
    def analyze_time_series(self, events, window_size=60):
        """Analyze time series patterns in events"""
        if not events:
            return None
            
        # Group events by time window
        time_windows = defaultdict(list)
        
        for event in events:
            timestamp = event.get('timestamp', '')
            if not timestamp:
                continue
                
            try:
                dt = time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                # Round to the nearest window
                window_key = time.strftime("%Y-%m-%d %H:00:00", dt)  # Hourly windows
                time_windows[window_key].append(event)
            except ValueError:
                continue
        
        # Analyze frequency patterns
        window_counts = {window: len(events) for window, events in time_windows.items()}
        
        if len(window_counts) < 3:
            return None  # Not enough data for meaningful analysis
            
        # Detect frequency anomalies
        values = list(window_counts.values())
        mean_count = np.mean(values)
        std_count = np.std(values)
        
        # Detect windows with unusual activity
        z_scores = {window: (count - mean_count) / max(std_count, 0.001) for window, count in window_counts.items()}
        anomalous_windows = {window: z for window, z in z_scores.items() if abs(z) > 2.0}
        
        if anomalous_windows:
            return {
                'anomalous_windows': anomalous_windows,
                'window_counts': window_counts,
                'mean_count': mean_count,
                'std_count': std_count
            }
        
        return None
