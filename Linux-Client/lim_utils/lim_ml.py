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
import json
import time
import pickle
import logging
import numpy as np
from datetime import datetime
from collections import defaultdict, Counter

# Define default paths
MODEL_DIR = os.path.join("lim_utils", "data", "models")

class LogAnomalyDetector:
    """Machine learning based log anomaly detection"""
    
    def __init__(self, config=None):
        """
        Initialize the log anomaly detector
        
        Args:
            config: Configuration dictionary with ML settings
        """
        self.config = config or {}
        
        # Default configuration
        self.training_period = self.config.get("training_period", 3600)  # 1 hour
        self.min_training_samples = self.config.get("min_training_samples", 1000)
        self.anomaly_threshold = self.config.get("anomaly_threshold", 0.8)
        
        # Create model directory if it doesn't exist
        os.makedirs(MODEL_DIR, exist_ok=True)
        
        # Initialize model tracking
        self.models = {}
        self.vectorizers = {}
        self.training_data = defaultdict(list)
        self.last_training_time = defaultdict(float)
        self.feature_extractors = {}
        
        # Initialize metrics tracking
        self.metrics = {
            "total_processed": 0,
            "anomalies_detected": 0,
            "models_trained": 0,
            "logs_by_source": defaultdict(int)
        }
        
        try:
            self._load_scikit_learn()
        except ImportError:
            logging.error("scikit-learn not installed. ML-based detection will be disabled.")
            self.sklearn_available = False
        else:
            self.sklearn_available = True
            
    def _load_scikit_learn(self):
        """Load scikit-learn components"""
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.preprocessing import StandardScaler
        
        self.IsolationForest = IsolationForest
        self.TfidfVectorizer = TfidfVectorizer
        self.StandardScaler = StandardScaler
    
    def process_log(self, source_key, log_entry):
        """
        Process a log entry for training or anomaly detection
        
        Args:
            source_key: Identifier for the log source
            log_entry: Parsed log entry dictionary
            
        Returns:
            dict: Anomaly detection result or None if in training mode
        """
        if not self.sklearn_available:
            return None
            
        self.metrics["total_processed"] += 1
        self.metrics["logs_by_source"][source_key] += 1
        
        # Extract features from the log entry
        features = self._extract_features(source_key, log_entry)
        
        # If we don't have a model yet, collect training data
        if source_key not in self.models:
            self.training_data[source_key].append((log_entry, features))
            
            # Train model if we have enough data and training period has elapsed
            now = time.time()
            if (len(self.training_data[source_key]) >= self.min_training_samples and 
                now - self.last_training_time[source_key] > self.training_period):
                self._train_model(source_key)
                
            return None
        
        # Predict using existing model
        return self._predict_anomaly(source_key, log_entry, features)
    
    def _extract_features(self, source_key, log_entry):
        """
        Extract features from a log entry
        
        Args:
            source_key: Identifier for the log source
            log_entry: Parsed log entry dictionary
            
        Returns:
            tuple: (text_features, numerical_features)
        """
        # Initialize or get feature extractor for this source
        if source_key not in self.feature_extractors:
            self.feature_extractors[source_key] = LogFeatureExtractor(source_key)
            
        # Extract features
        return self.feature_extractors[source_key].extract(log_entry)
    
    def _train_model(self, source_key):
        """
        Train an anomaly detection model for a specific log source
        
        Args:
            source_key: Identifier for the log source
        """
        if not self.sklearn_available:
            return
            
        logging.info(f"Training model for {source_key} with {len(self.training_data[source_key])} samples")
        
        # Prepare training data
        log_entries, features_list = zip(*self.training_data[source_key])
        text_features, numerical_features = zip(*features_list)
        
        # Train text vectorizer
        vectorizer = self.TfidfVectorizer(max_features=100)
        if any(text_features):  # Only fit if we have non-empty text
            text_vectors = vectorizer.fit_transform(text_features).toarray()
        else:
            text_vectors = np.zeros((len(text_features), 1))
        
        # Process numerical features
        if any(numerical_features) and len(numerical_features[0]) > 0:
            # Convert list of lists to 2D array
            numerical_array = np.array(numerical_features)
            
            # Scale numerical features
            scaler = self.StandardScaler()
            scaled_numerical = scaler.fit_transform(numerical_array)
        else:
            scaled_numerical = np.zeros((len(numerical_features), 1))
        
        # Combine features
        combined_features = np.hstack((text_vectors, scaled_numerical))
        
        # Train isolation forest model
        contamination = min(0.1, max(0.01, 100 / len(combined_features)))
        model = self.IsolationForest(contamination=contamination, random_state=42)
        model.fit(combined_features)
        
        # Save model and metadata
        self.models[source_key] = model
        self.vectorizers[source_key] = vectorizer
        self.last_training_time[source_key] = time.time()
        
        # Store preprocessing components
        self.feature_extractors[source_key].text_vectorizer = vectorizer
        self.feature_extractors[source_key].numerical_scaler = scaler
        
        # Create serialization directory for this source
        source_dir = os.path.join(MODEL_DIR, self._sanitize_key(source_key))
        os.makedirs(source_dir, exist_ok=True)
        
        # Save model components
        try:
            with open(os.path.join(source_dir, "model.pkl"), "wb") as f:
                pickle.dump(model, f)
                
            with open(os.path.join(source_dir, "vectorizer.pkl"), "wb") as f:
                pickle.dump(vectorizer, f)
                
            with open(os.path.join(source_dir, "scaler.pkl"), "wb") as f:
                pickle.dump(scaler, f)
                
            with open(os.path.join(source_dir, "metadata.json"), "w") as f:
                metadata = {
                    "source_key": source_key,
                    "training_samples": len(combined_features),
                    "training_time": datetime.now().isoformat(),
                    "feature_dimensions": combined_features.shape[1],
                    "text_dimensions": text_vectors.shape[1],
                    "numerical_dimensions": scaled_numerical.shape[1]
                }
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving model for {source_key}: {str(e)}")
        
        # Clear training data to save memory
        self.training_data[source_key] = []
        
        # Update metrics
        self.metrics["models_trained"] += 1
        
        logging.info(f"Model trained for {source_key} with {combined_features.shape[1]} features")
    
    def _predict_anomaly(self, source_key, log_entry, features):
        """
        Predict if a log entry is anomalous
        
        Args:
            source_key: Identifier for the log source
            log_entry: Parsed log entry dictionary
            features: Extracted features tuple
            
        Returns:
            dict: Anomaly prediction result
        """
        if not self.sklearn_available or source_key not in self.models:
            return None
            
        # Get model components
        model = self.models[source_key]
        extractor = self.feature_extractors[source_key]
        
        # Extract and preprocess features
        text_feature, numerical_features = features
        
        # Vectorize text
        if extractor.text_vectorizer:
            text_vector = extractor.text_vectorizer.transform([text_feature]).toarray()
        else:
            text_vector = np.zeros((1, 1))
        
        # Scale numerical features
        if extractor.numerical_scaler and len(numerical_features) > 0:
            numerical_array = np.array([numerical_features])
            scaled_numerical = extractor.numerical_scaler.transform(numerical_array)
        else:
            scaled_numerical = np.zeros((1, 1))
        
        # Combine features
        combined_features = np.hstack((text_vector, scaled_numerical))
        
        # Predict anomaly (-1 for anomaly, 1 for normal)
        prediction = model.predict(combined_features)[0]
        anomaly_score = model.decision_function(combined_features)[0]
        
        # Normalize score to 0-1 range where 1 is most anomalous
        normalized_score = (1 - (anomaly_score + 0.5)) / 1.5
        is_anomaly = prediction == -1 or normalized_score > self.anomaly_threshold
        
        if is_anomaly:
            self.metrics["anomalies_detected"] += 1
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": float(normalized_score),
            "confidence": abs(anomaly_score)
        }
    
    def load_model(self, source_key):
        """
        Load an existing model for a log source
        
        Args:
            source_key: Identifier for the log source
            
        Returns:
            bool: True if model was loaded successfully
        """
        if not self.sklearn_available:
            return False
            
        source_dir = os.path.join(MODEL_DIR, self._sanitize_key(source_key))
        if not os.path.exists(source_dir):
            return False
            
        try:
            # Load model components
            with open(os.path.join(source_dir, "model.pkl"), "rb") as f:
                model = pickle.load(f)
                
            with open(os.path.join(source_dir, "vectorizer.pkl"), "rb") as f:
                vectorizer = pickle.load(f)
                
            with open(os.path.join(source_dir, "scaler.pkl"), "rb") as f:
                scaler = pickle.load(f)
                
            # Initialize feature extractor if needed
            if source_key not in self.feature_extractors:
                self.feature_extractors[source_key] = LogFeatureExtractor(source_key)
                
            # Set components
            self.models[source_key] = model
            self.vectorizers[source_key] = vectorizer
            self.feature_extractors[source_key].text_vectorizer = vectorizer
            self.feature_extractors[source_key].numerical_scaler = scaler
            
            logging.info(f"Loaded existing model for {source_key}")
            return True
        except Exception as e:
            logging.error(f"Error loading model for {source_key}: {str(e)}")
            return False
    
    def _sanitize_key(self, key):
        """Sanitize a key for use as a directory name"""
        return re.sub(r'[^\w\-]', '_', key)
    
    def get_metrics(self):
        """Get detector metrics"""
        return self.metrics


class LogFeatureExtractor:
    """Feature extraction for log entries"""
    
    def __init__(self, source_key):
        """
        Initialize the feature extractor
        
        Args:
            source_key: Identifier for the log source
        """
        self.source_key = source_key
        self.text_vectorizer = None
        self.numerical_scaler = None
        
        # Track feature statistics for this source
        self.feature_stats = {
            "message_lengths": [],
            "tokens": Counter(),
            "numerical_fields": set(),
            "categorical_fields": {},
            "timestamp_patterns": Counter()
        }
    
    def extract(self, log_entry):
        """
        Extract features from a log entry
        
        Args:
            log_entry: Parsed log entry dictionary
            
        Returns:
            tuple: (text_features, numerical_features)
        """
        # Extract text features
        text_feature = self._extract_text_features(log_entry)
        
        # Extract numerical features
        numerical_features = self._extract_numerical_features(log_entry)
        
        return text_feature, numerical_features
    
    def _extract_text_features(self, log_entry):
        """Extract text features from log entry"""
        # Get message field or raw log line
        message = log_entry.get("message", "")
        if not message and "_raw" in log_entry:
            message = log_entry.get("_raw", "")
            
        if not isinstance(message, str):
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            else:
                message = str(message)
        
        # Update stats
        self.feature_stats["message_lengths"].append(len(message))
        for token in re.findall(r'\b\w+\b', message.lower()):
            self.feature_stats["tokens"][token] += 1
        
        return message
    
    def _extract_numerical_features(self, log_entry):
        """Extract numerical features from log entry"""
        numerical_features = []
        
        # Time-based features
        timestamp = log_entry.get("timestamp")
        if timestamp:
            try:
                # Try parsing as ISO format
                if "T" in timestamp:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    # Try common formats
                    dt = None
                    formats = [
                        "%Y-%m-%d %H:%M:%S",
                        "%b %d %H:%M:%S",
                        "%Y/%m/%d %H:%M:%S"
                    ]
                    
                    for fmt in formats:
                        try:
                            dt = datetime.strptime(timestamp, fmt)
                            break
                        except ValueError:
                            continue
                
                if dt:
                    self.feature_stats["timestamp_patterns"][dt.strftime("%H:%M")] += 1
                    
                    # Extract time features
                    hour = dt.hour
                    minute = dt.minute
                    second = dt.second
                    time_of_day = hour * 3600 + minute * 60 + second
                    is_business_hours = 1 if 9 <= hour <= 17 else 0
                    is_weekend = 1 if dt.weekday() >= 5 else 0
                    is_night = 1 if hour < 6 or hour >= 22 else 0
                    
                    numerical_features.extend([
                        hour, minute, second, time_of_day,
                        is_business_hours, is_weekend, is_night
                    ])
            except (ValueError, TypeError):
                # Add placeholder values if parsing fails
                numerical_features.extend([0, 0, 0, 0, 0, 0, 0])
        else:
            # No timestamp available
            numerical_features.extend([0, 0, 0, 0, 0, 0, 0])
        
        # Extract other numerical fields
        for key, value in log_entry.items():
            if key.startswith('_'):  # Skip internal fields
                continue
                
            if isinstance(value, (int, float)):
                self.feature_stats["numerical_fields"].add(key)
                numerical_features.append(float(value))
                
            elif isinstance(value, str) and value.isdigit():
                self.feature_stats["numerical_fields"].add(key)
                numerical_features.append(float(value))
        
        return numerical_features
