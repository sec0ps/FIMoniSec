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
import json
import logging
import yaml
from pathlib import Path

class ConfigManager:
    """Manages LIM configuration including loading, saving, and validation"""
    
    DEFAULT_CONFIG_FILE = "fim.config"
    DEFAULT_CONFIG = {
        "log_integrity_monitor": {
            "enabled": True,
            "monitored_logs": [],
            "log_categories": {},
            "excluded_ips": [],
            "excluded_users": [],
            "alert_level": "medium",
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
    
    def __init__(self, config_file=None):
        """Initialize the configuration manager"""
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        
        # Set up logging
        self.logger = logging.getLogger("lim.config")
        
        # Load configuration
        self.config = self.load_config()
        
    def load_config(self):
        """Load configuration from file or create default if not exists"""
        if not os.path.exists(self.config_file):
            self.logger.warning(f"Configuration file {self.config_file} not found. Creating default config.")
            return self._create_default_config()
            
        try:
            # Determine file type by extension
            if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                with open(self.config_file, 'r') as f:
                    config = yaml.safe_load(f)
            else:
                # Default to JSON
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
            # Ensure log_integrity_monitor section exists
            if "log_integrity_monitor" not in config:
                config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
                self.save_config(config)
                
            # Ensure all required fields exist
            self._ensure_config_structure(config)
            
            return config
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            return self._create_default_config()
    
    def _create_default_config(self):
        """Create and save a default configuration"""
        config = self.DEFAULT_CONFIG.copy()
        self.save_config(config)
        return config
    
    def _ensure_config_structure(self, config):
        """Ensure all required configuration sections and fields exist"""
        lim_config = config.get("log_integrity_monitor", {})
        default_lim = self.DEFAULT_CONFIG["log_integrity_monitor"]
        
        # Check for each field and use default if missing
        for key, value in default_lim.items():
            if key not in lim_config:
                lim_config[key] = value
                
        # Check nested structures
        for key in ["ml_analysis", "retention"]:
            if key not in lim_config:
                lim_config[key] = default_lim[key]
            else:
                for sub_key, sub_value in default_lim[key].items():
                    if sub_key not in lim_config[key]:
                        lim_config[key][sub_key] = sub_value
        
        # Update the config
        config["log_integrity_monitor"] = lim_config
        
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config
            
        try:
            # Determine file type by extension
            if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                with open(self.config_file, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
            else:
                # Default to JSON
                with open(self.config_file, 'w') as f:
                    json.dump(config, f, indent=4)
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def get_config(self, section=None):
        """Get the full configuration or a specific section"""
        if section is None:
            return self.config
            
        return self.config.get(section, {})
    
    def get_lim_config(self):
        """Get the LIM-specific configuration"""
        return self.config.get("log_integrity_monitor", {})
    
    def update_config_value(self, key_path, value):
        """
        Update a specific configuration value using a dot-notation path
        
        Args:
            key_path: Dot-separated path to the config value (e.g., "log_integrity_monitor.enabled")
            value: New value to set
            
        Returns:
            bool: True if successful, False otherwise
        """
        if "." not in key_path:
            # Top-level key
            self.config[key_path] = value
        else:
            # Nested key
            parts = key_path.split(".")
            
            # Navigate to the right level
            current = self.config
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
                
            # Set the value
            current[parts[-1]] = value
            
        return self.save_config()
    
    def update_log_files(self, log_categories):
        """Update the monitored log files in the configuration"""
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        # Extract flat list of all logs
        all_logs = []
        for category_logs in log_categories.values():
            all_logs.extend(category_logs)
            
        # Update configuration
        self.config["log_integrity_monitor"]["log_categories"] = log_categories
        self.config["log_integrity_monitor"]["monitored_logs"] = sorted(all_logs)
        
        # Save the updated configuration
        return self.save_config()
    
    def add_excluded_ip(self, ip):
        """Add an IP to the exclusion list"""
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        if ip not in self.config["log_integrity_monitor"]["excluded_ips"]:
            self.config["log_integrity_monitor"]["excluded_ips"].append(ip)
            return self.save_config()
        return True
    
    def add_excluded_user(self, user):
        """Add a user to the exclusion list"""
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        if user not in self.config["log_integrity_monitor"]["excluded_users"]:
            self.config["log_integrity_monitor"]["excluded_users"].append(user)
            return self.save_config()
        return True
    
    def remove_excluded_ip(self, ip):
        """Remove an IP from the exclusion list"""
        if "log_integrity_monitor" in self.config and ip in self.config["log_integrity_monitor"]["excluded_ips"]:
            self.config["log_integrity_monitor"]["excluded_ips"].remove(ip)
            return self.save_config()
        return True
    
    def remove_excluded_user(self, user):
        """Remove a user from the exclusion list"""
        if "log_integrity_monitor" in self.config and user in self.config["log_integrity_monitor"]["excluded_users"]:
            self.config["log_integrity_monitor"]["excluded_users"].remove(user)
            return self.save_config()
        return True
    
    def set_alert_level(self, level):
        """Set the alert level (low, medium, high)"""
        if level not in ["low", "medium", "high"]:
            self.logger.error(f"Invalid alert level: {level}")
            return False
            
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        self.config["log_integrity_monitor"]["alert_level"] = level
        return self.save_config()
    
    def set_log_level(self, level):
        """Set the logging level"""
        if level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            self.logger.error(f"Invalid log level: {level}")
            return False
            
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        self.config["log_integrity_monitor"]["log_level"] = level
        return self.save_config()
    
    def enable_ml_analysis(self, enabled=True):
        """Enable or disable ML-based analysis"""
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        if "ml_analysis" not in self.config["log_integrity_monitor"]:
            self.config["log_integrity_monitor"]["ml_analysis"] = self.DEFAULT_CONFIG["log_integrity_monitor"]["ml_analysis"]
            
        self.config["log_integrity_monitor"]["ml_analysis"]["enabled"] = enabled
        return self.save_config()
    
    def set_retention_period(self, alert_days=None, model_days=None):
        """Set retention periods for alerts and models"""
        if "log_integrity_monitor" not in self.config:
            self.config["log_integrity_monitor"] = self.DEFAULT_CONFIG["log_integrity_monitor"]
            
        if "retention" not in self.config["log_integrity_monitor"]:
            self.config["log_integrity_monitor"]["retention"] = self.DEFAULT_CONFIG["log_integrity_monitor"]["retention"]
            
        if alert_days is not None:
            try:
                alert_days = int(alert_days)
                if alert_days < 1:
                    raise ValueError("Alert retention days must be greater than 0")
                self.config["log_integrity_monitor"]["retention"]["alert_retention_days"] = alert_days
            except ValueError as e:
                self.logger.error(f"Invalid alert retention days: {e}")
                return False
                
        if model_days is not None:
            try:
                model_days = int(model_days)
                if model_days < 1:
                    raise ValueError("Model retention days must be greater than 0")
                self.config["log_integrity_monitor"]["retention"]["model_retention_days"] = model_days
            except ValueError as e:
                self.logger.error(f"Invalid model retention days: {e}")
                return False
                
        return self.save_config()
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = self.DEFAULT_CONFIG.copy()
        return self.save_config()

    def validate_config(self):
        """
        Validate the configuration
        
        Returns:
            tuple: (is_valid, errors)
        """
        errors = []
        
        # Check if log_integrity_monitor section exists
        if "log_integrity_monitor" not in self.config:
            errors.append("Missing log_integrity_monitor section")
            return False, errors
            
        lim_config = self.config["log_integrity_monitor"]
        
        # Check required fields
        required_fields = ["enabled", "alert_level", "log_level"]
        for field in required_fields:
            if field not in lim_config:
                errors.append(f"Missing required field: {field}")
        
        # Validate alert level
        if "alert_level" in lim_config and lim_config["alert_level"] not in ["low", "medium", "high"]:
            errors.append(f"Invalid alert level: {lim_config['alert_level']}")
            
        # Validate log level
        if "log_level" in lim_config and lim_config["log_level"] not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            errors.append(f"Invalid log level: {lim_config['log_level']}")
            
        # Check ml_analysis section
        if "ml_analysis" in lim_config:
            ml_config = lim_config["ml_analysis"]
            
            # Check enabled field
            if "enabled" not in ml_config:
                errors.append("Missing enabled field in ml_analysis section")
                
            # Check numeric parameters
            numeric_params = ["training_period", "anomaly_threshold", "min_training_samples"]
            for param in numeric_params:
                if param in ml_config:
                    try:
                        float(ml_config[param])
                    except (ValueError, TypeError):
                        errors.append(f"Invalid numeric value for {param}: {ml_config[param]}")
        
        # Check retention section
        if "retention" in lim_config:
            retention_config = lim_config["retention"]
            
            # Check retention days
            retention_params = ["alert_retention_days", "model_retention_days"]
            for param in retention_params:
                if param in retention_config:
                    try:
                        days = int(retention_config[param])
                        if days < 1:
                            errors.append(f"{param} must be greater than 0")
                    except (ValueError, TypeError):
                        errors.append(f"Invalid numeric value for {param}: {retention_config[param]}")
        
        return len(errors) == 0, errors
