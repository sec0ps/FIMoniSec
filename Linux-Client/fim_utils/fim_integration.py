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
# Integration with existing FIM system
import os
import signal
import time
import json
import threading
import sys

# Import enhanced FIM controller
try:
    from fim_utils.fim_controller import EnhancedFIM
except ImportError as e:
    print(f"[WARNING] Could not import EnhancedFIM: {e}")

class FIMIntegration:
    def __init__(self):
        """Initialize integration with the existing FIM system."""
        # Get base directory - corrected to properly find the parent directory
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_file = os.path.join(self.base_dir, "fim.config")
        self.config = self.load_config()
        
        # Initialize flags
        self.initialized = False
        self.enhanced_fim = None
        self.original_log_event = None
    
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"[WARNING] Could not load configuration: {e}. Using defaults.")
            return {}
    
    def initialize(self, config=None):
        """Initialize enhanced FIM components with config."""
        if self.initialized:
            return
            
        # Use provided config or reload from file
        if config:
            self.config = config
        else:
            self.config = self.load_config()
        
        # Only initialize if enhanced_fim is enabled in config
        if self.config.get('enhanced_fim', {}).get('enabled', True):
            try:
                # Initialize enhanced FIM controller
                self.enhanced_fim = EnhancedFIM(self.config.get('enhanced_fim', {}))
                self.enhanced_fim.start()
                self.initialized = True
                print("[INFO] Enhanced FIM controller started")
            except Exception as e:
                print(f"[ERROR] Failed to initialize enhanced FIM: {e}")
        else:
            print("[INFO] Enhanced FIM capabilities disabled in configuration")
    
    def install_hooks(self):
        """Install hooks into the existing FIM system"""
        try:
            # This must be a local import to avoid circular imports
            import fim_client
            
            # Store original function references
            self.original_log_event = fim_client.log_event
            
            # Replace with our enhanced versions
            fim_client.log_event = self.enhanced_log_event
            
            print("[INFO] Enhanced FIM hooks installed")
            
            # Start enhanced FIM if not already started
            if not self.initialized and self.enhanced_fim:
                self.enhanced_fim.start()
                self.initialized = True
        except ImportError as e:
            print(f"[ERROR] Could not install FIM hooks: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error during hook installation: {e}")
    
    def enhanced_log_event(self, event_type, file_path, previous_metadata=None, new_metadata=None, 
                          previous_hash=None, new_hash=None, changes=None):
        """Enhanced version of the log_event function"""
        # Call original function to maintain base functionality
        original_result = self.original_log_event(
            event_type, file_path, previous_metadata, new_metadata, 
            previous_hash, new_hash, changes
        )
        
        # Only proceed if enhanced FIM is initialized
        if not self.initialized or not self.enhanced_fim:
            return original_result
        
        try:
            # Create enhanced event object
            enhanced_event = {
                "event_type": event_type,
                "file_path": file_path,
                "previous_metadata": previous_metadata,
                "new_metadata": new_metadata,
                "previous_hash": previous_hash,
                "new_hash": new_hash,
                "changes": changes,
                "original_result": original_result,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "uuid": f"fim_{time.time()}"
            }
            
            # Process with enhanced systems
            result = self.enhanced_fim.handle_file_event(enhanced_event)
            
            # Enrich original result with any enhanced information
            if result and isinstance(original_result, dict):
                if 'enhanced_analysis' in result:
                    original_result['enhanced_analysis'] = result['enhanced_analysis']
                if 'enhanced_alerts' in result:
                    original_result['enhanced_alerts'] = result['enhanced_alerts']
        except Exception as e:
            print(f"[ERROR] Enhanced event processing failed: {e}")
        
        return original_result
    
    def process_enhanced_event(self, event):
        """Process events with enhanced analysis capabilities."""
        if not self.initialized or not self.enhanced_fim:
            return None
            
        try:
            # Pass event to enhanced controller for processing
            return self.enhanced_fim.handle_file_event(event)
        except Exception as e:
            print(f"[ERROR] Enhanced event processing failed: {e}")
            return None
    
    def shutdown(self):
        """Clean shutdown of enhanced systems"""
        if self.initialized and self.enhanced_fim:
            try:
                print("[INFO] Shutting down enhanced FIM systems...")
                self.enhanced_fim.stop()
                self.initialized = False
            except Exception as e:
                print(f"[ERROR] Error during enhanced FIM shutdown: {e}")


# Initialization hook to load enhanced systems - only use if this module
# is being imported directly, not when imported by fim_client
def initialize_enhanced_fim():
    try:
        integration = FIMIntegration()
        
        # If running as standalone, install hooks
        if not any('fim_client.py' in arg for arg in sys.argv):
            integration.install_hooks()
        
            # Register shutdown handler
            def handle_shutdown(signum=None, frame=None):
                integration.shutdown()
            
            signal.signal(signal.SIGTERM, handle_shutdown)
            signal.signal(signal.SIGINT, handle_shutdown)
        
        return integration
    except Exception as e:
        print(f"[ERROR] Failed to initialize enhanced FIM integration: {e}")
        return None


# Only initialize automatically if this is the main module
if __name__ == "__main__":
    fim_integration = initialize_enhanced_fim()
else:
    # Create the integration object but don't install hooks
    # Let fim_client.py control the initialization
    fim_integration = FIMIntegration()
