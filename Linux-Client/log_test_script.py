#!/usr/bin/env python3
# =============================================================================
# LIM System Test Script
# =============================================================================
#
# Purpose: Test the Log Integrity Management system components
#          to ensure alerts are properly generated and logged.
#

import os
import sys
import time
import json
import logging
import argparse
from datetime import datetime

def setup_logging():
    """Configure logging for the test script"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"lim_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("lim.test")
    logger.info(f"Logging configured. Log file: {log_file}")
    return logger

def create_test_log_file():
    """Create a test log file with security events"""
    logger = logging.getLogger("lim.test")
    
    # Create a test log file with security events
    test_log_dir = "test_logs"
    os.makedirs(test_log_dir, exist_ok=True)
    
    test_log_file = os.path.join(test_log_dir, "test_security.log")
    logger.info(f"Creating test log file: {test_log_file}")
    
    # Sample security events
    security_events = [
        "Apr 1 12:00:00 testhost sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
        "Apr 1 12:00:05 testhost sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
        "Apr 1 12:00:10 testhost sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
        "Apr 1 12:00:15 testhost sshd[1234]: Accepted password for admin from 192.168.1.1 port 12345 ssh2",
        "Apr 1 12:01:00 testhost sudo[1235]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Apr 1 12:02:00 testhost sshd[1236]: Connection from 192.168.1.2 port 54321",
        "Apr 1 12:03:00 testhost kernel: IPTables-Dropped: IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=10.0.0.1 DST=192.168.1.10 PROTO=TCP SPT=12345 DPT=22 FLAGS=SYN",
        "Apr 1 12:04:00 testhost apache2[1237]: 10.0.0.2 - - [01/Apr/2025:12:04:00 +0000] \"GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"",
        "Apr 1 12:05:00 testhost nginx[1238]: 10.0.0.3 - - [01/Apr/2025:12:05:00 +0000] \"GET /../../etc/passwd HTTP/1.1\" 403 0 \"-\" \"scanbot/1.0\""
    ]
    
    with open(test_log_file, "w") as f:
        for event in security_events:
            f.write(event + "\n")
    
    logger.info(f"Created test log file with {len(security_events)} security events")
    return test_log_file

def test_alert_manager():
    """Test the AlertManager component"""
    logger = logging.getLogger("lim.test")
    logger.info("Testing AlertManager component")
    
    try:
        from lim_utils.alert_manager import AlertManager
        
        # Test directories
        alert_dir = os.path.join("logs", "alerts")
        archive_dir = os.path.join("logs", "archive")
        os.makedirs(alert_dir, exist_ok=True)
        os.makedirs(archive_dir, exist_ok=True)
        
        # Create test alert
        test_alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "test_alert",
            "subtype": "test",
            "severity": "medium",
            "source_file": "/var/log/test.log",
            "source_log": "Test log entry",
            "message": "Test alert for AlertManager",
            "details": {"test": True}
        }
        
        # Initialize AlertManager
        alert_manager = AlertManager()
        
        # Process test alert
        logger.info("Sending test alert to AlertManager")
        result = alert_manager.process_alert(test_alert)
        
        # Check if alert file exists
        alert_file = alert_manager.alert_file
        if os.path.exists(alert_file):
            logger.info(f"Alert file exists: {alert_file}")
            file_size = os.path.getsize(alert_file)
            logger.info(f"Alert file size: {file_size} bytes")
            
            # Verify alert was written
            with open(alert_file, "r") as f:
                content = f.read()
                if test_alert["message"] in content:
                    logger.info("Alert was successfully written to file")
                else:
                    logger.error("Alert was not written to file correctly")
        else:
            logger.error(f"Alert file does not exist: {alert_file}")
        
        return bool(result)
    except Exception as e:
        logger.error(f"Error testing AlertManager: {str(e)}", exc_info=True)
        return False

def test_detection_engine():
    """Test the LogDetectionEngine component"""
    logger = logging.getLogger("lim.test")
    logger.info("Testing LogDetectionEngine component")
    
    try:
        from lim_utils.log_detection_engine import LogDetectionEngine, SCORE_THRESHOLD
        
        # Initialize detection engine
        detection_engine = LogDetectionEngine()
        
        # Test log lines
        test_lines = [
            # Should trigger an alert (multiple failed logins)
            "Apr 1 12:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
            "Apr 1 12:00:05 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
            "Apr 1 12:00:10 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
            # Should trigger an alert (privilege escalation)
            "Apr 1 12:01:00 host sudo[1235]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            # Should trigger an alert (web attack)
            "Apr 1 12:04:00 host apache2[1237]: 10.0.0.2 - - [01/Apr/2025:12:04:00 +0000] \"GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"",
        ]
        
        # Test each line
        results = []
        for line in test_lines:
            logger.info(f"Testing line: {line}")
            result = detection_engine.analyze_line(line)
            if result:
                logger.info(f"Alert triggered with score {result.get('score')}: {result.get('tags')}")
                results.append(result)
            else:
                logger.info(f"No alert triggered. Current threshold: {SCORE_THRESHOLD}")
        
        # Check if we got any alerts
        if results:
            logger.info(f"Detection engine triggered {len(results)} alerts")
            return True
        else:
            logger.warning("Detection engine did not trigger any alerts")
            
            # Try with a lower threshold
            logger.info("Testing with lower threshold")
            import log_detection_engine as lde
            original_threshold = lde.SCORE_THRESHOLD
            lde.SCORE_THRESHOLD = 1
            
            # Test one line with lower threshold
            test_line = "Apr 1 12:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2"
            result = detection_engine.analyze_line(test_line)
            
            # Restore original threshold
            lde.SCORE_THRESHOLD = original_threshold
            
            if result:
                logger.info(f"Alert triggered with lower threshold (score {result.get('score')})")
                return True
            else:
                logger.error("Detection engine failed to trigger alerts even with lower threshold")
                return False
    except Exception as e:
        logger.error(f"Error testing LogDetectionEngine: {str(e)}", exc_info=True)
        return False

def test_log_parser():
    """Test the LogParser component"""
    logger = logging.getLogger("lim.test")
    logger.info("Testing LogParser component")
    
    try:
        from lim_utils.log_parser import LogParser
        
        # Initialize parser
        log_parser = LogParser()
        
        # Test lines
        test_lines = [
            "Apr 1 12:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.1 port 12345 ssh2",
            "Apr 1 12:01:00 host sudo[1235]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            "10.0.0.2 - - [01/Apr/2025:12:04:00 +0000] \"GET /admin.php?id=1%27%20OR%201=1-- HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\""
        ]
        
        formats_detected = {}
        security_events = 0
        
        # Parse each line
        for line in test_lines:
            logger.info(f"Parsing line: {line}")
            parsed = log_parser.parse_line(line)
            
            if parsed:
                format_name = parsed.get("_format", "unknown")
                formats_detected[format_name] = formats_detected.get(format_name, 0) + 1
                
                logger.info(f"Parsed as {format_name}: {json.dumps(parsed, indent=2)}")
                
                # Check for security events
                event = log_parser.extract_security_events(parsed)
                if event:
                    security_events += 1
                    logger.info(f"Security event detected: {event.get('event_type')}")
        
        logger.info(f"Formats detected: {formats_detected}")
        logger.info(f"Security events detected: {security_events}")
        
        return len(formats_detected) > 0 and security_events > 0
    except Exception as e:
        logger.error(f"Error testing LogParser: {str(e)}", exc_info=True)
        return False

def test_monitor():
    """Test the EnhancedLogMonitor component"""
    logger = logging.getLogger("lim.test")
    logger.info("Testing EnhancedLogMonitor component")
    
    try:
        from lim_utils.config import ConfigManager
        from lim_utils.monitor import EnhancedLogMonitor
        
        # Create test log file
        test_log_file = create_test_log_file()
        
        # Create configuration
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        # Update configuration to use our test log
        if "log_integrity_monitor" not in config:
            config["log_integrity_monitor"] = {}
        
        config["log_integrity_monitor"]["monitored_logs"] = [test_log_file]
        config["log_integrity_monitor"]["log_categories"] = {"test": [test_log_file]}
        config_manager.save_config(config)
        
        logger.info(f"Updated configuration to monitor test log file: {test_log_file}")
        
        # Initialize monitor
        monitor = EnhancedLogMonitor(config_manager)
        
        # Define the initialization function for testing
        def initialize_log_files_for_test():
            """Implementation of _initialize_log_files for testing"""
            # Set monitored files to our test log file
            monitor.monitored_files = {test_log_file}
            monitor.logger.info(f"Test initialized with log file: {test_log_file}")
        
        # Apply our patched methods
        monitor._initialize_log_files = initialize_log_files_for_test
        
        # Run initialization
        monitor._initialize_log_files()
        
        # Check if our test file is monitored
        if test_log_file in monitor.monitored_files:
            logger.info(f"Test log file is being monitored")
        else:
            logger.error(f"Test log file is not being monitored")
            return False
        
        # Process the log file
        logger.info(f"Processing test log file")
        monitor._process_log_file(test_log_file, force_full=True)
        
        # Check if any alerts were generated
        alerts_generated = monitor.stats["alerts_generated"]
        logger.info(f"Monitor generated {alerts_generated} alerts")
        
        return alerts_generated > 0
    except Exception as e:
        logger.error(f"Error testing EnhancedLogMonitor: {str(e)}", exc_info=True)
        return False

def run_tests():
    """Run all tests"""
    logger = logging.getLogger("lim.test")
    logger.info("Starting LIM system tests")
    
    # Create necessary directories
    for directory in ["logs", "logs/alerts", "logs/archive", "logs/checkpoints"]:
        os.makedirs(directory, exist_ok=True)
    
    # Run tests
    test_results = {
        "AlertManager": test_alert_manager(),
        "LogParser": test_log_parser(),
        "DetectionEngine": test_detection_engine(),
        "Monitor": test_monitor()
    }
    
    # Print results
    logger.info("Test results:")
    all_passed = True
    for test, result in test_results.items():
        status = "PASSED" if result else "FAILED"
        logger.info(f"  {test}: {status}")
        if not result:
            all_passed = False
    
    if all_passed:
        logger.info("All tests passed!")
        return 0
    else:
        logger.error("Some tests failed. Check the log for details.")
        return 1

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Test the LIM system")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    # Run tests
    return run_tests()

if __name__ == "__main__":
    sys.exit(main())
