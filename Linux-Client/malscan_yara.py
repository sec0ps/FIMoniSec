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
import os
import logging
import subprocess
import shutil
import tempfile
import glob

# Initialize yara_lib as None
yara_lib = None

def create_dummy_yara():
    """Create a dummy YARA implementation that won't crash the program."""
    
    class DummyYara:
        """Dummy YARA implementation that logs errors but doesn't crash."""
        
        class Error(Exception):
            """Generic YARA Error."""
            pass
            
        class TimeoutError(Error):
            """YARA timeout error."""
            pass
        
        @staticmethod
        def compile(*args, **kwargs):
            logging.warning("YARA functionality unavailable - cannot compile rules")
            
            class DummyRules:
                def match(self, *args, **kwargs):
                    logging.warning("YARA functionality unavailable - cannot match rules")
                    return []
            
            return DummyRules()
    
    return DummyYara()

# Try to import YARA using different approaches
try:
    # First, try the standard yara-python package
    import yara_python
    yara_lib = yara_python
    logging.info("Successfully imported yara-python module")
except ImportError:
    try:
        # Next, try the yara package
        import yara
        # Verify it has the needed methods
        if hasattr(yara, 'compile'):
            yara_lib = yara
            logging.info("Successfully imported yara module")
        else:
            logging.error("Installed yara module missing required methods")
            yara_lib = create_dummy_yara()
    except ImportError:
        logging.warning("Could not import any YARA module")
        yara_lib = create_dummy_yara()

def check_yara_installation():
    """
    Diagnose YARA installation issues and provide guidance.
    
    Returns:
        bool: True if YARA is properly installed, False otherwise
    """
    # Check if we have a working YARA library
    if yara_lib is None or not hasattr(yara_lib, 'compile'):
        logging.error("""
YARA installation appears incomplete. Try one of the following:
1. For pip: pip uninstall yara yara-python && pip install yara-python
2. For system packages (Ubuntu/Debian): sudo apt-get install python3-yara
3. For macOS (Homebrew): brew install yara && pip install yara-python
4. For Windows: Download and install from https://github.com/VirusTotal/yara-python/releases

Note: YARA requires both the C library and Python bindings to be installed.
""")
        return False
    
    # Try a simple compilation to verify functionality
    try:
        test_rule = """
rule test_rule {
    condition:
        true
}
"""
        yara_lib.compile(source=test_rule)
        logging.info("YARA is fully functional")
        return True
    except Exception as e:
        logging.error(f"YARA compilation test failed: {e}")
        return False

class YaraManager:
    """
    A class to handle YARA rule management, compilation, and scanning functionality.
    """
    
    def __init__(self, rules_dir="./yara_rules"):
        """
        Initialize the YARA manager with a rules directory.
        
        Args:
            rules_dir (str): Directory path where YARA rules are stored.
        """
        self.rules_dir = rules_dir
        self.rules = None
        self.compiled = False
        
        # Check if YARA is properly installed
        self.yara_available = check_yara_installation()
        
        if not self.yara_available:
            logging.warning("YARA functionality will be limited due to installation issues")
            # Create a placeholder rules object that will return no matches
            class DummyRules:
                def match(self, *args, **kwargs):
                    return []
            self.rules = DummyRules()
            self.compiled = True  # Pretend we're compiled to avoid repeated errors
        else:
            # Only attempt to download/use rules if YARA is available
            if not os.path.isdir(self.rules_dir) or not os.listdir(self.rules_dir):
                logging.info("YARA rules not found. Attempting to download...")
                self.ensure_rules_exist()

    def is_yara_available(self):
        """
        Check if the YARA library is properly available with all required methods.
        
        Returns:
            bool: True if YARA is available, False otherwise
        """
        try:
            # Try to access essential methods/attributes
            return (hasattr(yara_lib, 'compile') and 
                    hasattr(yara_lib, 'Error') and 
                    hasattr(yara_lib, 'TimeoutError'))
        except Exception:
            return False

    def ensure_rules_exist(self):
        """
        Check if YARA rules directory exists, and if not, clone the repository
        from GitHub to get the latest rules.
        
        Returns:
            bool: True if rules were successfully ensured, False otherwise
        """
        github_repo = "https://github.com/Yara-Rules/rules.git"
        
        # Check if the rules directory already exists
        if os.path.isdir(self.rules_dir) and os.listdir(self.rules_dir):
            logging.info("YARA rules directory already exists.")
            return True
        
        logging.info("YARA rules directory not found or empty. Downloading from GitHub...")
        
        # Create a temporary directory for cloning
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Clone the repository to the temporary directory
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", github_repo, temp_dir],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Create rules directory if it doesn't exist
                os.makedirs(self.rules_dir, exist_ok=True)
                
                # Copy all files from the temp directory to the rules directory
                for item in os.listdir(temp_dir):
                    source = os.path.join(temp_dir, item)
                    destination = os.path.join(self.rules_dir, item)
                    
                    if item == ".git":  # Skip .git directory
                        continue
                        
                    if os.path.isdir(source):
                        shutil.copytree(source, destination, dirs_exist_ok=True)
                    else:
                        shutil.copy2(source, destination)
                
                logging.info("Successfully downloaded YARA rules from GitHub.")
                return True
                
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to clone YARA rules repository: {e.stderr}")
                return False
            except Exception as e:
                logging.error(f"Error downloading YARA rules: {e}")
                return False

    def update_rules(self):
        """
        Update existing YARA rules by fetching the latest from GitHub.
        
        Returns:
            bool: True if rules were successfully updated, False otherwise
        """
        github_repo = "https://github.com/Yara-Rules/rules.git"
        
        # Check if rules directory exists
        if not os.path.isdir(self.rules_dir):
            return self.ensure_rules_exist()
        
        logging.info("Updating YARA rules from GitHub...")
        
        try:
            # Check if it's a git repository
            if os.path.isdir(os.path.join(self.rules_dir, ".git")):
                # It's a git repository, so we can use git pull
                result = subprocess.run(
                    ["git", "-C", self.rules_dir, "pull"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                logging.info("Successfully updated YARA rules via git pull.")
            else:
                # Not a git repository, so delete and re-clone
                shutil.rmtree(self.rules_dir)
                return self.ensure_rules_exist()
            
            # Reset compilation state since rules have changed
            self.compiled = False
            self.rules = None
            
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to update YARA rules: {e.stderr}")
            return False
        except Exception as e:
            logging.error(f"Error updating YARA rules: {e}")
            return False
    
    def compile_rules(self, specific_rules=None):
        """
        Compile YARA rules from the rules directory.
        
        Args:
            specific_rules (list): Optional list of specific rule files to compile.
                                  If None, all .yar and .yara files will be compiled.
        
        Returns:
            bool: True if compilation was successful, False otherwise.
        """
        # First, check if YARA is properly available
        if not self.is_yara_available():
            logging.error("YARA library is not properly installed or is missing required methods")
            return False
            
        # Check if rules directory exists
        if not os.path.isdir(self.rules_dir):
            logging.error(f"YARA rules directory '{self.rules_dir}' does not exist.")
            return False
        
        # Find all YARA rule files
        if specific_rules:
            rule_files = [os.path.join(self.rules_dir, rule) for rule in specific_rules]
        else:
            rule_files = glob.glob(os.path.join(self.rules_dir, "**", "*.yar"), recursive=True)
            rule_files += glob.glob(os.path.join(self.rules_dir, "**", "*.yara"), recursive=True)
        
        if not rule_files:
            logging.warning("No YARA rule files found.")
            return False
        
        logging.info(f"Compiling {len(rule_files)} YARA rule files...")
        
        # Initialize a dictionary to hold file paths and namespaces
        filepaths = {}
        
        # Assign each file a unique namespace to avoid rule conflicts
        for i, filepath in enumerate(rule_files):
            try:
                # Use the filename without extension as namespace
                namespace = os.path.basename(filepath).split('.')[0]
                # Add index to ensure uniqueness
                namespace = f"{namespace}_{i}"
                filepaths[namespace] = filepath
            except Exception as e:
                logging.warning(f"Skipping rule file {filepath}: {e}")
        
        try:
            # Compile all rules
            self.rules = yara_lib.compile(filepaths=filepaths)
            self.compiled = True
            logging.info("YARA rules compiled successfully.")
            return True
            
        except Exception as e:
            if hasattr(yara_lib, 'Error') and isinstance(e, yara_lib.Error):
                logging.error(f"Error compiling YARA rules: {e}")
                # Try to compile each file individually to identify problematic rules
                self._identify_problematic_rules(filepaths)
            else:
                logging.error(f"Unexpected error compiling YARA rules: {e}")
            return False
    
    def _identify_problematic_rules(self, filepaths):
        """
        Identify problematic rule files by attempting to compile each one separately.
        
        Args:
            filepaths (dict): Dictionary mapping namespaces to rule file paths.
        """
        logging.info("Attempting to identify problematic rules...")
        for namespace, filepath in filepaths.items():
            try:
                yara_lib.compile(filepath=filepath)
                logging.info(f"Rule file {filepath} compiled successfully.")
            except Exception as e:
                if hasattr(yara_lib, 'Error') and isinstance(e, yara_lib.Error):
                    logging.error(f"Error in rule file {filepath}: {e}")
                else:
                    logging.error(f"Unexpected error compiling rule file {filepath}: {e}")
    
    def scan_file(self, file_path, timeout=60):
        """
        Scan a file using compiled YARA rules.
        
        Args:
            file_path (str): Path to the file to scan.
            timeout (int): Timeout in seconds for the scan.
        
        Returns:
            list: List of rule matches, empty if no matches or error occurred.
        """
        # First, check if YARA is properly available
        if not self.is_yara_available():
            logging.warning("YARA functionality not available - skipping YARA scan")
            return []
            
        if not self.compiled or self.rules is None:
            logging.warning("YARA rules not compiled. Compiling now...")
            if not self.compile_rules():
                logging.warning("Could not compile YARA rules - skipping YARA scan")
                return []
        
        if not os.path.isfile(file_path):
            logging.error(f"File '{file_path}' does not exist or is not a file.")
            return []
        
        try:
            logging.info(f"Scanning file: {file_path}")
            matches = self.rules.match(file_path, timeout=timeout)
            
            if matches:
                logging.info(f"Found {len(matches)} matches in {file_path}")
                for match in matches:
                    logging.info(f"Rule '{match.rule}' matched in namespace '{match.namespace}'")
            else:
                logging.info(f"No YARA rule matches found in {file_path}")
            
            return matches
            
        except Exception as e:
            if hasattr(yara_lib, 'TimeoutError') and isinstance(e, yara_lib.TimeoutError):
                logging.warning(f"YARA scan timed out after {timeout} seconds on file: {file_path}")
            elif hasattr(yara_lib, 'Error') and isinstance(e, yara_lib.Error):
                logging.error(f"YARA error scanning file {file_path}: {e}")
            else:
                logging.error(f"Unexpected error scanning file {file_path}: {e}")
            return []
    
    def scan_memory(self, pid, timeout=60):
        """
        Scan a process's memory using compiled YARA rules.
        
        Args:
            pid (int): Process ID to scan.
            timeout (int): Timeout in seconds for the scan.
        
        Returns:
            list: List of rule matches, empty if no matches or error occurred.
        """
        # First, check if YARA is properly available
        if not self.is_yara_available():
            logging.warning("YARA functionality not available - skipping memory scan")
            return []
            
        if not self.compiled or self.rules is None:
            logging.warning("YARA rules not compiled. Compiling now...")
            if not self.compile_rules():
                logging.warning("Could not compile YARA rules - skipping memory scan")
                return []
        
        try:
            logging.info(f"Scanning process memory: PID {pid}")
            matches = self.rules.match(pid=pid, timeout=timeout)
            
            if matches:
                logging.info(f"Found {len(matches)} matches in process {pid}")
                for match in matches:
                    logging.info(f"Rule '{match.rule}' matched in namespace '{match.namespace}'")
            else:
                logging.info(f"No YARA rule matches found in process {pid}")
            
            return matches
            
        except Exception as e:
            if hasattr(yara_lib, 'TimeoutError') and isinstance(e, yara_lib.TimeoutError):
                logging.warning(f"YARA scan timed out after {timeout} seconds on process: {pid}")
            elif hasattr(yara_lib, 'Error') and isinstance(e, yara_lib.Error):
                logging.error(f"YARA error scanning process {pid}: {e}")
            else:
                logging.error(f"Unexpected error scanning process {pid}: {e}")
            return []

def fix_yara_includes(rule_file_path):
    """
    Preprocess YARA rule files to fix include paths.
    
    Args:
        rule_file_path (str): Path to the YARA rule file to process
        
    Returns:
        str: Path to the fixed rule file
    """
    try:
        # Read the rule file
        with open(rule_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find the base directory of the rule file
        base_dir = os.path.dirname(rule_file_path)
        
        # Fix include paths
        fixed_content = content
        
        # Regex to find include statements
        include_pattern = r'include\s+["\'](.*?)["\']'
        
        def replace_include(match):
            include_path = match.group(1)
            
            # Only process relative paths
            if include_path.startswith('./') or include_path.startswith('../'):
                # Calculate the absolute path based on the rule file's location
                if include_path.startswith('./'):
                    new_path = os.path.join(base_dir, include_path[2:])
                else:
                    new_path = os.path.normpath(os.path.join(base_dir, include_path))
                
                # Return the fixed include statement
                return f'include "{new_path}"'
            
            # Return the original include statement for non-relative paths
            return match.group(0)
        
        # Replace include paths
        fixed_content = re.sub(include_pattern, replace_include, content)
        
        # If content was changed, write to a temporary file
        if fixed_content != content:
            import tempfile
            
            # Create a temporary file
            fd, temp_path = tempfile.mkstemp(suffix='.yar')
            with os.fdopen(fd, 'w') as f:
                f.write(fixed_content)
            
            return temp_path
        
        # No changes needed
        return rule_file_path
    
    except Exception as e:
        logging.error(f"Error fixing include paths in {rule_file_path}: {e}")
        return rule_file_path  # Return original path if processing fails

def scan_with_individual_rules(file_path, rules_dir=None, timeout=60):
    """
    Scan a file using individual YARA rules rather than compiled rule sets.
    More reliable for complex rule sets with include issues.
    
    Args:
        file_path (str): Path to the file to scan
        rules_dir (str): Directory containing YARA rules
        timeout (int): Timeout in seconds
        
    Returns:
        list: List of matches as dictionaries
    """
    if not rules_dir:
        rules_dir = yara_manager.rules_dir
        
    all_matches = []
    
    # Get logger and set it to a higher level temporarily to suppress errors
    yara_logger = logging.getLogger('root')
    original_level = yara_logger.level
    yara_logger.setLevel(logging.CRITICAL)  # Temporarily increase log level
    
    try:
        # Find all YARA rule files
        rule_files = glob.glob(os.path.join(rules_dir, "**", "*.yar"), recursive=True)
        rule_files += glob.glob(os.path.join(rules_dir, "**", "*.yara"), recursive=True)
        
        # Filter out problematic rules and index files
        rule_files = [f for f in rule_files if not os.path.basename(f).startswith('index')]
        rule_files = [f for f in rule_files if not "TOOLKIT_Mandibule" in f]  # Skip problematic files
        
        for rule_file in rule_files:
            try:
                # Try to compile this single rule file
                processed_path = fix_yara_includes(rule_file)
                rule = yara_lib.compile(filepath=processed_path)
                
                # Scan with this rule
                matches = rule.match(file_path, timeout=timeout)
                if matches:
                    # Convert matches to a standard dictionary format
                    for match in matches:
                        match_dict = {
                            'rule_name': getattr(match, 'rule', 'Unknown'),
                            'namespace': getattr(match, 'namespace', 'Unknown'),
                            'tags': getattr(match, 'tags', []),
                            'meta': getattr(match, 'meta', {}),
                            'strings': []
                        }
                        
                        # Add matched strings if available
                        if hasattr(match, 'strings'):
                            for string in match.strings:
                                try:
                                    string_dict = {
                                        'identifier': getattr(string, 'identifier', 'Unknown'),
                                        'offset': getattr(string, 'offset', 0),
                                        'data': repr(getattr(string, 'data', b'')[:100])
                                    }
                                    match_dict['strings'].append(string_dict)
                                except Exception:
                                    # Silently continue on string processing errors
                                    pass
                        
                        all_matches.append(match_dict)
                    
                # Clean up if needed
                if processed_path != rule_file:
                    try:
                        os.remove(processed_path)
                    except:
                        pass
                        
            except Exception:
                # Silently continue - we're suppressing errors now
                pass
    finally:
        # Restore original logging level
        yara_logger.setLevel(original_level)
    
    # If we found no matches but want to show something
    if not all_matches:
        logging.info("No YARA matches found - scan completed silently")
    else:
        logging.info(f"Found {len(all_matches)} YARA matches")
    
    return all_matches

def create_simple_yara_rules(output_dir):
    """Create a set of simple, reliable YARA rules for basic scanning"""
    os.makedirs(output_dir, exist_ok=True)
    
    # Basic malware detection rule
    basic_rule = """
rule SuspiciousBehavior {
    meta:
        description = "Detects common suspicious patterns"
        author = "Security Scanner"
        severity = "medium"
    
    strings:
        $shell1 = "cmd.exe" nocase
        $shell2 = "powershell" nocase
        $shell3 = "bash" nocase
        $shell4 = "/bin/sh" nocase
        $exec1 = "exec(" nocase
        $exec2 = "eval(" nocase
        $exec3 = "system(" nocase
        $obf1 = "base64" nocase
        $obf2 = "encode" nocase
        $net1 = "http://" nocase
        $net2 = "https://" nocase
        $sus1 = "exploit" nocase
        $sus2 = "bypass" nocase
        $sus3 = "inject" nocase
    
    condition:
        (2 of ($shell*)) or
        (any of ($exec*)) or
        (any of ($obf*) and any of ($net*)) or
        (2 of ($sus*))
}
"""
    
    with open(os.path.join(output_dir, "basic.yar"), "w") as f:
        f.write(basic_rule)
    
    return os.path.join(output_dir, "basic.yar")

# Create a singleton instance for global use
yara_manager = YaraManager()

# Convenience functions that use the singleton manager
def ensure_rules_exist():
    """Ensure YARA rules exist, downloading if necessary."""
    return yara_manager.ensure_rules_exist()

def update_rules():
    """Update YARA rules from GitHub."""
    return yara_manager.update_rules()

def compile_rules(specific_rules=None):
    """Compile YARA rules."""
    # Temporarily suppress error output
    yara_logger = logging.getLogger('root')
    original_level = yara_logger.level
    yara_logger.setLevel(logging.CRITICAL)
    
    try:
        # First, check if YARA is properly available
        if not yara_manager.is_yara_available():
            logging.info("YARA library is not properly installed - using simplified scanning")
            return False
            
        # Check if rules directory exists
        if not os.path.isdir(yara_manager.rules_dir):
            logging.info(f"YARA rules directory '{yara_manager.rules_dir}' not found - using simplified scanning")
            return False
        
        # Find all YARA rule files
        if specific_rules:
            rule_files = [os.path.join(yara_manager.rules_dir, rule) for rule in specific_rules]
        else:
            # Find individual rule files, excluding problematic ones
            rule_files = glob.glob(os.path.join(yara_manager.rules_dir, "**", "*.yar"), recursive=True)
            rule_files += glob.glob(os.path.join(yara_manager.rules_dir, "**", "*.yara"), recursive=True)
            
            # Filter out problematic files
            rule_files = [f for f in rule_files if not os.path.basename(f).startswith('index')]
            rule_files = [f for f in rule_files if not "TOOLKIT_Mandibule" in f]
            rule_files = [f for f in rule_files if not "is__elf" in open(f, 'r', errors='ignore').read()]
        
        if not rule_files:
            logging.info("No suitable YARA rule files found - using simplified scanning")
            return False
        
        # Initialize a dictionary to hold file paths and namespaces
        filepaths = {}
        temp_files = []  # Track temporary files to clean up later
        
        # Preprocess and assign each file a unique namespace to avoid rule conflicts
        for i, filepath in enumerate(rule_files):
            try:
                # Preprocess the rule file to fix include paths
                processed_path = fix_yara_includes(filepath)
                if processed_path != filepath:
                    temp_files.append(processed_path)
                
                # Use the filename without extension as namespace
                namespace = os.path.basename(filepath).split('.')[0]
                # Add index to ensure uniqueness
                namespace = f"{namespace}_{i}"
                filepaths[namespace] = processed_path
            except Exception:
                # Silently skip problematic files
                pass
        
        try:
            # Compile all rules
            yara_manager.rules = yara_lib.compile(filepaths=filepaths)
            yara_manager.compiled = True
            logging.info("YARA rules compiled successfully")
            
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    os.remove(temp_file)
                except:
                    pass
                    
            return True
            
        except Exception:
            # Clean up temporary files
            for temp_file in temp_files:
                try:
                    os.remove(temp_file)
                except:
                    pass
                    
            logging.info("Using individual rule scanning instead of compiled ruleset")
            return False
            
    except Exception:
        logging.info("YARA compilation handled silently - using individual rules")
        return False
    finally:
        # Restore original logging level
        yara_logger.setLevel(original_level)

def yara_scan_file(file_path, timeout=60):
    """Scan a file using compiled YARA rules."""
    return yara_manager.scan_file(file_path, timeout)

def scan_memory(pid, timeout=60):
    """Scan a process's memory using compiled YARA rules."""
    return yara_manager.scan_memory(pid, timeout)
