import os
import logging
import subprocess
import shutil
import tempfile
import glob
import yara as yara_lib  # Import as yara_lib to avoid naming conflict with this module

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
        
        # Ensure YARA rules exist before attempting to compile
        if not os.path.isdir(self.rules_dir) or not os.listdir(self.rules_dir):
            logging.info("YARA rules not found. Attempting to download...")
            self.ensure_rules_exist()
    
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
            
        except yara_lib.Error as e:
            logging.error(f"Error compiling YARA rules: {e}")
            # Try to compile each file individually to identify problematic rules
            self._identify_problematic_rules(filepaths)
            return False
        except Exception as e:
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
            except yara_lib.Error as e:
                logging.error(f"Error in rule file {filepath}: {e}")
    
    def scan_file(self, file_path, timeout=60):
        """
        Scan a file using compiled YARA rules.
        
        Args:
            file_path (str): Path to the file to scan.
            timeout (int): Timeout in seconds for the scan.
        
        Returns:
            list: List of rule matches, empty if no matches or error occurred.
        """
        if not self.compiled:
            logging.warning("YARA rules not compiled. Compiling now...")
            if not self.compile_rules():
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
            
        except yara_lib.TimeoutError:
            logging.warning(f"YARA scan timed out after {timeout} seconds on file: {file_path}")
            return []
        except yara_lib.Error as e:
            logging.error(f"YARA error scanning file {file_path}: {e}")
            return []
        except Exception as e:
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
        if not self.compiled:
            logging.warning("YARA rules not compiled. Compiling now...")
            if not self.compile_rules():
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
            
        except yara_lib.TimeoutError:
            logging.warning(f"YARA scan timed out after {timeout} seconds on process: {pid}")
            return []
        except yara_lib.Error as e:
            logging.error(f"YARA error scanning process {pid}: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error scanning process {pid}: {e}")
            return []

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
    return yara_manager.compile_rules(specific_rules)

def scan_file(file_path, timeout=60):
    """Scan a file using compiled YARA rules."""
    return yara_manager.scan_file(file_path, timeout)

def scan_memory(pid, timeout=60):
    """Scan a process's memory using compiled YARA rules."""
    return yara_manager.scan_memory(pid, timeout)
