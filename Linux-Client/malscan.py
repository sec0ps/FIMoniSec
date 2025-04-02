import os
import re
import math
import json
import csv
import hashlib
import logging
import argparse
import chardet
import zipfile
import mimetypes
import tempfile
import yara
import xml.etree.ElementTree as ET
from typing import List, Tuple, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party libraries
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from pdfminer.high_level import extract_text
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from docx import Document
import openpyxl
import requests
import yara
import warnings

# Filter out XML parsed as HTML warning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('malware_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Updated ScannerConfig class
class ScannerConfig:
    """Centralized configuration for the malware scanner"""
    ENTROPY_THRESHOLD = 7.5
    VIRUS_TOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    MAX_FILE_SIZE_MB = 50  # Maximum file size to scan
    ENABLED_CHECKS = {
        'entropy': True,
        'indicators': True,
        'virustotal': bool(VIRUS_TOTAL_API_KEY),
        'yara': True
    }
    # Default YARA rules directory - now with path resolution
    YARA_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yara_rules')
    
    @classmethod
    def create_default_directories(cls):
        """Create default directories if they don't exist"""
        # Create YARA rules directory if it doesn't exist
        if not os.path.exists(cls.YARA_RULES_DIR):
            try:
                os.makedirs(cls.YARA_RULES_DIR)
                logger.info(f"Created YARA rules directory at {cls.YARA_RULES_DIR}")
                
                # Create a sample YARA rule for demonstration
                sample_rule = """
rule SuspiciousFile {
    meta:
        description = "Detects suspicious file characteristics"
        author = "Scanner Framework"
        severity = "medium"
        date = "2025-04-02"
    
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "wget" nocase
        $s4 = "curl" nocase
        $exec1 = "Execute" nocase
        $exec2 = "eval(" nocase
        $exec3 = "exec(" nocase

    condition:
        2 of ($s*) or any of ($exec*)
}
"""
                with open(os.path.join(cls.YARA_RULES_DIR, "sample_rule.yar"), "w") as f:
                    f.write(sample_rule)
                logger.info("Created sample YARA rule")
            except Exception as e:
                logger.error(f"Error creating YARA rules directory: {e}")
    
    @classmethod
    def update_from_args(cls, args):
        """Update configuration based on command-line arguments"""
        if hasattr(args, 'virustotal') and args.virustotal:
            cls.ENABLED_CHECKS['virustotal'] = True
        
        if hasattr(args, 'no_entropy') and args.no_entropy:
            cls.ENABLED_CHECKS['entropy'] = False
            
        if hasattr(args, 'no_indicators') and args.no_indicators:
            cls.ENABLED_CHECKS['indicators'] = False
            
        if hasattr(args, 'yara') and args.yara:
            cls.ENABLED_CHECKS['yara'] = True
            
        if hasattr(args, 'yara_dir') and args.yara_dir:
            cls.YARA_RULES_DIR = args.yara_dir
            
        if hasattr(args, 'max_size') and args.max_size:
            cls.MAX_FILE_SIZE_MB = args.max_size

# === Advanced Threat Indicators ===
class ThreatIndicators:
    """Comprehensive collection of threat indicators"""
    GENERIC_INDICATORS = [
        # Suspicious command execution patterns
        r'(powershell|cmd\.exe|wscript|mshta|certutil|regsvr32|rundll32)',
        
        # Base64 encoded potential shellcode or commands
        r'(base64,?[A-Za-z0-9+/=]{20,})',
        
        # Dynamic code execution
        r'(eval\(|exec\(|unescape\(|Function\(|window\.eval)',
        
        # Potential obfuscation
        r'(chr\(|fromCharCode\(|atob\()',
        
        # Potential exploitation techniques
        r'(shellcode|bypass|UAC|escalate|exploit)',
    ]

    HTML_SVG_INDICATORS = [
        r'<script.*?>',
        r'on\w+="[^"]+"',
        r'javascript:',
        r'<iframe.*?>',
        r'data:text/html',
        r'window\.location',
    ]

    PDF_INDICATORS = [
        r'/JS', r'/JavaScript', r'/AA', r'/OpenAction',
        r'Launch', r'EmbeddedFile', r'GoToE', 
        r'/URI', r'/GoTo', r'/RichMedia'
    ]

    XML_INDICATORS = [
        r'<!ENTITY',
        r'<!DOCTYPE',
        r'http[s]?://',
        r'file://',
        r'php://filter',
        r'data:',
    ]

# === Threat Intelligence Integration ===
class ThreatIntelligence:
    """Threat intelligence and file reputation checks"""
    @staticmethod
    def virustotal_check(file_path: str) -> Dict[str, Any]:
        """Check file reputation on VirusTotal"""
        if not ScannerConfig.ENABLED_CHECKS['virustotal']:
            return {}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(
                    'https://www.virustotal.com/vtapi/v2/file/scan',
                    params={'apikey': ScannerConfig.VIRUS_TOTAL_API_KEY},
                    files=files
                )
                
            # Get scan results
            scan_results = response.json()
            
            # Retrieve detailed results
            if 'scan_id' in scan_results:
                results_response = requests.get(
                    'https://www.virustotal.com/vtapi/v2/file/report',
                    params={
                        'apikey': ScannerConfig.VIRUS_TOTAL_API_KEY,
                        'resource': scan_results['scan_id']
                    }
                )
                return results_response.json()
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return {}

    @staticmethod
    def hash_file(file_path: str) -> Dict[str, str]:
        """Generate file hashes"""
        hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        hashes = {}
        with open(file_path, 'rb') as f:
            file_content = f.read()
            for name, algo in hash_algorithms.items():
                hashes[name] = algo(file_content).hexdigest()
        
        return hashes

# === Entropy and Risk Analysis ===
def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    length = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy

# Updated YARA rule scanner
class YaraRuleScanner:
    """YARA rule-based malware detection"""
    @staticmethod
    def load_rules(rule_directory: str = None) -> List:
        """Load YARA rules from a directory"""
        rules = []
        
        # Get YARA module
        yara_module = yara_wrapper()
        if yara_module is None:
            logger.warning("Cannot load YARA rules - module unavailable")
            return rules
        
        # Use provided directory or default from config
        if rule_directory is None:
            rule_directory = ScannerConfig.YARA_RULES_DIR
            
        if not os.path.exists(rule_directory):
            logger.warning(f"YARA rule directory {rule_directory} not found.")
            return rules
        
        for filename in os.listdir(rule_directory):
            if filename.endswith('.yar') or filename.endswith('.yara'):
                try:
                    rule_path = os.path.join(rule_directory, filename)
                    
                    # Try compile methods based on what's available
                    if hasattr(yara_module, 'compile'):
                        rule = yara_module.compile(filepath=rule_path)
                        rules.append(rule)
                    elif hasattr(yara_module, 'compile_file'):
                        rule = yara_module.compile_file(filepath=rule_path)
                        rules.append(rule)
                    else:
                        logger.warning(f"No suitable YARA compilation method found for {filename}")
                except Exception as e:
                    logger.error(f"Error compiling YARA rule {filename}: {e}")
        
        return rules

def scan_with_yara_rules(file_path: str, rules: List) -> List[Dict[str, Any]]:
    """Scan a file against loaded YARA rules"""
    if not ScannerConfig.ENABLED_CHECKS['yara']:
        return []
        
    if not rules:
        return []
        
    matches = []
    for rule_set in rules:
        try:
            # Try different methods to match rules based on yara version
            if hasattr(rule_set, 'match'):
                # Modern yara-python approach
                file_matches = rule_set.match(filepath=file_path)
                
                # Handle different return types
                if isinstance(file_matches, list):
                    for match in file_matches:
                        match_info = {
                            'rule_name': getattr(match, 'rule', 'Unknown'),
                            'tags': getattr(match, 'tags', []),
                            'meta': getattr(match, 'meta', {})
                        }
                        matches.append(match_info)
                else:
                    # Some versions may return a dictionary
                    matches.append({
                        'rule_name': getattr(file_matches, 'rule', 'Unknown'),
                        'tags': getattr(file_matches, 'tags', []),
                        'meta': getattr(file_matches, 'meta', {})
                    })
            else:
                logger.warning(f"Incompatible YARA rule object: {type(rule_set)}")
        except AttributeError as e:
            logger.error(f"YARA attribute error: {e}")
        except Exception as e:
            logger.error(f"YARA scanning error: {e}")
    
    return matches

# === Content Scanning Functions ===
def scan_content(content: str, indicators: List[str], label: str = "Generic") -> List[Tuple[str, str, List[str]]]:
    """Scan content against threat indicators"""
    findings = []
    for pattern in indicators:
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
        if matches:
            findings.append((label, pattern, matches[:5]))
    return findings

# Updated scan_file function with fixed XML handling
def scan_file(file_path: str) -> Dict[str, Any]:
    """Comprehensive file scanning"""
    # File size check
    file_size = os.path.getsize(file_path)
    if file_size > ScannerConfig.MAX_FILE_SIZE_MB * 1024 * 1024:
        logger.warning(f"File {file_path} exceeds maximum scan size.")
        return {}
    
    # Rest of the existing function...
    
    # File type-specific scanning
    ftype = detect_filetype(file_path)
    try:
        if ftype == "pdf":
            # Existing PDF handling...
            pass
        elif ftype in ["html", "svg"]:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            soup = BeautifulSoup(content, "html.parser")
            raw = soup.prettify()
            scan_results['findings'] += scan_content(
                raw, 
                ThreatIndicators.HTML_SVG_INDICATORS + ThreatIndicators.GENERIC_INDICATORS, 
                "HTML/SVG"
            )
        elif ftype == "xml":
            try:
                # Use proper XML parser
                tree = ET.parse(file_path)
                root = tree.getroot()
                # Convert to string for scanning
                content = ET.tostring(root, encoding='unicode')
                scan_results['findings'] += scan_content(
                    content, 
                    ThreatIndicators.XML_INDICATORS + ThreatIndicators.GENERIC_INDICATORS, 
                    "XML"
                )
            except ET.ParseError as e:
                logger.warning(f"Could not parse {file_path} as XML: {e}")
                # Fallback to text scanning
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                scan_results['findings'] += scan_content(
                    content, 
                    ThreatIndicators.XML_INDICATORS + ThreatIndicators.GENERIC_INDICATORS, 
                    "XML"
                )
        # Rest of existing function...
        
    except Exception as e:
        logger.error(f"Error scanning {file_path}: {e}")
    
    return scan_results

def detect_filetype(filepath: str) -> str:
    """Improved file type detection"""
    ext = os.path.splitext(filepath)[1].lower()
    
    # Mapping of extensions to specific types
    type_map = {
        ".pdf": "pdf",
        ".svg": "svg",
        ".html": "html",
        ".htm": "html",
        ".xml": "xml",
        ".zip": "zip",
        ".txt": "text",
        ".csv": "text",
        ".log": "text",
        ".json": "text",
        ".docx": "docx",
        ".xlsx": "xlsx",
        ".eml": "eml"
    }
    
    # Check exact extension
    if ext in type_map:
        return type_map[ext]
    
    # Fallback to MIME type detection
    mime = mimetypes.guess_type(filepath)[0]
    if mime:
        if mime.startswith("text"):
            return "text"
        if "xml" in mime:
            return "xml"
        if "html" in mime:
            return "html"
    
    return "unknown"

def export_findings(scan_results: Dict[str, Any], output_prefix: str):
    """Export scan results to multiple formats"""
    csv_path = f"{output_prefix}_scan_results.csv"
    json_path = f"{output_prefix}_scan_results.json"
    
    # Consolidate findings
    all_findings = []
    
    # Add generic findings
    for label, pattern, matches in scan_results.get('findings', []):
        for match in matches:
            all_findings.append({
                'type': label,
                'pattern': pattern,
                'match': match
            })
    
    # Add YARA matches
    for yara_match in scan_results.get('yara_matches', []):
        all_findings.append({
            'type': 'YARA',
            'rule_name': yara_match.get('rule_name', ''),
            'tags': yara_match.get('tags', []),
            'meta': yara_match.get('meta', {})
        })
    
    # Write CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ['type', 'pattern', 'match']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for finding in all_findings:
            writer.writerow(finding)
    
    # Write JSON
    with open(json_path, "w", encoding="utf-8") as jsonfile:
        json.dump({
            'scan_results': scan_results,
            'findings': all_findings
        }, jsonfile, indent=2)
    
    logger.info(f"Scan results exported to {csv_path} and {json_path}")

def scan_directory(directory: str, recursive: bool = False):
    """Scan an entire directory for potential threats"""
    scan_results = []
    
    def scan_files(dir_path):
        nonlocal scan_results
        for root, _, files in os.walk(dir_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    result = scan_file(filepath)
                    if result.get('findings') or result.get('yara_matches'):
                        scan_results.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {filepath}: {e}")
                
                # Break early if recursive is False
                if not recursive:
                    break
    
    # Start scanning
    scan_files(directory)
    return scan_results

def main():
    """Main CLI entry point for the malware scanner"""
    parser = argparse.ArgumentParser(description="Advanced Malware Scanner")
    
    # Create default directories
    ScannerConfig.create_default_directories()
    
    # Add mutually exclusive group for file/directory scanning
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to the file to scan")
    group.add_argument("-d", "--directory", help="Directory to scan")
    
    # Additional optional arguments
    parser.add_argument("--recursive", action="store_true", 
                        help="Recursively scan subdirectories")
    parser.add_argument("--export", action="store_true", 
                        help="Export scan results to CSV and JSON")
    parser.add_argument("--virustotal", action="store_true", 
                        help="Enable VirusTotal scanning (requires API key)")
    parser.add_argument("--yara", action="store_true", 
                        help="Enable YARA rule scanning")
    parser.add_argument("--no-entropy", action="store_true", 
                        help="Disable entropy scanning")
    parser.add_argument("--no-indicators", action="store_true", 
                        help="Disable threat indicator scanning")
    parser.add_argument("--yara-dir", 
                        help="Custom YARA rules directory")
    parser.add_argument("--max-size", type=int, 
                        help="Maximum file size in MB to scan")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Configure scanner based on CLI arguments
    ScannerConfig.update_from_args(args)
    
    # Perform scanning
    if args.file:
        if not os.path.isfile(args.file):
            logger.error(f"File not found: {args.file}")
            return
        
        logger.info(f"Scanning file: {args.file}")
        result = scan_file(args.file)
        
        # Print and optionally export results
        print_findings(result)
        
        if args.export:
            export_findings(result, os.path.splitext(args.file)[0])
    
    elif args.directory:
        if not os.path.isdir(args.directory):
            logger.error(f"Directory not found: {args.directory}")
            return
        
        logger.info(f"Scanning directory: {args.directory}")
        results = scan_directory(args.directory, recursive=args.recursive)
        
        # Summary of findings
        total_files_scanned = len(results)
        files_with_findings = sum(1 for r in results if r.get('findings') or r.get('yara_matches'))
        
        print(f"\n[SCAN SUMMARY]")
        print(f"Total files scanned: {total_files_scanned}")
        print(f"Files with potential threats: {files_with_findings}")
        
        # Print detailed findings
        for result in results:
            if result.get('findings') or result.get('yara_matches'):
                print(f"\n--- Scan Results for {result['file_path']} ---")
                print_findings(result)
        
        # Export if requested
        if args.export:
            export_findings(
                {'scanned_files': results}, 
                f"{os.path.basename(args.directory)}_scan_results"
            )

def scan_file(file_path: str) -> Dict[str, Any]:
    """Comprehensive file scanning"""
    # File size check
    file_size = os.path.getsize(file_path)
    if file_size > ScannerConfig.MAX_FILE_SIZE_MB * 1024 * 1024:
        logger.warning(f"File {file_path} exceeds maximum scan size.")
        return {}
    
    # Scan results container
    scan_results = {
        'file_path': file_path,
        'file_size': file_size,
        'findings': [],
        'hashes': {},
        'entropy': 0.0,
        'virustotal': {},
        'yara_matches': []
    }
    
    # Compute file hashes
    scan_results['hashes'] = ThreatIntelligence.hash_file(file_path)
    
    # Read entire file content
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    # Entropy check
    entropy = calculate_entropy(file_content)
    scan_results['entropy'] = entropy
    logger.info(f"File entropy: {entropy:.2f}")
    if entropy > ScannerConfig.ENTROPY_THRESHOLD:
        scan_results['findings'].append(
            ("Entropy", "High entropy", [f"Entropy: {entropy:.2f}"])
        )
    
    # VirusTotal check
    if ScannerConfig.ENABLED_CHECKS['virustotal']:
        scan_results['virustotal'] = ThreatIntelligence.virustotal_check(file_path)
    
    # YARA rule scanning
    if ScannerConfig.ENABLED_CHECKS['yara']:
        try:
            yara_rules = YaraRuleScanner.load_rules()
            scan_results['yara_matches'] = scan_with_yara_rules(file_path, yara_rules)
            logger.info(f"YARA matches: {len(scan_results['yara_matches'])}")
        except Exception as e:
            logger.error(f"YARA scanning error: {e}")
            scan_results['yara_matches'] = []
    
    # File type-specific scanning
    ftype = detect_filetype(file_path)
    logger.info(f"Detected file type: {ftype}")
    
    try:
        if ftype == "pdf":
            # PDF handling...
            pass
        elif ftype in ["html", "svg"]:
            logger.info(f"Scanning as HTML/SVG file")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                soup = BeautifulSoup(content, "html.parser")
                raw = soup.prettify()
                
                # Debug output
                logger.info(f"File content length: {len(raw)} characters")
                
                # Perform the scan
                findings = scan_content(
                    raw, 
                    ThreatIndicators.HTML_SVG_INDICATORS + ThreatIndicators.GENERIC_INDICATORS, 
                    "HTML/SVG"
                )
                
                # Debug output
                logger.info(f"Found {len(findings)} indicators in HTML/SVG content")
                
                scan_results['findings'] += findings
            except Exception as e:
                logger.error(f"Error in HTML/SVG scanning: {e}")
        # Rest of the function...
    except Exception as e:
        logger.error(f"Error scanning {file_path}: {e}")
    
    # Debug output
    logger.info(f"Total findings: {len(scan_results['findings'])}")
    if len(scan_results['findings']) > 0:
        logger.info(f"First finding: {scan_results['findings'][0]}")
    
    return scan_results

def yara_wrapper():
    """Wrapper to manage YARA operations and handle missing functionality"""
    try:
        import yara
        
        # Test if yara is properly installed
        if not hasattr(yara, 'compile') and not hasattr(yara, 'compile_file'):
            logger.warning("YARA module installed but missing required methods")
            return None
            
        return yara
    except ImportError:
        logger.warning("YARA module not installed")
        return None
        
def print_findings(scan_result: Dict[str, Any]):
    """Pretty print scan findings"""
    if not scan_result:
        logger.info("No scan results to display.")
        return
    
    # Entropy check
    if scan_result.get('entropy', 0) > ScannerConfig.ENTROPY_THRESHOLD:
        logger.warning(f"High entropy detected: {scan_result['entropy']:.2f}")
    
    # File hashes
    hashes = scan_result.get('hashes', {})
    if hashes:
        print("\n[File Hashes]")
        for hash_type, hash_value in hashes.items():
            print(f"{hash_type.upper()}: {hash_value}")
    
    # YARA rule matches
    yara_matches = scan_result.get('yara_matches', [])
    if yara_matches:
        print("\n[YARA Rule Matches]")
        for match in yara_matches:
            print(f"Rule: {match.get('rule_name', 'Unknown')}")
            print(f"Tags: {match.get('tags', [])}")
            print(f"Meta: {match.get('meta', {})}\n")
    
    # Threat Indicators
    findings = scan_result.get('findings', [])
    if findings:
        print("\n[Threat Indicators]")
        for label, pattern, matches in findings:
            print(f"\n{label} Indicator:")
            print(f"  Pattern: {pattern}")
            for match in matches[:5]:  # Limit to 5 matches
                snippet = str(match)
                if len(snippet) > 100:
                    snippet = snippet[:100] + "..."
                print(f"  Match: {snippet}")
    else:
        print("\n[No Threat Indicators Found]")
    
    # VirusTotal results - only if there are positives
    vt_results = scan_result.get('virustotal', {})
    if vt_results and vt_results.get('positives', 0) > 0:
        print("\n[VirusTotal Scan]")
        print(f"Positives: {vt_results['positives']}/{vt_results.get('total', 'N/A')}")
        print(f"Scan Date: {vt_results.get('scan_date', 'N/A')}")

# Entrypoint
if __name__ == "__main__":
    main()
