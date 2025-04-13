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
# Advanced file content analysis
import os
import hashlib
import math
import re
import json
import difflib
import subprocess
from collections import Counter

# Import other modules
from fim_utils.fim_perf import AdaptiveScanner
from fim_utils.fim_context import ContextAwareDetection
from fim_utils.fim_behavioral import EnhancedBehavioralBaselining

class AdvancedFileContentAnalysis:
    def __init__(self, config=None):
        self.config = config or {}
        self.file_cache = {}  # Cache for file content
        self.diff_threshold = self.config.get('diff_threshold', 0.3)  # Threshold for significant diffs
        self.max_file_size = self.config.get('max_file_size', 10 * 1024 * 1024)  # 10MB max for content analysis
        self.content_signatures = {}  # Store file content signatures
        
    def analyze_file_changes(self, file_path, previous_hash, new_hash):
        """Analyze changes between file versions using diff and semantic analysis"""
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
            
        # Check file size before processing
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return {
                    'analysis_type': 'size_only',
                    'file_size': file_size,
                    'too_large': True,
                    'message': f"File too large for content analysis ({file_size} bytes)"
                }
        except OSError:
            return {'error': 'Cannot access file'}
        
        # Determine file type
        file_type = self.determine_file_type(file_path)
        
        # Select appropriate analysis method based on file type
        if file_type == 'binary':
            return self.analyze_binary_changes(file_path, previous_hash, new_hash)
        elif file_type in ['config', 'script', 'text']:
            return self.analyze_text_changes(file_path, previous_hash, new_hash, file_type)
        else:
            return {'analysis_type': 'hash_only', 'file_type': 'unknown'}
    
    def determine_file_type(self, file_path):
        """Determine file type based on extension and content sampling"""
        # Check by extension first
        _, ext = os.path.splitext(file_path.lower())
        
        # Binary file extensions
        binary_extensions = ['.exe', '.bin', '.o', '.so', '.dll', '.pyc', '.pyd', 
                             '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip', 
                             '.tar', '.gz', '.bz2', '.xz', '.pdf']
        
        # Config file extensions
        config_extensions = ['.conf', '.cfg', '.ini', '.json', '.yaml', '.yml', '.xml', '.properties']
        
        # Script file extensions
        script_extensions = ['.sh', '.py', '.rb', '.pl', '.js', '.php', '.ps1', '.bat', '.cmd']
        
        # Text file extensions
        text_extensions = ['.txt', '.md', '.log', '.csv', '.html', '.htm', '.css']
        
        if ext in binary_extensions:
            return 'binary'
        elif ext in config_extensions:
            return 'config'
        elif ext in script_extensions:
            return 'script'
        elif ext in text_extensions:
            return 'text'
        
        # If extension doesn't give a clear answer, check content
        try:
            # Read first few KB to determine content type
            with open(file_path, 'rb') as f:
                content = f.read(4096)
                
            # Check for binary content
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            binary_chars = bytearray(set(range(256)) - set(text_chars))
            
            # If >30% non-text chars, likely binary
            if float(len([b for b in content if b in binary_chars])) / len(content) > 0.3:
                return 'binary'
                
            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
                
                # Check for config patterns
                if any(pattern in text_content for pattern in ['<config', '<?xml', '{', '[', 'config', 'setting']):
                    return 'config'
                
                # Check for script patterns
                if any(pattern in text_content for pattern in ['#!/', 'import ', 'function ', 'def ', 'class ']):
                    return 'script'
                    
                # Default to text
                return 'text'
            except UnicodeDecodeError:
                return 'binary'
                
        except (IOError, OSError):
            # If we can't read the file, default to binary
            return 'binary'
    
    def analyze_binary_changes(self, file_path, previous_hash, new_hash):
        """Analyze changes in binary files using entropy and partial hashing"""
        # For binary files, we focus on entropy analysis and segment hashing
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Calculate entropy
            entropy = self.calculate_entropy(content)
            
            # Calculate segment hashes (divide file into segments and hash each)
            segment_size = min(4096, len(content) // 10) if len(content) > 0 else 0
            segments = []
            
            if segment_size > 0:
                for i in range(0, len(content), segment_size):
                    segment = content[i:i + segment_size]
                    segment_hash = hashlib.md5(segment).hexdigest()
                    segments.append({
                        'offset': i,
                        'size': len(segment),
                        'hash': segment_hash
                    })
            
            # Check if we have a previous signature to compare against
            diff_analysis = None
            if previous_hash in self.content_signatures:
                prev_sig = self.content_signatures[previous_hash]
                diff_analysis = self.compare_binary_signatures(prev_sig, {
                    'entropy': entropy,
                    'segments': segments,
                    'file_size': len(content)
                })
            
            # Store current signature
            self.content_signatures[new_hash] = {
                'entropy': entropy,
                'segments': segments,
                'file_size': len(content)
            }
            
            return {
                'analysis_type': 'binary',
                'file_size': len(content),
                'entropy': entropy,
                'segment_count': len(segments),
                'diff_analysis': diff_analysis
            }
            
        except (IOError, OSError):
            return {'error': 'Cannot access file for binary analysis'}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0
            
        entropy = 0
        data_len = len(data)
        
        # Count byte frequencies
        counter = Counter(data)
        
        # Calculate entropy
        for count in counter.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def compare_binary_signatures(self, old_sig, new_sig):
        """Compare binary file signatures to identify changes"""
        # Compare file sizes
        old_size = old_sig.get('file_size', 0)
        new_size = new_sig.get('file_size', 0)
        size_delta = new_size - old_size
        size_change_pct = (size_delta / old_size * 100) if old_size > 0 else float('inf')
        
        # Compare entropy
        old_entropy = old_sig.get('entropy', 0)
        new_entropy = new_sig.get('entropy', 0)
        entropy_delta = new_entropy - old_entropy
        
        # Compare segments
        old_segments = old_sig.get('segments', [])
        new_segments = new_sig.get('segments', [])
        
        # Find matching segments
        matching_segments = 0
        modified_segments = 0
        
        # Map of segment offset to hash
        old_segment_map = {seg['offset']: seg['hash'] for seg in old_segments}
        new_segment_map = {seg['offset']: seg['hash'] for seg in new_segments}
        
        # Find common offsets
        common_offsets = set(old_segment_map.keys()) & set(new_segment_map.keys())
        
        for offset in common_offsets:
            if old_segment_map[offset] == new_segment_map[offset]:
                matching_segments += 1
            else:
                modified_segments += 1
        
        # Calculate similarity
        total_segments = len(old_segments)
        similarity = matching_segments / total_segments if total_segments > 0 else 0
        
        # Analyze entropy change
        is_encrypted = entropy_delta > 1.0 and new_entropy > 7.0
        is_compressed = entropy_delta > 0.5 and size_delta < 0
        is_decompressed = entropy_delta < -0.5 and size_delta > 0
        
        return {
            'size_delta': size_delta,
            'size_change_pct': size_change_pct,
            'entropy_delta': entropy_delta,
            'matching_segments': matching_segments,
            'modified_segments': modified_segments,
            'similarity': similarity,
            'is_encrypted': is_encrypted,
            'is_compressed': is_compressed,
            'is_decompressed': is_decompressed,
            'significant_change': similarity < 0.7
        }
    
    def analyze_text_changes(self, file_path, previous_hash, new_hash, file_type):
        """Analyze changes in text files using diff and semantic analysis"""
        try:
            # Read current file content
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                new_content = f.read()
                
            # Get old content if available
            old_content = None
            if previous_hash in self.file_cache:
                old_content = self.file_cache[previous_hash]
            
            # Store new content in cache
            self.file_cache[new_hash] = new_content
            
            # If we don't have the old content, we can only analyze current state
            if old_content is None:
                return self.analyze_text_content(new_content, file_type)
            
            # Get diff between versions
            diff_result = self.compute_text_diff(old_content, new_content)
            
            # Combine with content analysis
            content_analysis = self.analyze_text_content(new_content, file_type)
            
            # Special handling for different file types
            type_specific = {}
            
            if file_type == 'config':
                type_specific = self.analyze_config_changes(old_content, new_content)
            elif file_type == 'script':
                type_specific = self.analyze_script_changes(old_content, new_content)
            
            # Combine all analyses
            result = {
                'analysis_type': 'text',
                'file_type': file_type,
                'diff': diff_result,
                'content': content_analysis
            }
            
            if type_specific:
                result['type_specific'] = type_specific
                
            return result
            
        except (IOError, OSError, UnicodeDecodeError) as e:
            return {'error': f'Text analysis failed: {str(e)}'}
    
    def compute_text_diff(self, old_content, new_content):
        """Compute diff between old and new content"""
        # Split into lines
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        
        # Get unified diff
        diff = list(difflib.unified_diff(old_lines, new_lines, n=2))
        
        # Count additions and deletions
        additions = len([line for line in diff if line.startswith('+')])
        deletions = len([line for line in diff if line.startswith('-')])
        
        # Calculate similarity using difflib's SequenceMatcher
        similarity = difflib.SequenceMatcher(None, old_content, new_content).ratio()
        
        # Get changed sections for more detailed analysis
        changed_sections = []
        diff_iter = iter(diff)
        
        # Skip the header lines
        for _ in range(3):
            next(diff_iter, None)
        
        current_section = {'context': [], 'additions': [], 'deletions': []}
        
        for line in diff_iter:
            if line.startswith(' '):  # Context line
                if current_section['additions'] or current_section['deletions']:
                    changed_sections.append(current_section)
                    current_section = {'context': [], 'additions': [], 'deletions': []}
                current_section['context'].append(line[1:])
            elif line.startswith('+'):  # Addition
                current_section['additions'].append(line[1:])
            elif line.startswith('-'):  # Deletion
                current_section['deletions'].append(line[1:])
        
        # Add the last section if non-empty
        if current_section['additions'] or current_section['deletions']:
            changed_sections.append(current_section)
        
        return {
            'additions': additions,
            'deletions': deletions,
            'similarity': similarity,
            'changed_sections': changed_sections[:5],  # Limit to first 5 sections
            'significant_change': similarity < self.diff_threshold
        }
    
    def analyze_text_content(self, content, file_type):
        """Analyze text content for patterns of interest"""
        # Basic text statistics
        line_count = content.count('\n') + 1
        word_count = len(content.split())
        char_count = len(content)
        
        # Look for patterns based on file type
        patterns = {}
        
        if file_type == 'config':
            patterns['ip_addresses'] = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
            patterns['urls'] = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
            patterns['uncommon_ports'] = re.findall(r'port\s*[=:]\s*(\d+)', content)
        elif file_type == 'script':
            patterns['functions'] = re.findall(r'function\s+(\w+)|def\s+(\w+)', content)
            patterns['imports'] = re.findall(r'import\s+(\w+)|from\s+(\w+)', content)
            patterns['suspicious_commands'] = re.findall(r'system\(|exec\(|eval\(|shell_exec|subprocess', content)
        
        return {
            'line_count': line_count,
            'word_count': word_count,
            'char_count': char_count,
            'patterns': patterns
        }
    
    def analyze_config_changes(self, old_content, new_content):
        """Special analysis for configuration files"""
        # Try to detect config format
        config_format = self.detect_config_format(new_content)
        
        if config_format == 'json':
            return self.analyze_json_config(old_content, new_content)
        elif config_format == 'ini':
            return self.analyze_ini_config(old_content, new_content)
        elif config_format == 'xml':
            return self.analyze_xml_config(old_content, new_content)
        else:
            # Generic key-value extraction for unknown formats
            old_settings = self.extract_generic_settings(old_content)
            new_settings = self.extract_generic_settings(new_content)
            return self.compare_settings(old_settings, new_settings)
    
    def detect_config_format(self, content):
        """Detect configuration file format"""
        # Check for JSON format
        if content.strip().startswith('{') and content.strip().endswith('}'):
            try:
                json.loads(content)
                return 'json'
            except json.JSONDecodeError:
                pass
        
        # Check for XML format
        if content.strip().startswith('<') and content.strip().endswith('>'):
            if '<?xml' in content or '<config' in content:
                return 'xml'
        
        # Check for INI format
        if '[' in content and ']' in content and '=' in content:
            if re.search(r'^\s*\[[^\]]+\]', content, re.MULTILINE):
                return 'ini'
        
        # Default to generic
        return 'generic'
    
    def analyze_json_config(self, old_content, new_content):
        """Analyze changes in JSON configuration files"""
        try:
            old_json = json.loads(old_content)
            new_json = json.loads(new_content)
            
            # Flatten nested JSON for comparison
            old_flat = self.flatten_json(old_json)
            new_flat = self.flatten_json(new_json)
            
            return self.compare_settings(old_flat, new_flat)
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON format'}
    
    def flatten_json(self, json_obj, prefix=''):
        """Flatten nested JSON object into key-value pairs"""
        flattened = {}
        
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    flattened.update(self.flatten_json(v, key))
                else:
                    flattened[key] = str(v)
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    flattened.update(self.flatten_json(item, key))
                else:
                    flattened[key] = str(item)
        else:
            flattened[prefix] = str(json_obj)
            
        return flattened
    
    def analyze_ini_config(self, old_content, new_content):
        """Analyze changes in INI configuration files"""
        # Parse INI-style settings
        old_settings = self.parse_ini_content(old_content)
        new_settings = self.parse_ini_content(new_content)
        
        return self.compare_settings(old_settings, new_settings)
    
    def parse_ini_content(self, content):
        """Parse INI-style configuration"""
        settings = {}
        current_section = 'DEFAULT'
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith(('#', ';')):
                continue
            
            # Parse section headers
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                continue
            
            # Parse key-value pairs
            if '=' in line:
                key, value = line.split('=', 1)
                settings[f"{current_section}.{key.strip()}"] = value.strip()
        
        return settings
    
    def analyze_xml_config(self, old_content, new_content):
        """Analyze changes in XML configuration files"""
        # Simple XML parsing
        old_settings = self.extract_xml_settings(old_content)
        new_settings = self.extract_xml_settings(new_content)
        
        return self.compare_settings(old_settings, new_settings)
    
    def extract_xml_settings(self, content):
        """Extract settings from XML content using regex"""
        settings = {}
        
        # Find all XML tags with values
        tag_pattern = re.compile(r'<([^>/\s]+)[^>]*>(.*?)</\1>', re.DOTALL)
        attribute_pattern = re.compile(r'(\w+)=["\'](.*?)["\']')
        
        for match in tag_pattern.finditer(content):
            tag_name = match.group(1)
            tag_value = match.group(2).strip()
            
            if tag_value:
                settings[tag_name] = tag_value
            
            # Also extract attributes
            tag_start = match.group(0)[:match.group(0).find('>')] # This line had an extra bracket
            for attr_match in attribute_pattern.finditer(tag_start):
                attr_name = attr_match.group(1)
                attr_value = attr_match.group(2)
                settings[f"{tag_name}.{attr_name}"] = attr_value
        
        return settings
    
    def extract_generic_settings(self, content):
        """Extract key-value pairs from generic config content"""
        settings = {}
        
        # Look for key-value patterns
        patterns = [
            r'(\w+)\s*[=:]\s*([^;#\n]+)',  # key=value or key: value
            r'(-{1,2}\w+)\s+([^-][^;#\n]*)'  # --key value
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                key = match.group(1).strip()
                value = match.group(2).strip()
                settings[key] = value
        
        return settings
    
    def compare_settings(self, old_settings, new_settings):
        """Compare settings between versions"""
        # Find added, removed, and modified settings
        old_keys = set(old_settings.keys())
        new_keys = set(new_settings.keys())
        
        added_keys = new_keys - old_keys
        removed_keys = old_keys - new_keys
        common_keys = old_keys & new_keys
        
        modified_keys = {key for key in common_keys if old_settings[key] != new_settings[key]}
        
        # Collect changes
        changes = {
            'added': {key: new_settings[key] for key in added_keys},
            'removed': {key: old_settings[key] for key in removed_keys},
            'modified': {key: {'old': old_settings[key], 'new': new_settings[key]} for key in modified_keys}
        }
        
        # Count changes
        total_changes = len(added_keys) + len(removed_keys) + len(modified_keys)
        
        # Calculate criticality based on changes
        criticality = 'low'
        if total_changes > 10:
            criticality = 'high'
        elif total_changes > 5:
            criticality = 'medium'
        
        return {
            'format': 'config',
            'changes': changes,
            'total_changes': total_changes,
            'criticality': criticality
        }
    
    def analyze_script_changes(self, old_content, new_content):
        """Analyze changes in script files for security implications"""
        # Extract functions and imports from both versions
        old_functions = set(re.findall(r'function\s+(\w+)|def\s+(\w+)', old_content))
        new_functions = set(re.findall(r'function\s+(\w+)|def\s+(\w+)', new_content))
        
        old_imports = set(re.findall(r'import\s+(\w+)|from\s+(\w+)', old_content))
        new_imports = set(re.findall(r'import\s+(\w+)|from\s+(\w+)', new_content))
        
        # Look for suspicious patterns
        suspicious_patterns = {
            'system_commands': r'system\s*\(|exec\s*\(|shell_exec|subprocess\..*call|os\.system',
            'network_access': r'socket\.|urllib|requests\.|http\.|connect\s*\(',
            'file_operations': r'open\s*\(|file\s*\(|read\s*\(|write\s*\(|unlink\s*\(',
            'eval_code': r'eval\s*\(|exec\s*\(|execfile|compile\s*\(|__import__',
            'privilege_escalation': r'sudo|su\s+|setuid|setgid|chmod\s+777|chown\s+root',
            'data_exfiltration': r'base64\.|encode\s*\(|encrypt\s*\(|\.send\s*\('
        }
        
        # Check for these patterns in new content
        suspicious_matches = {}
        for category, pattern in suspicious_patterns.items():
            matches = re.findall(pattern, new_content)
            if matches:
                suspicious_matches[category] = matches
        
        # Compare functions and imports
        added_functions = [f[0] or f[1] for f in new_functions - old_functions if any(f)]
        removed_functions = [f[0] or f[1] for f in old_functions - new_functions if any(f)]
        
        added_imports = [i[0] or i[1] for i in new_imports - old_imports if any(i)]
        removed_imports = [i[0] or i[1] for i in old_imports - new_imports if any(i)]
        
# Analyze criticality based on findings
        criticality = 'low'
        
        # Elevate criticality based on suspicious patterns
        if any(category in suspicious_matches for category in ['eval_code', 'privilege_escalation']):
            criticality = 'high'
        elif any(category in suspicious_matches for category in ['system_commands', 'network_access']):
            criticality = 'medium'
        elif suspicious_matches:
            criticality = 'low'
            
        return {
            'format': 'script',
            'added_functions': added_functions,
            'removed_functions': removed_functions,
            'added_imports': added_imports,
            'removed_imports': removed_imports,
            'suspicious_patterns': suspicious_matches,
            'criticality': criticality
        }
    
    def check_malware_indicators(self, file_path, file_hash):
        """Check file against known malware indicators"""
        # This would integrate with threat intelligence feeds
        # Simplified example implementation
        entropy = None
        strings_analysis = None
        
        try:
            # Calculate entropy for all files
            with open(file_path, 'rb') as f:
                content = f.read()
                entropy = self.calculate_entropy(content)
                
            # For non-binary files, extract suspicious strings
            if not self.determine_file_type(file_path) == 'binary':
                strings_analysis = self.extract_suspicious_strings(file_path)
                
            return {
                'file_hash': file_hash,
                'entropy': entropy,
                'high_entropy': entropy > 7.0 if entropy is not None else False,
                'strings_analysis': strings_analysis
            }
        except (IOError, OSError):
            return {'error': 'Cannot access file for malware analysis'}
    
    def extract_suspicious_strings(self, file_path):
        """Extract suspicious strings from a file using external 'strings' tool"""
        suspicious_categories = {
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'urls': r'https?://[^\s<>"]+|www\.[^\s<>"]+',
            'encoded_commands': r'base64 -d|base64 --decode|base64\.decode',
            'shell_commands': r'sh -c|bash -c|cmd\.exe|powershell',
            'common_exfil': r'curl|wget|nc \-|netcat|ssh|sftp'
        }
        
        try:
            # Use strings command if available (more efficient for binary files)
            if os.path.exists('/usr/bin/strings'):
                output = subprocess.check_output(['strings', file_path], stderr=subprocess.DEVNULL)
                strings_content = output.decode('utf-8', errors='replace')
            else:
                # Fallback to reading the file directly
                with open(file_path, 'rb') as f:
                    content = f.read()
                    strings_content = ''.join(chr(c) if c >= 32 and c < 127 else ' ' for c in content)
            
            # Look for suspicious patterns
            findings = {}
            for category, pattern in suspicious_categories.items():
                matches = set(re.findall(pattern, strings_content))
                if matches:
                    findings[category] = list(matches)[:10]  # Limit to first 10 matches
            
            return findings if findings else None
            
        except (IOError, OSError, subprocess.SubprocessError):
            return None
    
    def analyze_partial_file_changes(self, file_path, old_content, new_content):
        """Analyze changes in specific parts of files"""
        # Get diff
        diff_result = self.compute_text_diff(old_content, new_content)
        
        # Detect if changes are localized to specific sections
        changed_sections = diff_result.get('changed_sections', [])
        
        # Identify specific types of changes
        change_types = []
        for section in changed_sections:
            context = '\n'.join(section.get('context', []))
            additions = '\n'.join(section.get('additions', []))
            deletions = '\n'.join(section.get('deletions', []))
            
            # Look for specific patterns in changes
            if re.search(r'password|passwd|secret|key|token|auth', context, re.IGNORECASE):
                change_types.append('credential_change')
            
            if re.search(r'127\.0\.0\.1|localhost', deletions, re.IGNORECASE) and not re.search(r'127\.0\.0\.1|localhost', additions, re.IGNORECASE):
                change_types.append('localhost_removal')
            
            if re.search(r'deny|block|restrict', deletions, re.IGNORECASE) and not re.search(r'deny|block|restrict', additions, re.IGNORECASE):
                change_types.append('security_restriction_removal')
            
            # Check for added URLs or IPs
            new_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', additions)
            new_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', additions)
            
            if new_urls:
                change_types.append('new_url_added')
            
            if new_ips:
                change_types.append('new_ip_added')
        
        # Determine criticality based on change types
        criticality = 'low'
        if 'security_restriction_removal' in change_types or 'credential_change' in change_types:
            criticality = 'high'
        elif 'localhost_removal' in change_types or 'new_url_added' in change_types or 'new_ip_added' in change_types:
            criticality = 'medium'
        
        return {
            'localized_changes': len(changed_sections) <= 3,
            'change_types': change_types,
            'criticality': criticality
        }
