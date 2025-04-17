# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution (Windows Version)
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
import json
import os
import logging
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import win32security
import win32api
import win32con

# Define BASE_DIR for Windows
BASE_DIR = os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), "FIMoniSec\\Windows-Client")
# Define AUTH_FILE with Windows path format
AUTH_FILE = os.path.join(BASE_DIR, "auth_token.json")

def load_psks():
    """Load the PSK from auth_token.json and return it as bytes."""
    if not os.path.exists(AUTH_FILE):
        # Try to find the file if not in the expected location (for development environments)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(script_dir, "auth_token.json")
        
        if os.path.exists(alt_path):
            auth_file_path = alt_path
        else:
            raise FileNotFoundError(f"[ERROR] auth_token.json not found at either {AUTH_FILE} or {alt_path}.")
    else:
        auth_file_path = AUTH_FILE
    
    try:
        with open(auth_file_path, "r") as f:
            data = json.load(f)
            raw_psk = data["psk"]
            if len(raw_psk) != 64:
                raise ValueError("[ERROR] PSK format invalid. Expected 64-character hex string.")
            try:
                psk = bytes.fromhex(raw_psk)
                logging.info(f"[INFO] Loaded PSK from {auth_file_path}")
                return psk
            except ValueError as e:
                logging.error(f"[ERROR] Failed to convert PSK to bytes: {e}")
                raise ValueError("[ERROR] Invalid PSK format. Must be a valid hex string.")
    except PermissionError as e:
        logging.error(f"[ERROR] Permission denied when accessing {auth_file_path}: {e}")
        raise PermissionError(f"[ERROR] No permission to read {auth_file_path}. Run as administrator or check file permissions.")
    except json.JSONDecodeError as e:
        logging.error(f"[ERROR] JSON parsing error in {auth_file_path}: {e}")
        raise ValueError(f"[ERROR] auth_token.json contains invalid JSON: {e}")

def encrypt_data(plaintext):
    """Encrypts authentication request or logs before sending to the server."""
    try:
        psk = load_psks()
        aesgcm = AESGCM(psk)
        # Generate a fresh nonce for every message
        nonce = os.urandom(12)
        
        # Ensure plaintext is bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext
            
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        encrypted_data = nonce + ciphertext
        
        return encrypted_data
    
    except Exception as e:
        logging.error(f"Error encrypting data: {e}")
        if isinstance(plaintext, str) and len(plaintext) > 0:
            # Log a sample of the plaintext that failed to encrypt
            sample_length = min(100, len(plaintext))
            logging.error(f"Plaintext sample: {plaintext[:sample_length]}")
        raise

def decrypt_data(encrypted_data):
    """Decrypt received data."""
    if len(encrypted_data) < 13:
        raise ValueError("[ERROR] Encrypted data is too short to contain nonce and ciphertext.")
    
    try:
        psk = load_psks()
        aesgcm = AESGCM(psk)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        try:
            decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
            return json.loads(decrypted_text)
        except Exception as e:
            logging.error(f"[ERROR] AES-GCM decryption failed: {e}")
            # Additional error information for Windows-specific issues
            if "Windows error" in str(e):
                logging.error(f"[ERROR] Windows-specific crypto error: {e}")
            return None
    except PermissionError as e:
        logging.error(f"[ERROR] Permission error accessing crypto materials: {e}")
        return None
    except Exception as e:
        logging.error(f"[ERROR] Unexpected error during decryption: {e}")
        return None

def check_auth_file_permissions():
    """
    Check and fix permissions on the auth_token.json file for Windows.
    Returns True if permissions are correct or were fixed, False otherwise.
    """
    if not os.path.exists(AUTH_FILE):
        logging.warning(f"[WARNING] Cannot check permissions: {AUTH_FILE} does not exist")
        return False
    
    try:
        # Get current security descriptor
        sd = win32security.GetFileSecurity(
            AUTH_FILE, 
            win32security.DACL_SECURITY_INFORMATION
        )
        
        # Create a new DACL (Discretionary Access Control List)
        dacl = win32security.ACL()
        
        # Add ACEs (Access Control Entries) for Administrators and SYSTEM
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        
        # Grant full control to Administrators and SYSTEM
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, admin_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.FILE_ALL_ACCESS, system_sid)
        
        # Set the new DACL
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(
            AUTH_FILE, 
            win32security.DACL_SECURITY_INFORMATION, 
            sd
        )
        
        logging.info(f"[INFO] Set secure permissions on {AUTH_FILE}")
        return True
    
    except Exception as e:
        logging.error(f"[ERROR] Failed to set secure permissions on {AUTH_FILE}: {e}")
        return False

# Run permission check when module is imported
if __name__ != "__main__":
    try:
        check_auth_file_permissions()
    except Exception as e:
        logging.error(f"[ERROR] Exception during permission check: {e}")

# Main function for testing
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    # Test encryption/decryption
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        try:
            # Test data
            test_data = {"key": "value", "message": "This is a test"}
            test_json = json.dumps(test_data)
            
            # Encrypt
            logging.info("[TEST] Encrypting test data...")
            encrypted = encrypt_data(test_json)
            logging.info(f"[TEST] Encrypted data length: {len(encrypted)} bytes")
            
            # Decrypt
            logging.info("[TEST] Decrypting test data...")
            decrypted = decrypt_data(encrypted)
            
            # Verify
            if decrypted == test_data:
                logging.info("[TEST] Encryption/decryption test PASSED")
            else:
                logging.error("[TEST] Encryption/decryption test FAILED - data mismatch")
        
        except Exception as e:
            logging.error(f"[TEST] Encryption/decryption test FAILED with error: {e}")
    
    elif len(sys.argv) > 1 and sys.argv[1] == "check-permissions":
        check_auth_file_permissions()
