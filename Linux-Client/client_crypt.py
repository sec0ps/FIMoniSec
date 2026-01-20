# =============================================================================
# FIMonsec Tool - File Integrity Monitoring Security Solution
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
AUTH_FILE = "auth_token.json"

def load_psks():
    """Load the PSK from auth_token.json and return it as bytes."""
    if not os.path.exists(AUTH_FILE):
        raise FileNotFoundError("[ERROR] auth_token.json not found.")
    with open(AUTH_FILE, "r") as f:
        data = json.load(f)
        raw_psk = data["psk"]
        if len(raw_psk) != 64:
            raise ValueError("[ERROR] PSK format invalid. Expected 64-character hex string.")
        try:
            psk = bytes.fromhex(raw_psk)
            return psk
        except ValueError as e:
            logging.error(f"[ERROR] Failed to convert PSK to bytes: {e}")
            raise ValueError("[ERROR] Invalid PSK format. Must be a valid hex string.")

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
        if isinstance(plaintext, str):
            logging.error(f"Plaintext sample: {plaintext[:100]}")
        raise

def decrypt_data(encrypted_data):
    """Decrypt received data."""
    if len(encrypted_data) < 13:
        raise ValueError("[ERROR] Encrypted data is too short to contain nonce and ciphertext.")
    psk = load_psks()
    aesgcm = AESGCM(psk)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    try:
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        return json.loads(decrypted_text)
    except Exception as e:
        logging.error(f"[ERROR] AES-GCM decryption failed: {e}")
        return None
