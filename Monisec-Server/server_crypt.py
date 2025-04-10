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
import json
import logging
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PSK_FILE = "psk_store.json"

def load_psks(client_name):
    """Retrieve PSK for a client from psk_store.json and ensure it is in bytes."""
    if not os.path.exists(PSK_FILE):
        raise FileNotFoundError("[ERROR] psk_store.json not found.")
    with open(PSK_FILE, "r") as f:
        data = json.load(f)
        for agent in data.values():
            if agent["AgentName"] == client_name:
                raw_psk = agent["AgentPSK"]
                if len(raw_psk) != 64:
                    raise ValueError(f"[ERROR] Invalid PSK length for client '{client_name}'. Expected 64 hex chars.")
                try:
                    # Ensure PSK is properly converted to bytes
                    psk = bytes.fromhex(raw_psk)
                    logging.info(f"[INFO] Loaded PSK for {client_name}")
                    return psk
                except ValueError as e:
                    logging.error(f"[ERROR] Failed to convert PSK to bytes: {e}")
                    raise ValueError(f"[ERROR] Invalid PSK format for client '{client_name}'. Must be hex string.")
    raise ValueError(f"[ERROR] No PSK found for client: {client_name}")

def decrypt_data_with_psk(psk, encrypted_data):
    """Decrypt received log data using the provided PSK."""
    try:
        # Ensure we have a valid AESGCM cipher with the PSK
        aesgcm = AESGCM(psk)
        
        # Check if the encrypted data has the minimum required length
        if len(encrypted_data) < 12:
            logging.error(f"Encrypted data too short ({len(encrypted_data)} bytes)")
            return {"logs": []}
            
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        # Log what we're attempting to decrypt
        logging.info(f"Attempting to decrypt {len(ciphertext)} bytes with nonce {nonce.hex()[:8]}...")
        
        try:
            # Perform the decryption
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            decrypted_text = decrypted_bytes.decode("utf-8")
            
            # Log success
            logging.info(f"Successfully decrypted {len(decrypted_text)} bytes of data")
            
            try:
                # Parse as JSON
                parsed_data = json.loads(decrypted_text)
                
                # Ensure it has the expected structure
                if "logs" not in parsed_data:
                    logging.warning("Decrypted data doesn't contain 'logs' field")
                    parsed_data["logs"] = []
                
                return parsed_data
            except json.JSONDecodeError as e:
                logging.error(f"JSON parse error: {e}")
                logging.error(f"First 100 chars of decrypted text: {decrypted_text[:100]}")
                return {"logs": []}
                
        except Exception as e:
            # This is the critical error we're trying to fix
            logging.error(f"AES-GCM decryption failed: {e}")
            logging.error(f"Nonce: {nonce.hex()}, Ciphertext length: {len(ciphertext)}")
            return {"logs": []}
            
    except Exception as e:
        logging.error(f"General decryption error: {e}")
        import traceback
        logging.error(traceback.format_exc())
        return {"logs": []}

def encrypt_data(psk, plaintext):
    """
    Encrypt data using AES-GCM with the provided PSK.
    
    Args:
        psk (bytes): Pre-shared key
        plaintext (str): Data to encrypt
    
    Returns:
        bytes: Encrypted data (nonce + ciphertext)
    """
    try:
        aesgcm = AESGCM(psk)
        
        # Generate a fresh nonce for each message
        nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode("utf-8")
        
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
        encrypted_data = nonce + ciphertext
        
        return encrypted_data
    
    except Exception as e:
        logging.error(f"Error encrypting data: {e}")
        raise
