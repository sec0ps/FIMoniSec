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
# Purpose: This script is part of the DumpSec-Py tool, which is designed to
#          perform detailed security audits on Windows systems. It covers
#          user rights, services, registry permissions, file/share permissions,
#          group policy enumeration, risk assessments, and more.
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

def load_psk(client_name):
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
                psk = bytes.fromhex(raw_psk)
                logging.info(f"[INFO] Loaded PSK for {client_name}: {raw_psk}")
                return psk

    raise ValueError(f"[ERROR] No PSK found for client: {client_name}")

def decrypt_data(client_name, encrypted_data):
    """Decrypt received log data."""
    try:
        psk = load_psk(client_name)
    except ValueError:
        raise ValueError(f"[ERROR] No PSK found for client: {client_name}")

    aesgcm = AESGCM(psk)

    try:
        if len(encrypted_data) < 12:
            raise ValueError(f"[ERROR] Data too short to contain nonce ({len(encrypted_data)} bytes)")
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        return json.loads(decrypted_text)
    except Exception as e:
        raise ValueError(f"[ERROR] Decryption failed: {e}")
        
def decrypt_data_with_psk(psk, encrypted_data):
    """Decrypt received log data using the provided PSK."""
    aesgcm = AESGCM(psk)
    
    try:
        logging.debug(f"Decrypting data of length: {len(encrypted_data)} bytes")
        
        if len(encrypted_data) < 12:
            logging.error(f"Encrypted data too short ({len(encrypted_data)} bytes)")
            return {"logs": []}
            
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        try:
            decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
            logging.debug(f"Successfully decrypted {len(decrypted_text)} bytes of text")
        except Exception as e:
            logging.error(f"AES-GCM decryption failed: {str(e)}")
            return {"logs": []}
        
        try:
            result = json.loads(decrypted_text)
            return result
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error: {e}")
            logging.error(f"Decrypted text sample: {decrypted_text[:100]}")
            return {"logs": []}
            
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        return {"logs": []}
