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
                psk = bytes.fromhex(agent["AgentPSK"])
                logging.info(f"[INFO] Loaded PSK for {client_name}: {agent['AgentPSK']}")  # ✅ Debugging log
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
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")  # ✅ Decode string
        return json.loads(decrypted_text)  # ✅ Convert back to JSON
    except Exception as e:
        raise ValueError(f"[ERROR] Decryption failed: {e}")

def decrypt_data_with_psk(psk, encrypted_data):
    aesgcm = AESGCM(psk)
    try:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        print(f"[DEBUG] Raw decrypted log: {decrypted_text}")  # ADD THIS LINE
        return json.loads(decrypted_text)  # Ensure this is valid JSON
    except Exception as e:
        raise ValueError(f"[ERROR] Decryption failed: {e}")
