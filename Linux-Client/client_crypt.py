import json
import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AUTH_FILE = "auth_token.json"

def load_psk():
    """Load the PSK from auth_token.json and return it as bytes."""
    if not os.path.exists(AUTH_FILE):
        raise FileNotFoundError("[ERROR] auth_token.json not found.")

    with open(AUTH_FILE, "r") as f:
        data = json.load(f)
        raw_psk = data["psk"]

        if len(raw_psk) != 64:
            raise ValueError("[ERROR] PSK format invalid. Expected 64-character hex string.")

        psk = bytes.fromhex(raw_psk)
        logging.info(f"[INFO] Loaded PSK from auth_token.json: {raw_psk}")
        return psk

def encrypt_data(plaintext):
    """Encrypts authentication request or logs before sending to the server."""
    psk = load_psk()
    aesgcm = AESGCM(psk)

    nonce = os.urandom(12)  # ✅ Generate a 12-byte nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)  # ✅ Ensure plaintext is encoded
    return nonce + ciphertext  # ✅ Prepend nonce to encrypted data

def decrypt_data(encrypted_data):
    """Decrypt received data."""
    if len(encrypted_data) < 13:
        raise ValueError("[ERROR] Encrypted data is too short to contain nonce and ciphertext.")

    psk = load_psk()
    aesgcm = AESGCM(psk)

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    try:
        decrypted_text = aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        return json.loads(decrypted_text)
    except Exception as e:
        logging.error(f"[ERROR] AES-GCM decryption failed: {e}")
        return None
