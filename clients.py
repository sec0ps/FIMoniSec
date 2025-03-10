import json
import os
import hashlib

PSK_STORE_FILE = "psk_store.json"

def load_psks():
    """Load existing PSKs from the file."""
    if os.path.exists(PSK_STORE_FILE):
        with open(PSK_STORE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_psks(psks):
    """Save the PSKs back to the file."""
    with open(PSK_STORE_FILE, "w") as f:
        json.dump(psks, f, indent=4)

def generate_psk():
    """Generate a new PSK and return its hashed version."""
    return hashlib.sha256(os.urandom(32)).hexdigest()

def add_client(client_name):
    """Add a new client with a generated PSK."""
    psks = load_psks()
    if client_name in psks:
        print(f"Client {client_name} already exists.")
        return

    new_psk = generate_psk()
    psks[client_name] = new_psk
    save_psks(psks)
    print(f"Client {client_name} added successfully. PSK: {new_psk}")

def remove_client(client_name):
    """Remove a client from the PSK store."""
    psks = load_psks()
    if client_name in psks:
        del psks[client_name]
        save_psks(psks)
        print(f"Client {client_name} removed successfully.")
    else:
        print(f"Client {client_name} not found.")

def list_clients():
    """List all registered clients and their PSKs."""
    psks = load_psks()
    if psks:
        print("Registered Clients:")
        for client, psk in psks.items():
            print(f" - {client}: {psk}")
    else:
        print("No clients registered.")
