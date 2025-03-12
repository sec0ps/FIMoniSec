import os
import json
import hmac
import hashlib
import logging

PSK_STORE_FILE = "psk_store.json"
ENDPOINT_LOG_FILE = "./logs/endpoint-integrity-logs.json"

def load_psks():
    """Load stored PSKs from a JSON file as a structured list."""
    if not os.path.exists(PSK_STORE_FILE):
        return {}

    try:
        with open(PSK_STORE_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_psks(psks):
    """Save PSK store as a structured list."""
    with open(PSK_STORE_FILE, "w") as f:
        json.dump(psks, f, indent=4)

# Generate a new PSK
def generate_psk():
    """Generate a random 32-byte PSK."""
    return os.urandom(32).hex()

def get_next_agent_id(psks):
    """Find the next available Agent ID."""
    if not psks:
        return 0
    return max(int(agent["AgentID"]) for agent in psks.values()) + 1

def add_client():
    """Prompts user for Agent Name and IP, assigns a unique Agent ID, and stores it in JSON."""
    psks = load_psks()

    # Prompt the user for input
    agent_name = input("Enter Agent Name: ").strip()
    if not agent_name:
        print("[ERROR] Agent name cannot be empty.")
        return

    # Ensure unique agent name
    for agent in psks.values():
        if agent["AgentName"] == agent_name:
            print(f"[ERROR] Agent '{agent_name}' already exists.")
            return

    agent_ip = input("Enter Agent IP Address: ").strip()
    if not agent_ip:
        print("[ERROR] Agent IP cannot be empty.")
        return

    # Assign next available Agent ID
    agent_id = get_next_agent_id(psks)
    new_psk = generate_psk()

    # Store the new agent information
    psks[str(agent_id)] = {
        "AgentID": str(agent_id),
        "AgentName": agent_name,
        "AgentPSK": new_psk,
        "AgentIP": agent_ip
    }

    save_psks(psks)
    print(f"[INFO] Agent '{agent_name}' added with Agent ID {agent_id}. IP: {agent_ip}, PSK: {new_psk}")

def remove_client(agent_id):
    """Removes a client from the PSK store using Agent ID."""
    psks = load_psks()

    if str(agent_id) in psks:
        removed_agent = psks.pop(str(agent_id))
        save_psks(psks)
        print(f"[INFO] Agent '{removed_agent['AgentName']}' (ID: {agent_id}, IP: {removed_agent['AgentIP']}) removed.")
        return True

    print(f"[ERROR] Agent ID {agent_id} not found.")
    return False

def list_clients():
    """Lists all registered clients with their Agent IDs, Names, and IPs."""
    psks = load_psks()
    if not psks:
        print("[INFO] No clients registered.")
        return

    print("[INFO] Registered Agents:")
    for agent_id, details in psks.items():
        print(f"  - Agent ID: {details['AgentID']}, Name: {details['AgentName']}, IP: {details['AgentIP']}")

def authenticate_client(client_socket):
    """Authenticates a client using stored PSK and IP."""
    try:
        # Receive authentication data from client
        auth_data = client_socket.recv(1024).decode("utf-8")

        if not auth_data:
            logging.warning("[ERROR] No authentication data received.")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Extract authentication parameters sent by the client
        try:
            client_name, nonce, client_hmac = auth_data.split(":")
        except ValueError:
            logging.warning(f"[ERROR] Malformed authentication data received: {auth_data}")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Load stored PSKs
        psks = load_psks()
        logging.debug(f"[DEBUG] Loaded PSKs: {json.dumps(psks, indent=4)}")  # Debugging

        # Check if client name exists in PSKs
        matching_agent = None
        for agent_id, agent_data in psks.items():
            if agent_data["AgentName"] == client_name:
                matching_agent = agent_data
                break

        if not matching_agent:
            logging.warning(f"[ERROR] Unknown client: {client_name}")
            client_socket.sendall(b"AUTH_FAILED")
            return None

        # Retrieve stored PSK for the client
        client_psk = matching_agent["AgentPSK"]
        logging.debug(f"[DEBUG] Retrieved PSK for {client_name}: {client_psk[:6]}********")  # Masked for security

        # Compute expected HMAC
        expected_hmac = hmac.new(client_psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()

        # Validate authentication
        if hmac.compare_digest(client_hmac, expected_hmac):
            client_socket.sendall(b"AUTH_SUCCESS")
            logging.info(f"[SUCCESS] Client {client_name} authenticated successfully.")
            return client_name
        else:
            logging.warning(f"[ERROR] Authentication failed for {client_name}")
            client_socket.sendall(b"AUTH_FAILED")
            return None

    except Exception as e:
        logging.error(f"[ERROR] Authentication error: {e}")
        client_socket.sendall(b"AUTH_FAILED")
        return None

def handle_client(client_socket, client_address):
    """Handles authentication and logs reception from an authenticated client."""
    logging.info(f"New connection from {client_address}")

    authenticated_client = authenticate_client(client_socket)
    if not authenticated_client:
        logging.warning(f"Authentication failed for client {client_address}")
        client_socket.close()
        return

    logging.info(f"Client {authenticated_client} authenticated successfully. Awaiting logs...")

    try:
        while True:
            data = client_socket.recv(4096).decode("utf-8")  # Increase buffer size
            if not data:
                break  # Disconnect if client stops sending

            try:
                log_entry = json.loads(data)
                append_log(log_entry)
                logging.info(f"[DEBUG] Received log from {authenticated_client}: {log_entry}")
            except json.JSONDecodeError:
                logging.warning(f"Received malformed log data from {authenticated_client}: {data}")

    except Exception as e:
        logging.error(f"Error with client {authenticated_client}: {e}")
    finally:
        logging.info(f"Client {authenticated_client} disconnected.")
        client_socket.close()

def append_log(log_entry):
    """Appends incoming logs to the endpoint-integrity-logs.json file."""
    try:
        with open(ENDPOINT_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        logging.info(f"[DEBUG] Log appended: {log_entry}")
    except Exception as e:
        logging.error(f"[ERROR] Failed to write log: {e}")

# Function to send commands to clients
def send_command(client_ip, command):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((client_ip, PORT))
        client_socket.sendall(f"COMMAND:{command}".encode("utf-8"))
        response = client_socket.recv(1024).decode("utf-8")
        logging.info(f"Client {client_ip} response: {response}")
        client_socket.close()
    except Exception as e:
        logging.error(f"Error sending command to {client_ip}: {e}")
