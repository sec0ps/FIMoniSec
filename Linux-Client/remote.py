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
import socket
import threading
import logging
import sys
import json
import os
import hmac
import hashlib
import time
from client_crypt import encrypt_data
from monisec_client import start_process, stop_process, restart_process, is_process_running, PROCESSES

CLIENT_HOST = "0.0.0.0"  # Listen on all interfaces
CLIENT_PORT = 6000       # Port for receiving commands
AUTH_TOKEN_FILE = "auth_token.json"
LOG_FILES = ["./logs/monisec-endpoint.log", "./logs/file_monitor.json"]
LOG_FILE = "./logs/file_monitor.json"

def start_client_listener():
    """Starts a TCP server to receive and execute remote commands from monisec-server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((CLIENT_HOST, CLIENT_PORT))
    server_socket.listen(5)
    logging.info(f"MoniSec client listening for commands on {CLIENT_HOST}:{CLIENT_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Received connection from {addr}")
        client_thread = threading.Thread(target=handle_server_commands, args=(client_socket,))
        client_thread.start()

def handle_server_commands(client_socket):
    """Handles incoming commands from monisec-server and executes only allowed actions."""
    try:
        data = client_socket.recv(1024).decode("utf-8")
        if not data:
            return

        if data.startswith("EXECUTE:"):
            command_parts = data.split(":", 1)[1].strip().split()

            if len(command_parts) != 2:
                logging.warning(f"Invalid command format received: {data}")
                client_socket.sendall(b"ERROR: Invalid command format")
                return

            target, action = command_parts
            if target in PROCESSES and action in ["start", "stop", "restart"]:
                logging.info(f"Executing {action} on {target}")

                if action == "restart":
                    restart_process(target)
                elif action == "start":
                    start_process(target)
                elif action == "stop":
                    stop_process(target)

                client_socket.sendall(b"SUCCESS: Command executed")
            else:
                logging.warning(f"Unauthorized command received: {target} {action}")
                client_socket.sendall(b"ERROR: Unauthorized command")

    except Exception as e:
        logging.error(f"Error handling server command: {e}")
    finally:
        client_socket.close()

def import_psk():
    """Prompts user to enter the Server IP, Client Name, and PSK for authentication and stores them."""
    server_ip = input("Enter Server IP Address: ").strip()
    client_name = input("Enter Client Name: ").strip()
    psk_value = input("Enter PSK: ").strip()

    if not server_ip or not client_name or not psk_value:
        print("[ERROR] Server IP, Client Name, and PSK cannot be empty.")
        return

    token_data = {
        "server_ip": server_ip,
        "client_name": client_name,
        "psk": psk_value
    }

    with open("auth_token.json", "w") as f:
        json.dump(token_data, f, indent=4)
    os.chmod("auth_token.json", 0o600)

    print("[INFO] PSK imported and stored securely.")
    
def authenticate_with_server():
    """Authenticates with the MoniSec server using stored IP and PSK from auth_token.json."""

    token_file = "auth_token.json"

    # Load stored authentication data
    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
            server_ip = token_data.get("server_ip")
            client_name = token_data.get("client_name")

            if not server_ip or not client_name:
                raise ValueError("Missing Server IP or Client Name in auth_token.json.")

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to load authentication data: {e}")
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server_ip, 5555))

        # ✅ Send the initial JSON handshake with client_name
        handshake = json.dumps({ "client_name": client_name })
        sock.sendall(handshake.encode("utf-8"))

        logging.info("Handshake sent to server.")
        sock.close()
        return True

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

def connect_to_server(server_ip, client_name, psk):
    """Establishes a new connection to the MoniSec server and authenticates."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # Enable TCP Keep-Alive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        sock.connect((server_ip, 5555))

        nonce = os.urandom(16).hex()
        client_hmac = hmac.new(psk.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        sock.sendall(f"{client_name}:{nonce}:{client_hmac}".encode("utf-8"))

        response = sock.recv(1024).decode("utf-8")

        if response != "AUTH_SUCCESS":
            logging.error(f"Authentication failed. Server response: {response}")
            sock.close()
            return None

        logging.info("Authentication successful. Monitoring logs...")
        return sock

    except (socket.timeout, socket.error, BrokenPipeError) as e:
        logging.error(f"Connection to server failed: {e}. Retrying...")
        return None

def send_logs_to_server():
    RETRIES = 5
    DELAY = 3  # seconds between retries

    try:
        with open(AUTH_TOKEN_FILE, "r") as f:
            token_data = json.load(f)
            server_ip = token_data["server_ip"]
            client_name = token_data["client_name"]
            psk = token_data["psk"]  # Not used directly; client_crypt loads it

        sock = None
        for attempt in range(RETRIES):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((server_ip, 5555))

                # Send cleartext client_name as JSON handshake
                handshake = json.dumps({"client_name": client_name})
                sock.sendall(handshake.encode("utf-8"))

                logging.info(f"[INFO] Connected to server and sent handshake. Attempt {attempt + 1}")
                break
            except Exception as e:
                logging.error(f"[ERROR] Connection attempt {attempt + 1} failed: {e}")
                time.sleep(DELAY)
        else:
            logging.critical("[CRITICAL] Could not connect to server after multiple attempts.")
            return

        file_positions = {}
        for log_file in LOG_FILES:
            file_positions[log_file] = os.path.getsize(log_file) if os.path.exists(log_file) else 0

        while True:
            logs_to_send = []

            for log_file in LOG_FILES:
                if os.path.exists(log_file):
                    with open(log_file, "r") as f:
                        f.seek(file_positions[log_file])
                        new_logs = f.read().strip()
                        file_positions[log_file] = f.tell()

                    if new_logs:
                        entries = extract_valid_json_objects(new_logs)
                        for entry in entries:
                            if isinstance(entry, dict):
                                entry["client_name"] = client_name
                                logs_to_send.append(entry)

            if logs_to_send:
                try:
                    message = json.dumps({"logs": logs_to_send})
                    encrypted = encrypt_data(message)
                    sock.sendall(encrypted)
                    ack = sock.recv(1024)
                    if ack != b"ACK":
                        logging.warning("No ACK received from server.")
                except Exception as e:
                    logging.error(f"[SEND ERROR] {e}")
                    break

            time.sleep(2)

    except Exception as e:
        logging.error(f"[CLIENT ERROR] {e}")
    finally:
        if sock:
            sock.close()

def extract_valid_json_objects(buffer):
    logs = []
    buffer = buffer.strip()
    while buffer:
        try:
            obj, idx = json.JSONDecoder().raw_decode(buffer)
            logs.append(obj)
            buffer = buffer[idx:].strip()
        except json.JSONDecodeError:
            break
    return logs
    
def check_auth_and_send_logs():
    """Checks if auth_token.json exists and starts log transmission if valid."""
    if os.path.exists(AUTH_TOKEN_FILE):
        try:
            with open(AUTH_TOKEN_FILE, "r") as f:
                token_data = json.load(f)
                server_ip = token_data.get("server_ip")
                client_name = token_data.get("client_name")
                psk = token_data.get("psk")

            if server_ip and client_name and psk:
                logging.info("[INFO] Authentication token found. Connecting to server...")

                # Authenticate with server and proceed if successful
                success = authenticate_with_server()
                if success:
                    logging.info("[INFO] Authentication successful. Starting real-time log transmission...")
                    log_thread = threading.Thread(target=send_logs_to_server, daemon=True)
                    log_thread.start()
                else:
                    logging.warning("[WARNING] Authentication failed. Logging locally only.")
            else:
                logging.warning("[WARNING] auth_token.json is incomplete. Logging locally only.")
        except (json.JSONDecodeError, FileNotFoundError, ValueError) as e:
            logging.error(f"[ERROR] Failed to parse auth_token.json: {e}")
    else:
        logging.info("[INFO] No authentication token found. Logging locally only.")
