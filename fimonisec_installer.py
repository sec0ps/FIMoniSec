
#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
from datetime import datetime

REPO_URL = "https://github.com/sec0ps/FIMoniSec.git"
INSTALL_DIR = "/opt/FIMoniSec"
FIM_USER = "fimonisec"
FIM_GROUP = "fimonisec"

def error_exit(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def status(msg):
    print(f"[INFO] {msg}")

def run_cmd(cmd, check=True):
    try:
        subprocess.run(cmd, shell=True, check=check)
    except subprocess.CalledProcessError:
        error_exit(f"Command failed: {cmd}")

def check_root():
    if os.geteuid() != 0:
        error_exit("This script must be run as root. Use sudo.")

def get_current_user():
    return os.getenv("SUDO_USER") or os.getenv("USER")

def install_git():
    if shutil.which("git") is None:
        status("Installing Git...")
        run_cmd("apt-get update -qq && apt-get install -y git -qq")

def create_user_group():
    status("Creating fimonisec user and group...")
    if subprocess.run(f"getent group {FIM_GROUP}", shell=True).returncode != 0:
        run_cmd(f"groupadd {FIM_GROUP}")
    if subprocess.run(f"id -u {FIM_USER}", shell=True).returncode != 0:
        run_cmd(f"useradd -m -d {INSTALL_DIR} -g {FIM_GROUP} -s /bin/bash {FIM_USER}")

def clone_or_update_repo():
    install_git()
    if os.path.isdir(os.path.join(INSTALL_DIR, ".git")):
        status("Existing Git repo detected. Pulling latest changes...")
        run_cmd(f"cd {INSTALL_DIR} && git pull")
    else:
        if os.path.isdir(INSTALL_DIR):
            backup = f"{INSTALL_DIR}.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            status(f"Backing up existing directory to {backup}")
            shutil.move(INSTALL_DIR, backup)
        status("Cloning repository...")
        run_cmd(f"git clone {REPO_URL} {INSTALL_DIR}")

def set_permissions():
    status("Setting permissions...")
    run_cmd(f"chown -R {FIM_USER}:{FIM_GROUP} {INSTALL_DIR}")
    run_cmd(f"chmod -R 750 {INSTALL_DIR}")

def install_dependencies():
    status("Installing Python dependencies...")
    run_cmd("apt-get update -qq && apt-get install -y python3-pip yara -qq")
    run_cmd(f"su - {FIM_USER} -c 'cd {INSTALL_DIR} && pip install -r requirements.txt'")

def create_systemd_service():
    service_file = "/etc/systemd/system/fimonisec-client.service"
    status("Creating systemd service for client...")
    service_content = f"""[Unit]
Description=FIMoniSec Client Service
After=network.target

[Service]
Type=simple
User={FIM_USER}
Group={FIM_GROUP}
WorkingDirectory={INSTALL_DIR}
ExecStart=/usr/bin/python3 {INSTALL_DIR}/Linux-Client/monisec_client.py -d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""
    with open(service_file, "w") as f:
        f.write(service_content)
    run_cmd("systemctl daemon-reload && systemctl enable fimonisec-client")

def uninstall():
    status("Stopping and removing services...")
    run_cmd("systemctl stop fimonisec-client || true")
    run_cmd("systemctl disable fimonisec-client || true")
    run_cmd("rm -f /etc/systemd/system/fimonisec-client.service")
    run_cmd("systemctl daemon-reload")
    status("Removing files...")
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    status("Removing user and group...")
    run_cmd(f"userdel -r {FIM_USER} || true")
    run_cmd(f"groupdel {FIM_GROUP} || true")
    status("Uninstallation complete.")

def main():
    check_root()
    user = get_current_user()
    status(f"Running as {user}")

    print("Choose an action:")
    print("1) Install FIMoniSec")
    print("2) Remove FIMoniSec")
    choice = input("Enter choice (1-2): ").strip()

    if choice == "1":
        clone_or_update_repo()
        create_user_group()
        set_permissions()
        install_dependencies()
        create_systemd_service()
        status("Installation complete. Start service with: systemctl start fimonisec-client")
    elif choice == "2":
        confirm = input("Are you sure you want to remove FIMoniSec? (y/n): ").strip().lower()
        if confirm == "y":
            uninstall()
        else:
            status("Uninstallation cancelled.")
    else:
        error_exit("Invalid choice.")

if __name__ == "__main__":
    main()
``
