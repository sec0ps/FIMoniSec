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
#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
from datetime import datetime

REPO_URL = "https://github.com/sec0ps/FIMoniSec.git"
INSTALL_DIR = "/opt/FIMoniSec"
FIM_USER = "fimonisec"
FIM_GROUP = "fimonisec"
PROFILE_SCRIPT = "/etc/profile.d/fimonisec_path.sh"
SUDOERS_D_FILE = "/etc/sudoers.d/fimonisec"
SUDO_CMDS = "/usr/bin/lsof, /bin/cat, /bin/ps, /bin/netstat, /bin/ss, /usr/bin/readlink, /usr/bin/head, /usr/bin/tail, /usr/bin/find, /usr/bin/grep, /usr/bin/nice, /usr/bin/renice, /usr/bin/kill, /usr/bin/pkill, /usr/bin/pgrep, /bin/mkdir, /usr/bin/touch, /usr/bin/ulimit, /bin/systemctl, /usr/bin/python3"

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
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    if not user:
        error_exit("Could not determine current user.")
    return user

def create_user_group(current_user):
    status("Creating fimonisec user and group...")
    if subprocess.run(f"getent group {FIM_GROUP}", shell=True).returncode != 0:
        run_cmd(f"groupadd {FIM_GROUP}")
    else:
        status("Group fimonisec already exists.")
    if subprocess.run(f"id -u {FIM_USER}", shell=True).returncode != 0:
        run_cmd(f"useradd -m -d {INSTALL_DIR} -g {FIM_GROUP} -s /bin/bash {FIM_USER}")
    else:
        status("User fimonisec already exists.")
    run_cmd(f"usermod -a -G {FIM_GROUP} {current_user}")
    status(f"User {current_user} added to fimonisec group.")

def clone_or_update_repo():
    if shutil.which("git") is None:
        status("Installing Git...")
        run_cmd("apt-get update -qq && apt-get install -y git -qq")

    if os.path.isdir(os.path.join(INSTALL_DIR, ".git")):
        # Existing Git repo → update
        status("Existing Git repo detected. Pulling latest changes...")
        run_cmd(f"su - {FIM_USER} -c 'cd {INSTALL_DIR} && git reset --hard && git pull'")
    else:
        if os.path.exists(INSTALL_DIR) and os.listdir(INSTALL_DIR):
            # Directory exists but not a Git repo → backup
            backup = f"{INSTALL_DIR}.backup.{datetime.now().strftime('%Y%m%d%H%M%S')}"
            status(f"Backing up existing directory to {backup}")
            shutil.move(INSTALL_DIR, backup)

        # Fresh clone
        status("Cloning repository...")
        run_cmd(f"su - {FIM_USER} -c 'git clone {REPO_URL} {INSTALL_DIR}'")

def configure_git_settings():
    status("Configuring Git settings to ignore file mode changes...")
    run_cmd(f"su - {FIM_USER} -c 'cd {INSTALL_DIR} && git config core.fileMode false'")

def set_permissions():
    status("Setting permissions...")
    run_cmd(f"chown -R {FIM_USER}:{FIM_GROUP} {INSTALL_DIR}")
    run_cmd(f"chmod -R 750 {INSTALL_DIR}")

def install_python_dependencies():
    status("Installing Python dependencies via apt-get...")
    run_cmd("apt-get update -qq")
    packages = [
        "python3-daemon",
        "python3-pyinotify",
        "python3-numpy",
        "python3-pandas",
        "python3-sklearn",
        "python3-psutil",
        "python3-websockets",
        "python3-joblib"
    ]
    run_cmd(f"apt-get install -y {' '.join(packages)} -qq")
    status("All Python dependencies installed successfully.")

def update_path(current_user):
    status("Updating PATH for users...")
    fim_bashrc = os.path.join(INSTALL_DIR, ".bashrc")
    with open(fim_bashrc, "a") as f:
        f.write('export PATH="$HOME/.local/bin:$PATH"\n')
    user_home = os.path.expanduser(f"~{current_user}")
    user_bashrc = os.path.join(user_home, ".bashrc")
    with open(user_bashrc, "a") as f:
        f.write('export PATH="$HOME/.local/bin:$PATH"\n')
    with open(PROFILE_SCRIPT, "w") as f:
        f.write(f'export PATH="/opt/FIMoniSec/.local/bin:$PATH"\n')
        f.write(f'export PATH="/home/{current_user}/.local/bin:$PATH"\n')
    run_cmd(f"chmod +x {PROFILE_SCRIPT}")

def update_sudoers(current_user):
    status("Updating sudoers using /etc/sudoers.d/fimonisec...")
    try:
        with open(SUDOERS_D_FILE, "w") as f:
            f.write(f"{current_user} ALL=(ALL) NOPASSWD: {SUDO_CMDS}\n")
            f.write(f"{FIM_USER} ALL=(ALL) NOPASSWD: {SUDO_CMDS}\n")
        run_cmd(f"chmod 440 {SUDOERS_D_FILE}")
        run_cmd("chmod 440 /etc/sudoers")  # Fix main sudoers permissions
        run_cmd(f"visudo -cf {SUDOERS_D_FILE}")
    except Exception as e:
        error_exit(f"Failed to update sudoers: {e}")

def detect_init_system():
    if shutil.which("systemctl"):
        return "systemd"
    elif shutil.which("service") and os.path.isdir("/etc/init.d"):
        return "sysvinit"
    elif shutil.which("initctl"):
        return "upstart"
    else:
        error_exit("Could not determine init system.")

def create_services(install_type, init_system):
    status(f"Creating services for {install_type} using {init_system}...")
    if init_system == "systemd":
        client_service = f"""
[Unit]
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
        with open("/etc/systemd/system/fimonisec-client.service", "w") as f:
            f.write(client_service)
        run_cmd("systemctl daemon-reload && systemctl enable fimonisec-client")
        if install_type == "server":
            server_service = f"""
[Unit]
Description=FIMoniSec Server Service
After=network.target
[Service]
Type=simple
User={FIM_USER}
Group={FIM_GROUP}
WorkingDirectory={INSTALL_DIR}
ExecStart=/usr/bin/python3 {INSTALL_DIR}/Monisec-Server/monisec-server.py -d
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
"""
            with open("/etc/systemd/system/fimonisec-server.service", "w") as f:
                f.write(server_service)
            run_cmd("systemctl daemon-reload && systemctl enable fimonisec-server")

def uninstall():
    status("Stopping and removing services...")
    run_cmd("systemctl stop fimonisec-client || true")
    run_cmd("systemctl disable fimonisec-client || true")
    run_cmd("rm -f /etc/systemd/system/fimonisec-client.service")
    run_cmd("systemctl stop fimonisec-server || true")
    run_cmd("systemctl disable fimonisec-server || true")
    run_cmd("rm -f /etc/systemd/system/fimonisec-server.service")
    run_cmd("systemctl daemon-reload")

    status("Removing files...")
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)

    status("Removing profile script...")
    if os.path.exists(PROFILE_SCRIPT):
        os.remove(PROFILE_SCRIPT)

    status("Cleaning sudoers...")
    run_cmd("chmod 440 /etc/sudoers")
    if os.path.exists(SUDOERS_D_FILE):
        os.remove(SUDOERS_D_FILE)
    run_cmd("visudo -c")

    status("Removing user and group...")
    run_cmd(f"userdel -r {FIM_USER} || true")
    run_cmd(f"groupdel {FIM_GROUP} || true")

    status("Uninstallation complete.")

def main():
    check_root()
    current_user = get_current_user()
    status(f"Running as {current_user}")

    print("Choose an action:")
    print("1) Install FIMoniSec")
    print("2) Remove FIMoniSec")
    choice = input("Enter choice (1-2): ").strip()

    if choice == "1":
        print("Select installation type:")
        print("1) Linux Client")
        print("2) Server")
        type_choice = input("Enter choice (1-2): ").strip()
        install_type = "linux_client" if type_choice == "1" else "server"

        create_user_group(current_user)
        clone_or_update_repo()
        configure_git_settings()
        set_permissions()
        install_python_dependencies()
        update_path(current_user)
        update_sudoers(current_user)
        init_system = detect_init_system()
        create_services(install_type, init_system)

        status("Installation complete!")
        start_now = input("Do you want to start the client service now? (y/n): ").strip().lower()
        if start_now == "y":
            run_cmd("systemctl start fimonisec-client")
        if install_type == "server":
            start_server = input("Do you want to start the server service now? (y/n): ").strip().lower()
            if start_server == "y":
                run_cmd("systemctl start fimonisec-server")

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
