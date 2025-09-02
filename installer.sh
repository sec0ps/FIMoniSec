#!/bin/bash

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

# Function to display error messages
error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# Function to display status messages
status_message() {
    echo "[INFO] $1"
}

# Check if script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root. Please use sudo."
fi

# Get the current user who invoked sudo
CURRENT_USER=$(logname || echo $SUDO_USER)
if [ -z "$CURRENT_USER" ]; then
    error_exit "Could not determine the current user"
fi

status_message "Starting installation as user: $CURRENT_USER"

# Step 0: Determine installation or removal action
ACTION=""
while [ "$ACTION" != "install" ] && [ "$ACTION" != "remove" ]; do
    echo "What would you like to do?"
    echo "1) Install FIMoniSec"
    echo "2) Remove FIMoniSec"
    read -p "Enter your choice (1-2): " action_choice
    
    case $action_choice in
        1) ACTION="install" ;;
        2) ACTION="remove" ;;
        *) echo "Invalid choice. Please select 1 or 2." ;;
    esac
done

# If installing, determine installation type
INSTALL_TYPE=""
if [ "$ACTION" = "install" ]; then
    while [ "$INSTALL_TYPE" != "linux_client" ] && [ "$INSTALL_TYPE" != "windows_client" ] && [ "$INSTALL_TYPE" != "server" ]; do
        echo "What would you like to do?"
        echo "1) Install FIMoniSec Linux Client"
        echo "2) Install FIMoniSec Windows Client (Not Currently Available)"
        echo "3) Install FIMoniSec Server"
        read -p "Enter your choice (1-3): " choice
        
        case $choice in
            1) INSTALL_TYPE="linux_client" ;;
            2) 
                echo "Windows Client installation is not currently available."
                echo "Please choose another option."
                continue
                ;;
            3) INSTALL_TYPE="server" ;;
            *) echo "Invalid choice. Please select 1, 2 or 3." ;;
        esac
    done
    
    status_message "Performing $INSTALL_TYPE installation"
fi

# If removing, proceed with uninstallation
if [ "$ACTION" = "remove" ]; then
    status_message "Preparing to remove FIMoniSec..."
    
    # Function to perform uninstallation
    uninstall_fimonisec() {
        # Step 1: Stop services
        status_message "Stopping FIMoniSec services..."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop fimonisec-client 2>/dev/null
            systemctl stop fimonisec-server 2>/dev/null
            systemctl disable fimonisec-client 2>/dev/null
            systemctl disable fimonisec-server 2>/dev/null
            rm -f /etc/systemd/system/fimonisec-client.service 2>/dev/null
            rm -f /etc/systemd/system/fimonisec-server.service 2>/dev/null
            systemctl daemon-reload
        elif command -v service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
            service fimonisec-client stop 2>/dev/null
            service fimonisec-server stop 2>/dev/null
            update-rc.d fimonisec-client remove 2>/dev/null
            update-rc.d fimonisec-server remove 2>/dev/null
            rm -f /etc/init.d/fimonisec-client 2>/dev/null
            rm -f /etc/init.d/fimonisec-server 2>/dev/null
        elif command -v initctl >/dev/null 2>&1; then
            initctl stop fimonisec-client 2>/dev/null
            initctl stop fimonisec-server 2>/dev/null
            rm -f /etc/init/fimonisec-client.conf 2>/dev/null
            rm -f /etc/init/fimonisec-server.conf 2>/dev/null
        fi
        
        # Step 2: Remove FIMoniSec directory
        status_message "Removing FIMoniSec files..."
        rm -rf /opt/FIMoniSec 2>/dev/null
        
        # Step 3: Remove system-wide profile script
        status_message "Removing system profile script..."
        rm -f /etc/profile.d/fimonisec_path.sh 2>/dev/null
        
        # Step 4: Remove from sudoers file
        status_message "Cleaning up sudoers file..."
        # Create a temporary file
        TEMP_SUDOERS=$(mktemp)
        # Copy the sudoers file to the temporary file, excluding FIMoniSec lines
        grep -v "fimonisec.*NOPASSWD" /etc/sudoers > "$TEMP_SUDOERS"
        # Copy the temporary file back to sudoers
        cp "$TEMP_SUDOERS" /etc/sudoers
        # Validate the sudoers file
        visudo -c || error_exit "Failed to validate sudoers file after removal"
        # Remove the temporary file
        rm -f "$TEMP_SUDOERS"
        
        # Step 5: Remove fimonisec user and group
        status_message "Removing fimonisec user and group..."
        if id -u fimonisec > /dev/null 2>&1; then
            userdel -r fimonisec 2>/dev/null
        fi
        if getent group fimonisec > /dev/null; then
            groupdel fimonisec 2>/dev/null
        fi
        
        status_message "FIMoniSec has been successfully removed from your system."
        exit 0
    }
    
    # Ask for confirmation before uninstalling
    read -p "Are you sure you want to remove FIMoniSec from your system? (y/n): " confirm
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        uninstall_fimonisec
    else
        status_message "Uninstallation cancelled."
        exit 0
    fi
fi

# Step 1: Install git if not present
if [ "$ACTION" = "install" ]; then
    status_message "Checking for git installation..."
    if ! command -v git &> /dev/null; then
        status_message "Installing git..."
        apt-get update -qq > /dev/null 2>&1
        apt-get install -y git -qq > /dev/null 2>&1 || error_exit "Failed to install git"
    fi
    status_message "Git is available."
fi

# Step 2: Create fimonisec user and group
status_message "Creating fimonisec user and group..."
if getent group fimonisec > /dev/null; then
    status_message "Group fimonisec already exists"
else
    groupadd fimonisec || error_exit "Failed to create fimonisec group"
fi

if id -u fimonisec > /dev/null 2>&1; then
    status_message "User fimonisec already exists"
else
    useradd -m -d /opt/FIMoniSec -g fimonisec -s /bin/bash fimonisec || error_exit "Failed to create fimonisec user"
fi

# Add current user to fimonisec group
status_message "Adding current user to fimonisec group..."
usermod -a -G fimonisec $CURRENT_USER || error_exit "Failed to add current user to fimonisec group"
status_message "User $CURRENT_USER added to fimonisec group"

# Step 3: Clone or update FIMoniSec repository to /opt
clone_fimonisec_repo() {
    local install_type=$1
    
    status_message "Setting up FIMoniSec repository in /opt..."
    
    # Create backup of existing installation if present
    if [ -d "/opt/FIMoniSec" ]; then
        status_message "Backing up existing /opt/FIMoniSec directory"
        mv /opt/FIMoniSec /opt/FIMoniSec.backup.$(date +%Y%m%d%H%M%S)
    fi
    
    # Clone the repository directly to /opt/FIMoniSec
    status_message "Cloning FIMoniSec repository from GitHub..."
    git clone https://github.com/sec0ps/FIMoniSec.git /opt/FIMoniSec || error_exit "Failed to clone FIMoniSec repository"
    
    # Verify required directories exist based on installation type
    case "$install_type" in
        "linux_client")
            status_message "Verifying Linux Client installation..."
            if [ ! -d "/opt/FIMoniSec/Linux-Client" ]; then
                error_exit "Linux-Client directory not found in cloned repository!"
            fi
            ;;
            
        "server")
            status_message "Verifying Server installation (includes Linux Client)..."
            if [ ! -d "/opt/FIMoniSec/Linux-Client" ]; then
                error_exit "Linux-Client directory not found in cloned repository!"
            fi
            
            if [ ! -d "/opt/FIMoniSec/Monisec-Server" ]; then
                error_exit "Monisec-Server directory not found in cloned repository!"
            fi
            ;;
            
        *)
            error_exit "Unknown installation type: $install_type"
            ;;
    esac
    
    # Create logs directory
    mkdir -p /opt/FIMoniSec/logs
    
    # Set permissions
    chown -R fimonisec:fimonisec /opt/FIMoniSec || error_exit "Failed to set ownership on /opt/FIMoniSec"
    
    # Ensure .git directory has proper permissions for updates
    chmod -R g+w /opt/FIMoniSec/.git
    
    status_message "FIMoniSec repository has been cloned to /opt/FIMoniSec"
    status_message "Git repository is maintained for future updates"
}

# Call the clone function with the installation type
clone_fimonisec_repo "$INSTALL_TYPE"

# Step 4: Modify sudoers file for required commands
status_message "Updating sudoers file..."
CMDS="/usr/bin/lsof, /bin/cat, /bin/ps, /bin/netstat, /bin/ss, /usr/bin/readlink, /usr/bin/head, /usr/bin/tail, /usr/bin/find, /usr/bin/grep, /usr/bin/nice, /usr/bin/renice, /usr/bin/kill, /usr/bin/pkill, /usr/bin/pgrep, /bin/mkdir, /usr/bin/touch, /usr/bin/ulimit, /bin/systemctl, /usr/bin/python3"

# Check if the entries already exist
if grep -q "^$CURRENT_USER.*NOPASSWD:.*lsof" /etc/sudoers; then
    status_message "Sudoers entry for $CURRENT_USER already exists"
else
    echo "$CURRENT_USER ALL=(ALL) NOPASSWD: $CMDS" >> /etc/sudoers || error_exit "Failed to update sudoers for $CURRENT_USER"
fi

if grep -q "^fimonisec.*NOPASSWD:.*lsof" /etc/sudoers; then
    status_message "Sudoers entry for fimonisec already exists"
else
    echo "fimonisec ALL=(ALL) NOPASSWD: $CMDS" >> /etc/sudoers || error_exit "Failed to update sudoers for fimonisec"
fi

# Validate sudoers file
visudo -c || error_exit "Sudoers file is invalid. Please check /etc/sudoers manually"

# Step 5: Install dependencies
status_message "Installing Python dependencies..."
cd /opt/FIMoniSec || error_exit "Failed to change directory to /opt/FIMoniSec"

# Check if pip is installed
if ! command -v pip &> /dev/null; then
    status_message "Installing pip..."
    apt-get update -qq > /dev/null 2>&1
    apt-get install -y python3-pip -qq > /dev/null 2>&1 || error_exit "Failed to install pip"
fi

# Install Python requirements for both current user and fimonisec
status_message "Installing Python requirements for fimonisec user. This may take a few minutes..."
su - fimonisec -c "cd /opt/FIMoniSec && pip install -r requirements.txt --user -q --no-warn-script-location" || error_exit "Failed to install Python requirements for fimonisec"

status_message "Installing Python requirements for current user. This may take a few minutes..."
if [ "$CURRENT_USER" != "root" ]; then
    su - $CURRENT_USER -c "cd /opt/FIMoniSec && pip install -r requirements.txt --user -q --no-warn-script-location" || error_exit "Failed to install Python requirements for $CURRENT_USER"
else
    pip install -r requirements.txt -q --no-warn-script-location || error_exit "Failed to install Python requirements for root"
fi

# Step 6: Add Python local bin to PATH for both current user and fimonisec
status_message "Adding Python local bin directories to PATH..."

# For fimonisec user
if [ ! -f "/opt/FIMoniSec/.bashrc" ]; then
    touch /opt/FIMoniSec/.bashrc
    chown fimonisec:fimonisec /opt/FIMoniSec/.bashrc
fi

if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' /opt/FIMoniSec/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> /opt/FIMoniSec/.bashrc
    chown fimonisec:fimonisec /opt/FIMoniSec/.bashrc
fi

# For current user (if not root)
if [ "$CURRENT_USER" != "root" ]; then
    USER_HOME=$(eval echo ~$CURRENT_USER)
    if [ -d "$USER_HOME" ]; then
        if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' $USER_HOME/.bashrc 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $USER_HOME/.bashrc
            chown $CURRENT_USER: $USER_HOME/.bashrc
        fi
    fi
fi

# Create system-wide profile script for immediate availability
status_message "Creating system-wide PATH configuration..."
cat > /etc/profile.d/fimonisec_path.sh << EOF
#!/bin/bash
# Add local bin directories to PATH for FIMoniSec users
export PATH="/opt/FIMoniSec/.local/bin:\$PATH"
if [ "\$USER" != "root" ] && [ -d "\$HOME/.local/bin" ]; then
    export PATH="\$HOME/.local/bin:\$PATH"
fi
EOF
chmod +x /etc/profile.d/fimonisec_path.sh

# Export paths for current session
export PATH="/opt/FIMoniSec/.local/bin:$PATH"
if [ "$CURRENT_USER" != "root" ]; then
    USER_HOME=$(eval echo ~$CURRENT_USER)
    if [ -d "$USER_HOME/.local/bin" ]; then
        export PATH="$USER_HOME/.local/bin:$PATH"
    fi
fi

# Step 7: Install YARA
status_message "Installing YARA..."
apt-get update -qq > /dev/null 2>&1
apt-get install -y yara -qq > /dev/null 2>&1 || error_exit "Failed to install YARA"

# Step 8: Set up proper permissions for the FIMoniSec directory
status_message "Setting up proper permissions..."
chmod -R 750 /opt/FIMoniSec
mkdir -p /opt/FIMoniSec/logs 2>/dev/null
chmod -R g+s /opt/FIMoniSec/logs

# Step 9: Detect the init system
INIT_SYSTEM=""
if command -v systemctl >/dev/null 2>&1; then
    INIT_SYSTEM="systemd"
elif command -v service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    INIT_SYSTEM="sysvinit"
elif command -v initctl >/dev/null 2>&1; then
    INIT_SYSTEM="upstart"
else
    error_exit "Could not determine init system"
fi

status_message "Detected init system: $INIT_SYSTEM"

# Step 10: Create client service
status_message "Creating FIMoniSec client service..."

if [ "$INIT_SYSTEM" = "systemd" ]; then
    # Create systemd service for client
    cat > /etc/systemd/system/fimonisec-client.service << 'EOF'
[Unit]
Description=FIMoniSec Client - File Integrity Monitoring Service
After=network.target

[Service]
Type=simple
User=fimonisec
Group=fimonisec
WorkingDirectory=/opt/FIMoniSec
Environment="PATH=/opt/FIMoniSec/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/python3 /opt/FIMoniSec/Linux-Client/fimonisec_client.py -d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable fimonisec-client.service
    status_message "Client systemd service created and enabled"
    
elif [ "$INIT_SYSTEM" = "sysvinit" ]; then
    # Create SysV init script for client
    cat > /etc/init.d/fimonisec-client << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          fimonisec-client
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: FIMoniSec Client Service
# Description:       File Integrity Monitoring Client Service
### END INIT INFO

DAEMON_PATH="/opt/FIMoniSec/Linux-Client"
DAEMON="/usr/bin/python3"
DAEMONOPTS="fimonisec_client.py -d"
NAME="fimonisec-client"
DESC="FIMoniSec Client Service"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=fimonisec

case "$1" in
start)
    printf "%-50s" "Starting $NAME..."
    cd $DAEMON_PATH
    PID=`su -c "PATH=/opt/FIMoniSec/.local/bin:\$PATH $DAEMON $DAEMONOPTS > /dev/null 2>&1 & echo \$!" $USER`
    if [ -z $PID ]; then
        printf "%s\n" "Fail"
    else
        echo $PID > $PIDFILE
        printf "%s\n" "Ok"
    fi
;;
status)
    printf "%-50s" "Checking $NAME..."
    if [ -f $PIDFILE ]; then
        PID=`cat $PIDFILE`
        if [ -z "`ps axf | grep ${PID} | grep -v grep`" ]; then
            printf "%s\n" "Process dead but pidfile exists"
        else
            echo "Running"
        fi
    else
        printf "%s\n" "Service not running"
    fi
;;
stop)
    printf "%-50s" "Stopping $NAME"
    if [ -f $PIDFILE ]; then
        PID=`cat $PIDFILE`
        cd $DAEMON_PATH
        if [ -z "`ps axf | grep ${PID} | grep -v grep`" ]; then
            printf "%s\n" "Process dead but pidfile exists"
        else
            kill -9 $PID
            printf "%s\n" "Ok"
            rm -f $PIDFILE
        fi
    else
        printf "%s\n" "pidfile not found"
    fi
;;
restart)
    $0 stop
    $0 start
;;
*)
    echo "Usage: $0 {status|start|stop|restart}"
    exit 1
esac

exit 0
EOF
    chmod +x /etc/init.d/fimonisec-client
    update-rc.d fimonisec-client defaults
    status_message "Client SysV init service created and enabled"
    
elif [ "$INIT_SYSTEM" = "upstart" ]; then
    # Create Upstart conf for client
    cat > /etc/init/fimonisec-client.conf << 'EOF'
description "FIMoniSec Client Service"
author "FIMoniSec"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

setuid fimonisec
setgid fimonisec

chdir /opt/FIMoniSec

env PATH="/opt/FIMoniSec/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exec /usr/bin/python3 Linux-Client/fimonisec_client.py -d
EOF
    status_message "Client Upstart service created"
fi

# Step 11: Create server service if server installation was selected
if [ "$INSTALL_TYPE" = "server" ]; then
    status_message "Creating FIMoniSec server service..."
    
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        # Create systemd service for server
        cat > /etc/systemd/system/fimonisec-server.service << 'EOF'
[Unit]
Description=FIMoniSec Server - Central Monitoring Service
After=network.target

[Service]
Type=simple
User=fimonisec
Group=fimonisec
WorkingDirectory=/opt/FIMoniSec
Environment="PATH=/opt/FIMoniSec/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/python3 /opt/FIMoniSec/Monisec-Server/fimonisec-server.py -d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable fimonisec-server.service
        status_message "Server systemd service created and enabled"
        
    elif [ "$INIT_SYSTEM" = "sysvinit" ]; then
        # Create SysV init script for server
        cat > /etc/init.d/fimonisec-server << 'EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          fimonisec-server
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: FIMoniSec Server Service
# Description:       File Integrity Monitoring Server Service
### END INIT INFO

DAEMON_PATH="/opt/FIMoniSec/Monisec-Server"
DAEMON="/usr/bin/python3"
DAEMONOPTS="fimonisec-server.py -d"
NAME="fimonisec-server"
DESC="FIMoniSec Server Service"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=fimonisec

case "$1" in
start)
    printf "%-50s" "Starting $NAME..."
    cd $DAEMON_PATH
    PID=`su -c "PATH=/opt/FIMoniSec/.local/bin:\$PATH $DAEMON $DAEMONOPTS > /dev/null 2>&1 & echo \$!" $USER`
    if [ -z $PID ]; then
        printf "%s\n" "Fail"
    else
        echo $PID > $PIDFILE
        printf "%s\n" "Ok"
    fi
;;
status)
    printf "%-50s" "Checking $NAME..."
    if [ -f $PIDFILE ]; then
        PID=`cat $PIDFILE`
        if [ -z "`ps axf | grep ${PID} | grep -v grep`" ]; then
            printf "%s\n" "Process dead but pidfile exists"
        else
            echo "Running"
        fi
    else
        printf "%s\n" "Service not running"
    fi
;;
stop)
    printf "%-50s" "Stopping $NAME"
    if [ -f $PIDFILE ]; then
        PID=`cat $PIDFILE`
        cd $DAEMON_PATH
        if [ -z "`ps axf | grep ${PID} | grep -v grep`" ]; then
            printf "%s\n" "Process dead but pidfile exists"
        else
            kill -9 $PID
            printf "%s\n" "Ok"
            rm -f $PIDFILE
        fi
    else
        printf "%s\n" "pidfile not found"
    fi
;;
restart)
    $0 stop
    $0 start
;;
*)
    echo "Usage: $0 {status|start|stop|restart}"
    exit 1
esac

exit 0
EOF
        chmod +x /etc/init.d/fimonisec-server
        update-rc.d fimonisec-server defaults
        status_message "Server SysV init service created and enabled"
        
    elif [ "$INIT_SYSTEM" = "upstart" ]; then
        # Create Upstart conf for server
        cat > /etc/init/fimonisec-server.conf << 'EOF'
description "FIMoniSec Server Service"
author "FIMoniSec"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

setuid fimonisec
setgid fimonisec

chdir /opt/FIMoniSec

env PATH="/opt/FIMoniSec/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exec /usr/bin/python3 Monisec-Server/fimonisec-server.py -d
EOF
        status_message "Server Upstart service created"
    fi
    
    # Create server control script
    cat > /opt/FIMoniSec/control-server.sh << 'EOF'
#!/bin/bash
# FIMoniSec Server Control Script

# Ensure PATH includes local bin directories
export PATH="/opt/FIMoniSec/.local/bin:$PATH"

case "$1" in
    start)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl start fimonisec-server
        elif [ -f /etc/init.d/fimonisec-server ]; then
            /etc/init.d/fimonisec-server start
        elif command -v initctl >/dev/null 2>&1; then
            initctl start fimonisec-server
        else
            echo "Could not determine how to start the service"
            exit 1
        fi
        echo "FIMoniSec server started"
        ;;
    stop)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop fimonisec-server
        elif [ -f /etc/init.d/fimonisec-server ]; then
            /etc/init.d/fimonisec-server stop
        elif command -v initctl >/dev/null 2>&1; then
            initctl stop fimonisec-server
        else
            echo "Could not determine how to stop the service"
            exit 1
        fi
        echo "FIMoniSec server stopped"
        ;;
    restart)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart fimonisec-server
        elif [ -f /etc/init.d/fimonisec-server ]; then
            /etc/init.d/fimonisec-server restart
        elif command -v initctl >/dev/null 2>&1; then
            initctl restart fimonisec-server
        else
            echo "Could not determine how to restart the service"
            exit 1
        fi
        echo "FIMoniSec server restarted"
        ;;
    status)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl status fimonisec-server
        elif [ -f /etc/init.d/fimonisec-server ]; then
            /etc/init.d/fimonisec-server status
        elif command -v initctl >/dev/null 2>&1; then
            initctl status fimonisec-server
        else
            echo "Could not determine how to check service status"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
EOF
    chmod +x /opt/FIMoniSec/control-server.sh
    chown fimonisec:fimonisec /opt/FIMoniSec/control-server.sh
    status_message "Server control script created at /opt/FIMoniSec/control-server.sh"
fi

# Create client control script  
cat > /opt/FIMoniSec/control-client.sh << 'EOF'
#!/bin/bash
# FIMoniSec Client Control Script

# Ensure PATH includes local bin directories
export PATH="/opt/FIMoniSec/.local/bin:$PATH"

case "$1" in
    start)
        echo "Starting FIMoniSec client
