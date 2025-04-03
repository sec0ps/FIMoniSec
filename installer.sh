#!/bin/bash

# Enterprise-Grade Intrusion Detection and Response Framework Installer
# This script installs FIMoniSec and configures the necessary environment
# Supports client, server, or both installation types

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

# Step 0: Determine installation type
INSTALL_TYPE=""
while [ "$INSTALL_TYPE" != "client" ] && [ "$INSTALL_TYPE" != "server" ] && [ "$INSTALL_TYPE" != "both" ]; do
    echo "What type of installation would you like to perform?"
    echo "1) Client installation"
    echo "2) Server installation"
    echo "3) Both client and server installation"
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1) INSTALL_TYPE="client" ;;
        2) INSTALL_TYPE="server" ;;
        3) INSTALL_TYPE="both" ;;
        *) echo "Invalid choice. Please select 1, 2, or 3." ;;
    esac
done

status_message "Performing $INSTALL_TYPE installation"

# Step 1: Verify we're in the FIMoniSec directory
if [ ! -f "$(pwd)/README.md" ] || [ ! -d "$(pwd)/.git" ]; then
    status_message "This script should be run from within the FIMoniSec repository."
    status_message "Please navigate to the FIMoniSec directory and try again."
    exit 1
fi

status_message "FIMoniSec repository detected in current directory."

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

# Step 3: Move current directory to /opt
status_message "Moving FIMoniSec to /opt..."
if [ -d "/opt/FIMoniSec" ]; then
    status_message "Backing up existing /opt/FIMoniSec directory"
    mv /opt/FIMoniSec /opt/FIMoniSec.backup.$(date +%Y%m%d%H%M%S)
fi

# Get the current directory name
CURRENT_DIR=$(basename "$(pwd)")
cd ..

# Move the directory to /opt
cp -r "$CURRENT_DIR" /opt/FIMoniSec || error_exit "Failed to copy FIMoniSec to /opt"
chown -R fimonisec:fimonisec /opt/FIMoniSec || error_exit "Failed to set ownership on /opt/FIMoniSec"

# Change to the new directory
cd /opt/FIMoniSec || error_exit "Failed to change directory to /opt/FIMoniSec"

# Step 4: Modify sudoers file for required commands
status_message "Updating sudoers file..."
CMDS="/usr/bin/lsof, /bin/cat, /bin/ps, /bin/netstat, /bin/ss, /usr/bin/readlink"

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
    apt-get update
    apt-get install -y python3-pip || error_exit "Failed to install pip"
fi

# Install Python requirements
su - fimonisec -c "cd /opt/FIMoniSec && pip install -r requirements.txt" || error_exit "Failed to install Python requirements"

# Step 6: Install YARA
status_message "Installing YARA..."
apt-get update
apt-get install -y yara || error_exit "Failed to install YARA"

# Step 7: Set up proper permissions for the FIMoniSec directory
status_message "Setting up proper permissions..."
chmod -R 750 /opt/FIMoniSec
chmod -R g+s /opt/FIMoniSec/logs 2>/dev/null || mkdir -p /opt/FIMoniSec/logs && chmod -R g+s /opt/FIMoniSec/logs

# Step 8: Detect the init system
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

# Create client service if needed
if [ "$INSTALL_TYPE" = "client" ] || [ "$INSTALL_TYPE" = "both" ]; then
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
ExecStart=/usr/bin/python3 /opt/FIMoniSec/monisec_client.py -d
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

DAEMON_PATH="/opt/FIMoniSec"
DAEMON="/usr/bin/python3"
DAEMONOPTS="monisec_client.py -d"
NAME="fimonisec-client"
DESC="FIMoniSec Client Service"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=fimonisec

case "$1" in
start)
    printf "%-50s" "Starting $NAME..."
    cd $DAEMON_PATH
    PID=`su -c "$DAEMON $DAEMONOPTS > /dev/null 2>&1 & echo \$!" $USER`
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

exec /usr/bin/python3 monisec_client.py -d
EOF
        status_message "Client Upstart service created"
    fi
    
    # Create client control script
    cat > /opt/FIMoniSec/control-client.sh << 'EOF'
#!/bin/bash
# FIMoniSec Client Control Script

case "$1" in
    start)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl start fimonisec-client
        elif [ -f /etc/init.d/fimonisec-client ]; then
            /etc/init.d/fimonisec-client start
        elif command -v initctl >/dev/null 2>&1; then
            initctl start fimonisec-client
        else
            echo "Could not determine how to start the service"
            exit 1
        fi
        echo "FIMoniSec client started"
        ;;
    stop)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop fimonisec-client
        elif [ -f /etc/init.d/fimonisec-client ]; then
            /etc/init.d/fimonisec-client stop
        elif command -v initctl >/dev/null 2>&1; then
            initctl stop fimonisec-client
        else
            echo "Could not determine how to stop the service"
            exit 1
        fi
        echo "FIMoniSec client stopped"
        ;;
    restart)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart fimonisec-client
        elif [ -f /etc/init.d/fimonisec-client ]; then
            /etc/init.d/fimonisec-client restart
        elif command -v initctl >/dev/null 2>&1; then
            initctl restart fimonisec-client
        else
            echo "Could not determine how to restart the service"
            exit 1
        fi
        echo "FIMoniSec client restarted"
        ;;
    status)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl status fimonisec-client
        elif [ -f /etc/init.d/fimonisec-client ]; then
            /etc/init.d/fimonisec-client status
        elif command -v initctl >/dev/null 2>&1; then
            initctl status fimonisec-client
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
    chmod +x /opt/FIMoniSec/control-client.sh
    status_message "Client control script created at /opt/FIMoniSec/control-client.sh"
fi

# Create server service if needed
if [ "$INSTALL_TYPE" = "server" ] || [ "$INSTALL_TYPE" = "both" ]; then
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
ExecStart=/usr/bin/python3 /opt/FIMoniSec/monisec-server.py -d
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

DAEMON_PATH="/opt/FIMoniSec"
DAEMON="/usr/bin/python3"
DAEMONOPTS="monisec-server.py -d"
NAME="fimonisec-server"
DESC="FIMoniSec Server Service"
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=fimonisec

case "$1" in
start)
    printf "%-50s" "Starting $NAME..."
    cd $DAEMON_PATH
    PID=`su -c "$DAEMON $DAEMONOPTS > /dev/null 2>&1 & echo \$!" $USER`
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

exec /usr/bin/python3 monisec-server.py -d
EOF
        status_message "Server Upstart service created"
    fi
    
    # Create server control script
    cat > /opt/FIMoniSec/control-server.sh << 'EOF'
#!/bin/bash
# FIMoniSec Server Control Script

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
    status_message "Server control script created at /opt/FIMoniSec/control-server.sh"
fi

# Final steps
status_message "Installation completed successfully!"

if [ "$INSTALL_TYPE" = "client" ] || [ "$INSTALL_TYPE" = "both" ]; then
    status_message "Client components installed in /opt/FIMoniSec"
    status_message "Client control script: /opt/FIMoniSec/control-client.sh"
    
    # Ask if user wants to start the client service now
    read -p "Do you want to start the FIMoniSec client service now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl start fimonisec-client
        elif [ "$INIT_SYSTEM" = "sysvinit" ]; then
            service fimonisec-client start
        elif [ "$INIT_SYSTEM" = "upstart" ]; then
            start fimonisec-client
        fi
        status_message "FIMoniSec client service started"
    fi
fi

if [ "$INSTALL_TYPE" = "server" ] || [ "$INSTALL_TYPE" = "both" ]; then
    status_message "Server components installed in /opt/FIMoniSec"
    status_message "Server control script: /opt/FIMoniSec/control-server.sh"
    
    # Ask if user wants to start the server service now
    read -p "Do you want to start the FIMoniSec server service now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl start fimonisec-server
        elif [ "$INIT_SYSTEM" = "sysvinit" ]; then
            service fimonisec-server start
        elif [ "$INIT_SYSTEM" = "upstart" ]; then
            start fimonisec-server
        fi
        status_message "FIMoniSec server service started"
    fi
fi

status_message "Thank you for installing FIMoniSec!"

exit 0
