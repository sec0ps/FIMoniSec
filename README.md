# FIMoniSec: System Security Monitoring

**FIMoniSec** is an enterprise-grade security monitoring solution for Linux systems that provides real-time file integrity monitoring (FIM), process integrity monitoring (PIM), and optional log integrity monitoring (LIM). It detects unauthorized modifications, tracks process behavior, and maps security events to the MITRE ATT&CK framework.

## Features

### File Integrity Monitoring (FIM)
- **Baseline Management**: Create and maintain SHA-256 hash baselines for critical system files
- **Real-time Monitoring**: Instant detection of file changes using pyinotify
- **Scheduled Scanning**: Configurable periodic integrity scans
- **Change Detection**: Tracks file creation, modification, deletion, moves, and metadata changes
- **Config File Tracking**: Automatic backup and diff generation for configuration files
- **MITRE ATT&CK Mapping**: Events mapped to relevant ATT&CK techniques and tactics

### Process Integrity Monitoring (PIM)
- **Process Enumeration**: Monitor all running processes with full metadata
- **Listening Port Detection**: Track processes with open network sockets
- **Process Lineage**: Build and track parent-child process relationships
- **State Change Detection**: Detect when processes start/stop listening on ports

### Security & Integration
- **SIEM Integration**: Forward events to SIEM solutions via TCP/UDP
- **Exclusion Management**: Flexible exclusion rules by directory, file, pattern, or extension
- **Daemon Mode**: Run as a background service with automatic process recovery
- **Process Guardian**: Self-healing capabilities with automatic restart of monitored components
- **Remote Management**: WebSocket-based remote communication (optional)

## Installation

### Prerequisites
- Python 3.8+
- Linux operating system (Ubuntu 20.04+ recommended)
- Root/sudo access

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/sec0ps/FIMoniSec.git
cd FIMoniSec
```

2. **Run the installer as root:**
```bash
sudo python3 fimonisec_installer.py
```

3. **Follow the prompts:**
   - Select `1` to Install FIMoniSec
   - Select `1` for Linux Client or `2` for Server installation
   - Choose whether to start the service immediately

The installer will automatically:
- Create a dedicated `fimonisec` user and group
- Clone/update the repository to `/opt/FIMoniSec`
- Install required Python dependencies
- Configure sudo permissions for required commands
- Create and enable systemd service(s)

### Post-Installation

After installation, the service can be managed with systemctl:
```bash
# Start the service
sudo systemctl start fimonisec-client

# Stop the service
sudo systemctl stop fimonisec-client

# Check status
sudo systemctl status fimonisec-client

# View logs
sudo journalctl -u fimonisec-client -f
```

### Uninstallation

To remove FIMoniSec completely:
```bash
sudo python3 fimonisec_installer.py
# Select option 2 to Remove FIMoniSec
```

This will stop services, remove files, clean up sudoers entries, and delete the fimonisec user/group.
```

## Usage

### Start FIMoniSec (Daemon Mode)
```bash
python fimonisec_client.py start
```

### Stop FIMoniSec
```bash
python fimonisec_client.py stop
```

### Restart FIMoniSec
```bash
python fimonisec_client.py restart
```

### Control Individual Components
```bash
# File Integrity Monitor
python fimonisec_client.py fim start|stop|restart

# Process Integrity Monitor
python fimonisec_client.py pim start|stop|restart

# Log Integrity Monitor (if enabled)
python fimonisec_client.py lim start|stop|restart
```

### Manage Exclusions
```bash
# Add exclusion
python fimonisec_client.py exclusion add directory /path/to/exclude
python fimonisec_client.py exclusion add file /path/to/file
python fimonisec_client.py exclusion add pattern "*.log"
python fimonisec_client.py exclusion add extension .tmp

# Remove exclusion
python fimonisec_client.py exclusion remove directory /path/to/exclude

# List exclusions
python fimonisec_client.py exclusion list
python fimonisec_client.py exclusion list directory
```

## Contact
```bash
For professional services, integrations, or support contact: operations@redcellsecurity.org
```
### License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

### Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
