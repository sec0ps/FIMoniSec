# FIMoniSec: System Security Monitoring

FIMoniSec is a lightweight yet powerful Python-based system security monitoring application designed for Linux environments. It offers comprehensive intrusion detection through advanced behavioral analysis, machine learning, and real-time monitoring of process and file integrity.

## Features

### Process Integrity Monitoring (PIM)
- **Real-time Process Monitoring**: Continuously tracks all listening processes for suspicious behavior
- **ML-Based Anomaly Detection**: Uses Isolation Forest algorithm to detect statistical anomalies in process behavior
- **Memory Analysis**: Scans process memory regions to detect code injection and other memory-based attacks
- **Behavioral Pattern Detection**: Identifies suspicious patterns like unusual execution paths or encoded commands
- **MITRE ATT&CK Mapping**: Maps detected threats to the MITRE ATT&CK framework for better threat intelligence
- **Threat Scoring System**: Prioritizes alerts based on calculated severity scores

### File Integrity Monitoring (FIM)
- Monitors critical system files for unexpected changes
- Tracks file modifications, permissions changes, and ownership changes
- Provides detailed logging of file system events

### Client-Server Architecture
- Centralized security monitoring for multiple endpoints
- Secure communication using TLS/SSL and PSK authentication
- Remote command functionality for security management
- SIEM integration for comprehensive security operations

## Requirements

### System Requirements
- Python 3.6 or higher
- Linux-based operating system
- Required Python packages:
  - `numpy`
  - `pandas`
  - `scikit-learn`
  - `psutil`

### Required Permissions
To ensure proper functionality, the user running the management scripts must have sudo access to the following commands:

```
username ALL=(ALL) NOPASSWD: /usr/bin/lsof, /bin/cat, /bin/ps, /bin/netstat, /bin/ss, /usr/bin/readlink
```

Add the above line to your sudoers file using `visudo` to ensure MoniSec has the necessary permissions to monitor system processes.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/monisec.git
   cd monisec
   ```

2. Install required Python packages:
   ```
   pip install numpy pandas scikit-learn psutil
   ```

3. Set up the proper permissions in the sudoers file:
   ```
   sudo visudo
   ```
   Add the required permissions line mentioned above.

4. Run the server component (central monitoring):
   ```
   python monisec-server.py
   ```

5. On each client, configure and run the client:
   ```
   python monisec_client.py import-psk
   python monisec_client.py -d
   ```

## Usage

### Server Commands
```
python monisec-server.py [command] [client_name]

Commands:
  add-agent <agent_name>     Add a new client and generate a unique PSK.
  remove-agent <agent_name>  Remove an existing client.
  list-agents                List all registered clients.
  configure-siem             Configure SIEM settings for log forwarding.
  -d                         Launch the MoniSec Server as a daemon.
  stop                       Stop the running MoniSec Server daemon.
  -h, --help                 Show this help message.
```

### Client Commands
```
python monisec_client.py [command]

Commands:
  restart                    Restart monisec_client
  stop                       Stop monisec_client daemon
  pim start|stop|restart     Control Process Integrity Monitor
  fim start|stop|restart     Control File Integrity Monitor
  import-psk                 Import PSK for authentication
  auth test                  Test authentication, then exit
  -d                         Run client in daemon mode
```

## Security Alert Levels

MoniSec uses a sophisticated threat scoring system to categorize security events:

- **Critical (80-100)**: Severe security threats requiring immediate attention
- **High (60-79)**: Significant security concerns that should be addressed promptly
- **Medium (40-59)**: Potential security issues requiring investigation
- **Low (20-39)**: Minor security concerns
- **Informational (0-19)**: Behavioral anomalies with low security impact

## Future Plans

- Windows version compatibility
- Additional detection capabilities
- Enhanced automated response actions
- Further machine learning model improvements
- Broader SIEM integration options
