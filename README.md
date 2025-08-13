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

## Installation

1. Execute the installer
    ```
    sudo sh installer.sh

4. Run the server component (central monitoring):
   ```
   python monisec-server.py (create the initial configuration file)
   python monisec-server.py -d
   python monisec-server.py add-agent
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

## Contact
For professional services, integrations, or support contact: operations@redcellsecurity.org

## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.
