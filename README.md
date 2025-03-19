# Network Mapping Tool

A comprehensive network analysis and scanning tool with a modern web interface. This tool provides various network information gathering capabilities, port scanning, and system monitoring features.

## Features

- **Network Information**
  - Local IP Address detection
  - MAC Address lookup
  - Router details
  - ISP Information
  - Connected devices
  - Connection type detection
  - Anonymity checking

- **System Information**
  - OS details
  - Network statistics
  - Disk usage
  - CPU monitoring
  - Authentication logs

- **Advanced Scanning**
  - Port scanning
  - Service detection
  - OS fingerprinting
  - Whois information
  - SSH remote connection

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd network-mapping-tool
```

2. Install required packages:
```bash
pip install flask python-whois paramiko cryptography psutil requests
```

## Usage

1. Start the application:
```bash
python index.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Use the web interface to:
   - Install required packages (first time only)
   - Check network information
   - Monitor system status
   - Perform port scans
   - Connect to remote systems via SSH

## Features in Detail

### Network Information
- **Local IP**: Shows your local network IP address
- **MAC Address**: Displays your device's MAC address
- **Router Details**: Shows your default gateway IP
- **ISP Info**: Displays your ISP and location information
- **Connected Devices**: Lists devices on your local network
- **Connection Type**: Shows if you're using WiFi or Ethernet
- **Anonymity Check**: Detects VPN/proxy usage

### System Information
- **System Info**: Shows OS and system architecture
- **Network Stats**: Displays detailed network configuration
- **Disk Usage**: Shows storage space information
- **CPU Usage**: Real-time CPU monitoring
- **Auth Logs**: Recent authentication attempts

### Advanced Scanning
- **Port Scan**: Checks common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080)
- **Service Detection**: Identifies running services
- **OS Detection**: Attempts to identify target OS
- **Whois Lookup**: Domain registration information
- **SSH Connection**: Remote system access and command execution

## File Structure

```
network-mapping-tool/
├── index.py          # Main application file
├── index.html        # Web interface
├── README.md         # This file
└── scan_results/     # Directory for scan results
```

## Logging

The application maintains logs in `network_scan.log` for debugging and auditing purposes.

## Security Notes

- The tool requires appropriate permissions to access network information
- Some features may require administrative privileges
- Use SSH connections responsibly and only on systems you have permission to access
- Port scanning should only be performed on networks you own or have permission to scan

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.
