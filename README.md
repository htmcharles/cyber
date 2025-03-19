# Network Mapping and Security Analysis Tool

A comprehensive network mapping and security analysis tool that provides detailed information about network devices, system information, and security vulnerabilities.

## Features

### 1. Network Information
- Local IP address detection
- MAC address retrieval
- Router details
- ISP information
- Connected devices discovery
- Connection type detection
- Anonymity check (VPN/proxy detection)

### 2. System Information
- Operating system details
- Network statistics
- Disk usage monitoring
- CPU usage tracking
- Authentication log parsing
- System architecture information

### 3. Advanced Scanning
- Target scanning with port detection
- SSH connection testing
- Service version detection
- OS fingerprinting
- Whois information lookup

### 4. Network Attack Simulation
- Network host discovery
- Multiple attack types:
  - Ping Flood Attack
  - SYN Flood Attack
  - Port Scan Attack
- Random attack selection
- Attack logging and monitoring

### 5. Comprehensive Network Mapping
- Network range scanning
- Host discovery
- Port and service enumeration
- OS detection
- Vulnerability assessment
- Detailed reporting

### 6. Vulnerability Assessment
- Nmap vulnerability scanning
- Searchsploit integration
- Service version detection
- Security gap identification
- Comprehensive reporting

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)
- Required Python packages:
  - flask
  - python-nmap
  - python-whois
  - paramiko
  - cryptography
  - psutil
  - requests

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python index.py
```

4. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

### Basic Network Information
1. Click "Install Required Packages" to ensure all dependencies are installed
2. Use the Network Information section to:
   - Get local IP address
   - Retrieve MAC address
   - View router details
   - Check ISP information
   - Discover connected devices
   - Verify connection type
   - Check anonymity status

### System Information
1. Use the System Information section to:
   - View system details
   - Monitor network statistics
   - Check disk usage
   - Track CPU usage
   - Parse authentication logs

### Advanced Scanning
1. Enter a target IP or domain in the Target Scan section
2. Click "Scan Target" to perform a comprehensive scan
3. For SSH connections:
   - Enter hostname, username, and password/key file
   - Click "Connect SSH" to test the connection

### Network Attack Simulation
1. Click "Discover Network Hosts" to find available targets
2. Select an attack type or use "Random Attack"
3. Enter or select a target IP
4. Click "Start Attack" to begin the simulation

### Comprehensive Network Mapping
1. Enter a network range (e.g., 192.168.1.0/24)
2. Click "Scan Network" to begin the mapping process
3. View detailed results including:
   - Discovered hosts
   - Open ports
   - Running services
   - OS information

### Vulnerability Assessment
1. Enter a target IP in the Vulnerability Assessment section
2. Click "Scan Vulnerabilities" to begin the assessment
3. Review the findings including:
   - Nmap vulnerability scan results
   - Searchsploit matches
   - Potential security issues

## Results and Logging

- All scan results are saved in the `scan_results` directory
- Attack simulations are logged in `network_scan.log`
- Results are displayed in a clean, organized format in the web interface
- Detailed JSON reports are generated for each scan

## Security Notes

- This tool is intended for legitimate network analysis and security testing
- Always obtain proper authorization before scanning networks
- Some features may require administrative privileges
- Use responsibly and in accordance with local laws and regulations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legitimate security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations when using this tool.
