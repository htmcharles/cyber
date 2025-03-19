# Network Mapping Tool

A comprehensive network analysis and security tool with a web interface.

## Features

- Network Information Gathering
- System Information Monitoring
- Security Analysis
- Remote SSH Access
- Data Management with Encryption
- Anonymity Checking
- Port Scanning
- WHOIS Lookup

## Prerequisites

- Python 3.7 or higher
- Nmap (will be installed automatically on Linux/macOS, manual installation required for Windows)
- Administrator/root privileges (for some features)

## Installation

### Windows

1. Install Nmap:
   - Download Nmap from [https://nmap.org/download.html](https://nmap.org/download.html)
   - Run the installer
   - Add Nmap to your system PATH

2. Install Python packages:
```bash
python setup.py
```

### Linux/macOS

1. Run the setup script:
```bash
sudo python3 setup.py
```

## Usage

1. Start the server:
```bash
python index.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Directory Structure

- `data/` - Directory for storing encrypted data
- `logs/` - Directory for log files
- `index.py` - Main application file
- `index.html` - Web interface
- `setup.py` - Installation script
- `requirements.txt` - Python package dependencies

## Security Notes

- The tool uses encryption for storing sensitive data
- SSH connections are secured with key-based authentication
- All operations are logged for audit purposes
- Some features require administrator/root privileges

## Troubleshooting

1. If you encounter permission errors:
   - Run the setup script with administrator/root privileges
   - Check file permissions in the data and logs directories

2. If Nmap is not found:
   - Windows: Ensure Nmap is installed and added to PATH
   - Linux: Run `sudo apt-get install nmap`
   - macOS: Run `brew install nmap`

3. For package installation issues:
   - Update pip: `python -m pip install --upgrade pip`
   - Install requirements manually: `pip install -r requirements.txt`

## Logging

All operations are logged to:
- `setup.log` - Installation and setup logs
- `network_analysis.log` - Application operation logs

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author
**Charles**

## Contributing
Feel free to fork the repository and submit pull requests.
