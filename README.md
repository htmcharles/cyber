# Network Mapping Tool

## Overview
The **Network Mapping Tool** is a Python script that provides comprehensive details about a local network. It retrieves information such as local IP address, MAC address, router details, ISP information, connected devices, and connection type. The script is interactive and allows users to choose specific network details to display.

## Features
- **Retrieve Local IP Address**: Gets the local IP of the machine.
- **Retrieve MAC Address**: Extracts the machine's MAC address.
- **Get Router Details**: Identifies the router's IP and other relevant details.
- **ISP Information**: Fetches ISP details using an external API.
- **Connected Devices**: Lists devices currently connected to the network.
- **Connection Type**: Determines if the connection is Ethernet or Wireless.
- **Complete Network Overview**: Displays all network-related details in one go.
- **System Information**: Identifies the operating system and system details.
- **Network Statistics**: Extracts network configuration details.
- **Disk Usage**: Lists the five largest directories and provides disk space statistics.
- **CPU Monitoring**: Monitors CPU usage in real-time.
- **Authentication Log Analysis**: Parses `/var/log/auth.log` to track command usage and user authentication changes.
- **Interactive Menu**: Allows users to select which details to retrieve.

## Installation
### Prerequisites
- Python 3.x installed on your system
- Permissions to read `/var/log/auth.log` (requires sudo privileges on Linux)

### Clone the Repository
```sh
git clone https://github.com/yourusername/system-monitor.git
cd system-monitor
```

### Install Dependencies
This script primarily uses built-in Python libraries. However, ensure you have `psutil` installed for CPU monitoring:
```sh
pip install psutil
```

## Usage
Run the script using:
```sh
python system_monitor.py
```

You'll be presented with an interactive menu to choose the system information you want to retrieve.

## Notes
- Some functions require administrative privileges to execute certain commands.
- On Linux/macOS, `sudo` may be required to fetch certain network details.
- The ISP information is retrieved using `http://ip-api.com/json`, so an active internet connection is needed.
- The log analysis feature is tailored for Linux systems with `/var/log/auth.log`.
- Running the script as a non-root user may restrict access to some system details.

## License
This project is licensed under the MIT License.

## Author
**Charles**

## Contributing
Feel free to fork the
