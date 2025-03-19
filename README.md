# System Monitoring and Log Analysis Tool

## Overview
This project is a Python-based system monitoring and log analysis tool that gathers various system metrics and parses authentication logs. It provides insights into system performance, network activity, disk usage, and security events.

## Features
- **System Information:** Identifies the operating system and system details.
- **Network Statistics:** Extracts network configuration details.
- **Disk Usage:** Lists the five largest directories and provides disk space statistics.
- **CPU Monitoring:** Monitors CPU usage in real-time.
- **Authentication Log Analysis:** Parses `/var/log/auth.log` to track command usage and user authentication changes.
- **Interactive Menu:** Allows users to select which details to retrieve.

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
- The log analysis feature is tailored for Linux systems with `/var/log/auth.log`.
- Running the script as a non-root user may restrict access to some system details.

## Author
Charles

## Contributing
Feel free to fork the repository, open issues, or submit pull requests to improve the tool.
