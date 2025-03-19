# Network Mapping Tool

A modern web-based network mapping and security assessment tool with a sleek dark/light theme interface.

## Features

- 🌐 Network Information Gathering
- 💻 System Information Analysis
- 🔍 Advanced Network Scanning
- 🛡️ Network Attack Simulation
- 🗺️ Comprehensive Network Mapping
- 🔒 Vulnerability Assessment
- 🌓 Dark/Light Theme Support
- 📱 Responsive Design

## Prerequisites

- Python 3.8+
- Flask
- Modern web browser
- Network access rights

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-mapping-tool.git
cd network-mapping-tool
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Required Files

The application requires only these core files:
- `index.html` - The main web interface
- `index.py` - The Flask backend server
- `requirements.txt` - Python dependencies

## Running the Application

1. Start the Flask server:
```bash
python index.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Security Notice

⚠️ This tool should only be used on networks and systems you have explicit permission to test. Unauthorized network scanning and attack simulation may be illegal.

## Features Usage

### System Setup
- Install required packages automatically
- Check system compatibility

### Network Information
- Get local IP and MAC address
- Retrieve router details
- Get ISP information
- List connected devices
- Check network connection type
- Verify anonymity status

### System Information
- View detailed system info
- Monitor network statistics
- Check disk usage
- Track CPU usage
- Review authentication logs

### Advanced Scanning
- Target specific IP/domain scanning
- SSH connection testing
- Port scanning
- Service detection

### Network Attack Simulation
- Network host discovery
- Various attack type simulations
- Customizable attack parameters

### Network Mapping
- CIDR range scanning
- Vulnerability assessment
- Real-time results display

## Customization

The interface supports both light and dark themes. Toggle between themes using the theme switch button in the top bar.

## Contributing

Feel free to submit issues and enhancement requests!

## License

[MIT License](LICENSE)
