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
- 📝 Automatic Log Rotation

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

## Project Structure

The application uses a minimal file structure:
- `index.html` - The main web interface
- `index.py` - The Flask backend server
- `requirements.txt` - Python dependencies
- `README.md` - Project documentation

The following directories are created automatically when needed:
- `logs/` - Contains application logs with automatic rotation
  - `network_scan.log` - Current log file
  - `network_scan.log.1` to `network_scan.log.5` - Rotated log files
- `scan_results/` - Created when scans are performed

## Running the Application

1. Start the Flask server:
```bash
python index.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Logging System

The application uses a robust logging system with the following features:
- Automatic log rotation (max 1MB per file)
- Keeps last 5 log files
- Logs are stored in the `logs` directory
- Console output for development
- Structured log format with timestamp and log level

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

## Environment Variables

The application uses the following environment variables:
- `PYTHON_VERSION`: Python version
- `FLASK_ENV`: Flask environment
- `SECRET_KEY`: Secret key for security

## Deployment

To deploy the application on Render.com, follow these steps:
1. Sign up/login to Render.com
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure the service:
   - Name: `network-mapping-tool` (or your preferred name)
   - Environment: `Python 3`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn index:app`
   - Plan: Free tier (or choose paid plan)
5. Add Environment Variables:
   ```
   PYTHON_VERSION=3.8.0
   FLASK_ENV=production
   SECRET_KEY=your-secure-random-string
   ```
6. Click "Create Web Service"

Your application will be deployed and available at `https://your-app-name.onrender.com`. Render will automatically handle:
- SSL/HTTPS
- Load balancing
- Auto-restarts
- Logging
- Continuous deployment from GitHub

The application is now production-ready with:
- Multiple worker processes (via Gunicorn)
- Proper static file serving
- Health check endpoint for monitoring
- Secure configuration
- Log rotation
- Error handling

Would you like me to explain any part of the deployment process in more detail?
