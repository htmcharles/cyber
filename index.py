import os
import platform
import socket
import subprocess
import psutil
import requests
import re
import json
import paramiko
import nmap
import whois
import logging
import time
import random
from datetime import datetime
from flask import Flask, send_file, jsonify, request
from cryptography.fernet import Fernet
import threading
import sys

app = Flask(__name__)

# Setup logging
logging.basicConfig(
    filename='network_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global variables for installation status
INSTALLED_PACKAGES = set()

# Network attack types and their descriptions
NETWORK_ATTACKS = {
    "ping_flood": {
        "name": "Ping Flood Attack",
        "description": "Simulates a ping flood attack by sending multiple ICMP echo requests to overwhelm the target.",
        "command": "ping -n 1000 -l 65500 {target}",
        "duration": 5
    },
    "syn_flood": {
        "name": "SYN Flood Attack",
        "description": "Simulates a SYN flood attack by sending multiple TCP SYN packets to exhaust target's connection queue.",
        "command": "hping3 -S -p 80 --flood {target}",
        "duration": 5
    },
    "port_scan": {
        "name": "Port Scan Attack",
        "description": "Performs a rapid port scan to identify open ports and services on the target.",
        "command": "nmap -T4 -F {target}",
        "duration": 10
    }
}

def check_and_install_requirements():
    """Check and install required packages if not already installed."""
    required_packages = {
        'python-whois': 'whois',
        'paramiko': 'paramiko',
        'cryptography': 'cryptography'
    }

    # Install Python packages
    for package, import_name in required_packages.items():
        if package not in INSTALLED_PACKAGES:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                INSTALLED_PACKAGES.add(package)
                logging.info(f"Installed package: {package}")
            except Exception as e:
                logging.error(f"Failed to install {package}: {str(e)}")
                return {
                    "success": False,
                    "message": f"Failed to install {package}: {str(e)}"
                }

    return {
        "success": True,
        "message": "All requirements installed successfully"
    }

def check_anonymity():
    """Check if the connection is anonymous and detect VPN/proxy usage."""
    try:
        # Get real IP
        real_ip = requests.get('https://api.ipify.org').text

        # Get VPN/proxy detection
        response = requests.get(f'https://ipapi.co/{real_ip}/json/')
        data = response.json()

        # Check for common VPN/proxy indicators
        is_anonymous = False
        spoofed_country = None

        if data.get('proxy') or data.get('hosting'):
            is_anonymous = True
            spoofed_country = data.get('country_name')

        return {
            "is_anonymous": is_anonymous,
            "real_ip": real_ip,
            "spoofed_country": spoofed_country,
            "connection_type": "VPN/Proxy" if is_anonymous else "Direct Connection"
        }
    except Exception as e:
        logging.error(f"Anonymity check failed: {str(e)}")
        return {"error": str(e)}

def scan_target(target):
    """Perform comprehensive scan on specified target using socket-based scanning."""
    try:
        scan_results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "ports": {},
            "os_info": {},
            "vulnerabilities": []
        }

        # Common ports to scan
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP Proxy"
        }

        # Port scanning
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service_info = socket.getservbyport(port)
                    except:
                        service_info = service

                    scan_results["ports"][port] = {
                        "state": "open",
                        "service": service_info,
                        "version": "unknown"
                    }
                sock.close()
            except Exception as e:
                logging.warning(f"Error scanning port {port}: {str(e)}")

        # OS detection using socket
        try:
            scan_results["os_info"] = {
                "platform": platform.system(),
                "version": platform.version(),
                "architecture": platform.architecture()[0]
            }
        except Exception as e:
            logging.warning(f"OS detection failed: {str(e)}")

        # Whois information
        try:
            w = whois.whois(target)
            scan_results["whois"] = {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date
            }
        except Exception as e:
            logging.warning(f"Whois lookup failed for {target}: {str(e)}")

        return scan_results
    except Exception as e:
        logging.error(f"Scan failed for target {target}: {str(e)}")
        return {"error": str(e)}

def ssh_connect(hostname, username, password=None, key_filename=None):
    """Establish SSH connection and execute commands."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_filename:
            ssh.connect(hostname, username=username, key_filename=key_filename)
        else:
            ssh.connect(hostname, username=username, password=password)

        commands = [
            "uname -a",
            "cat /etc/os-release",
            "df -h",
            "free -m",
            "netstat -tuln"
        ]

        results = {}
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            results[cmd] = stdout.read().decode()

        ssh.close()
        return results
    except Exception as e:
        logging.error(f"SSH connection failed: {str(e)}")
        return {"error": str(e)}

def save_scan_results(results, filename=None):
    """Save scan results to a file."""
    try:
        if filename is None:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)

        logging.info(f"Scan results saved to {filename}")
        return {"status": "success", "filename": filename}
    except Exception as e:
        logging.error(f"Failed to save scan results: {str(e)}")
        return {"error": str(e)}

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        return f"Error retrieving local IP: {e}"

def get_mac_address():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("getmac", shell=True).decode()
            mac_address = re.findall(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", output)
        else:
            output = subprocess.check_output("ifconfig" if platform.system() == "Darwin" else "ip link", shell=True).decode()
            mac_address = re.findall(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", output)
        return mac_address if mac_address else "MAC address not found"
    except Exception as e:
        return f"Error retrieving MAC address: {e}"

def get_router_details():
    try:
        output = subprocess.check_output("ipconfig" if platform.system() == "Windows" else "ip route", shell=True).decode()
        router_ip = re.search(r"Default Gateway.*?: (\d+\.\d+\.\d+\.\d+)" if platform.system() == "Windows" else r"default via (\d+\.\d+\.\d+\.\d+)", output)
        return router_ip.group(1) if router_ip else "Router IP not found"
    except Exception as e:
        return f"Error retrieving router details: {e}"

def get_isp_info():
    try:
        response = requests.get("http://ip-api.com/json")
        data = response.json()
        return {
            "ISP": data.get("isp"),
            "Organization": data.get("org"),
            "Country": data.get("country"),
            "Region": data.get("regionName"),
            "City": data.get("city"),
            "Public IP": data.get("query")
        }
    except Exception as e:
        return f"Error retrieving ISP details: {e}"

def get_connected_devices():
    try:
        output = subprocess.check_output("arp -a" if platform.system() == "Windows" else "arp -n", shell=True).decode()
        devices = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:-]{17})", output)
        return [{"IP": ip, "MAC": mac} for ip, mac in devices] if devices else "No devices found"
    except Exception as e:
        return f"Error retrieving connected devices: {e}"

def get_connection_type():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netsh interface show interface", shell=True).decode()
            connection = re.findall(r"(Wireless|Ethernet)", output)
        else:
            output = subprocess.check_output("nmcli device status", shell=True).decode()
            connection = re.findall(r"(wifi|ethernet)", output)
        return connection if connection else "Connection type not identified"
    except Exception as e:
        return f"Error retrieving connection type: {e}"

def get_system_info():
    return {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.architecture()[0]
    }

def get_network_statistics():
    try:
        output = subprocess.check_output("ipconfig /all" if platform.system() == "Windows" else "ifconfig", shell=True).decode()
        return output
    except Exception as e:
        return f"Error retrieving network statistics: {e}"

def get_disk_usage():
    try:
        usage = psutil.disk_usage('/')
        output = subprocess.check_output("du -ah / | sort -rh | head -n 5", shell=True).decode()
        return {
            "Total": usage.total,
            "Used": usage.used,
            "Free": usage.free,
            "Largest Directories": output
        }
    except Exception as e:
        return f"Error retrieving disk usage: {e}"

def monitor_cpu_usage():
    return f"CPU Usage: {psutil.cpu_percent(interval=1)}%"

def parse_auth_log():
    try:
        with open("/var/log/auth.log", "r") as f:
            logs = f.readlines()
        return logs[-10:] if logs else "No recent authentication logs found"
    except Exception as e:
        return f"Error reading auth.log: {e}"

def discover_network_hosts():
    """Discover hosts on the local network."""
    try:
        local_ip = get_local_ip()
        network_prefix = '.'.join(local_ip.split('.')[:-1])
        hosts = []

        # Scan common network ranges
        for i in range(1, 255):
            ip = f"{network_prefix}.{i}"
            try:
                # Try to resolve hostname
                hostname = socket.gethostbyaddr(ip)[0]
                hosts.append({
                    "ip": ip,
                    "hostname": hostname,
                    "status": "active"
                })
            except:
                continue

        return hosts
    except Exception as e:
        logging.error(f"Network discovery failed: {str(e)}")
        return []

def simulate_network_attack(attack_type, target_ip):
    """Simulate a network attack and log the results."""
    try:
        if attack_type not in NETWORK_ATTACKS:
            return {"error": "Invalid attack type"}

        attack_info = NETWORK_ATTACKS[attack_type]
        start_time = time.time()

        # Log attack initiation
        logging.info(f"Starting {attack_info['name']} on target {target_ip}")

        # Simulate attack (using safe commands for testing)
        if attack_type == "ping_flood":
            # Use a limited number of pings for testing
            command = f"ping -n 10 -l 1000 {target_ip}"
        elif attack_type == "syn_flood":
            # Use a safe port scanning command instead
            command = f"nmap -sS -p 80 {target_ip}"
        else:
            command = f"nmap -T4 -F {target_ip}"

        # Execute command and capture output
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # Calculate duration
        duration = time.time() - start_time

        # Log attack completion
        logging.info(f"Completed {attack_info['name']} on {target_ip}. Duration: {duration:.2f}s")

        return {
            "attack_type": attack_type,
            "target_ip": target_ip,
            "duration": duration,
            "output": result.stdout,
            "status": "completed"
        }
    except Exception as e:
        logging.error(f"Attack simulation failed: {str(e)}")
        return {"error": str(e)}

def get_random_attack():
    """Get a random attack type from the available attacks."""
    return random.choice(list(NETWORK_ATTACKS.keys()))

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/local-ip')
def api_local_ip():
    return jsonify({"local_ip": get_local_ip()})

@app.route('/api/mac-address')
def api_mac_address():
    return jsonify({"mac_address": get_mac_address()})

@app.route('/api/router-details')
def api_router_details():
    return jsonify({"router_details": get_router_details()})

@app.route('/api/isp-info')
def api_isp_info():
    return jsonify(get_isp_info())

@app.route('/api/connected-devices')
def api_connected_devices():
    return jsonify({"connected_devices": get_connected_devices()})

@app.route('/api/connection-type')
def api_connection_type():
    return jsonify({"connection_type": get_connection_type()})

@app.route('/api/system-info')
def api_system_info():
    return jsonify(get_system_info())

@app.route('/api/network-stats')
def api_network_stats():
    return jsonify({"network_stats": get_network_statistics()})

@app.route('/api/disk-usage')
def api_disk_usage():
    return jsonify(get_disk_usage())

@app.route('/api/cpu-usage')
def api_cpu_usage():
    return jsonify({"cpu_usage": monitor_cpu_usage()})

@app.route('/api/auth-logs')
def api_auth_logs():
    return jsonify({"auth_logs": parse_auth_log()})

@app.route('/api/check-anonymity')
def api_check_anonymity():
    return jsonify(check_anonymity())

@app.route('/api/scan-target', methods=['POST'])
def api_scan_target():
    data = request.get_json()
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target specified"}), 400

    results = scan_target(target)
    save_scan_results(results)
    return jsonify(results)

@app.route('/api/ssh-connect', methods=['POST'])
def api_ssh_connect():
    data = request.get_json()
    hostname = data.get('hostname')
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')

    if not all([hostname, username]):
        return jsonify({"error": "Missing required parameters"}), 400

    results = ssh_connect(hostname, username, password, key_filename)
    return jsonify(results)

@app.route('/api/install-requirements')
def api_install_requirements():
    result = check_and_install_requirements()
    return jsonify(result)

@app.route('/api/discover-hosts')
def api_discover_hosts():
    return jsonify({"hosts": discover_network_hosts()})

@app.route('/api/attack-types')
def api_attack_types():
    return jsonify(NETWORK_ATTACKS)

@app.route('/api/simulate-attack', methods=['POST'])
def api_simulate_attack():
    data = request.get_json()
    attack_type = data.get('attack_type')
    target_ip = data.get('target_ip')

    if not attack_type or not target_ip:
        return jsonify({"error": "Missing attack type or target IP"}), 400

    result = simulate_network_attack(attack_type, target_ip)
    return jsonify(result)

@app.route('/api/random-attack')
def api_random_attack():
    return jsonify({"attack_type": get_random_attack()})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
