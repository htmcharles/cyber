import os
import platform
import socket
import subprocess
import psutil
import requests
import re
import json
import logging
import paramiko
import nmap
import whois
from datetime import datetime
from flask import Flask, send_file, jsonify, request
from cryptography.fernet import Fernet
import threading
import time

app = Flask(__name__)

# Set up logging
logging.basicConfig(
    filename='network_analysis.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize encryption key for sensitive data
def initialize_encryption():
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

encryption_key = initialize_encryption()
fernet = Fernet(encryption_key)

def check_required_packages():
    required_packages = {
        'nmap': 'nmap',
        'python-whois': 'whois',
        'paramiko': 'paramiko',
        'cryptography': 'cryptography'
    }

    missing_packages = []
    for package, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        logging.warning(f"Missing required packages: {', '.join(missing_packages)}")
        return False
    return True

# Initialize required packages
if not check_required_packages():
    logging.error("Missing required packages. Please install them first.")
    print("Error: Missing required packages. Please run setup.py first.")

def check_anonymity():
    try:
        # Check VPN/Proxy status
        response = requests.get('https://api.ipify.org?format=json')
        real_ip = response.json()['ip']

        # Get geolocation data
        geo_response = requests.get(f'http://ip-api.com/json/{real_ip}')
        geo_data = geo_response.json()

        # Check for common VPN/Proxy indicators
        is_anonymous = False
        if geo_data.get('proxy') or geo_data.get('hosting'):
            is_anonymous = True

        return {
            "is_anonymous": is_anonymous,
            "real_ip": real_ip,
            "country": geo_data.get('country'),
            "isp": geo_data.get('isp'),
            "proxy": geo_data.get('proxy'),
            "hosting": geo_data.get('hosting')
        }
    except Exception as e:
        logging.error(f"Error checking anonymity: {str(e)}")
        return {"error": str(e)}

def scan_target(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sS -sV -O')

        scan_results = {
            "target": target,
            "hosts": []
        }

        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "state": nm[host].state(),
                "os": nm[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                "ports": []
            }

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    host_info["ports"].append({
                        "port": port,
                        "state": nm[host][proto][port]['state'],
                        "service": nm[host][proto][port].get('name', 'unknown'),
                        "version": nm[host][proto][port].get('version', 'unknown')
                    })

            scan_results["hosts"].append(host_info)

        return scan_results
    except Exception as e:
        logging.error(f"Error scanning target {target}: {str(e)}")
        return {"error": str(e)}

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        logging.error(f"Error performing whois lookup for {domain}: {str(e)}")
        return {"error": str(e)}

def ssh_connect(hostname, username, password=None, key_filename=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_filename:
            ssh.connect(hostname, username=username, key_filename=key_filename)
        else:
            ssh.connect(hostname, username=username, password=password)

        return ssh
    except Exception as e:
        logging.error(f"Error connecting to SSH host {hostname}: {str(e)}")
        return None

def execute_ssh_command(ssh, command):
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        return {
            "output": stdout.read().decode(),
            "error": stderr.read().decode()
        }
    except Exception as e:
        logging.error(f"Error executing SSH command: {str(e)}")
        return {"error": str(e)}

def save_data(data, filename):
    try:
        # Encrypt sensitive data before saving
        encrypted_data = fernet.encrypt(json.dumps(data).encode())

        with open(filename, 'wb') as f:
            f.write(encrypted_data)

        logging.info(f"Data saved to {filename}")
        return True
    except Exception as e:
        logging.error(f"Error saving data to {filename}: {str(e)}")
        return False

def load_data(filename):
    try:
        with open(filename, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        logging.error(f"Error loading data from {filename}: {str(e)}")
        return None

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
    return jsonify(scan_target(target))

@app.route('/api/whois', methods=['POST'])
def api_whois():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "No domain specified"}), 400
    return jsonify(whois_lookup(domain))

@app.route('/api/ssh-connect', methods=['POST'])
def api_ssh_connect():
    data = request.get_json()
    hostname = data.get('hostname')
    username = data.get('username')
    password = data.get('password')
    key_filename = data.get('key_filename')

    if not all([hostname, username]):
        return jsonify({"error": "Missing required parameters"}), 400

    ssh = ssh_connect(hostname, username, password, key_filename)
    if not ssh:
        return jsonify({"error": "Failed to connect"}), 500

    return jsonify({"message": "Connected successfully"})

@app.route('/api/ssh-command', methods=['POST'])
def api_ssh_command():
    data = request.get_json()
    command = data.get('command')
    if not command:
        return jsonify({"error": "No command specified"}), 400

    # Note: In a real application, you would maintain SSH connections in a session
    # This is just a demonstration
    return jsonify({"error": "SSH connection not maintained"}), 400

@app.route('/api/save-data', methods=['POST'])
def api_save_data():
    data = request.get_json()
    filename = data.get('filename')
    if not filename:
        return jsonify({"error": "No filename specified"}), 400

    success = save_data(data.get('data', {}), filename)
    return jsonify({"success": success})

@app.route('/api/load-data', methods=['POST'])
def api_load_data():
    data = request.get_json()
    filename = data.get('filename')
    if not filename:
        return jsonify({"error": "No filename specified"}), 400

    loaded_data = load_data(filename)
    return jsonify(loaded_data)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
