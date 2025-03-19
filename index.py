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
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import ipaddress
import struct
from typing import Dict, List, Optional
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Create logs directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging with rotation
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = RotatingFileHandler(
    'logs/network_scan.log',
    maxBytes=1024 * 1024,  # 1MB
    backupCount=5
)
log_handler.setFormatter(log_formatter)
logger = logging.getLogger('NetworkScanner')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Add console handler for development
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

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

# Add new constants after the existing ones
SCAN_RESULTS_DIR = "scan_results"
VULNERABILITY_DATABASE = "vulnerability_database.json"

# Add new constants
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    8080: 'HTTP-Proxy'
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
                logger.info(f"Installed package: {package}")
            except Exception as e:
                logger.error(f"Failed to install {package}: {str(e)}")
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
        logger.error(f"Anonymity check failed: {str(e)}")
        return {"error": str(e)}

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
    """Scan a single port and return service information if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
            except:
                return {
                    "port": port,
                    "state": "open",
                    "service": "unknown"
                }
        return None
    except:
        return None
    finally:
        sock.close()

def scan_host(ip: str) -> Dict:
    """Perform a comprehensive scan of a single host."""
    host_info = {
        "ip": ip,
        "hostname": "",
        "state": "unknown",
        "ports": {},
        "os_info": {},
        "vulnerabilities": []
    }

    try:
        # Get hostname
        host_info["hostname"] = socket.gethostbyaddr(ip)[0]
    except:
        host_info["hostname"] = "Unknown"

    # Scan ports using thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in COMMON_PORTS.keys()}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                host_info["ports"][result["port"]] = result

    # Basic OS detection using TTL
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, 80))
        ttl = struct.unpack('!B', sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)[0])[0]
        if ttl <= 64:
            host_info["os_info"]["type"] = "Linux/Unix"
        else:
            host_info["os_info"]["type"] = "Windows"
    except:
        host_info["os_info"]["type"] = "Unknown"

    # Check for common vulnerabilities
    vulnerabilities = check_common_vulnerabilities(ip, host_info["ports"])
    host_info["vulnerabilities"] = vulnerabilities

    return host_info

def check_common_vulnerabilities(ip: str, ports: Dict) -> List[Dict]:
    """Check for common vulnerabilities based on open ports and services."""
    vulnerabilities = []

    # Check for weak SSH configuration
    if 22 in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 22))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if "OpenSSH" in banner and "7.0" in banner:
                vulnerabilities.append({
                    "type": "SSH",
                    "description": "Potentially outdated OpenSSH version",
                    "severity": "Medium"
                })
        except:
            pass

    # Check for weak HTTP configuration
    if 80 in ports or 443 in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            port = 443 if 443 in ports else 80
            sock.connect((ip, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if "Server:" in response:
                server = response.split("Server:")[1].split("\r\n")[0].strip()
                if "Apache/2.4.49" in server or "Apache/2.4.50" in server:
                    vulnerabilities.append({
                        "type": "HTTP",
                        "description": "Potentially vulnerable Apache version",
                        "severity": "High"
                    })
        except:
            pass

    return vulnerabilities

def scan_network_range(network_range: str) -> Dict:
    """Perform comprehensive network scan using pure Python."""
    try:
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "network_range": network_range,
            "hosts": {},
            "summary": {}
        }

        # Parse network range
        try:
            network = ipaddress.ip_network(network_range)
        except ValueError:
            return {"error": "Invalid network range format"}

        # Scan hosts using thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_ip = {executor.submit(scan_host, str(ip)): str(ip) for ip in network.hosts()}
            for future in concurrent.futures.as_completed(future_to_ip):
                host_info = future.result()
                if host_info["ports"]:  # Only include hosts with open ports
                    scan_results["hosts"][host_info["ip"]] = host_info

        scan_results["summary"]["total_hosts"] = len(scan_results["hosts"])

        # Save results
        filename = f"{SCAN_RESULTS_DIR}/network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(scan_results, f, indent=4)

        return scan_results
    except Exception as e:
        logger.error(f"Network scan failed: {str(e)}")
        return {"error": str(e)}

def scan_vulnerabilities(target: str) -> Dict:
    """Perform vulnerability scanning using pure Python."""
    try:
        vulnerabilities = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "findings": []
        }

        # Perform host scan
        host_info = scan_host(target)

        # Add port-based vulnerabilities
        for port, info in host_info["ports"].items():
            if info["state"] == "open":
                vulnerabilities["findings"].append({
                    "tool": "port_scan",
                    "type": "open_port",
                    "port": port,
                    "service": info["service"],
                    "description": f"Open port {port} running {info['service']}"
                })

        # Add OS-based vulnerabilities
        if host_info["os_info"].get("type"):
            vulnerabilities["findings"].append({
                "tool": "os_detection",
                "type": "os_info",
                "os": host_info["os_info"]["type"],
                "description": f"Detected OS: {host_info['os_info']['type']}"
            })

        # Add service-specific vulnerabilities
        for vuln in host_info["vulnerabilities"]:
            vulnerabilities["findings"].append({
                "tool": "service_check",
                "type": "vulnerability",
                "description": vuln["description"],
                "severity": vuln["severity"]
            })

        # Save vulnerability results
        filename = f"{SCAN_RESULTS_DIR}/vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(vulnerabilities, f, indent=4)

        return vulnerabilities
    except Exception as e:
        logger.error(f"Vulnerability scan failed: {str(e)}")
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
        logger.error(f"SSH connection failed: {str(e)}")
        return {"error": str(e)}

def save_scan_results(results, filename=None):
    """Save scan results to a file."""
    try:
        if filename is None:
            filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)

        logger.info(f"Scan results saved to {filename}")
        return {"status": "success", "filename": filename}
    except Exception as e:
        logger.error(f"Failed to save scan results: {str(e)}")
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
        logger.error(f"Network discovery failed: {str(e)}")
        return []

def simulate_network_attack(attack_type, target_ip):
    """Simulate a network attack and log the results."""
    try:
        if attack_type not in NETWORK_ATTACKS:
            return {"error": "Invalid attack type"}

        attack_info = NETWORK_ATTACKS[attack_type]
        start_time = time.time()

        # Log attack initiation
        logger.info(f"Starting {attack_info['name']} on target {target_ip}")

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
        logger.info(f"Completed {attack_info['name']} on {target_ip}. Duration: {duration:.2f}s")

        return {
            "attack_type": attack_type,
            "target_ip": target_ip,
            "duration": duration,
            "output": result.stdout,
            "status": "completed"
        }
    except Exception as e:
        logger.error(f"Attack simulation failed: {str(e)}")
        return {"error": str(e)}

def get_random_attack():
    """Get a random attack type from the available attacks."""
    return random.choice(list(NETWORK_ATTACKS.keys()))

def create_scan_directory():
    """Create directory for storing scan results if it doesn't exist."""
    if not os.path.exists(SCAN_RESULTS_DIR):
        os.makedirs(SCAN_RESULTS_DIR)
        logger.info(f"Created scan results directory: {SCAN_RESULTS_DIR}")

def generate_scan_report(scan_results, vuln_results):
    """Generate a comprehensive scan report."""
    try:
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_hosts": scan_results.get("summary", {}).get("total_hosts", 0),
                "vulnerabilities_found": len(vuln_results.get("findings", [])),
                "scan_duration": "N/A"  # Could be calculated from timestamps
            },
            "hosts": scan_results.get("hosts", {}),
            "vulnerabilities": vuln_results.get("findings", [])
        }

        # Save report
        filename = f"{SCAN_RESULTS_DIR}/scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)

        return report
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return {"error": str(e)}

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

    try:
        # Enhanced domain resolution
        try:
            # Try to resolve domain to IP
            ip = socket.gethostbyname(target)

            # Get additional DNS information
            try:
                dns_info = socket.getaddrinfo(target, None)
                dns_details = {
                    "ipv4": [],
                    "ipv6": [],
                    "aliases": []
                }

                for addr in dns_info:
                    if addr[0] == socket.AF_INET:
                        dns_details["ipv4"].append(addr[4][0])
                    elif addr[0] == socket.AF_INET6:
                        dns_details["ipv6"].append(addr[4][0])

                # Get domain aliases
                try:
                    dns_details["aliases"] = socket.gethostbyaddr(ip)[1]
                except:
                    pass
            except:
                dns_details = {"error": "Could not get detailed DNS information"}

        except socket.gaierror as e:
            return jsonify({
                "error": f"Could not resolve domain: {target}",
                "details": str(e),
                "suggestion": "Please check if the domain is correct and if you have an active internet connection"
            }), 400

        scan_results = {
            "target": target,
            "ip": ip,
            "dns_info": dns_details,
            "timestamp": datetime.now().isoformat(),
            "ports": {},
            "os_info": {},
            "vulnerabilities": []
        }

        # Port scanning
        for port, service in COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    try:
                        service_info = socket.getservbyport(port)
                        banner = ""
                        try:
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        except:
                            pass
                        scan_results["ports"][port] = {
                            "state": "open",
                            "service": service_info,
                            "banner": banner
                        }
                    except:
                        scan_results["ports"][port] = {
                            "state": "open",
                            "service": service
                        }
                sock.close()
            except Exception as e:
                logger.warning(f"Error scanning port {port}: {str(e)}")

        # OS detection using TTL
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, 80))
            ttl = struct.unpack('!B', sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)[0])[0]
            if ttl <= 64:
                scan_results["os_info"]["type"] = "Linux/Unix"
            else:
                scan_results["os_info"]["type"] = "Windows"
        except:
            scan_results["os_info"]["type"] = "Unknown"

        # Check for common vulnerabilities
        vulnerabilities = check_common_vulnerabilities(ip, scan_results["ports"])
        scan_results["vulnerabilities"] = vulnerabilities

        return jsonify(scan_results)
    except Exception as e:
        logger.error(f"Scan failed for target {target}: {str(e)}")
        return jsonify({
            "error": str(e),
            "target": target,
            "timestamp": datetime.now().isoformat()
        }), 500

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

@app.route('/api/scan-network', methods=['POST'])
def api_scan_network():
    data = request.get_json()
    network_range = data.get('network_range')

    if not network_range:
        return jsonify({"error": "No network range specified"}), 400

    create_scan_directory()
    scan_results = scan_network_range(network_range)
    return jsonify(scan_results)

@app.route('/api/scan-vulnerabilities', methods=['POST'])
def api_scan_vulnerabilities():
    data = request.get_json()
    target = data.get('target')

    if not target:
        return jsonify({"error": "No target specified"}), 400

    vuln_results = scan_vulnerabilities(target)
    return jsonify(vuln_results)

@app.route('/api/generate-report', methods=['POST'])
def api_generate_report():
    data = request.get_json()
    scan_results = data.get('scan_results')
    vuln_results = data.get('vuln_results')

    if not scan_results or not vuln_results:
        return jsonify({"error": "Missing scan or vulnerability results"}), 400

    report = generate_scan_report(scan_results, vuln_results)
    return jsonify(report)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
