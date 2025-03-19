import os
import platform
import socket
import subprocess
import psutil
import requests
import re
import json
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
        router_ip = re.search(r"Default Gateway.*?: (\d+\.\d+\.\d+\.\d+)" if platform.system() == "Windows" else "default via (\d+\.\d+\.\d+\.\d+)", output)
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

def main():
    while True:
        print("\nNetwork Mapping Menu")
        print("="*30)
        print("1. Get Local IP Address")
        print("2. Get MAC Address")
        print("3. Get Router Details")
        print("4. Get ISP Information")
        print("5. Get Connected Devices")
        print("6. Get Connection Type")
        print("7. Show All Network Details")
        print("8. Get System Information")
        print("9. Get Network Statistics")
        print("10. Get Disk Usage")
        print("11. Monitor CPU Usage")
        print("12. Parse Authentication Logs")
        print("13. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            print(f"Local IP Address: {get_local_ip()}")
        elif choice == "2":
            print(f"MAC Address: {get_mac_address()}")
        elif choice == "3":
            print(f"Router Details: {get_router_details()}")
        elif choice == "4":
            print("ISP Information:", json.dumps(get_isp_info(), indent=4))
        elif choice == "5":
            print("Connected Devices:", json.dumps(get_connected_devices(), indent=4))
        elif choice == "6":
            print(f"Connection Type: {get_connection_type()}")
        elif choice == "7":
            print("\nComplete Network Overview", "="*50)
            print(f"Local IP: {get_local_ip()}")
            print(f"MAC Address: {get_mac_address()}")
            print(f"Router: {get_router_details()}")
            print("ISP Info:", json.dumps(get_isp_info(), indent=4))
            print("Devices:", json.dumps(get_connected_devices(), indent=4))
        elif choice == "8":
            print("System Info:", json.dumps(get_system_info(), indent=4))
        elif choice == "9":
            print(get_network_statistics())
        elif choice == "10":
            print("Disk Usage:", json.dumps(get_disk_usage(), indent=4))
        elif choice == "11":
            print(monitor_cpu_usage())
        elif choice == "12":
            print("Auth Logs:", "\n".join(parse_auth_log()))
        elif choice == "13":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
