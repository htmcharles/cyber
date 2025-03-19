import os
import platform
import socket
import subprocess
import requests
import re
import json

def get_local_ip():
    """Retrieve the local IP address of the machine."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        return f"Error retrieving local IP: {e}"

def get_mac_address():
    """Retrieve the MAC address of the machine."""
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
    """Retrieve the router's IP address and other details."""
    try:
        output = subprocess.check_output("ipconfig" if platform.system() == "Windows" else "ip route", shell=True).decode()
        if platform.system() == "Windows":
            router_ip = re.search(r"Default Gateway.*?: (\d+\.\d+\.\d+\.\d+)", output)
        else:
            router_ip = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
        return router_ip.group(1) if router_ip else "Router IP not found"
    except Exception as e:
        return f"Error retrieving router details: {e}"

def get_isp_info():
    """Retrieve ISP information using an external API."""
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
    """Retrieve the list of connected devices on the network."""
    try:
        output = subprocess.check_output("arp -a" if platform.system() == "Windows" else "arp -n", shell=True).decode()
        devices = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:-]{17})", output)
        return [{"IP": ip, "MAC": mac} for ip, mac in devices] if devices else "No devices found"
    except Exception as e:
        return f"Error retrieving connected devices: {e}"

def get_connection_type():
    """Identify whether the connection is Ethernet or Wireless."""
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
        print("8. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            print(f"Local IP Address: {get_local_ip()}")
        elif choice == "2":
            print(f"MAC Address: {get_mac_address()}")
        elif choice == "3":
            print(f"Router Details: {get_router_details()}")
        elif choice == "4":
            isp_info = get_isp_info()
            print("ISP Information:")
            print(json.dumps(isp_info, indent=4))
        elif choice == "5":
            devices = get_connected_devices()
            print("Connected Devices:")
            print(json.dumps(devices, indent=4))
        elif choice == "6":
            print(f"Connection Type: {get_connection_type()}")
        elif choice == "7":
            print("\nNetwork Mapping Details\n" + "="*50)
            print(f"Local IP Address: {get_local_ip()}")
            print(f"MAC Address: {get_mac_address()}")
            print(f"Router Details: {get_router_details()}")
            print(f"Connection Type: {get_connection_type()}")
            isp_info = get_isp_info()
            print("\nISP Information:")
            print(json.dumps(isp_info, indent=4))
            devices = get_connected_devices()
            print("\nConnected Devices:")
            print(json.dumps(devices, indent=4))
        elif choice == "8":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")

if __name__ == "__main__":
    main()
