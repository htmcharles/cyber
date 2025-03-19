import os
import platform
import psutil
import socket
import subprocess
from datetime import datetime

def get_system_info():
    """Retrieve system details"""
    system_data = {
        "OS": platform.system(),
        "Version": platform.version(),
        "Architecture": platform.architecture()[0],
        "Processor": platform.processor(),
        "Machine": platform.machine(),
        "Hostname": socket.gethostname()
    }
    return system_data

def get_network_info():
    """Retrieve network information"""
    net_info = {
        "Hostname": socket.gethostname(),
        "Local IP": socket.gethostbyname(socket.gethostname()),
        "Interfaces": {}
    }
    for iface, addrs in psutil.net_if_addrs().items():
        net_info["Interfaces"][iface] = [addr.address for addr in addrs if addr.family == socket.AF_INET]
    return net_info

def get_disk_usage():
    """Retrieve disk usage details"""
    partitions = psutil.disk_partitions()
    disk_usage = {}
    for partition in partitions:
        usage = psutil.disk_usage(partition.mountpoint)
        disk_usage[partition.mountpoint] = {
            "Total": usage.total,
            "Used": usage.used,
            "Free": usage.free,
            "Percentage": usage.percent
        }
    return disk_usage

def get_largest_directories(path="/"):
    """Find the 5 largest directories"""
    dir_sizes = {}
    for root, dirs, files in os.walk(path):
        total_size = sum(os.path.getsize(os.path.join(root, f)) for f in files if os.path.exists(os.path.join(root, f)))
        dir_sizes[root] = total_size
    return sorted(dir_sizes.items(), key=lambda x: x[1], reverse=True)[:5]

def monitor_cpu_usage(interval=5):
    """Monitor CPU usage in real-time"""
    print("Monitoring CPU Usage (Press Ctrl+C to stop)")
    try:
        while True:
            print(f"CPU Usage: {psutil.cpu_percent(interval=interval)}%")
    except KeyboardInterrupt:
        print("\nCPU Monitoring stopped.")

def parse_auth_log(log_file="/var/log/auth.log"):
    """Parse authentication log for security events"""
    if not os.path.exists(log_file):
        return "Log file not found."
    events = []
    with open(log_file, 'r') as log:
        for line in log:
            if "Failed password" in line or "Accepted password" in line:
                timestamp = line.split()[0:3]
                events.append({
                    "timestamp": " ".join(timestamp),
                    "event": line.strip()
                })
    return events

def main():
    """Main function to interactively choose what to retrieve"""
    while True:
        print("\nSystem Monitoring Tool")
        print("1. System Info")
        print("2. Network Info")
        print("3. Disk Usage")
        print("4. Largest Directories")
        print("5. Monitor CPU Usage")
        print("6. Parse Auth Logs")
        print("7. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            print(get_system_info())
        elif choice == "2":
            print(get_network_info())
        elif choice == "3":
            print(get_disk_usage())
        elif choice == "4":
            print(get_largest_directories())
        elif choice == "5":
            monitor_cpu_usage()
        elif choice == "6":
            print(parse_auth_log())
        elif choice == "7":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
