import os
import sys
import subprocess
import platform
import logging
from pathlib import Path

def setup_logging():
    logging.basicConfig(
        filename='setup.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def check_python_version():
    required_version = (3, 7)
    current_version = sys.version_info[:2]
    if current_version < required_version:
        logging.error(f"Python version {'.'.join(map(str, required_version))} or higher is required")
        return False
    return True

def install_nmap():
    system = platform.system().lower()
    try:
        if system == 'windows':
            # Check if nmap is already installed
            try:
                subprocess.run(['nmap', '--version'], capture_output=True, check=True)
                logging.info("Nmap is already installed")
                return True
            except subprocess.CalledProcessError:
                logging.info("Nmap is not installed. Please install it from https://nmap.org/download.html")
                return False
        elif system == 'linux':
            # Try to install nmap using package manager
            try:
                subprocess.run(['sudo', 'apt-get', 'install', 'nmap', '-y'], check=True)
                logging.info("Nmap installed successfully")
                return True
            except subprocess.CalledProcessError:
                logging.error("Failed to install nmap")
                return False
        elif system == 'darwin':
            # Try to install nmap using Homebrew
            try:
                subprocess.run(['brew', 'install', 'nmap'], check=True)
                logging.info("Nmap installed successfully")
                return True
            except subprocess.CalledProcessError:
                logging.error("Failed to install nmap")
                return False
    except Exception as e:
        logging.error(f"Error installing nmap: {str(e)}")
        return False

def install_python_packages():
    try:
        # Upgrade pip first
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)

        # Install requirements
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        logging.info("Python packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to install Python packages: {str(e)}")
        return False

def create_directories():
    try:
        # Create directories for data storage
        directories = ['data', 'logs']
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
            logging.info(f"Created directory: {directory}")
        return True
    except Exception as e:
        logging.error(f"Error creating directories: {str(e)}")
        return False

def main():
    setup_logging()
    logging.info("Starting setup process")

    # Check Python version
    if not check_python_version():
        print("Error: Python version requirement not met")
        return False

    # Install nmap
    if not install_nmap():
        print("Error: Failed to install or verify nmap installation")
        return False

    # Install Python packages
    if not install_python_packages():
        print("Error: Failed to install Python packages")
        return False

    # Create necessary directories
    if not create_directories():
        print("Error: Failed to create necessary directories")
        return False

    logging.info("Setup completed successfully")
    print("Setup completed successfully!")
    return True

if __name__ == "__main__":
    main()
