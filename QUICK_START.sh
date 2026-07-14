#!/bin/bash

# MITM Detection Tool - Quick Start Script
# Run this script to quickly set up and start the tool on Kali Linux

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     MITM ATTACK DETECTION TOOL - Quick Start                  ║"
echo "║     Setup and Initialization Script                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root or with sudo"
   echo "    Usage: sudo ./QUICK_START.sh"
   exit 1
fi

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[1/6] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing..."
    apt-get update
    apt-get install -y python3 python3-pip
else
    PYTHON_VERSION=$(python3 --version)
    echo "[✓] $PYTHON_VERSION found"
fi

echo ""
echo "[2/6] Checking Scapy installation..."
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "[!] Scapy not found. Installing..."
    pip3 install scapy==2.5.0
else
    echo "[✓] Scapy is installed"
fi

echo ""
echo "[3/6] Checking Tkinter installation..."
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "[!] Tkinter not found. Installing..."
    apt-get install -y python3-tk
else
    echo "[✓] Tkinter is installed"
fi

echo ""
echo "[4/6] Creating required directories..."
mkdir -p logs/
chmod 755 logs/
echo "[✓] Logs directory created"

echo ""
echo "[5/6] Verifying installation..."
python3 -c "
from src.packet_capture import PacketCapture
from src.arp_detector import ARPDetector
from src.tcp_monitor import TCPMonitor
from src.alert_system import alert_system
from src.logger import mitm_logger
print('[✓] All modules imported successfully')
"

if [ $? -ne 0 ]; then
    echo "[!] Verification failed!"
    exit 1
fi

echo ""
echo "[6/6] Installation complete!"
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   SETUP SUCCESSFUL                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "To run the tool, choose an option:"
echo ""
echo "Option 1: Command-line version (Recommended for servers)"
echo "  $ sudo python3 main.py"
echo ""
echo "Option 2: GUI Dashboard (Recommended for desktops)"
echo "  $ sudo python3 gui_dashboard.py"
echo ""
echo "Option 3: Background mode (Server with logging)"
echo "  $ sudo nohup python3 main.py > detection.log 2>&1 &"
echo ""
echo "For more information, see README.md or INSTALLATION_GUIDE.md"
echo ""
