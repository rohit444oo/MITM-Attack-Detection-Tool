# MITM Detection Tool - Installation Guide for Kali Linux

This guide provides step-by-step instructions to install and run the MITM Detection Tool on Kali Linux.

## Prerequisites

- Kali Linux 2023.x or newer (or any Linux distribution with Python)
- Python 3.8 or higher
- Internet connection for downloading packages
- Root/sudo access

## Quick Start (5 minutes)

### Step 1: Clone the Repository

```bash
# Navigate to home directory
cd ~

# Clone or copy the project
git clone https://github.com/yourusername/mitmdec.git
cd mitmdec
```

### Step 2: Install Dependencies

```bash
# Update package manager
sudo apt-get update

# Install Python pip (if not already installed)
sudo apt-get install -y python3-pip

# Install Scapy library
sudo pip3 install scapy==2.5.0

# Verify installation
pip3 list | grep scapy
python3 -c "import scapy; print('Scapy installed:', scapy.__version__)"
```

### Step 3: Run the Tool

```bash
# Start the command-line version
sudo python3 main.py

# OR start the GUI version
sudo python3 gui_dashboard.py
```

## Detailed Installation Guide

### Method 1: Using APT Package Manager (Recommended)

```bash
# Update package lists
sudo apt-get update
sudo apt-get upgrade -y

# Install Python and dependencies
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libpcap-dev \
    git

# Install Scapy
sudo pip3 install scapy

# Install optional dependencies
sudo pip3 install pycryptodome  # For encrypted packet handling
```

### Method 2: Using Python Virtual Environment (Best Practice)

```bash
# Create virtual environment
python3 -m venv mitmdec_env

# Activate environment
source mitmdec_env/bin/activate

# Install dependencies in virtual environment
pip3 install -r requirements.txt

# When finished, deactivate:
# deactivate
```

### Method 3: Docker Container (Isolated Environment)

```bash
# Create Dockerfile
cat > Dockerfile <<'EOF'
FROM kalilinux/kali-last-release

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libpcap-dev

WORKDIR /app
COPY . /app

RUN pip3 install -r requirements.txt

CMD ["sudo", "python3", "main.py"]
EOF

# Build and run
docker build -t mitmdec .
docker run --net=host --privileged mitmdec
```

## Troubleshooting Installation

### Issue: "scapy not found" or "ModuleNotFoundError"

```bash
# Reinstall Scapy
sudo pip3 uninstall scapy
sudo pip3 install scapy==2.5.0

# Or install from github for latest version
sudo pip3 install git+https://github.com/secdev/scapy.git
```

### Issue: "Permission Denied" when running

```bash
# Ensure root privileges
sudo python3 main.py

# Or add user to pcap group (Kali Linux)
sudo usermod -a -G pcap $USER
sudo usermod -a -G wireshark $USER
newgrp pcap  # Activate new group

# Now can run without sudo:
python3 main.py
```

### Issue: "No module named 'scapy'"

```bash
# Check Python version (should be 3.8+)
python3 --version

# If using Python 2, use python3 explicitly
which python3
sudo /usr/bin/python3 -m pip install scapy

# Then run with:
sudo /usr/bin/python3 main.py
```

### Issue: Tkinter GUI not working

```bash
# Install tkinter
sudo apt-get install -y python3-tk

# Test tkinter
python3 -m tkinter  # Should open a window

# If still not working, reinstall
sudo apt-get remove python3-tk
sudo apt-get install python3-tk
```

## Network Interface Detection

### Finding Your Network Interface

```bash
# List all network interfaces
ip link show
# or
ifconfig

# Look for interfaces like:
# - eth0 (Ethernet)
# - wlan0 (WiFi)
# - tun0 (VPN tunnel)
```

### Setting the Interface in Configuration

```bash
# Edit config/config.py
nano config/config.py

# Find this line:
SNIFF_INTERFACE = None  # Auto-detect

# Change to:
SNIFF_INTERFACE = 'eth0'  # Your interface

# Save and exit (Ctrl+X, then Y, then Enter)
```

## Running the Tool

### Command Line Version

```bash
# Basic run
sudo python3 main.py

# Run in background with logging
sudo nohup python3 main.py > detection.log 2>&1 &

# Monitor the log
tail -f detection.log

# Stop the background process
pkill -f "python3 main.py"
```

### GUI Dashboard

```bash
# Run GUI version
sudo python3 gui_dashboard.py

# Features in GUI:
# - Start/Stop monitoring
# - View real-time statistics
# - Alert management
# - ARP table viewer
# - TCP session monitor
```

### As System Service (Advanced)

```bash
# Create systemd service file
sudo nano /etc/systemd/system/mitmdec.service
```

Paste this content:
```ini
[Unit]
Description=MITM Detection Tool
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/mitmdec
ExecStart=/usr/bin/python3 /root/mitmdec/main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then:
```bash
# Enable service
sudo systemctl enable mitmdec

# Start service
sudo systemctl start mitmdec

# Check status
sudo systemctl status mitmdec

# View logs
sudo journalctl -u mitmdec -f
```

## Verifying Successful Installation

```bash
# 1. Check Python version
python3 --version  # Should be 3.8+

# 2. Verify Scapy
python3 -c "from scapy.all import sniff, ARP, IP, TCP; print('✓ Scapy OK')"

# 3. Check directory structure
ls -la ~/mitmdec/
# Should show: config/, src/, logs/, main.py, gui_dashboard.py, etc.

# 4. Verify network access
sudo python3 -c "from scapy.all import get_if_list; print('Network interfaces:', get_if_list())"

# 5. Run tool with 10s timeout
timeout 10s sudo python3 main.py || true
# Should start and show "Captured X packets"
```

## Performance Tuning

### For Low-Resource Systems

```bash
# Edit config/config.py:
ABNORMAL_PACKET_RATE = 5000          # Raise threshold
ARP_SPOOF_THRESHOLD = 10             # Less sensitive
TCP_SESSION_TIMEOUT = 300            # Clean up faster
PACKET_BUFFER_SIZE = 50              # Smaller buffer
```

### For High-Traffic Networks

```bash
# Edit config/config.py:
PACKET_FILTER = "arp or (tcp port 22 or tcp port 443)"  # Filter traffic
MAX_CONCURRENT_SESSIONS = 5000                           # Track more
STATS_REFRESH_INTERVAL = 10                             # Less frequent updates
```

## Security Hardening

### Run as Non-Root (Advanced)

```bash
# Create dedicated user
sudo useradd -m -s /bin/bash mitmlogtool

# Give necessary capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3

# Run as user
sudo -u mitmlogtool python3 main.py
```

### Secure Log Files

```bash
# Change log permissions
sudo chmod 700 logs/
sudo chmod 600 logs/*.log

# Prevent tampering
sudo chattr +a logs/*  # Append-only (can't be modified)
sudo chattr -a logs/*  # Remove append-only when done
```

### Monitor the Monitor

```bash
# Watch process
watch -n 1 'ps aux | grep main.py'

# Monitor resource usage
nohup python3 -c "
import psutil
import time
while True:
    p = psutil.Process()
    print(f'CPU: {p.cpu_percent()}% Memory: {p.memory_info().rss/1024/1024:.1f}MB')
    time.sleep(5)
" &
```

## Updating the Tool

```bash
# Pull latest version
cd ~/mitmdec
git pull origin main

# Update dependencies
sudo pip3 install --upgrade -r requirements.txt
```

## Uninstallation

```bash
# Remove the project directory
rm -rf ~/mitmdec

# Remove Scapy (if not needed for other tools)
sudo pip3 uninstall scapy

# Remove any created logs
rm -rf ~/detection_logs
```

##FAQ

**Q: Do I need to run as root?**  
A: Yes, capturing raw network packets requires root/sudo privileges.

**Q: Can this work on WiFi networks (wlan0)?**  
A: Yes! Set `SNIFF_INTERFACE = 'wlan0'` in config.py

**Q: Can I run on a router?**  
A: Yes, if the router supports Linux/Python (OpenWrt, DD-WRT, etc.)

**Q: How much disk space is needed?**  
A: ~100 MB for the tool + logs (depends on network size and duration)

**Q: Can I monitor multiple interfaces?**  
A: Currently monitors one interface. For multiple, run multiple instances with different configs.

**Q: Is this a replacement for Wireshark?**  
A: No, Wireshark is for packet analysis. This tool is specifically for MITM detection alerts.

---

**Next Steps:**  
1. Run the tool: `sudo python3 main.py`
2. Check the logs: `ls -la logs/`
3. Read the main [README.md](README.md) for features and usage
4. Test the detection: [See Testing section in README](README.md#example-scenarios)

For issues or questions, check the Troubleshooting section or review the code comments.
