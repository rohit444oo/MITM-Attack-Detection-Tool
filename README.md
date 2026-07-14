# MITM Attack Detection Tool

A comprehensive, production-ready cybersecurity monitoring system for detecting Man-in-the-Middle (MITM) attacks in real-time on Linux/Kali Linux networks.

## 🎯 Overview

This tool monitors network traffic in real-time and detects various MITM attack vectors including:
- **ARP Spoofing** - The most common MITM attack vector
- **TCP Session Anomalies** - Unusual connection patterns
- **Port Scanning** - Reconnaissance activity
- **DDoS Attacks** - Abnormal traffic patterns

## 📋 Table of Contents

1. [How MITM Attacks Work](#how-mitm-attacks-work)
2. [Detection Mechanisms](#detection-mechanisms)
3. [Features](#features)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Project Structure](#project-structure)
7. [Configuration](#configuration)
8. [Logs and Reports](#logs-and-reports)

---

## 🔴 How MITM Attacks Work

### Attack Chain

```
┌─────────────┐
│   Victim A  │  (192.168.1.10)
└──────┬──────┘
       │
       │ ARP Request: Who has 192.168.1.1?
       ▼
┌─────────────────┐          ┌──────────────┐
│  Router/gateway │◄────────►│   Attacker   │
│   192.168.1.1   │ ARP SPOOF │ 192.168.1.20 │
└─────────────────┘          └──────────────┘
       ▲
       │ Receives IP traffic
       │
```

### ARP Spoofing Attack Flow

1. **Normal Operation:**
   - Victim A wants to reach Router (IP: 192.168.1.1)
   - Victim asks: "Who has 192.168.1.1? Tell me your MAC"
   - Router replies: "I have 192.168.1.1, my MAC is AA:AA:AA:AA:AA:AA"
   - Victim stores: 192.168.1.1 → AA:AA:AA:AA:AA:AA

2. **Spoofing Attack:**
   - Attacker sends **fake ARP reply**: "I have 192.168.1.1, my MAC is BB:BB:BB:BB:BB:BB"
   - Victim updates ARP cache: 192.168.1.1 → BB:BB:BB:BB:BB:BB ❌ (WRONG!)
   - Now traffic to gateway goes to ATTACKER first
   - Attacker intercepts, reads, modifies, or drops packets

3 **Consequences:**
   - Data Exfiltration (stealing passwords, files, cookies)
   - Session Hijacking (taking over connections)
   - Malware Injection (modifying responses)
   - DoS Attacks (dropping traffic)

### Other MITM Techniques

- **DNS Spoofing:** Fake DNS responses redirecting to attacker's site
- **SSL/HTTPS Stripping:** Downgrading HTTPS to HTTP
- **Evil Twin WiFi:** Fake WiFi network luring users to connect

---

## 🔍 Detection Mechanisms

### 1. ARP Spoofing Detection

**Detection Logic:**

```
FOR EACH ARP PACKET:
  1. Extract Source IP and Source MAC
  2. Check if we've seen this IP before
  3. IF we have:
     a. Compare stored MAC with current MAC
     b. IF different:
        - ALERT: ARP SPOOF DETECTED!
        - Log the change
        - Record both MACs
  4. Track MAC changes for each IP in time window
  5. IF same IP has 5+ different MACs in 60 seconds:
     - ALERT: Excessive ARP activity
```

**Why This Works:**
- Normal networks should have stable IP-MAC mappings
- A host's MAC address doesn't change frequently
- Multiple different MACs for one IP = Spoofing attempt
- Rapid MAC changes indicate active MITM attack

**Python Implementation:**
```python
def _check_arp_spoofing(self, ip, mac):
    existing_mac = self.arp_table[ip]['mac']
    
    if existing_mac != mac:  # Different MAC for same IP!
        self._handle_arp_spoof_alert(ip, existing_mac, mac)
```

### 2. TCP Session Anomaly Detection

**Monitored Parameters:**
- **Packet Count:** Track packets per session
- **Flags:** Monitor SYN, ACK, FIN, RST flags
- **Payload Size:** Detect unusually large transfers
- **Session Duration:** Track how long connections last
- **Packet Rate:** Detect abnormal transmission speed

**SYN Flood Detection:**
```python
# SYN floods have many SYN packets but few ACKs
syn_count = len([f for f in flags if f & 0x02])
ack_count = len([f for f in flags if f & 0x10])

if syn_count > 10 and ack_count < 2:
    ALERT("Possible SYN Flood Attack")
```

### 3. Port Scanning Detection

**Logic:**
```
FOR EACH TCP PACKET:
  1. Track unique destination ports per source IP
  2. IF source connects to 20+ different ports in short time:
     - ALERT: Port Scanning Detected!
     - Indicates reconnaissance before MITM attack
```

Port scanning is often the first step in attacking a network.

### 4. DDoS Attack Detection

**Indicators:**
- Source IP sending >1000 packets/second (configurable)
- Multiple TCP connections to same port
- Rapid SYN packets followed by RST (SYN flood)
- Unusually large payload sizes (>64KB)

---

## ✨ Features

### Core Detection

- ✅ **Real-time Packet Capture** - Uses Scapy for network sniffing
- ✅ **ARP Spoofing Detection** - Identifies fake ARP replies
- ✅ **TCP Anomaly Detection** - Detects unusual sessions
- ✅ **Port Scanning Detection** - Identifies reconnaissance
- ✅ **DDoS Detection** - Alerts on abnormal traffic

### Alert System

- 🔔 **Console Alerts** - Colored output in terminal
- 🔊 **Sound Alerts** - System beep with different tones per severity
- 🖼️ **GUI Popups** - Desktop notifications (optional)
- 📝 **Severity Levels** - LOW, MEDIUM, HIGH, CRITICAL

### Logging & Reporting

- 📋 **Main Log** - All activity with timestamps
- 🚨 **Alert Log** - Only security-related events
- 📊 **ARP Log** - ARP spoofing details
- 🌐 **TCP Log** - TCP anomalies

### User Interface

- 💻 **Command Line** - Real-time statistics in terminal
- 🎨 **GUI Dashboard** - Tkinter-based monitoring interface
- 📈 **Live Statistics** - Real-time metrics
- 📋 **Alert Management** - View and analyze alerts

---

## 🚀 Installation

### Prerequisites

- **Linux/Kali Linux** (or any Linux distribution)
- **Python 3.7+**
- **Root/sudo privileges** (required for packet capture)
- **pip** (Python package manager)

### Step 1: Clone/Download the Project

```bash
cd ~/
git clone https://github.com/yourusername/mitmdec.git
cd mitmdec
```

Or navigate to your existing `mitmdec` directory.

### Step 2: Install Python Dependencies

```bash
# Install required packages
sudo pip3 install -r requirements.txt

# Or manually:
sudo pip3 install scapy==2.5.0
```

### Step 3: Make Scripts Executable

```bash
chmod +x main.py
chmod +x gui_dashboard.py
```

### Step 4: Verify Installation

```bash
# Test that Scapy is installed
python3 -c "import scapy; print('Scapy version:', scapy.__version__)"
```

---

## 💻 Usage

### Option 1: Command Line Version (Recommended for Servers)

```bash
# Run with root privileges
sudo python3 main.py
```

**Output will show:**
```
╔════════════════════════════════════════════════════════════════╗
║         MITM ATTACK DETECTION TOOL                            ║
║         Cybersecurity Monitoring System                       ║
║                                                                ║
║  Features:                                                     ║
║  - ARP Spoofing Detection                                     ║
║  - TCP Session Monitoring                                    ║
║  - Real-time Alerts                                          ║
║  - Comprehensive Logging                                     ║
╚════════════════════════════════════════════════════════════════╝

[+] MITM Detection Tool is running...
[+] Monitoring on interface: eth0
[+] Press Ctrl+C to stop

[INFO] Initializing MITM Detection Tool...
[INFO] Started packet capture on eth0
```

**Once running:**
- Real-time alerts appear with color-coding
- Statistics update every 5 seconds
- Press `Ctrl+C` to gracefully stop

### Option 2: GUI Dashboard (Recommended for Desktops)

```bash
# Run GUI dashboard with root privileges (needed for packet capture)
sudo python3 gui_dashboard.py
```

**GUI Features:**
- 📊 **Statistics Tab** - Real-time metrics
- 🚨 **Alerts Tab** - Recent security alerts
- 🔍 **ARP Monitor** - IP-MAC mappings
- 🌐 **TCP Sessions** - Active connections
- 📝 **Log Output** - Live activity log

**Controls:**
- Click **▶ Start** to begin monitoring
- Click **⏹ Stop** to end monitoring
- Use menu options to view detailed tables
- Check logs in real-time

### Option 3: Run in Background (Server Mode)

```bash
# Run tool and save output to file
sudo nohup python3 main.py > detection.log 2>&1 &

# Monitor the log in real-time
tail -f detection.log

# Find and kill the process later
ps aux | grep main.py
sudo kill <PID>
```

---

## 📁 Project Structure

```
mitmdec/
├── main.py                  # Main application entry point
├── gui_dashboard.py         # GUI dashboard (Tkinter)
├── requirements.txt         # Python dependencies
├── README.md               # This file
│
├── src/                    # Source code modules
│   ├── __init__.py
│   ├── packet_capture.py   # Network packet sniffing
│   ├── arp_detector.py     # ARP spoofing detection
│   ├── tcp_monitor.py      # TCP session monitoring
│   ├── alert_system.py     # Alert management
│   └── logger.py           # Logging system
│
├── config/                 # Configuration files
│   └── config.py          # All tunable parameters
│
└── logs/                  # Log files (created at runtime)
    ├── mitm_detector.log         # Main activity log
    ├── alerts.log               # Security alerts only
    ├── arp_spoofing.log         # ARP spoofing details
    └── tcp_anomalies.log        # TCP anomalies
```

---

## ⚙️ Configuration

Edit `config/config.py` to customize the tool:

### Logging Settings
```python
# Log files location
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
MAIN_LOG_FILE = os.path.join(LOG_DIR, 'mitm_detector.log')
ALERT_LOG_FILE = os.path.join(LOG_DIR, 'alerts.log')

# Enable/disable logging
ENABLE_FILE_LOGGING = True
ENABLE_CONSOLE_OUTPUT = True
```

### ARP Detection Parameters
```python
# Alert if same IP has this many different MACs in short time
ARP_SPOOF_THRESHOLD = 5

# How long to cache ARP mappings
ARP_CACHE_TIMEOUT = 3600  # 1 hour

# Time window for detecting duplicate IPs
ARP_DUPLICATE_WINDOW = 60  # 1 minute
```

### TCP Detection Parameters
```python
# Alert if > 1000 packets/second from single IP
ABNORMAL_PACKET_RATE = 1000

# Alert for packets larger than 64KB
ABNORMAL_PAYLOAD_SIZE = 65535

# How long before closing inactive sessions
TCP_SESSION_TIMEOUT = 600  # 10 minutes
```

### Network Interface
```python
# Auto-detect interface, or specify manually:
SNIFF_INTERFACE = None      # Auto-detect (eth0, wlan0, etc.)
# SNIFF_INTERFACE = 'eth0'  # Or force specific interface
```

### Alert Methods
```python
ENABLE_SOUND_ALERT = True      # System beep alerts
ENABLE_GUI_POPUP = True        # Desktop notifications
ENABLE_CONSOLE_OUTPUT = True   # Print to terminal
```

---

## 📊 Logs and Reports

### Log Files Location
```
mitmdec/logs/
├── mitm_detector.log      # All debug information
├── alerts.log            # Security alerts with timestamps
├── arp_spoofing.log      # ARP spoofing incidents
└── tcp_anomalies.log     # TCP session anomalies
```

### Example Log Entries

**alerts.log:**
```
2024-04-03 14:25:33 - WARNING - [mitm_alerts] [CRITICAL] [ARP_SPOOFING] IP 192.168.1.5 with different MACs detected
2024-04-03 14:26:01 - WARNING - [mitm_alerts] [HIGH] [PORT_SCANNING] 192.168.1.50: Port scanning detected
2024-04-03 14:27:15 - WARNING - [mitm_alerts] [HIGH] [TCP_ANOMALY] 192.168.1.60 -> 8.8.8.8: Abnormal packet rate
```

**arp_spoofing.log:**
```
2024-04-03 14:25:33 - WARNING - [arp_spoof] ARP SPOOF DETECTED: IP 192.168.1.5 spoofed - MAC1: aa:bb:cc:dd:ee:ff -> MAC2: 11:22:33:44:55:66
```

### Viewing Logs in Real-time

```bash
# Watch main activity log
tail -f logs/mitm_detector.log

# Watch alerts only
tail -f logs/alerts.log

# Search for specific attack types
grep "ARP_SPOOFING" logs/alerts.log
grep "PORT_SCANNING" logs/alerts.log

# Count alerts by type
grep "ARP_SPOOFING" logs/alerts.log | wc -l
```

---

## 🛡️ Security Best Practices

### 1. Deploy on Secure Network

⚠️ **Important:** Run this tool on:
- Production network monitoring infrastructure
- Isolated security monitoring systems
- Network security operations center (SOC)
- Never a workstation with internet access

### 2. Rotate Logs Regularly

```bash
# Archive old logs weekly
tar -czf logs_backup_$(date +%Y%m%d).tar.gz logs/

# Delete logs older than 30 days
find logs/ -mtime +30 -delete
```

### 3. Monitor the Monitors

- Ensure the detection tool itself isn't compromised
- Run integrity checks on Python files
- Monitor CPU/memory usage for anomalies
- Verify log file permissions (read-only after rotation)

### 4. Correlate with Other Tools

Combine with:
- Network flow analysis (Wireshark, Zeek/Bro)
- Host-based IDS (OSSEC, Wazuh)
- SIEM systems (ELK Stack, Splunk)
- Firewall logs and IPS logs

---

## 📈 Performance Considerations

### Resource Usage

- **Memory:** ~50-100 MB (depends on tracked connections)
- **CPU:** 5-15% (single packet per second rate)
- **Network:** Passive monitoring (no extra traffic)

### Scaling for Large Networks

For networks with 1000+ devices:

1. **Filter non-essential packets:**
   ```python
   # Only monitor critical subnets
   PACKET_FILTER = "arp or (tcp port 22 or tcp port 443 or tcp port 80)"
   ```

2. **Increase cleanup intervals:**
   ```python
   TCP_SESSION_TIMEOUT = 300  # 5 minutes instead of 10
   ```

3. **Disable low-priority checks:**
   ```python
   # In tcp_monitor.py, skip port scanning check
   # self._check_port_scanning(src_ip, dst_port)
   ```

---

## 🐛 Troubleshooting

### Issue: "Permission Denied" Error

```
ERROR: This tool requires root/administrator privileges!
```

**Solution:**
```bash
# Run with sudo
sudo python3 main.py

# Or give sudo permissions without password (advanced)
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/python3" | sudo tee /etc/sudoers.d/mitmdec
sudo python3 main.py
```

### Issue: No Packets Captured

```bash
# Check if interface is correct
ip link show          # List all interfaces
sudo python3 -c "from scapy.all import get_if_list; print(get_if_list())"

# Manually specify interface
# Edit config/config.py:
SNIFF_INTERFACE = 'eth0'  # Change to correct interface
```

### Issue: High CPU Usage

**Solution:** Reduce detection sensitivity:
```python
# In config.py
ARP_SPOOF_THRESHOLD = 10        # Raise from 5
ABNORMAL_PACKET_RATE = 5000     # Raise from 1000
```

### Issue: Logs Not Creating

```bash
# Check directory permissions
ls -la logs/
chmod 755 logs/

# Manual run to see errors
python3 main.py  # (without sudo first to see import errors)
```

---

## 🔧 Advanced Usage

### Testing ARP Spoofing Detection

On another machine, trigger an ARP spoof:

```bash
# Install arpspoof
sudo apt-get install dsniff

# Spoof ARP (replace with actual IPs)
sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1

# The MITM detector should immediately alert!
```

### Integrating with SIEM

Send logs to ELK Stack:

```bash
# Install Filebeat
curl https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.14.1-linux-x86_64.tar.gz | tar xz

# Configure Filebeat to monitor our logs
# Edit filebeat.yml and point to logs/ directory
```

### Custom Alert Integrations

Modify `alert_system.py` to:
- Send Slack notifications
- Email alerts
- Webhook POST requests
- Custom database logging

---

## 📝 Example Scenarios

### Scenario 1: Detecting ARP Spoofing Attack

1. Start tool: `sudo python3 main.py`
2. On another machine, run: `sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1`
3. **Detection Tool Output:**
   ```
   [CRITICAL] ARP SPOOFING DETECTED!
   IP Address: 192.168.1.1
   Previous MAC: aa:bb:cc:dd:ee:ff
   New MAC: 11:22:33:44:55:66
   This is a classic MITM attack signature!
   ```

### Scenario 2: DDoS Attack Detection

1. Start tool on target machine
2. Launch SYN flood: `sudo hping3 -S -p 80 --flood target_machine`
3. **Detection Tool Output:**
   ```
   [HIGH] ABNORMAL PACKET RATE!
   Source IP: 192.168.1.50
   Packets per second: 5423
   This may indicate DDoS or port scanning
   ```

### Scenario 3: Port Scanning Detection

1. Start tool on target network
2. Run Nmap from attacker: `nmap -p- target_network`
3. **Detection Tool Output:**
   ```
   [HIGH] PORT SCANNING DETECTED!
   Source IP: 192.168.1.50
   Unique ports accessed: 25
   This is reconnaissance activity preceding MITM attacks
   ```

---

## 📚 References

### MITM Attack Resources
- [OWASP: Man-in-the-Middle Attack](https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack)
- [RFC 826: An Ethernet Address Resolution Protocol](https://tools.ietf.org/html/rfc826)
- [ARP Spoofing - Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing)

### Detection Techniques
- [Zeek IDS ARP Detection](https://docs.zeek.org/en/master/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Network Anomaly Detection](https://en.wikipedia.org/wiki/Anomaly_detection)

### Tools & Systems
- [Wireshark - Network Protocol Analyzer](https://www.wireshark.org/)
- [Suricata IDS/IPS](https://suricata.io/)
- [ELK Stack - Log Management](https://www.elastic.co/what-is/elk-stack)

---

## 📄 License

This project is provided for educational and security research purposes.

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- DNS spoofing detection
- SSL/TLS stripping detection
- IPv6 ARP (neighbor discovery) support
- Machine learning for anomaly detection
- Performance optimizations

---

## ⚖️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized network security monitoring
- ✅ Security research and education
- ✅ Penetration testing (with permission)

⚠️ Unauthorized access to computer networks is **ILLEGAL**. Only use this tool on networks you own or have explicit written permission to test.

---

**Created for cybersecurity professionals and network administrators**  
Version: 1.0  
Last Updated: 2024-04-03

This project is forked from original repository.
I have reviewed and modified the project.

Changes:
- Updated README
- Tested basic functionality
hi 
