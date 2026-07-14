# MITM Detection Tool - Usage Examples & Tutorials

Practical examples and tutorials for using the detection tool in various scenarios.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Advanced Scenarios](#advanced-scenarios)
3. [Network Monitoring Setup](#network-monitoring-setup)
4. [Integration Examples](#integration-examples)
5. [Troubleshooting Guide](#troubleshooting-guide)

---

## Basic Usage

### Example 1: Start Detection (Command Line)

**Scenario:** Monitor a specific network interface for MITM attacks

**Command:**
```bash
sudo python3 main.py
```

**Expected Output:**
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

======================================================================
[2024-04-03 14:25:32] DETECTION STATISTICS
======================================================================
PACKET CAPTURE:
  Total Packets: 1234
  Interface: eth0

ARP SPOOFING DETECTION:
  ARP Packets: 456
  Tracked IPs: 23
  Suspicious Mappings: 0
  Suspicious IPs: 0
  Alerts: 0

TCP SESSION MONITORING:
  TCP Packets: 778
  Active Sessions: 12
  Anomalies Detected: 0
  Alerts: 0

ALERT SUMMARY:
  Total Alerts: 0
  By Type: {}
  By Severity: {}
======================================================================
```

**What's Happening:**
1. Tool starts and detects interface `eth0`
2. Begins capturing packets
3. Analyzes ARP packets for spoofing
4. Monitors TCP connections
5. Reports statistics every 5 seconds
6. Updates alerts and logs in real-time

**Stopping:** Press `Ctrl+C` to gracefully stop

---

### Example 2: Start GUI Dashboard

**Scenario:** Monitor attacks visually with dashboard

**Command:**
```bash
sudo python3 gui_dashboard.py
```

**Expected Window:**
- Title: "MITM Attack Detection Tool - Dashboard"
- Size: 1000x700 pixels
- Tabs: Statistics, Alerts, ARP Monitor, TCP Sessions
- Controls: Start/Stop buttons
- Live log output at bottom

**Using the GUI:**
1. Click **▶ Start** to begin monitoring
2. Switch between tabs to view different data
3. Statistics update every 1 second
4. Alerts appear in real-time in the Alerts tab
5. Click **Refresh** buttons to manually update tables

---

### Example 3: Background Monitoring with Logging

**Scenario:** Run on a server with persistent logging

**Command:**
```bash
# Start in background
sudo nohup python3 main.py > detection.log 2>&1 &

# Show output in real-time
tail -f detection.log

# Get PID of running process
ps aux | grep main.py

# Kill the process later
kill <PID>
```

**Output File:**
- `detection.log` - Contains all console output
- `logs/mitm_detector.log` - Tool's detailed log
- `logs/alerts.log` - Only security alerts

---

## Advanced Scenarios

### Scenario 1: Detecting ARP Spoofing Attack

**Objective:** Detect an active ARP spoofing attack on the network

**Setup:**
```bash
# Terminal 1: Start the detection tool
cd ~/mitmdec
sudo python3 main.py

# Terminal 2: Simulate ARP spoofing attack
# Install arpspoof (if not already installed)
sudo apt-get install dsniff

# Get the gateway IP and victim IP
# Example: Gateway 192.168.1.1, Victim 192.168.1.10
sudo arpspoof -i eth0 -t 192.168.1.10 192.168.1.1
```

**Expected Detection in Tool:**
```
[CRITICAL] ARP SPOOFING DETECTED!
IP Address: 192.168.1.1
Previous MAC: aa:bb:cc:dd:ee:ff
New MAC: 11:22:33:44:55:66
This is a classic MITM attack signature!

[CRITICAL] [ARP_SPOOFING] IP 192.168.1.1 with different MACs detected
```

**In Logs:**
```
# alerts.log
2024-04-03 14:35:22 - WARNING - [mitm_alerts] [CRITICAL] [ARP_SPOOFING] IP 192.168.1.1 with different MACs detected

# arp_spoofing.log
2024-04-03 14:35:22 - WARNING - [arp_spoof] ARP SPOOF DETECTED: IP 192.168.1.1 spoofed - MAC1: aa:bb:cc:dd:ee:ff -> MAC2: 11:22:33:44:55:66
```

---

### Scenario 2: Detecting DDoS/SYN Flood Attack

**Objective:** Detect a DDoS attack (SYN flood)

**Setup:**
```bash
# Terminal 1: Start the detection tool
sudo python3 main.py

# Terminal 2: Simulate SYN flood attack
# Using hping3 (install: sudo apt-get install hping3)

# Get target IP
TARGET_IP="192.168.1.100"

# Launch SYN flood
sudo hping3 -S -p 80 --flood $TARGET_IP
```

**Expected Detection:**
```
[HIGH] ABNORMAL PACKET RATE!
Source IP: 192.168.1.50
Packets per second: 5423
This may indicate DDoS or port scanning

[HIGH] POSSIBLE SYN FLOOD DETECTED!
Source: 192.168.1.50:12345
Target: 192.168.1.100:80
SYN packets: 523, ACKs: 0
```

---

### Scenario 3: Detecting Port Scanning Reconnaissance

**Objective:** Detect port scanning (often precedes MITM attacks)

**Setup:**
```bash
# Terminal 1: Start detection tool
sudo python3 main.py

# Terminal 2: Run Nmap port scan
TARGET="192.168.1.100"
nmap -p 1-1000 $TARGET

# Or faster scan
nmap -F $TARGET  # Fast scan
nmap -p- $TARGET  # All ports
```

**Expected Detection:**
```
[HIGH] PORT SCANNING DETECTED!
Source IP: 192.168.1.50
Unique ports accessed: 25
This is reconnaissance activity preceding MITM attacks
```

---

### Scenario 4: Monitoring a WiFi Network

**Objective:** Monitor a WiFi network for MITM attacks

**Setup:**
```bash
# 1. Find the WiFi interface
iwconfig
# Output shows: wlan0, wlan1, etc.

# 2. Edit config to use WiFi interface
nano config/config.py
# Change: SNIFF_INTERFACE = 'wlan0'
# Or keep as None for auto-detect

# 3. Start monitoring
sudo python3 main.py

# 4. WiFi is especially vulnerable to MITM!
# Watch for ARP spoofing alerts
```

---

### Scenario 5: Long-Term Network Monitoring

**Objective:** Monitor a network over extended period (days/weeks)

**Setup:**
```bash
# 1. Create monitoring script
cat > monitor.sh <<'EOF'
#!/bin/bash
cd ~/mitmdec
LOG_DIR="logs_archive"
mkdir -p $LOG_DIR

while true; do
    echo "Starting MITM detection..."
    sudo python3 main.py > $LOG_DIR/run_$(date +%s).log 2>&1
    
    # Run for 24 hours, then restart for log rotation
    sleep 86400
done
EOF

# 2. Make executable
chmod +x monitor.sh

# 3. Run in background
nohup ./monitor.sh &

# 4. Archive logs periodically
0 0 * * * tar -czf logs_backup_$(date +\%Y\%m\%d).tar.gz logs/ && rm -rf logs/*
```

---

## Network Monitoring Setup

### Enterprise Deployment

**Architecture:**
```
┌──────────────────┐
│  Network Segment │
│   (VLAN, Subnet) │
└────────┬─────────┘
         │
         ▼
┌──────────────────────┐
│  Monitoring Server   │
│  (Kali Linux)        │
├──────────────────────┤
│ mitmdec tool running │
│ sudo python3 main.py │
└────────┬─────────────┘
         │
         ├──► logs/ (local filesystem)
         ├──► SIEM (Splunk, ELK)
         ├──► Email Alerts
         └──► Slack Notifications
```

**Setup Steps:**

1. **Deploy on Dedicated Hardware:**
```bash
# Server specs: 2GB RAM, 1-2 CPU cores minimum
# OS: Kali Linux / Ubuntu
# Interface: Connected to network segment to monitor

# Install on monitoring server
sudo apt-get update
sudo pip3 install scapy==2.5.0
cd /opt/mitmdec
sudo python3 main.py
```

2. **Integrate with SIEM (ELK Stack Example):**
```bash
# Install Filebeat
curl https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.14.1-linux-x86_64.tar.gz | tar xz

# Configure filebeat.yml
cat > filebeat.yml <<'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/mitmdec/logs/*.log

output.elasticsearch:
  hosts: ["elasticsearch-server:9200"]

processors:
  - add_kubernetes_metadata:
      host: ${HOSTNAME}
EOF

# Start Filebeat
./filebeat -c filebeat.yml
```

3. **Send Alerts to Slack:**
```python
# Modify src/alert_system.py
import requests

def send_slack_alert(self, message, severity):
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    
    color = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'good',
        'LOW': '#439FE0'
    }[severity]
    
    payload = {
        'attachments': [{
            'text': message,
            'color': color,
            'title': 'MITM Detection Alert'
        }]
    }
    
    requests.post(webhook_url, json=payload)
```

---

## Integration Examples

### Integration 1: Splunk Integration

**Goal:** Send MITM alerts to Splunk SIEM

**Steps:**
```bash
# 1. Install Splunk Forwarder
cd /opt/splunkforwarder/bin
./splunk add forward-server splunk-server:9997

# 2. Configure to monitor our logs
./splunk add monitor /opt/mitmdec/logs/ -index main

# 3. In Splunk, create alert rule
# Search: source="/opt/mitmdec/logs/alerts.log" severity="CRITICAL"
# Action: Send email to security@company.com
```

### Integration 2: Prometheus Metrics

**Goal:** Export metrics to Prometheus for monitoring

```python
# In main.py, add:
from prometheus_client import start_http_server, Gauge

# Create metrics
arp_spoofs = Gauge('mitmdec_arp_spoofing_detected', 'ARP spoofing attempts')
tcp_anomalies = Gauge('mitmdec_tcp_anomalies', 'TCP anomalies detected')

# Update periodically
start_http_server(8000)
while True:
    arp_spoofs.set(detector.arp_detector.stats['alerts_triggered'])
    tcp_anomalies.set(detector.tcp_monitor.stats['alerts_triggered'])
    time.sleep(5)
```

### Integration 3: Email Notifications

**Goal:** Send email alerts when attacks detected

```python
# Modify alert_system.py
import smtplib
from email.mime.text import MIMEText

def send_email_alert(severity, message):
    if severity not in ['HIGH', 'CRITICAL']:
        return
    
    msg = MIMEText(message)
    msg['Subject'] = f'[{severity}] MITM Attack Detected'
    msg['From'] = 'alerts@company.com'
    msg['To'] = 'security-team@company.com'
    
    s = smtplib.SMTP('mail.company.com')
    s.send_message(msg)
    s.quit()
```

---

## Troubleshooting Guide

### Issue 1: "No packets captured"

**Problem:** Tool starts but no packets are being captured

**Solutions:**

```bash
# Check 1: Verify interface is up
sudo ifconfig
# Look for 'eth0', 'wlan0', etc. with UP status

# Check 2: Test with tcpdump first
sudo tcpdump -i eth0 -c 5
# If tcpdump works, issue is with tool configuration

# Check 3: Verify Scapy can see interface
python3 -c "from scapy.all import get_if_list; print(get_if_list())"

# Check 4: Manually set interface in config
nano config/config.py
# Change: SNIFF_INTERFACE = 'eth0'  # Your interface

# Check 5: Run with verbose output (add to logger):
# In src/logger.py, change log level to DEBUG
```

---

### Issue 2: "Too many false alerts"

**Problem:** Tool is alerting on normal network activity

**Solution:**

```bash
# Increase thresholds in config/config.py
ARP_SPOOF_THRESHOLD = 10        # Was: 5 (needs 10 MACs to alert)
ARP_DUPLICATE_WINDOW = 120       # Was: 60 (check over 2 minutes)
ABNORMAL_PACKET_RATE = 5000      # Was: 1000 (allow 5000 pps)
ABNORMAL_PAYLOAD_SIZE = 131072   # Was: 65535 (allow 128KB)

# Or disable specific detections:
# Comment out in tcp_monitor.py:
# self._check_port_scanning(src_ip, dst_port)

# Adjust cooldown to reduce spam:
# In alert_system.py, change:
self.alert_cooldown = 60  # 1 minute between same alerts
```

---

### Issue 3: "High CPU usage"

**Problem:** Tool is consuming too much CPU

**Solutions:**

```bash
# 1. Filter packets more aggressively
echo 'PACKET_FILTER = "arp or (tcp port 22 or tcp port 443)"' >> config/config.py
# Only capture important protocols

# 2. Reduce stats refresh interval
STATS_REFRESH_INTERVAL = 30  # Was: 5 (report every 30s instead)

# 3. Increase session cleanup interval
TCP_SESSION_TIMEOUT = 300  # Was: 600 (cleanup more often)

# 4. Monitor actual usage
watch -n 1 'ps aux | grep python3 | grep main'
```

---

### Issue 4: "Logs are too large"

**Problem:** Log files growing too quickly

**Solutions:**

```bash
# 1. Implement log rotation (Linux logrotate)
cat > /etc/logrotate.d/mitmdec <<'EOF'
/opt/mitmdec/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF

# 2. Or manually rotate
tar -czf logs_$(date +%Y%m%d_%H%M%S).tar.gz logs/
rm logs/*.log
touch logs/{mitm_detector,alerts,arp_spoofing,tcp_anomalies}.log

# 3. Or reduce logging verbosity
ENABLE_FILE_LOGGING = False  # Log to console only
```

---

### Issue 5: "Can't capture packets (permission denied)"

**Problem:** Getting permission errors despite using sudo

**Solutions:**

```bash
# 1. Ensure using sudo
sudo python3 main.py  # CORRECT
python3 main.py      # WRONG - will fail

# 2. Or grant persistent permissions (advanced)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.9
# Then can run without sudo:
python3 main.py

# 3. Or create dedicated user
sudo useradd -m mitmdec
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
su - mitmdec
python3 main.py
```

---

## Real-World Attack Detection Examples

### Example Attack 1: Ferretbox ARP Spoofing

```
Timeline:
12:00 - Attacker connects to network, runs Ferretbox
12:05 - First ARP packet shows attacker's MAC for router IP
12:10 - Victim's traffic starts going to attacker

Detection Output:
[CRITICAL] ARP SPOOFING DETECTED!
IP Address: 192.168.1.1 (gateway)
Previous MAC: 00:11:22:33:44:55 (real gateway)
New MAC: aa:bb:cc:dd:ee:ff (attacker)
This is a classic MITM attack signature!
```

### Example Attack 2: DNSChanger Malware

```
Timeline:
15:30 - Infected host sends fake DNS responses
15:35 - Google.com DNS queries resolve to attacker's IP
15:40 - Victims see fake Google login page

Detection Output:
[HIGH] EXCESSIVE ARP ACTIVITY!
IP 192.168.1.50 has 8 different MAC addresses in 60s
This suggests ARP spoofing or network misconfiguration
```

### Example Attack 3: Network Reconnaissance (Pre-Attack)

```
Timeline:
11:00 - Attacker scans network with Nmap
11:02 - Identifies all active hosts and open ports
11:05 - Begins ARP spoofing attack

Detection Output:
[HIGH] PORT SCANNING DETECTED!
Source IP: 192.168.1.99
Unique ports accessed: 42
This is reconnaissance activity preceding MITM attacks
```

---

## Performance Monitoring

### Monitor Tool's Own Performance

```bash
# Check memory usage
watch -n 1 'ps aux | grep "[m]ain.py" | awk "{print \$6}" && free -h'

# Check CPU usage over time
mpstat 1 -P ALL

# Monitor network interface statistics
watch -n 1 'ethtool -S eth0'

# Count packets in tool
tail -f logs/mitm_detector.log | grep "Captured"
```

### Baseline Performance

```
Light traffic (< 100 pps):
  Memory: 60 MB
  CPU: < 1%
  Detection Latency: < 100ms

Normal traffic (100-1000 pps):
  Memory: 80 MB
  CPU: 2-5%
  Detection Latency: 100-500ms

Heavy traffic (>10,000 pps):
  Memory: 150+ MB
  CPU: 20-30%
  Detection Latency: 500ms-2sec
```

---

## Pro Tips

1. **Run Multiple Instances for Large Networks:**
```bash
# Monitor different interfaces
sudo python3 main.py &  # Interface 1
SNIFF_INTERFACE='eth1' sudo python3 main.py &  # Interface 2
```

2. **Create Alert Dashboards:**
```bash
# Search for CRITICAL alerts
grep "CRITICAL" logs/alerts.log | wc -l

# Show timeline of alerts
grep "\[.*\]" logs/alerts.log | cut -d' ' -f1-2 | uniq -c

# Find most attacked IP
grep "IP" logs/alerts.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c
```

3. **Automate Response:**
```bash
# Block suspicious IP with iptables
while true; do
    SUSPICIOUS=$(grep "PORT_SCANNING\|ARP_SPOOFING" logs/alerts.log | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    if [ ! -z "$SUSPICIOUS" ]; then
        sudo iptables -A INPUT -s $SUSPICIOUS -j DROP
        echo "Blocked: $SUSPICIOUS"
    fi
    sleep 60
done
```

---

**For more information, see:**
- README.md - Feature overview
- TECHNICAL_DOCUMENTATION.md - Algorithm details
- Code comments - Implementation details

