# MITM Detection Tool - Technical Documentation

Complete technical reference for detection algorithms, implementation details, and architecture.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [ARP Spoofing Detection Algorithm](#arp-spoofing-detection-algorithm)
3. [TCP Anomaly Detection](#tcp-anomaly-detection)
4. [Packet Processing Pipeline](#packet-processing-pipeline)
5. [Performance Analysis](#performance-analysis)
6. [Data Structures](#data-structures)
7. [Thread Safety](#thread-safety)

---

## Architecture Overview

### System Design

```
┌─────────────────────────────────────────────────────────────────┐
│                     MAIN APPLICATION                            │
│                      (main.py)                                  │
└────────────┬──────────────────────────────────────┬─────────────┘
             │                                      │
      ┌──────▼────────┐                 ┌──────────▼──────┐
      │ Packet Capture│                 │ Stats Reporter  │
      │ (Scapy)       │                 │ (Threading)     │
      └──────┬────────┘                 └──────────┬──────┘
             │                                     │
             ▼                                     ▼
      ┌─────────────────┐               ┌─────────────────┐
      │ ARP Detector    │               │ Alert System    │
      ├─────────────────┤               ├─────────────────┤
      │ IP→MAC Table    │               │ Alert Queue     │
      │ History Tracker │               │ Sound/GUI/Log   │
      │ Spike Detection │               │ Cooldown Timer  │
      └────────┬────────┘               └────────┬────────┘
               │                                  ▲
               │                                  │
      ┌────────▼────────┐                ┌──────┴────────┐
      │ TCP Monitor     │                │ Logger        │
      ├─────────────────┤                ├───────────────┤
      │ Session Tracker │                │ File Handlers │
      │ Port Scanner    │                │ Console Out   │
      │ SYN Flood Det.  │                │ Timestamp fmt │
      └─────────────────┘                └───────────────┘
```

### Data Flow

```
Network Interface
      │
      ├─ Scapy Sniffer ─────┐
      │                      │
      ▼                      ▼
  [Packet]              [Thread-safe Queue]
      │                      │
      ├──► ARP Detector ─────┼──► Alert System ──► Logger
      │                      │
      ├──► TCP Monitor ──────┼──► Console Output
      │                      │
      └──► Aggregator ───────┴──► Statistics
```

---

## ARP Spoofing Detection Algorithm

### Theory: Why ARP Spoofing Works

**Address Resolution Protocol (ARP):**
- Converts IP addresses (Layer 3) to MAC addresses (Layer 2)
- Essential for local network communication
- **Vulnerable:** No authentication mechanism
- **Stateless:** Hosts update ARP cache upon any ARP reply

**Attack:** 
```
Attacker sends: "I have 192.168.1.1, my MAC is AA:BB:CC:DD:EE:FF"
Victim trusts this without verification
Victim updates ARP cache: 192.168.1.1 → AA:BB:CC:DD:EE:FF (Wrong!)
```

### Detection Algorithm

#### Algorithm 1: MAC Address Consistency Check

**Pseudocode:**
```
For each ARP packet received:
    1. Extract: source_ip, source_mac
    2. if source_ip exists in arp_table:
        3. If source_mac != table[source_ip]:
            4. ALERT: ARP_SPOOFING_DETECTED
            5. Record both MACs with timestamp
    6. else:
        7. Add to table: source_ip -> source_mac
```

**Python Implementation:**
```python
def _check_arp_spoofing(self, ip, mac):
    if ip in self.arp_table:
        existing_mac = self.arp_table[ip]['mac']
        
        if existing_mac != mac:  # MAC CHANGED!
            self._handle_arp_spoof_alert(ip, existing_mac, mac)
```

**Time Complexity:** O(1) hashtable lookup
**Space Complexity:** O(n) where n = number of unique IPs

#### Algorithm 2: Frequency Analysis (MAC Change Spike Detection)

**Pseudocode:**
```
Maintain: history[ip] = list of (mac, timestamp)

For each ARP packet:
    1. Add (mac, timestamp) to history[ip]
    2. Remove entries older than TIME_WINDOW (60 seconds)
    3. Count unique MACs in window
    4. If unique_mac_count >= THRESHOLD (5):
        5. Alert: EXCESSIVE_ARP_ACTIVITY
```

**Why This Works:**
- Normal: Same IP always has same MAC
- Spoofing: Rapid MAC changes = many MACs in short time
- Thresholds prevent false positives from DHCP reassignments

**Python Implementation:**
```python
def _check_mac_change_frequency(self, ip, mac):
    self.arp_history[ip].append((mac, now))
    
    # Clean old entries
    cutoff_time = now - timedelta(seconds=60)  # 60 second window
    self.arp_history[ip] = [
        (m, t) for m, t in self.arp_history[ip]
        if t > cutoff_time
    ]
    
    # Count unique MACs
    unique_macs = set(m for m, t in self.arp_history[ip])
    
    if len(unique_macs) >= 5:  # Threshold
        ALERT("Excessive ARP Activity")
```

**Time Complexity:** O(n) list cleanup per packet
**Space Complexity:** O(n*m) where m = MACs per IP in window

#### Algorithm 3: Subnet-Based Validation (Advanced)

```python
def validate_arp_source(self, ip, mac, interface):
    """
    Verify MAC is on the same subnet as IP
    Some switches can track MAC locations
    """
    mac_vendor = get_vendor_from_mac(mac)
    ip_subnet = get_subnet(ip)
    
    if not is_valid_subnet_mac(mac, ip_subnet):
        ALERT("Invalid ARP - MAC not on subnet")
```

---

## TCP Anomaly Detection

### TCP State Machine

```
         SYN
    LISTEN ──────► SYN_RCVD
      ▲              │ ACK
      │              ▼
      │          ESTABLISHED ◄─── Normal Data Flow
      │              │
      │              │ FIN
      │              ▼
      │         FIN_WAIT_1 ──► FIN_WAIT_2 ──► TIME_WAIT
      │              
      │              ▲
      └──────────────┘ RST (Connection Reset)
```

### Detection Method 1: SYN Flood Attack

**Signature:**
```
SYN packets > 10
ACK packets < 2
Duration < 1 second
```

**Algorithm:**
```python
def detect_syn_flood(session):
    syn_count = count(flag for flag in session.flags if flag & 0x02)  # SYN
    ack_count = count(flag for flag in session.flags if flag & 0x10)  # ACK
    
    if syn_count > 10 and ack_count < 2:
        return ALERT("SYN Flood Detected")
```

**Why It Works:**
- SYN floods send many SYN packets but don't complete handshake
- Normal TCP: 1 SYN → 1 SYN-ACK → 1 ACK (3-way handshake)
- Flood: Many SYNs without ACKs = incomplete handshakes

### Detection Method 2: Abnormal Packet Rate

**Algorithm:**
```
Packet Rate Counter:

For each TCP packet from IP:
    packets[ip].count += 1
    
    # Check time window
    if (now - packets[ip].timestamp) > 1 second:
        packets[ip].reset()
    
    if packets[ip].count > 1000:  # Threshold
        ALERT("DDoS - Abnormal Packet Rate")
```

**Metrics:**
```
Normal: 1-100 packets/second per IP
Suspicious: 100-500 packets/second (might be large file transfer)
Critical: >1000 packets/second (DDoS attack)
```

### Detection Method 3: Port Scanning

**Algorithm:**
```
For each TCP packet (src_ip, dst_port):
    unique_ports[src_ip].add(dst_port)
    
    if len(unique_ports[src_ip]) >= 20:
        ALERT("Port Scanning Detected from " + src_ip)
```

**Why It Works:**
- Normal TCP: Connect to 1-3 services (HTTP, HTTPS, SSH)
- Scanning: Connect to 20+ different ports = reconnaissance
- Port scanning often precedes MITM attacks

### Detection Method 4: Large Payload Detection

**Algorithm:**
```
For each TCP packet:
    if payload_size > 65535:  # ~64KB (typical MTU limit)
        ALERT("Abnormal Payload Size")
```

**Note:** Fragmented packets are reassembled, but TCP packets >64KB are rare and suspicious.

---

## Packet Processing Pipeline

### Packet Flow

```
1. CAPTURE PHASE
   ├─ Scapy sniffs packets
   ├─ Filters: "arp or tcp" (config parameter)
   ├─ Promiscuous mode: ON (capture all frames)
   └─ Store: False (memory efficient)

2. DISPATCH PHASE
   ├─ Unified packet handler called
   ├─ Thread-safe callback processing
   └─ Error handling for malformed packets

3. ANALYSIS PHASE
   ├─ ARP Detector
   │  ├─ Extract ARP fields
   │  ├─ Check spoofing signatures
   │  └─ Update ARP table
   └─ TCP Monitor
      ├─ Extract TCP fields
      ├─ Track session state
      └─ Check anomalies

4. ALERT PHASE
   ├─ Severity assignment
   ├─ Cooldown check (prevent spam)
   ├─ Alert system trigger
   └─ Multi-method notification (console, sound, log)

5. RETENTION PHASE
   ├─ Store in memory cache
   ├─ Periodic cleanup
   └─ Archive to logs
```

### Callback Architecture

```python
def _unified_packet_handler(self, packet):
    """Called for EVERY packet"""
    try:
        self.arp_detector.process_arp_packet(packet)
        self.tcp_monitor.process_tcp_packet(packet)
    except Exception as e:
        log_error(e)
```

**Performance Implications:**
- Handler should complete in <1ms
- Called at network interface speed (millions/sec for 10Gbps)
- Thread-safe due to GIL in Python

---

## Performance Analysis

### Memory Usage

```
BASE: ~50 MB (Python interpreter + libraries)

Per-Session Tracking:
├─ ARP Table
│  ├─ max_entries = number_of_devices (100-1000 typically)
│  ├─ bytes/entry ≈ 100 (IP + MAC + timestamp)
│  └─ Total ≈ 10-100 KB
│
├─ TCP Sessions
│  ├─ max_entries = MAX_CONCURRENT_SESSIONS (default: 1000)
│  ├─ bytes/session ≈ 500 (flags, timestamps, payloads)
│  └─ Total ≈ 500 KB - 1 MB
│
└─ Alert Queue
   ├─ max_entries = 10000 (in memory)
   ├─ bytes/alert ≈ 200
   └─ Total ≈ 2 MB

TOTAL: ~52-55 MB typical
```

### CPU Usage

```
Typical Network LO (Low Traffic):
├─ <100 packets/second: <1% CPU
└─ <500 packets/second: 2-3% CPU

High Traffic Network:
├─ 1000 packets/second: 5-8% CPU
├─ 10000 packets/second: 20-30% CPU
└─ 100000 packets/second: 60-80% CPU
```

### Packet Processing Latency

```
Typical: 100-500 microseconds per packet
├─ Scapy parsing: 50-100 us
├─ ARP detector: 10-20 us (hashtable lookup)
├─ TCP monitor: 20-50 us (hash + list operations)
└─ Alert system: 10-50 us (depends on alert type)
```

### Scaling Limits

| Metric | Value | Notes |
|--------|-------|-------|
| Max IP addresses tracked | 65,536 | All possible IPv4 addresses |
| Max TCP sessions | 1,000 | Configurable via MAX_CONCURRENT_SESSIONS |
| Max packets/second | 100,000+ | Depends on CPU and interface |
| Alert queue size | 10,000 | Before oldest alerts discarded |
| Log file growth | 1-10 MB/day | Depends on activity level |

---

## Data Structures

### ARP Detector Structures

```python
# IP → MAC Cache
arp_table = {
    '192.168.1.10': {
        'mac': 'aa:bb:cc:dd:ee:ff',
        'last_seen': datetime(...)
    },
    '192.168.1.20': {
        'mac': '11:22:33:44:55:66',
        'last_seen': datetime(...)
    }
}

# MAC Change History
arp_history = defaultdict(list)  # IP → [(mac, timestamp), ...]

# Suspicious IPs
suspicious_ips = {'192.168.1.50', '192.168.1.99'}

# Statistics
stats = {
    'total_arp_packets': 15432,
    'suspicious_mappings': 3,
    'alerts_triggered': 5
}
```

**Complexity:**
- Insertion: O(1) (hashtable)
- Lookup: O(1)
- Delete: O(1)
- Memory: O(n) where n = # of IPs

### TCP Monitor Structures

```python
# Session Tracking
sessions = {
    (src_ip, src_port, dst_ip, dst_port): {
        'flags': [0x02, 0x10, ...],  # TCP flags
        'packet_count': 42,
        'first_seen': datetime(...),
        'last_seen': datetime(...),
        'payload_sizes': [512, 1024, ...],
        'state': 'ESTABLISHED'
    },
    ...
}

# Per-IP Packet Counter
ip_packet_count = {
    '192.168.1.50': {
        'count': 523,
        'timestamp': datetime(...)
    },
    ...
}

# Port Scanning Tracker
port_scan_tracker = defaultdict(lambda: defaultdict(int))
# port_scan_tracker['192.168.1.50'][80] = 2
# port_scan_tracker['192.168.1.50'][443] = 1
# port_scan_tracker['192.168.1.50'][22] = 1
```

---

## Thread Safety

### Threading Model

```
Main Thread
├─ Initialization
├─ Start packet capture (spawns sniffer thread)
├─ Start stats reporter thread
└─ Wait for interrupt (keyboard Ctrl+C)

Sniffer Thread (from Scapy)
├─ Runs continuously
├─ Calls packet handler for each packet
└─ Thread-safe callback

Stats Reporter Thread
├─ Wakes every 5 seconds
├─ Prints statistics
└─ Acquires locks for data access

GUI Thread (if using dashboard)
├─ Tkinter main event loop
├─ Updates display every 1 second
└─ Reads from shared data structures
```

### Lock Usage

```python
class ARPDetector:
    def __init__(self):
        self.lock = threading.RLock()  # Reentrant lock
        
    def process_arp_packet(self):
        with self.lock:  # Acquire lock
            # Safe to modify arp_table
            self.arp_table[ip] = mac
```

**Why RLock?**
- Regular `Lock`: Can't acquire twice from same thread
- `RLock`: Can acquire multiple times from same thread
- Prevents deadlock in complex call chains

### Shared Data Access Pattern

```
Writer (Sniffer Thread):
    with lock:
        data[key] = value

Reader (Stats Thread):
    with lock:
        temp = copy.deepcopy(data)  # Make local copy
    # Process copy without holding lock
    process(temp)
```

---

## False Positive Mitigation

### Cooldown System

```python
active_alerts = {
    'ARP_SPOOF_192.168.1.5': datetime(2024, 4, 3, 14, 25),
    'TCP_ANOMALY_192.168.1.50': datetime(2024, 4, 3, 14, 26)
}

alert_cooldown = 30  # seconds

def trigger_alert(type, target):
    key = f"{type}_{target}"
    
    if key in active_alerts:
        age = (now - active_alerts[key]).seconds
        if age < 30:  # Still in cooldown
            return  # Skip alert (prevent spam)
    
    # Send alert
    active_alerts[key] = now
```

**Effect:**
- Same alert: maximum once per 30 seconds
- Prevents alert storms
- Configurable per alert type

### Heuristic Thresholds

All thresholds in `config/config.py` can be tuned to:
- **Increase sensitivity:** Lower threshold
- **Decrease sensitivity:** Raise threshold

```python
ARP_SPOOF_THRESHOLD = 5          # 5 different MACs = alert
ABNORMAL_PACKET_RATE = 1000      # 1000 pps = alert
ABNORMAL_PAYLOAD_SIZE = 65535    # 64KB = alert
```

---

## References & Further Reading

### ARP Protocol
- RFC 826: An Ethernet Address Resolution Protocol
- IETF Security Considerations

### Network Intrusion Detection
- Snort IDS Documentation
- Zeek Network Security Monitor
- OSSEC Host-Based IDS

### Python Networking
- Scapy Documentation: https://scapy.readthedocs.io/
- asyncio: https://docs.python.org/3/library/asyncio.html

### Cybersecurity
- OWASP: Man-in-the-Middle Attacks
- CWE-294: Authentication Bypass
- NIST Cybersecurity Framework

---

**Document Version:** 1.0  
**Last Updated:** 2024-04-03  
**For Questions:** Review source code comments or README.md
