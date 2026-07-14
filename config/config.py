"""
Configuration module for MITM Detection Tool
Contains all configurable parameters and constants
"""

import os

# ============= LOGGING CONFIGURATION =============
LOG_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
MAIN_LOG_FILE = os.path.join(LOG_DIR, 'mitm_detector.log')
ALERT_LOG_FILE = os.path.join(LOG_DIR, 'alerts.log')
ARP_SPOOF_LOG = os.path.join(LOG_DIR, 'arp_spoofing.log')
TCP_ANOMALY_LOG = os.path.join(LOG_DIR, 'tcp_anomalies.log')

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# ============= DETECTION PARAMETERS =============
# ARP Spoofing Detection
ARP_SPOOF_THRESHOLD = 5  # Alert if same IP appears with 5+ different MACs in short time
ARP_CACHE_TIMEOUT = 3600  # Cache ARP mappings for 1 hour (seconds)
ARP_DUPLICATE_WINDOW = 60  # Time window for detecting duplicate IPs (seconds)

# TCP Session Monitoring
MAX_CONCURRENT_SESSIONS = 1000  # Maximum tracked TCP sessions
TCP_SESSION_TIMEOUT = 600  # Close inactive sessions after 10 minutes (seconds)
ABNORMAL_PACKET_RATE = 1000  # Alert if > 1000 packets/sec from single IP
ABNORMAL_PAYLOAD_SIZE = 65535  # Alert for packets larger than typical (~64KB)

# ============= NETWORK INTERFACE =============
# Set to None for automatic interface detection, or specify interface name
SNIFF_INTERFACE = None  # Auto-detect, or use 'eth0', 'wlan0', etc.
PACKET_COUNT = 0  # 0 = infinite

# ============= ALERT SETTINGS =============
ENABLE_SOUND_ALERT = True
ENABLE_GUI_POPUP = True
ENABLE_CONSOLE_OUTPUT = True
ENABLE_FILE_LOGGING = True

# ============= TIMING SETTINGS =============
STATS_REFRESH_INTERVAL = 5  # GUI refresh interval (seconds)
PACKET_BUFFER_SIZE = 100  # Process packets in batches

# ============= GUI SETTINGS =============
GUI_WIDTH = 1000
GUI_HEIGHT = 700
GUI_UPDATE_INTERVAL = 1000  # milliseconds

# ============= NETWORK SETTINGS =============
PACKET_FILTER = "arp or tcp"  # Capture only ARP and TCP packets
PROMISCUOUS_MODE = True  # Capture all packets on network

print("[CONFIG] Configuration loaded from config.py")
