"""
ARP Spoofing Detection module
Detects ARP spoofing attacks by monitoring IP-MAC mappings
"""

import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import ARP
from config.config import ARP_SPOOF_THRESHOLD, ARP_CACHE_TIMEOUT, ARP_DUPLICATE_WINDOW
from src.logger import mitm_logger
from src.alert_system import alert_system

class ARPDetector:
    """
    Detects ARP spoofing attacks
    
    How ARP Spoofing Works:
    - ARP (Address Resolution Protocol) maps IP addresses to MAC addresses
    - Attacker sends false ARP replies claiming their MAC owns a target IP
    - Victims update their ARP cache with wrong mapping
    - Traffic meant for target IP is sent to attacker instead
    - Attacker can intercept, modify, or drop packets (MITM attack)
    
    Detection Logic:
    - Monitor all ARP packets
    - Maintain IP -> MAC mapping database
    - Alert when same IP appears with different MAC addresses
    - Check for suspicious ARP requests (gratuitous ARPs)
    - Track frequency of ARP changes for each IP
    """
    
    def __init__(self):
        """Initialize ARP spoofing detector"""
        self.arp_table = {}  # IP -> {'mac': MAC, 'last_seen': timestamp}
        self.arp_history = defaultdict(list)  # IP -> [list of (MAC, timestamp)]
        self.lock = threading.RLock()
        self.suspicious_ips = set()
        self.stats = {
            'total_arp_packets': 0,
            'suspicious_mappings': 0,
            'alerts_triggered': 0
        }
    
    def process_arp_packet(self, packet):
        """
        Process captured ARP packet
        
        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(ARP):
            return
        
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        dst_ip = arp_layer.pdst
        
        with self.lock:
            self.stats['total_arp_packets'] += 1
            
            # Check for ARP spoofing
            self._check_arp_spoofing(src_ip, src_mac)
            
            # Update ARP table
            self._update_arp_table(src_ip, src_mac)
    
    def _check_arp_spoofing(self, ip, mac):
        """
        Check if this ARP packet indicates spoofing
        
        Args:
            ip (str): IP address from ARP packet
            mac (str): MAC address from ARP packet
        """
        # Skip localhost and broadcast addresses
        if ip in ['127.0.0.1', '255.255.255.255', '0.0.0.0']:
            return
        
        if ip in self.arp_table:
            existing_mac = self.arp_table[ip]['mac']
            
            # Different MAC for same IP = POTENTIAL SPOOFING
            if existing_mac != mac:
                self._handle_arp_spoof_alert(ip, existing_mac, mac)
        
        # Check for rapid MAC changes (high frequency = suspicious)
        self._check_mac_change_frequency(ip, mac)
    
    def _handle_arp_spoof_alert(self, ip, old_mac, new_mac):
        """
        Handle ARP spoofing detection
        
        Args:
            ip (str): IP address that changed MAC
            old_mac (str): Previous MAC address
            new_mac (str): New MAC address
        """
        self.stats['suspicious_mappings'] += 1
        self.suspicious_ips.add(ip)
        
        alert_msg = (
            f"ARP SPOOFING DETECTED!\n"
            f"IP Address: {ip}\n"
            f"Previous MAC: {old_mac}\n"
            f"New MAC: {new_mac}\n"
            f"This is a classic MITM attack signature!"
        )
        
        alert_system.trigger_alert('ARP_SPOOFING', alert_msg, 'CRITICAL')
        mitm_logger.log_arp_spoof(ip, old_mac, new_mac)
        
        self.stats['alerts_triggered'] += 1
    
    def _check_mac_change_frequency(self, ip, mac):
        """
        Check if MAC address is changing too frequently for one IP
        
        Args:
            ip (str): IP address
            mac (str): MAC address
        """
        now = datetime.now()
        
        # Add this observation to history
        if ip not in self.arp_history or self.arp_history[ip][-1][0] != mac:
            self.arp_history[ip].append((mac, now))
        
        # Clean old entries (older than ARP_DUPLICATE_WINDOW)
        cutoff_time = now - timedelta(seconds=ARP_DUPLICATE_WINDOW)
        self.arp_history[ip] = [
            (m, t) for m, t in self.arp_history[ip]
            if t > cutoff_time
        ]
        
        # Get unique MACs in recent window
        unique_macs = set(m for m, t in self.arp_history[ip])
        
        # Alert if many different MACs for same IP
        if len(unique_macs) >= ARP_SPOOF_THRESHOLD:
            alert_msg = (
                f"EXCESSIVE ARP ACTIVITY!\n"
                f"IP {ip} has {len(unique_macs)} different MAC addresses in last {ARP_DUPLICATE_WINDOW}s\n"
                f"This suggests ARP spoofing or network misconfiguration"
            )
            alert_system.trigger_alert('ARP_EXCESSIVE_CHANGES', alert_msg, 'HIGH')
    
    def _update_arp_table(self, ip, mac):
        """
        Update ARP cache table
        
        Args:
            ip (str): IP address
            mac (str): MAC address
        """
        self.arp_table[ip] = {
            'mac': mac,
            'last_seen': datetime.now()
        }
    
    def cleanup_old_entries(self):
        """
        Remove ARP table entries older than ARP_CACHE_TIMEOUT
        Usually called periodically to free memory
        """
        with self.lock:
            now = datetime.now()
            expired = []
            
            for ip, entry in self.arp_table.items():
                age = (now - entry['last_seen']).total_seconds()
                if age > ARP_CACHE_TIMEOUT:
                    expired.append(ip)
            
            for ip in expired:
                del self.arp_table[ip]
            
            if expired:
                mitm_logger.log_packet_info(f"Cleaned {len(expired)} expired ARP entries")
    
    def get_arp_table(self):
        """
        Get current ARP table
        
        Returns:
            dict: IP -> MAC mappings
        """
        with self.lock:
            return {ip: entry['mac'] for ip, entry in self.arp_table.items()}
    
    def get_suspicious_ips(self):
        """
        Get list of IPs involved in suspicious activity
        
        Returns:
            set: Suspicious IP addresses
        """
        with self.lock:
            return self.suspicious_ips.copy()
    
    def get_stats(self):
        """
        Get ARP detector statistics
        
        Returns:
            dict: Statistics
        """
        with self.lock:
            return {
                'total_arp_packets': self.stats['total_arp_packets'],
                'suspicious_mappings': self.stats['suspicious_mappings'],
                'alerts_triggered': self.stats['alerts_triggered'],
                'tracked_ips': len(self.arp_table),
                'suspicious_ips': len(self.suspicious_ips)
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                'total_arp_packets': 0,
                'suspicious_mappings': 0,
                'alerts_triggered': 0
            }

print("[ARP_DETECTOR] ARP spoofing detector initialized")
