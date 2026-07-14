"""
TCP Session Monitoring module
Detects suspicious TCP session behavior and anomalies
"""

import threading
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import IP, TCP
from config.config import (
    TCP_SESSION_TIMEOUT, ABNORMAL_PACKET_RATE, 
    ABNORMAL_PAYLOAD_SIZE, MAX_CONCURRENT_SESSIONS
)
from src.logger import mitm_logger
from src.alert_system import alert_system

class TCPMonitor:
    """
    Monitors TCP sessions for anomalous behavior
    
    Detection Features:
    - Track active TCP sessions
    - Monitor packet count and size
    - Detect abnormal packet rates (DDoS indicator)
    - Identify unusual payload sizes
    - Monitor session state transitions
    - Detect port scanning activity
    """
    
    def __init__(self):
        """Initialize TCP monitor"""
        self.sessions = {}  # (src_ip, src_port, dst_ip, dst_port) -> session_data
        self.ip_packet_count = defaultdict(lambda: {'count': 0, 'timestamp': datetime.now()})
        self.port_scan_tracker = defaultdict(lambda: defaultdict(int))  # src_ip -> {dst_port: count}
        self.lock = threading.RLock()
        self.stats = {
            'total_tcp_packets': 0,
            'active_sessions': 0,
            'anomalies_detected': 0,
            'alerts_triggered': 0
        }
    
    def process_tcp_packet(self, packet):
        """
        Process captured TCP packet
        
        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return
        
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        payload_size = len(tcp_layer.payload)
        
        with self.lock:
            self.stats['total_tcp_packets'] += 1
            
            # Track session
            session_key = (src_ip, src_port, dst_ip, dst_port)
            self._update_session(session_key, tcp_layer, payload_size)
            
            # Check for anomalies
            self._check_packet_rate_anomaly(src_ip)
            self._check_payload_size_anomaly(src_ip, payload_size)
            self._check_port_scanning(src_ip, dst_port)
            
            # Cleanup old sessions
            if self.stats['total_tcp_packets'] % 100 == 0:
                self._cleanup_old_sessions()
    
    def _update_session(self, session_key, tcp_layer, payload_size):
        """
        Update or create TCP session record
        
        Args:
            session_key (tuple): (src_ip, src_port, dst_ip, dst_port)
            tcp_layer: Scapy TCP layer
            payload_size (int): Size of TCP payload
        """
        if session_key not in self.sessions:
            # New session
            self.sessions[session_key] = {
                'flags': [],
                'packet_count': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'payload_sizes': [],
                'state': 'ESTABLISHED'
            }
            self.stats['active_sessions'] = len(self.sessions)
        
        session = self.sessions[session_key]
        session['packet_count'] += 1
        session['last_seen'] = datetime.now()
        session['flags'].append(tcp_layer.flags)
        session['payload_sizes'].append(payload_size)
        
        # Track TCP state transitions
        self._track_tcp_state(session_key, tcp_layer.flags)
    
    def _track_tcp_state(self, session_key, flags):
        """
        Track TCP state (SYN, ACK, FIN, RST, etc.)
        
        Args:
            session_key (tuple): Session identifier
            flags (int): TCP flags
        """
        # TCP flags: S=SYN, A=ACK, F=FIN, R=RST, P=PUSH
        flag_names = []
        if flags & 0x02:  # SYN
            flag_names.append('SYN')
        if flags & 0x10:  # ACK
            flag_names.append('ACK')
        if flags & 0x01:  # FIN
            flag_names.append('FIN')
        if flags & 0x04:  # RST
            flag_names.append('RST')
        
        session = self.sessions[session_key]
        
        # Detect SYN flooding (many SYNs without ACKs)
        syn_count = session['flags'].count(0x02)
        ack_count = session['flags'].count(0x10)
        
        if syn_count > 10 and ack_count < 2:
            self.stats['anomalies_detected'] += 1
            src_ip, src_port, dst_ip, dst_port = session_key
            alert_msg = (
                f"POSSIBLE SYN FLOOD DETECTED!\n"
                f"Source: {src_ip}:{src_port}\n"
                f"Target: {dst_ip}:{dst_port}\n"
                f"SYN packets: {syn_count}, ACKs: {ack_count}"
            )
            alert_system.trigger_alert('TCP_SYN_FLOOD', alert_msg, 'HIGH')
            self.stats['alerts_triggered'] += 1
    
    def _check_packet_rate_anomaly(self, src_ip):
        """
        Detect abnormally high packet rate from single IP
        Indicates DDoS or scan activity
        
        Args:
            src_ip (str): Source IP address
        """
        now = datetime.now()
        
        # Initialize or update counter
        if src_ip not in self.ip_packet_count:
            self.ip_packet_count[src_ip] = {'count': 1, 'timestamp': now}
        else:
            counter = self.ip_packet_count[src_ip]
            elapsed = (now - counter['timestamp']).total_seconds()
            
            # Reset counter if time window passed
            if elapsed > 1:
                counter['count'] = 1
                counter['timestamp'] = now
            else:
                counter['count'] += 1
            
            # Alert if too many packets in short time
            if counter['count'] > ABNORMAL_PACKET_RATE:
                self.stats['anomalies_detected'] += 1
                alert_msg = (
                    f"ABNORMAL PACKET RATE!\n"
                    f"Source IP: {src_ip}\n"
                    f"Packets per second: {counter['count']}\n"
                    f"This may indicate DDoS or port scanning"
                )
                alert_system.trigger_alert('ABNORMAL_PACKET_RATE', alert_msg, 'HIGH')
                self.stats['alerts_triggered'] += 1
    
    def _check_payload_size_anomaly(self, src_ip, payload_size):
        """
        Detect unusually large payloads
        
        Args:
            src_ip (str): Source IP
            payload_size (int): Payload size in bytes
        """
        if payload_size > ABNORMAL_PAYLOAD_SIZE:
            self.stats['anomalies_detected'] += 1
            alert_msg = (
                f"ABNORMAL PAYLOAD SIZE!\n"
                f"Source: {src_ip}\n"
                f"Payload size: {payload_size} bytes\n"
                f"Expected max: {ABNORMAL_PAYLOAD_SIZE} bytes"
            )
            alert_system.trigger_alert('ABNORMAL_PAYLOAD', alert_msg, 'MEDIUM')
            self.stats['alerts_triggered'] += 1
    
    def _check_port_scanning(self, src_ip, dst_port):
        """
        Detect port scanning activity
        
        Args:
            src_ip (str): Source IP
            dst_port (int): Destination port
        """
        # Track ports accessed by each IP
        self.port_scan_tracker[src_ip][dst_port] += 1
        
        # If accessing many different ports in short time = scanning
        unique_ports = len(self.port_scan_tracker[src_ip])
        
        if unique_ports > 20:  # Accessing 20+ different ports
            self.stats['anomalies_detected'] += 1
            alert_msg = (
                f"PORT SCANNING DETECTED!\n"
                f"Source IP: {src_ip}\n"
                f"Unique ports accessed: {unique_ports}\n"
                f"This is reconnaissance activity preceding MITM attacks"
            )
            alert_system.trigger_alert('PORT_SCANNING', alert_msg, 'HIGH')
            self.stats['alerts_triggered'] += 1
            
            # Reset to avoid repeated alerts
            self.port_scan_tracker[src_ip].clear()
    
    def _cleanup_old_sessions(self):
        """Remove inactive sessions to save memory"""
        now = datetime.now()
        expired = []
        
        for session_key, session_data in self.sessions.items():
            age = (now - session_data['last_seen']).total_seconds()
            if age > TCP_SESSION_TIMEOUT:
                expired.append(session_key)
        
        for session_key in expired:
            del self.sessions[session_key]
        
        self.stats['active_sessions'] = len(self.sessions)
        
        if expired:
            mitm_logger.log_packet_info(f"Cleaned {len(expired)} expired TCP sessions")
    
    def get_active_sessions(self):
        """
        Get list of active TCP sessions
        
        Returns:
            list: List of session information
        """
        with self.lock:
            sessions_list = []
            for session_key, session_data in self.sessions.items():
                src_ip, src_port, dst_ip, dst_port = session_key
                sessions_list.append({
                    'src': f"{src_ip}:{src_port}",
                    'dst': f"{dst_ip}:{dst_port}",
                    'packets': session_data['packet_count'],
                    'duration': (datetime.now() - session_data['first_seen']).total_seconds()
                })
            return sessions_list
    
    def get_stats(self):
        """
        Get TCP monitor statistics
        
        Returns:
            dict: Statistics
        """
        with self.lock:
            return {
                'total_tcp_packets': self.stats['total_tcp_packets'],
                'active_sessions': self.stats['active_sessions'],
                'anomalies_detected': self.stats['anomalies_detected'],
                'alerts_triggered': self.stats['alerts_triggered']
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                'total_tcp_packets': 0,
                'active_sessions': 0,
                'anomalies_detected': 0,
                'alerts_triggered': 0
            }

print("[TCP_MONITOR] TCP session monitor initialized")
