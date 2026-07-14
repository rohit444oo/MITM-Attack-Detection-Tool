"""
Packet Capture module for MITM Detection Tool
Captures ARP and TCP packets from network interface
"""

import threading
import socket
from scapy.all import sniff, ARP, TCP, IP, get_if_list
from config.config import SNIFF_INTERFACE, PACKET_FILTER, PROMISCUOUS_MODE, PACKET_COUNT
from src.logger import mitm_logger

class PacketCapture:
    """Captures network packets using Scapy"""
    
    def __init__(self, callback=None, interface=None):
        """
        Initialize packet capture
        
        Args:
            callback (function): Callback function to process captured packets
            interface (str): Network interface to sniff on
        """
        self.callback = callback
        self.interface = interface or SNIFF_INTERFACE or self._get_default_interface()
        self.is_running = False
        self.packet_count = 0
        self.capture_thread = None
        self.lock = threading.Lock()
    
    def _get_default_interface(self):
        """
        Auto-detect primary network interface
        
        Returns:
            str: Interface name (eth0, wlan0, etc.)
        """
        try:
            interfaces = get_if_list()
            # Prioritize common network interfaces
            for iface in ['eth0', 'en0', 'wlan0', 'en1', 'wifi0']:
                if iface in interfaces:
                    mitm_logger.log_main(f"Auto-detected interface: {iface}")
                    return iface
            # Return first available interface
            if interfaces:
                mitm_logger.log_main(f"Auto-detected interface: {interfaces[0]}")
                return interfaces[0]
        except Exception as e:
            mitm_logger.log_main(f"Error detecting interface: {e}", 'ERROR')
        
        return 'eth0'  # Default fallback
    
    def _packet_handler(self, packet):
        """
        Handle captured packet
        
        Args:
            packet: Scapy packet object
        """
        with self.lock:
            self.packet_count += 1
            
            # Call user-defined callback if provided
            if self.callback:
                try:
                    self.callback(packet)
                except Exception as e:
                    mitm_logger.log_main(f"Error in packet callback: {e}", 'ERROR')
            
            # Log packet info every 100 packets
            if self.packet_count % 100 == 0:
                mitm_logger.log_packet_info(
                    f"Captured {self.packet_count} packets on {self.interface}"
                )
    
    def start(self):
        """Start packet capturing in background thread"""
        if self.is_running:
            mitm_logger.log_main("Packet capture already running")
            return
        
        self.is_running = True
        self.capture_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.capture_thread.start()
        mitm_logger.log_main(f"Started packet capture on {self.interface}")
    
    def _sniff_packets(self):
        """
        Main packet sniffing loop
        Runs in separate thread
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                filter=PACKET_FILTER,
                store=False,
                stop_filter=lambda x: not self.is_running,
                quiet=True
            )
        except PermissionError:
            mitm_logger.log_main(
                "ERROR: Root privileges required to capture packets. "
                "Run with 'sudo' on Linux/Mac",
                'ERROR'
            )
            self.is_running = False
        except Exception as e:
            mitm_logger.log_main(f"Packet capture error: {e}", 'ERROR')
            self.is_running = False
    
    def stop(self):
        """Stop packet capturing"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        mitm_logger.log_main(f"Stopped packet capture. Total packets: {self.packet_count}")
    
    def get_stats(self):
        """
        Get packet capture statistics
        
        Returns:
            dict: Statistics including packet count and interface
        """
        with self.lock:
            return {
                'packets_captured': self.packet_count,
                'interface': self.interface,
                'is_running': self.is_running
            }
    
    def reset_stats(self):
        """Reset packet counter"""
        with self.lock:
            self.packet_count = 0

print("[CAPTURE] Packet capture module initialized")
