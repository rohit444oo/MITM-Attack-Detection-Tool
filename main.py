"""
Main MITM Detection Tool Application
Orchestrates all detection modules and coordinates packet processing
"""

import threading
import time
from datetime import datetime
from src.packet_capture import PacketCapture
from src.arp_detector import ARPDetector
from src.tcp_monitor import TCPMonitor
from src.alert_system import alert_system
from src.logger import mitm_logger
from config.config import STATS_REFRESH_INTERVAL

class MITMDetector:
    """
    Main MITM Detection Tool
    Coordinates all detection modules and manages application lifecycle
    """
    
    def __init__(self):
        """Initialize MITM detector with all modules"""
        mitm_logger.log_main("Initializing MITM Detection Tool...")
        
        # Initialize detection modules
        self.arp_detector = ARPDetector()
        self.tcp_monitor = TCPMonitor()
        
        # Initialize packet capture with unified callback
        self.packet_capture = PacketCapture(
            callback=self._unified_packet_handler
        )
        
        # Control flags
        self.is_running = False
        self.stats_thread = None
        self.lock = threading.RLock()
        
        mitm_logger.log_main("MITM Detection Tool initialized successfully!")
    
    def _unified_packet_handler(self, packet):
        """
        Unified packet handler that processes packets through all detectors
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Process through ARP detector
            self.arp_detector.process_arp_packet(packet)
            
            # Process through TCP monitor
            self.tcp_monitor.process_tcp_packet(packet)
        except Exception as e:
            mitm_logger.log_main(f"Error in packet handler: {e}", 'ERROR')
    
    def start(self):
        """Start the MITM detection tool"""
        if self.is_running:
            print("[!] MITM Detector already running!")
            return
        
        self.is_running = True
        
        # Start packet capture
        self.packet_capture.start()
        
        # Start statistics and log reporting thread
        self.stats_thread = threading.Thread(target=self._stats_reporter, daemon=True)
        self.stats_thread.start()
        
        mitm_logger.log_main("=" * 70)
        mitm_logger.log_main("MITM DETECTION TOOL STARTED")
        mitm_logger.log_main("=" * 70)
        mitm_logger.log_main(f"Monitoring interface: {self.packet_capture.interface}")
        mitm_logger.log_main("Press Ctrl+C to stop")
        mitm_logger.log_main("=" * 70)
        
        print("\n[+] MITM Detection Tool is running...")
        print(f"[+] Monitoring on interface: {self.packet_capture.interface}")
        print("[+] Press Ctrl+C to stop\n")
    
    def stop(self):
        """Stop the MITM detection tool"""
        self.is_running = False
        
        # Stop packet capture
        self.packet_capture.stop()
        
        # Wait for stats thread
        if self.stats_thread:
            self.stats_thread.join(timeout=5)
        
        # Print final statistics
        self._print_final_stats()
        
        mitm_logger.log_main("=" * 70)
        mitm_logger.log_main("MITM DETECTION TOOL STOPPED")
        mitm_logger.log_main("=" * 70)
    
    def _stats_reporter(self):
        """
        Background thread that periodically logs statistics
        Runs while detection is active
        """
        while self.is_running:
            try:
                time.sleep(STATS_REFRESH_INTERVAL)
                
                if self.is_running:
                    self._print_stats()
            except Exception as e:
                mitm_logger.log_main(f"Error in stats reporter: {e}", 'ERROR')
    
    def _print_stats(self):
        """Print current detection statistics"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get stats from all modules
        capture_stats = self.packet_capture.get_stats()
        arp_stats = self.arp_detector.get_stats()
        tcp_stats = self.tcp_monitor.get_stats()
        alert_stats = alert_system.get_alert_stats()
        
        stats_msg = (
            f"\n{'='*70}\n"
            f"[{timestamp}] DETECTION STATISTICS\n"
            f"{'='*70}\n"
            f"PACKET CAPTURE:\n"
            f"  Total Packets: {capture_stats['packets_captured']}\n"
            f"  Interface: {capture_stats['interface']}\n\n"
            f"ARP SPOOFING DETECTION:\n"
            f"  ARP Packets: {arp_stats['total_arp_packets']}\n"
            f"  Tracked IPs: {arp_stats['tracked_ips']}\n"
            f"  Suspicious Mappings: {arp_stats['suspicious_mappings']}\n"
            f"  Suspicious IPs: {arp_stats['suspicious_ips']}\n"
            f"  Alerts: {arp_stats['alerts_triggered']}\n\n"
            f"TCP SESSION MONITORING:\n"
            f"  TCP Packets: {tcp_stats['total_tcp_packets']}\n"
            f"  Active Sessions: {tcp_stats['active_sessions']}\n"
            f"  Anomalies Detected: {tcp_stats['anomalies_detected']}\n"
            f"  Alerts: {tcp_stats['alerts_triggered']}\n\n"
            f"ALERT SUMMARY:\n"
            f"  Total Alerts: {alert_stats['total']}\n"
            f"  By Type: {alert_stats['by_type']}\n"
            f"  By Severity: {alert_stats['by_severity']}\n"
            f"{'='*70}\n"
        )
        
        print(stats_msg)
        mitm_logger.log_main(stats_msg)
    
    def _print_final_stats(self):
        """Print final statistics before shutdown"""
        print("\n" + "="*70)
        print("FINAL DETECTION REPORT")
        print("="*70)
        
        # Get final stats
        capture_stats = self.packet_capture.get_stats()
        arp_stats = self.arp_detector.get_stats()
        tcp_stats = self.tcp_monitor.get_stats()
        alert_stats = alert_system.get_alert_stats()
        
        print(f"\nPackets Captured: {capture_stats['packets_captured']}")
        print(f"ARP Packets Analyzed: {arp_stats['total_arp_packets']}")
        print(f"TCP Packets Analyzed: {tcp_stats['total_tcp_packets']}")
        
        print(f"\n--- ARP Spoofing Detection ---")
        print(f"Unique IPs Tracked: {arp_stats['tracked_ips']}")
        print(f"Suspicious Mappings Found: {arp_stats['suspicious_mappings']}")
        print(f"ARP Spoofing Alerts: {arp_stats['alerts_triggered']}")
        
        print(f"\n--- TCP Anomaly Detection ---")
        print(f"Active Sessions: {tcp_stats['active_sessions']}")
        print(f"Anomalies Detected: {tcp_stats['anomalies_detected']}")
        print(f"TCP-related Alerts: {tcp_stats['alerts_triggered']}")
        
        print(f"\n--- Overall Alerts ---")
        print(f"Total Alerts Triggered: {alert_stats['total']}")
        if alert_stats['by_type']:
            print(f"Alerts by Type: {alert_stats['by_type']}")
        if alert_stats['by_severity']:
            print(f"Alerts by Severity: {alert_stats['by_severity']}")
        
        print(f"\nCheck the 'logs/' directory for detailed reports:")
        print(f"  - mitm_detector.log (All activity)")
        print(f"  - alerts.log (Security alerts)")
        print(f"  - arp_spoofing.log (ARP spoofing details)")
        print(f"  - tcp_anomalies.log (TCP anomalies)")
        print("="*70 + "\n")
    
    def get_arp_table(self):
        """Get current ARP mapping table"""
        return self.arp_detector.get_arp_table()
    
    def get_suspicious_ips(self):
        """Get IPs involved in suspicious activity"""
        return self.arp_detector.get_suspicious_ips()
    
    def get_active_sessions(self):
        """Get active TCP sessions"""
        return self.tcp_monitor.get_active_sessions()
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts"""
        return alert_system.get_recent_alerts(count)

def main():
    """Main entry point for MITM Detection Tool"""
    print("""
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
    """)
    
    # Create detector instance
    detector = MITMDetector()
    
    try:
        # Start detection
        detector.start()
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n[!] Stopping MITM Detection Tool...")
        detector.stop()
        print("[+] Tool stopped successfully")
    
    except PermissionError:
        print("\n[ERROR] This tool requires root/administrator privileges!")
        print("[INFO] Run with: sudo python3 main.py")
    
    except Exception as e:
        mitm_logger.log_main(f"Fatal error: {e}", 'ERROR')
        print(f"[ERROR] Fatal error occurred: {e}")
        detector.stop()

if __name__ == "__main__":
    main()
