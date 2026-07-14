"""
Test Script for MITM Detection Tool
Verifies installation and tests basic functionality
"""

import sys
import time
import threading
from datetime import datetime

def test_imports():
    """Test if all required modules can be imported"""
    print("\n" + "="*70)
    print("TEST 1: Module Imports")
    print("="*70)
    
    modules = [
        ("scapy", "Scapy Network Packet Library"),
        ("socket", "Python Socket Module"),
        ("threading", "Python Threading Module"),
        ("tkinter", "Tkinter GUI (optional)"),
    ]
    
    passed = 0
    failed = 0
    
    for module, description in modules:
        try:
            __import__(module)
            print(f"[✓] {module:<20} - {description}")
            passed += 1
        except ImportError as e:
            print(f"[✗] {module:<20} - {description}")
            print(f"    Error: {e}")
            failed += 1
    
    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0

def test_project_imports():
    """Test if all project modules can be imported"""
    print("\n" + "="*70)
    print("TEST 2: Project Module Imports")
    print("="*70)
    
    modules = [
        ("config.config", "Configuration Module"),
        ("src.logger", "Logger Module"),
        ("src.alert_system", "Alert System Module"),
        ("src.packet_capture", "Packet Capture Module"),
        ("src.arp_detector", "ARP Detector Module"),
        ("src.tcp_monitor", "TCP Monitor Module"),
        ("main", "Main Application"),
    ]
    
    passed = 0
    failed = 0
    
    for module, description in modules:
        try:
            __import__(module)
            print(f"[✓] {module:<25} - {description}")
            passed += 1
        except ImportError as e:
            print(f"[✗] {module:<25} - {description}")
            print(f"    Error: {e}")
            failed += 1
    
    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0

def test_arp_detector():
    """Test ARP detector functionality"""
    print("\n" + "="*70)
    print("TEST 3: ARP Detector")
    print("="*70)
    
    try:
        from src.arp_detector import ARPDetector
        from src.alert_system import alert_system
        
        detector = ARPDetector()
        print("[✓] ARPDetector instantiated")
        
        # Simulate ARP packets
        class MockARPPacket:
            def __init__(self):
                self.layer_name = 'ARP'
            
            def __getitem__(self, key):
                if key == 'ARP':
                    return self
                return None
            
            def haslayer(self, layer):
                return True
            
            @property
            def psrc(self):
                return '192.168.1.10'
            
            @property
            def hwsrc(self):
                return 'aa:bb:cc:dd:ee:ff'
            
            @property
            def pdst(self):
                return '192.168.1.1'
        
        # Test packet processing
        packet = MockARPPacket()
        detector.process_arp_packet(packet)
        print("[✓] ARP packet processing works")
        
        # Test ARP table
        arp_table = detector.get_arp_table()
        print(f"[✓] ARP table contains {len(arp_table)} entries")
        
        # Test statistics
        stats = detector.get_stats()
        print(f"[✓] Statistics: {stats['total_arp_packets']} ARP packets processed")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_tcp_monitor():
    """Test TCP monitor functionality"""
    print("\n" + "="*70)
    print("TEST 4: TCP Monitor")
    print("="*70)
    
    try:
        from src.tcp_monitor import TCPMonitor
        
        monitor = TCPMonitor()
        print("[✓] TCPMonitor instantiated")
        
        # Test statistics
        stats = monitor.get_stats()
        print(f"[✓] Initial statistics: {stats['total_tcp_packets']} TCP packets")
        
        # Test active sessions
        sessions = monitor.get_active_sessions()
        print(f"[✓] Active sessions: {len(sessions)}")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_alert_system():
    """Test alert system functionality"""
    print("\n" + "="*70)
    print("TEST 5: Alert System")
    print("="*70)
    
    try:
        from src.alert_system import alert_system
        
        # Trigger a test alert
        print("[*] Triggering test alert...")
        alert_system.trigger_alert(
            'TEST_ALERT',
            'This is a test alert to verify the alerting system works correctly',
            'MEDIUM'
        )
        
        print("[✓] Alert triggered successfully")
        
        # Check alert queue
        recent = alert_system.get_recent_alerts(5)
        print(f"[✓] Recent alerts in queue: {len(recent)}")
        
        # Check statistics
        stats = alert_system.get_alert_stats()
        print(f"[✓] Total alerts: {stats['total']}")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_logger():
    """Test logging functionality"""
    print("\n" + "="*70)
    print("TEST 6: Logger")
    print("="*70)
    
    try:
        from src.logger import mitm_logger
        
        # Log test messages
        mitm_logger.log_main("TEST: Main log message", 'INFO')
        print("[✓] Main logger works")
        
        mitm_logger.log_arp_spoof('192.168.1.1', 'aa:bb:cc:dd:ee:00', 'aa:bb:cc:dd:ee:01')
        print("[✓] ARP logger works")
        
        # Check if log files exist
        import os
        from config.config import MAIN_LOG_FILE, ALERT_LOG_FILE
        
        if os.path.exists(MAIN_LOG_FILE):
            print(f"[✓] Main log file created: {MAIN_LOG_FILE}")
        
        if os.path.exists(ALERT_LOG_FILE):
            print(f"[✓] Alert log file created: {ALERT_LOG_FILE}")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_config():
    """Test configuration loading"""
    print("\n" + "="*70)
    print("TEST 7: Configuration")
    print("="*70)
    
    try:
        from config.config import (
            ARP_SPOOF_THRESHOLD,
            ABNORMAL_PACKET_RATE,
            TCP_SESSION_TIMEOUT,
            SNIFF_INTERFACE,
            GUI_WIDTH, GUI_HEIGHT
        )
        
        print(f"[✓] ARP Spoof Threshold: {ARP_SPOOF_THRESHOLD}")
        print(f"[✓] Abnormal Packet Rate: {ABNORMAL_PACKET_RATE}")
        print(f"[✓] TCP Session Timeout: {TCP_SESSION_TIMEOUT} seconds")
        print(f"[✓] Sniff Interface: {SNIFF_INTERFACE} (auto-detect)")
        print(f"[✓] GUI Size: {GUI_WIDTH}x{GUI_HEIGHT}")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_network_interfaces():
    """Test network interface detection"""
    print("\n" + "="*70)
    print("TEST 8: Network Interfaces")
    print("="*70)
    
    try:
        from scapy.all import get_if_list
        
        interfaces = get_if_list()
        print(f"[✓] Found {len(interfaces)} network interfaces:")
        
        for iface in interfaces[:10]:  # Show first 10
            print(f"    - {iface}")
        
        if len(interfaces) > 10:
            print(f"    ... and {len(interfaces) - 10} more")
        
        return True
    except Exception as e:
        print(f"[✗] Error: {e}")
        print("[!] Note: This may fail on Windows (Scapy limitation)")
        return False

def print_summary(results):
    """Print test summary"""
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r)
    
    for i, (test_name, result) in enumerate(results, 1):
        status = "[✓ PASSED]" if result else "[✗ FAILED]"
        print(f"{i}. {test_name:<40} {status}")
    
    print("="*70)
    print(f"Total: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("[✓] All tests passed! Installation is successful.")
    elif passed_tests >= total_tests - 2:
        print("[!] Most tests passed. Some features may not work.")
    else:
        print("[✗] Multiple tests failed. Please review the errors above.")
    
    print("="*70)
    
    return passed_tests == total_tests

def main():
    """Run all tests"""
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║         MITM DETECTION TOOL - TEST SUITE                      ║
    ║         Installation Verification                             ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    results = []
    
    # Run tests
    results.append(("1. Module Imports", test_imports()))
    results.append(("2. Project Module Imports", test_project_imports()))
    results.append(("3. ARP Detector", test_arp_detector()))
    results.append(("4. TCP Monitor", test_tcp_monitor()))
    results.append(("5. Alert System", test_alert_system()))
    results.append(("6. Logger", test_logger()))
    results.append(("7. Configuration", test_config()))
    results.append(("8. Network Interfaces", test_network_interfaces()))
    
    # Print summary
    success = print_summary(results)
    
    # Print next steps
    print("\nNEXT STEPS:")
    print("="*70)
    if success:
        print("[1] Review the README.md for features and usage")
        print("[2] Run the main tool: sudo python3 main.py")
        print("[3] Or try the GUI: sudo python3 gui_dashboard.py")
        print("[4] Check logs in the logs/ directory")
    else:
        print("[1] Review the errors above")
        print("[2] Ensure all dependencies are installed:")
        print("    sudo pip3 install scapy==2.5.0")
        print("[3] Check that you're using Python 3.8 or higher:")
        print("    python3 --version")
    
    print("="*70)
    print()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
