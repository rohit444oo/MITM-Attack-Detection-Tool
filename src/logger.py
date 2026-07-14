"""
Logger module for MITM Detection Tool
Handles all logging to files and console
"""

import logging
import sys
from datetime import datetime
from config.config import (
    MAIN_LOG_FILE, ALERT_LOG_FILE, ARP_SPOOF_LOG, 
    TCP_ANOMALY_LOG, ENABLE_FILE_LOGGING, ENABLE_CONSOLE_OUTPUT
)

class MITMLogger:
    """Unified logger for all MITM detection events"""
    
    def __init__(self):
        """Initialize logger with multiple handlers"""
        self.main_logger = self._create_logger('mitm_main', MAIN_LOG_FILE)
        self.alert_logger = self._create_logger('mitm_alerts', ALERT_LOG_FILE)
        self.arp_logger = self._create_logger('arp_spoof', ARP_SPOOF_LOG)
        self.tcp_logger = self._create_logger('tcp_anomaly', TCP_ANOMALY_LOG)
    
    def _create_logger(self, name, log_file):
        """
        Create a logger with file and console handlers
        
        Args:
            name (str): Logger name
            log_file (str): Path to log file
            
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # Format string for logs
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        if ENABLE_FILE_LOGGING:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                print(f"[ERROR] Could not create file handler for {log_file}: {e}")
        
        # Console handler
        if ENABLE_CONSOLE_OUTPUT:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        return logger
    
    def log_main(self, message, level='INFO'):
        """Log to main logger"""
        getattr(self.main_logger, level.lower())(message)
    
    def log_alert(self, alert_type, message, severity='HIGH'):
        """
        Log security alert
        
        Args:
            alert_type (str): Type of alert (ARP_SPOOF, TCP_ANOMALY, etc.)
            message (str): Alert message
            severity (str): Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
        """
        alert_msg = f"[{severity}] [{alert_type}] {message}"
        self.alert_logger.warning(alert_msg)
    
    def log_arp_spoof(self, src_ip, mac1, mac2):
        """Log ARP spoofing detection"""
        msg = f"ARP SPOOF DETECTED: IP {src_ip} spoofed - MAC1: {mac1} -> MAC2: {mac2}"
        self.arp_logger.warning(msg)
        self.log_alert('ARP_SPOOFING', f"IP {src_ip} with different MACs detected", 'CRITICAL')
    
    def log_tcp_anomaly(self, src_ip, dst_ip, anomaly_type, details):
        """Log TCP session anomaly"""
        msg = f"TCP ANOMALY: {src_ip} -> {dst_ip} | Type: {anomaly_type} | Details: {details}"
        self.tcp_logger.warning(msg)
        self.log_alert('TCP_ANOMALY', f"{src_ip} -> {dst_ip}: {anomaly_type}", 'HIGH')
    
    def log_packet_info(self, message):
        """Log general packet information"""
        self.main_logger.debug(message)

# Global logger instance
mitm_logger = MITMLogger()

print("[LOGGER] Logger initialized successfully")
