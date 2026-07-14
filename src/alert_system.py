"""
Alert System module for MITM Detection Tool
Handles alerts, notifications, and sound/popup alerts
"""

import os
import threading
import time
from datetime import datetime
from config.config import ENABLE_SOUND_ALERT, ENABLE_GUI_POPUP, ENABLE_CONSOLE_OUTPUT
from src.logger import mitm_logger

class AlertSystem:
    """Manages all types of alerts and notifications"""
    
    def __init__(self):
        """Initialize alert system"""
        self.alert_queue = []
        self.alert_lock = threading.Lock()
        self.active_alerts = {}  # Track active alerts to avoid spam
        self.alert_cooldown = 30  # seconds between same alerts
    
    def trigger_alert(self, alert_type, message, severity='HIGH'):
        """
        Trigger an alert with multiple notification methods
        
        Args:
            alert_type (str): Type of alert (ARP_SPOOF, TCP_ANOMALY, DDOS, etc.)
            message (str): Detailed alert message
            severity (str): Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
        """
        timestamp = datetime.now()
        
        # Create unique alert key to prevent spam
        alert_key = f"{alert_type}_{message[:30]}"
        
        # Check cooldown to prevent alert spam
        if alert_key in self.active_alerts:
            last_alert = self.active_alerts[alert_key]
            if (timestamp - last_alert).total_seconds() < self.alert_cooldown:
                return  # Alert already triggered recently, skip
        
        # Update last alert time
        self.active_alerts[alert_key] = timestamp
        
        # Add to alert queue
        with self.alert_lock:
            self.alert_queue.append({
                'type': alert_type,
                'message': message,
                'severity': severity,
                'timestamp': timestamp
            })
        
        # Execute notification methods
        if ENABLE_CONSOLE_OUTPUT:
            self._console_alert(alert_type, message, severity)
        
        if ENABLE_SOUND_ALERT:
            self._sound_alert(severity)
        
        if ENABLE_GUI_POPUP:
            self._gui_alert(alert_type, message, severity)
        
        # Log the alert
        mitm_logger.log_alert(alert_type, message, severity)
    
    def _console_alert(self, alert_type, message, severity):
        """Display alert in console"""
        colors = {
            'LOW': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',   # Blue
            'HIGH': '\033[91m',     # Red
            'CRITICAL': '\033[41m'  # Red background
        }
        reset = '\033[0m'
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        color = colors.get(severity, '\033[91m')
        alert_msg = f"\n{color}[{severity}] {timestamp} - {alert_type}:{reset}\n{message}\n"
        print(alert_msg)
    
    def _sound_alert(self, severity):
        """
        Trigger sound alert
        Different tones for different severity levels
        """
        try:
            # Try using system beep
            import winsound
            frequencies = {
                'LOW': 440,
                'MEDIUM': 880,
                'HIGH': 1320,
                'CRITICAL': 2640
            }
            duration = {'LOW': 200, 'MEDIUM': 300, 'HIGH': 500, 'CRITICAL': 1000}
            
            freq = frequencies.get(severity, 880)
            dur = duration.get(severity, 300)
            
            # Only on Windows with winsound
            try:
                winsound.Beep(freq, dur)
            except:
                # Fallback for Linux/Mac
                os.system(f'echo -e "\\a"')
        except ImportError:
            # Linux/Mac: use system commands
            try:
                os.system('printf "\\a"')  # System bell
            except:
                pass
    
    def _gui_alert(self, alert_type, message, severity):
        """
        Display GUI popup alert
        Uses tkinter for desktop notification
        """
        try:
            import tkinter as tk
            from tkinter import messagebox
            
            # Create hidden root window
            root = tk.Tk()
            root.withdraw()
            root.after(200, lambda: root.destroy())  # Auto-close after 0.2s
            
            # Determine message box type
            if severity == 'CRITICAL':
                messagebox.showerror(f"CRITICAL ALERT - {alert_type}", message)
            elif severity == 'HIGH':
                messagebox.showwarning(f"HIGH ALERT - {alert_type}", message)
            else:
                messagebox.showinfo(f"Alert - {alert_type}", message)
            
            root.mainloop()
        except Exception as e:
            mitm_logger.log_packet_info(f"GUI alert failed: {e}")
    
    def get_recent_alerts(self, count=10):
        """
        Get recent alerts
        
        Args:
            count (int): Number of recent alerts to return
            
        Returns:
            list: List of recent alerts
        """
        with self.alert_lock:
            return self.alert_queue[-count:]
    
    def clear_alerts(self):
        """Clear all alerts from queue"""
        with self.alert_lock:
            self.alert_queue.clear()
    
    def get_alert_stats(self):
        """Get statistics about alerts"""
        with self.alert_lock:
            total_alerts = len(self.alert_queue)
            
            type_count = {}
            severity_count = {}
            
            for alert in self.alert_queue:
                alert_type = alert['type']
                severity = alert['severity']
                
                type_count[alert_type] = type_count.get(alert_type, 0) + 1
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            return {
                'total': total_alerts,
                'by_type': type_count,
                'by_severity': severity_count
            }

# Global alert system instance
alert_system = AlertSystem()

print("[ALERT] Alert system initialized successfully")
