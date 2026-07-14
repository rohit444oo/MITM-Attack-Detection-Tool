"""
GUI Dashboard for MITM Detection Tool
Tkinter-based real-time monitoring interface
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
from main import MITMDetector
from config.config import GUI_WIDTH, GUI_HEIGHT, GUI_UPDATE_INTERVAL
from src.logger import mitm_logger

class MITMDashboard:
    """Tkinter GUI for MITM Detection Tool"""
    
    def __init__(self, root):
        """Initialize GUI dashboard"""
        self.root = root
        self.root.title("MITM Attack Detection Tool - Dashboard")
        self.root.geometry(f"{GUI_WIDTH}x{GUI_HEIGHT}")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize detector
        self.detector = MITMDetector()
        self.running = False
        
        # Create GUI components
        self._create_menu()
        self._create_widgets()
        
        # Start update loop
        self._update_display()
        
        mitm_logger.log_main("GUI Dashboard created successfully")
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Start Detection", command=self.start_detection)
        file_menu.add_command(label="Stop Detection", command=self.stop_detection)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="ARP Table", command=self.show_arp_table)
        view_menu.add_command(label="Active Sessions", command=self.show_active_sessions)
        view_menu.add_command(label="Recent Alerts", command=self.show_recent_alerts)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Instructions", command=self.show_instructions)
    
    def _create_widgets(self):
        """Create main GUI widgets"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # ===== TOP PANEL: Status and Controls =====
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Status indicator
        self.status_label = ttk.Label(top_frame, text="Status: STOPPED", font=('Arial', 12, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        self.start_btn = ttk.Button(top_frame, text="▶ Start", command=self.start_detection)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(top_frame, text="⏹ Stop", command=self.stop_detection, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # ===== MAIN NOTEBOOK (Tabbed Interface) =====
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Statistics
        self._create_stats_tab()
        
        # Tab 2: Alerts
        self._create_alerts_tab()
        
        # Tab 3: ARP Monitor
        self._create_arp_tab()
        
        # Tab 4: TCP Monitor
        self._create_tcp_tab()
        
        # ===== BOTTOM PANEL: Log Output =====
        log_frame = ttk.LabelFrame(self.root, text="Log Output")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Log with scrollbar
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.log_text = tk.Text(log_frame, height=8, yscrollcommand=scrollbar.set)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.log_text.yview)
    
    def _create_stats_tab(self):
        """Create Statistics tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Statistics")
        
        # Create grid for statistics
        stats_frame = ttk.LabelFrame(frame, text="Real-time Detection Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Statistics labels
        self.stats_labels = {}
        
        stats_to_show = [
            ('Total Packets', 'total_packets'),
            ('ARP Packets', 'arp_packets'),
            ('TCP Packets', 'tcp_packets'),
            ('Tracked IPs', 'tracked_ips'),
            ('Suspicious IPs', 'suspicious_ips'),
            ('Active TCP Sessions', 'active_sessions'),
            ('ARP Spoofing Alerts', 'arp_alerts'),
            ('TCP Anomaly Alerts', 'tcp_alerts'),
            ('Total Alerts', 'total_alerts'),
        ]
        
        row = 0
        col = 0
        for label_text, key in stats_to_show:
            # Label
            ttk.Label(stats_frame, text=label_text, font=('Arial', 10, 'bold')).grid(row=row, column=col, sticky='w', padx=10, pady=5)
            
            # Value
            value_label = ttk.Label(stats_frame, text="0", font=('Arial', 10), foreground='blue')
            value_label.grid(row=row, column=col+1, sticky='w', padx=20, pady=5)
            
            self.stats_labels[key] = value_label
            
            col += 2
            if col >= 6:
                col = 0
                row += 1
    
    def _create_alerts_tab(self):
        """Create Alerts tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🚨 Alerts")
        
        # Button to refresh
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(btn_frame, text="Refresh Alerts", command=self.update_alerts_tab).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear Alerts", command=self.clear_alerts).pack(side=tk.LEFT, padx=5)
        
        # Treeview for alerts
        columns = ('Time', 'Type', 'Severity', 'Message')
        self.alerts_tree = ttk.Treeview(frame, columns=columns, height=15, show='tree headings')
        self.alerts_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Define column headings and widths
        self.alerts_tree.heading('#0', text='#')
        self.alerts_tree.column('#0', width=30)
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            if col == 'Time':
                self.alerts_tree.column(col, width=150)
            elif col == 'Type':
                self.alerts_tree.column(col, width=150)
            elif col == 'Severity':
                self.alerts_tree.column(col, width=80)
            else:
                self.alerts_tree.column(col, width=250)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_tree.config(yscroll=scrollbar.set)
    
    def _create_arp_tab(self):
        """Create ARP Monitor tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🔍 ARP Monitor")
        
        # Button to refresh
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(btn_frame, text="Refresh ARP Table", command=self.update_arp_tab).pack(side=tk.LEFT)
        
        # Treeview for ARP table
        columns = ('IP Address', 'MAC Address')
        self.arp_tree = ttk.Treeview(frame, columns=columns, height=15, show='tree headings')
        self.arp_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for col in columns:
            self.arp_tree.heading(col, text=col)
            self.arp_tree.column(col, width=200)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.arp_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.arp_tree.config(yscroll=scrollbar.set)
    
    def _create_tcp_tab(self):
        """Create TCP Monitor tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 TCP Sessions")
        
        # Button to refresh
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(btn_frame, text="Refresh Sessions", command=self.update_tcp_tab).pack(side=tk.LEFT)
        
        # Treeview for TCP sessions
        columns = ('Source', 'Destination', 'Packets', 'Duration (s)')
        self.tcp_tree = ttk.Treeview(frame, columns=columns, height=15, show='tree headings')
        self.tcp_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        for col in columns:
            self.tcp_tree.heading(col, text=col)
            if col == 'Duration (s)':
                self.tcp_tree.column(col, width=100)
            else:
                self.tcp_tree.column(col, width=180)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tcp_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tcp_tree.config(yscroll=scrollbar.set)
    
    def start_detection(self):
        """Start the detection tool"""
        if self.running:
            messagebox.showwarning("Warning", "Detection is already running!")
            return
        
        self.running = True
        self.detector.start()
        
        # Update UI
        self.status_label.config(text="Status: RUNNING ✓", foreground='green')
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        self._log_message("Detection started successfully")
    
    def stop_detection(self):
        """Stop the detection tool"""
        if not self.running:
            messagebox.showwarning("Warning", "Detection is not running!")
            return
        
        self.running = False
        self.detector.stop()
        
        # Update UI
        self.status_label.config(text="Status: STOPPED ✗", foreground='red')
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self._log_message("Detection stopped")
    
    def _update_display(self):
        """Update display with latest data"""
        if self.running:
            try:
                # Update statistics
                self._update_stats_tab()
                # Update alerts
                self._update_alerts_tab()
                # Update ARP table
                self._update_arp_tab()
                # Update TCP sessions
                self._update_tcp_tab()
            except Exception as e:
                self._log_message(f"Error updating display: {e}")
        
        # Schedule next update
        self.root.after(GUI_UPDATE_INTERVAL, self._update_display)
    
    def _update_stats_tab(self):
        """Update statistics display"""
        try:
            capture_stats = self.detector.packet_capture.get_stats()
            arp_stats = self.detector.arp_detector.get_stats()
            tcp_stats = self.detector.tcp_monitor.get_stats()
            
            # Update labels
            updates = {
                'total_packets': capture_stats['packets_captured'],
                'arp_packets': arp_stats['total_arp_packets'],
                'tcp_packets': tcp_stats['total_tcp_packets'],
                'tracked_ips': arp_stats['tracked_ips'],
                'suspicious_ips': arp_stats['suspicious_ips'],
                'active_sessions': tcp_stats['active_sessions'],
                'arp_alerts': arp_stats['alerts_triggered'],
                'tcp_alerts': tcp_stats['alerts_triggered'],
                'total_alerts': arp_stats['alerts_triggered'] + tcp_stats['alerts_triggered'],
            }
            
            for key, value in updates.items():
                if key in self.stats_labels:
                    self.stats_labels[key].config(text=str(value))
        except Exception as e:
            self._log_message(f"Error updating stats: {e}")
    
    def _update_alerts_tab(self):
        """Update alerts display"""
        try:
            # Clear existing items
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            # Get recent alerts
            alerts = self.detector.get_recent_alerts(20)
            
            # Add alerts to tree
            for i, alert in enumerate(alerts):
                timestamp = alert['timestamp'].strftime('%H:%M:%S')
                self.alerts_tree.insert('', 'end', text=str(i+1), values=(
                    timestamp,
                    alert['type'],
                    alert['severity'],
                    alert['message'][:60] + '...' if len(alert['message']) > 60 else alert['message']
                ))
        except Exception as e:
            self._log_message(f"Error updating alerts: {e}")
    
    def _update_arp_tab(self):
        """Update ARP table display"""
        try:
            # Clear existing items
            for item in self.arp_tree.get_children():
                self.arp_tree.delete(item)
            
            # Get ARP table
            arp_table = self.detector.get_arp_table()
            
            # Add entries to tree
            for i, (ip, mac) in enumerate(arp_table.items()):
                self.arp_tree.insert('', 'end', text=str(i+1), values=(ip, mac))
        except Exception as e:
            self._log_message(f"Error updating ARP table: {e}")
    
    def _update_tcp_tab(self):
        """Update TCP sessions display"""
        try:
            # Clear existing items
            for item in self.tcp_tree.get_children():
                self.tcp_tree.delete(item)
            
            # Get active sessions
            sessions = self.detector.get_active_sessions()[:20]  # Show top 20
            
            # Add sessions to tree
            for i, session in enumerate(sessions):
                self.tcp_tree.insert('', 'end', text=str(i+1), values=(
                    session['src'],
                    session['dst'],
                    session['packets'],
                    f"{session['duration']:.2f}"
                ))
        except Exception as e:
            self._log_message(f"Error updating TCP sessions: {e}")
    
    def update_alerts_tab(self):
        """Manually update alerts tab"""
        self._update_alerts_tab()
    
    def update_arp_tab(self):
        """Manually update ARP tab"""
        self._update_arp_tab()
    
    def update_tcp_tab(self):
        """Manually update TCP tab"""
        self._update_tcp_tab()
    
    def show_arp_table(self):
        """Show ARP table in new window"""
        arp_table = self.detector.get_arp_table()
        arp_text = "IP Address\t\t\tMAC Address\n"
        arp_text += "=" * 60 + "\n"
        for ip, mac in arp_table.items():
            arp_text += f"{ip:<20}\t{mac}\n"
        
        self._show_text_window("ARP Table", arp_text)
    
    def show_active_sessions(self):
        """Show active TCP sessions"""
        sessions = self.detector.get_active_sessions()
        text = "Active TCP Sessions\n"
        text += "=" * 80 + "\n"
        text += f"{'Source':<25} {'Destination':<25} {'Packets':<10} {'Duration':<10}\n"
        text += "-" * 80 + "\n"
        for session in sessions[:50]:
            text += f"{session['src']:<25} {session['dst']:<25} {session['packets']:<10} {session['duration']:.2f}s\n"
        
        self._show_text_window("Active TCP Sessions", text)
    
    def show_recent_alerts(self):
        """Show recent alerts"""
        alerts = self.detector.get_recent_alerts(50)
        text = "Recent Alerts\n"
        text += "=" * 100 + "\n"
        text += f"{'Time':<20} {'Type':<20} {'Severity':<15} {'Message':<45}\n"
        text += "-" * 100 + "\n"
        for alert in alerts:
            timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            msg = alert['message'][:40] + '...' if len(alert['message']) > 40 else alert['message']
            text += f"{timestamp:<20} {alert['type']:<20} {alert['severity']:<15} {msg:<45}\n"
        
        self._show_text_window("Recent Alerts", text)
    
    def _show_text_window(self, title, text):
        """Show text in a new window"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("800x600")
        
        text_widget = tk.Text(window)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)
        
        scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscroll=scrollbar.set)
    
    def clear_logs(self):
        """Clear log display"""
        self.log_text.delete(1.0, tk.END)
    
    def clear_alerts(self):
        """Clear alerts"""
        from src.alert_system import alert_system
        alert_system.clear_alerts()
        self._log_message("Alerts cleared")
    
    def _log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
        # Keep only last 1000 lines
        line_count = int(self.log_text.index('end-1c').split('.')[0])
        if line_count > 1000:
            self.log_text.delete('1.0', '2.0')
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", 
            "MITM Attack Detection Tool\n\n"
            "A comprehensive cybersecurity monitoring system\n"
            "that detects Man-in-the-Middle attacks in real-time.\n\n"
            "Version 1.0\n"
            "Platform: Linux/Kali Linux")
    
    def show_instructions(self):
        """Show instructions dialog"""
        instructions = """
MITM Detection Tool - Instructions

1. START DETECTION:
   - Click the 'Start' button or use File > Start Detection
   - The tool will begin monitoring network traffic

2. MONITOR ACTIVITY:
   - Statistics Tab: View real-time detection metrics
   - Alerts Tab: See all triggered security alerts
   - ARP Monitor: Track IP-MAC mappings
   - TCP Sessions: Monitor active connections

3. INTERPRETING ALERTS:
   - ARP Spoofing: Same IP with different MAC addresses
   - TCP Anomalies: Unusual session behavior
   - Port Scanning: Multiple connections to different ports
   - Abnormal Packet Rate: Possible DDoS attack

4. LOGS:
   - All activity is saved in the 'logs/' directory
   - Check logs for detailed forensic analysis

5. STOP DETECTION:
   - Click 'Stop' or close the application
   - Final report will be displayed
"""
        self._show_text_window("Instructions", instructions)
    
    def on_closing(self):
        """Handle window closing"""
        if self.running:
            if messagebox.askyesno("Exit", "Detection is running. Stop and exit?"):
                self.stop_detection()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main entry point for GUI"""
    root = tk.Tk()
    dashboard = MITMDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    main()
