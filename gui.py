"""
Modern GUI for Flash Drive Antivirus using CustomTkinter
Professional dashboard with real-time monitoring and threat management
"""

import customtkinter as ctk
from customtkinter import CTkLabel, CTkButton, CTkFrame, CTkProgressBar, CTkTextbox
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import threading
import time
from datetime import datetime
from antivirus import AntvirusEngine, USBDevice

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class AntvirusGUI:
    """Main GUI Application"""
    
    def __init__(self, root):
        """Initialize GUI"""
        self.root = root
        self.root.title("Flash Drive Antivirus - Professional Edition")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Initialize antivirus engine
        self.engine = AntvirusEngine()
        self.engine.initialize_signatures()
        
        # State variables
        self.scanning = False
        self.monitoring = False
        self.current_scan_id = None
        self.selected_device = None
        
        # Setup GUI
        self.setup_ui()
        self.refresh_devices()
        self.start_monitor()
    
    def setup_ui(self):
        """Setup user interface"""
        # Main container
        main_container = CTkFrame(self.root)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header(main_container)
        
        # Content area
        content_frame = CTkFrame(main_container)
        content_frame.pack(fill="both", expand=True, pady=10)
        
        # Left panel - Devices
        left_panel = self.setup_left_panel(content_frame)
        left_panel.pack(side="left", fill="both", padx=(0, 10))
        
        # Right panel - Scan details
        right_panel = self.setup_right_panel(content_frame)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Footer
        self.setup_footer(main_container)
    
    def setup_header(self, parent):
        """Setup header section"""
        header = CTkFrame(parent, fg_color="#1e1e1e", corner_radius=10)
        header.pack(fill="x", pady=(0, 10))
        
        # Title
        title = CTkLabel(
            header,
            text="🛡️ Flash Drive Antivirus",
            font=("Helvetica", 24, "bold"),
            text_color="#00a8ff"
        )
        title.pack(side="left", padx=20, pady=15)
        
        # Status
        self.status_label = CTkLabel(
            header,
            text="Status: Idle",
            font=("Helvetica", 12),
            text_color="#90EE90"
        )
        self.status_label.pack(side="right", padx=20, pady=15)
    
    def setup_left_panel(self, parent):
        """Setup left panel with device list"""
        left_panel = CTkFrame(parent, fg_color="#2b2b2b", corner_radius=10)
        
        # Title
        title = CTkLabel(
            left_panel,
            text="📱 USB Devices",
            font=("Helvetica", 14, "bold")
        )
        title.pack(fill="x", padx=10, pady=10)
        
        # Device list frame
        self.devices_frame = CTkFrame(left_panel, fg_color="#1e1e1e", corner_radius=10)
        self.devices_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Refresh button
        refresh_btn = CTkButton(
            left_panel,
            text="🔄 Refresh Devices",
            command=self.refresh_devices,
            fg_color="#00a8ff",
            text_color="#000000"
        )
        refresh_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        return left_panel
    
    def setup_right_panel(self, parent):
        """Setup right panel with scan details"""
        right_panel = CTkFrame(parent, fg_color="#2b2b2b", corner_radius=10)
        
        # Scan controls
        controls_frame = CTkFrame(right_panel, fg_color="#1e1e1e", corner_radius=10)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        # Scan button
        self.scan_btn = CTkButton(
            controls_frame,
            text="🔍 Start Scan",
            command=self.start_scan,
            fg_color="#00a800",
            text_color="#ffffff",
            font=("Helvetica", 12, "bold"),
            height=40
        )
        self.scan_btn.pack(fill="x", pady=5)
        
        # Cancel button
        self.cancel_btn = CTkButton(
            controls_frame,
            text="⏹️ Cancel Scan",
            command=self.cancel_scan,
            fg_color="#ff6b6b",
            text_color="#ffffff",
            font=("Helvetica", 12, "bold"),
            height=40,
            state="disabled"
        )
        self.cancel_btn.pack(fill="x", pady=5)
        
        # Progress bar
        self.progress_bar = CTkProgressBar(controls_frame, mode="indeterminate")
        self.progress_bar.pack(fill="x", pady=5)
        
        # Results area
        results_frame = CTkFrame(right_panel, fg_color="#1e1e1e", corner_radius=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Results title
        results_title = CTkLabel(
            results_frame,
            text="📋 Scan Results",
            font=("Helvetica", 12, "bold")
        )
        results_title.pack(fill="x", padx=10, pady=5)
        
        # Results text box
        self.results_text = CTkTextbox(
            results_frame,
            font=("Courier", 10),
            text_color="#00ff00",
            fg_color="#0a0a0a"
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # History button
        history_btn = CTkButton(
            right_panel,
            text="📊 View Scan History",
            command=self.show_history,
            fg_color="#00a8ff",
            text_color="#000000"
        )
        history_btn.pack(fill="x", padx=10, pady=(0, 10))
        
        return right_panel
    
    def setup_footer(self, parent):
        """Setup footer section"""
        footer = CTkFrame(parent, fg_color="#1e1e1e", corner_radius=10)
        footer.pack(fill="x", pady=(10, 0))
        
        # Info label
        self.info_label = CTkLabel(
            footer,
            text="Ready for USB scanning | Monitor enabled",
            font=("Helvetica", 10),
            text_color="#cccccc"
        )
        self.info_label.pack(side="left", padx=20, pady=10)
        
        # Settings button
        settings_btn = CTkButton(
            footer,
            text="⚙️ Settings",
            command=self.show_settings,
            fg_color="#444444",
            text_color="#ffffff",
            width=100
        )
        settings_btn.pack(side="right", padx=20, pady=10)
    
    def refresh_devices(self):
        """Refresh USB device list"""
        # Clear current devices
        for widget in self.devices_frame.winfo_children():
            widget.destroy()
        
        # Get devices
        devices = self.engine.usb_detector.detect_usb_devices()
        
        if not devices:
            no_device_label = CTkLabel(
                self.devices_frame,
                text="No USB devices detected",
                text_color="#888888",
                font=("Helvetica", 11)
            )
            no_device_label.pack(fill="both", expand=True, padx=10, pady=20)
        else:
            for device in devices:
                self.add_device_button(device)
    
    def add_device_button(self, device: USBDevice):
        """Add device button to list"""
        device_btn_frame = CTkFrame(
            self.devices_frame,
            fg_color="#333333",
            corner_radius=8
        )
        device_btn_frame.pack(fill="x", padx=5, pady=5)
        
        # Device info
        info_text = f"{device.name}\n{device.mount_point}\n{device.size / (1024**3):.2f} GB"
        
        device_btn = CTkButton(
            device_btn_frame,
            text=info_text,
            command=lambda d=device: self.select_device(d),
            fg_color="#00a8ff" if self.selected_device == device else "#444444",
            text_color="#000000" if self.selected_device == device else "#ffffff",
            font=("Helvetica", 10),
            height=80
        )
        device_btn.pack(fill="both", expand=True, padx=2, pady=2)
    
    def select_device(self, device: USBDevice):
        """Select USB device for scanning"""
        self.selected_device = device
        self.results_text.delete("1.0", "end")
        self.results_text.insert("end", f"Selected device: {device.name}\n")
        self.results_text.insert("end", f"Mount point: {device.mount_point}\n")
        self.results_text.insert("end", f"Size: {device.size / (1024**3):.2f} GB\n")
        self.results_text.insert("end", "\nReady to scan. Click 'Start Scan' to begin.\n")
        self.refresh_devices()
    
    def start_scan(self):
        """Start scanning selected device"""
        if not self.selected_device:
            messagebox.showwarning("No Device Selected", "Please select a USB device to scan")
            return
        
        if self.scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running")
            return
        
        self.scanning = True
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress_bar.start()
        self.status_label.configure(text="Status: Scanning...", text_color="#ffff00")
        
        # Start scan in thread
        scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(self.selected_device.mount_point,),
            daemon=True
        )
        scan_thread.start()
    
    def _perform_scan(self, mount_point):
        """Perform scan (runs in thread)"""
        try:
            self.results_text.delete("1.0", "end")
            self.results_text.insert("end", f"Starting scan of {mount_point}...\n\n")
            
            start_time = time.time()
            
            def on_progress(total, result):
                """Update progress"""
                status = f"Scanned: {total} files"
                if result.is_suspicious:
                    status += f" | Found threat: {result.file_name}"
                self.info_label.configure(text=status)
            
            # Perform scan
            self.current_scan_id = self.engine.start_scan(mount_point)
            
            # Get results
            if self.current_scan_id > 0:
                history = self.engine.db_manager.get_scan_history(1)
                threats = self.engine.db_manager.get_detected_threats(self.current_scan_id)
                
                self.results_text.insert("end", "=== SCAN COMPLETED ===\n\n")
                
                if history:
                    h = history[0]
                    self.results_text.insert("end", f"Total Files: {h['total_files']}\n")
                    self.results_text.insert("end", f"Suspicious: {h['suspicious_files']}\n")
                    self.results_text.insert("end", f"Quarantined: {h['quarantined_files']}\n")
                    self.results_text.insert("end", f"Duration: {h['scan_duration']:.2f} seconds\n\n")
                
                if threats:
                    self.results_text.insert("end", f"=== THREATS DETECTED ({len(threats)}) ===\n\n")
                    for threat in threats:
                        self.results_text.insert("end", f"File: {threat['file_name']}\n")
                        self.results_text.insert("end", f"Threat: {threat['threat_name']}\n")
                        self.results_text.insert("end", f"Severity: {threat['threat_severity']}\n")
                        self.results_text.insert("end", f"Method: {threat['detection_method']}\n")
                        self.results_text.insert("end", f"Quarantined: {'Yes' if threat['quarantined'] else 'No'}\n")
                        self.results_text.insert("end", "-" * 50 + "\n")
                else:
                    self.results_text.insert("end", "✓ No threats detected!\n")
                
                self.status_label.configure(text="Status: Scan Complete", text_color="#00ff00")
            else:
                self.results_text.insert("end", "Scan failed. Check logs for details.\n")
                self.status_label.configure(text="Status: Scan Failed", text_color="#ff6b6b")
        
        except Exception as e:
            self.results_text.insert("end", f"Error during scan: {str(e)}\n")
            self.status_label.configure(text="Status: Error", text_color="#ff6b6b")
        
        finally:
            self.scanning = False
            self.scan_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.progress_bar.stop()
    
    def cancel_scan(self):
        """Cancel current scan"""
        self.engine.file_scanner.cancel_scan()
        self.results_text.insert("end", "\n[SCAN CANCELLED]\n")
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress_bar.stop()
        self.status_label.configure(text="Status: Cancelled", text_color="#ffff00")
    
    def show_history(self):
        """Show scan history window"""
        history_window = ctk.CTkToplevel(self.root)
        history_window.title("Scan History")
        history_window.geometry("800x600")
        
        # Get history
        history = self.engine.db_manager.get_scan_history(50)
        
        # Create text widget
        text_widget = CTkTextbox(history_window, font=("Courier", 10))
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)
        
        if history:
            text_widget.insert("end", "SCAN HISTORY\n")
            text_widget.insert("end", "=" * 80 + "\n\n")
            
            for h in history:
                text_widget.insert("end", f"ID: {h['id']}\n")
                text_widget.insert("end", f"Device: {h['usb_name']} ({h['usb_path']})\n")
                text_widget.insert("end", f"Date: {h['scan_date']}\n")
                text_widget.insert("end", f"Files: {h['total_files']} | Suspicious: {h['suspicious_files']} | Quarantined: {h['quarantined_files']}\n")
                text_widget.insert("end", f"Duration: {h['scan_duration']:.2f}s | Status: {h['status']}\n")
                text_widget.insert("end", "-" * 80 + "\n\n")
        else:
            text_widget.insert("end", "No scan history available")
        
        text_widget.configure(state="disabled")
    
    def show_settings(self):
        """Show settings window"""
        settings_window = ctk.CTkToplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x400")
        
        # Title
        title = CTkLabel(settings_window, text="⚙️ Antivirus Settings", font=("Helvetica", 14, "bold"))
        title.pack(fill="x", padx=10, pady=10)
        
        # Settings frame
        settings_frame = CTkFrame(settings_window, fg_color="#1e1e1e", corner_radius=10)
        settings_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Auto-scan option
        auto_scan_label = CTkLabel(settings_frame, text="Auto-scan on USB connection:", font=("Helvetica", 11))
        auto_scan_label.pack(fill="x", padx=15, pady=(15, 5))
        
        auto_scan_switch = ctk.CTkSwitch(settings_frame, text="Enable", onvalue=1, offvalue=0)
        auto_scan_switch.pack(fill="x", padx=15, pady=(0, 15))
        
        # Real-time monitoring
        monitor_label = CTkLabel(settings_frame, text="Real-time USB monitoring:", font=("Helvetica", 11))
        monitor_label.pack(fill="x", padx=15, pady=(10, 5))
        
        monitor_switch = ctk.CTkSwitch(settings_frame, text="Enable", onvalue=1, offvalue=0)
        monitor_switch.pack(fill="x", padx=15, pady=(0, 15))
        
        # Auto-quarantine
        quarantine_label = CTkLabel(settings_frame, text="Auto-quarantine threats:", font=("Helvetica", 11))
        quarantine_label.pack(fill="x", padx=15, pady=(10, 5))
        
        quarantine_switch = ctk.CTkSwitch(settings_frame, text="Enable", onvalue=1, offvalue=0)
        quarantine_switch.pack(fill="x", padx=15, pady=(0, 15))
        
        # Close button
        close_btn = CTkButton(
            settings_window,
            text="Close",
            command=settings_window.destroy,
            fg_color="#00a8ff"
        )
        close_btn.pack(fill="x", padx=10, pady=10)
    
    def start_monitor(self):
        """Start USB monitoring"""
        def on_device_change(action, device):
            if action == "connected":
                self.info_label.configure(text=f"USB Connected: {device.name}")
                self.refresh_devices()
            else:
                self.info_label.configure(text=f"USB Disconnected: {device.name}")
                self.refresh_devices()
        
        self.engine.usb_detector.register_callback(on_device_change)
        self.engine.usb_detector.start_monitoring()
        self.monitoring = True

class AntvirusApp:
    """Main application"""
    
    def __init__(self):
        """Initialize application"""
        self.root = ctk.CTk()
    
    def run(self):
        """Run application"""
        gui = AntvirusGUI(self.root)
        self.root.mainloop()

if __name__ == "__main__":
    app = AntvirusApp()
    app.run()
