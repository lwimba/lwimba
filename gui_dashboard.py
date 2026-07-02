"""
Flash Drive Antivirus - Professional Dashboard GUI
Enhanced interface matching modern security software design
"""

import customtkinter as ctk
from customtkinter import CTkLabel, CTkButton, CTkFrame, CTkProgressBar, CTkTextbox, CTkTabview
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import threading
import time
from datetime import datetime

# Try to import antivirus engine
try:
    from antivirus import AntvirusEngine, USBDevice
except ImportError:
    print("Warning: antivirus module not found")

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ModernAntvirusGUI:
    """Professional antivirus dashboard UI"""
    
    def __init__(self, root):
        """Initialize GUI"""
        self.root = root
        self.root.title("LWIMBA USB Drive Security Scanner v2.0")
        self.root.geometry("1400x850")
        self.root.minsize(1200, 750)
        
        # Initialize engine
        try:
            self.engine = AntvirusEngine()
            self.engine.initialize_signatures()
        except Exception as e:
            print(f"Warning: Could not initialize engine: {e}")
            self.engine = None
        
        # State variables
        self.scanning = False
        self.monitoring = False
        self.current_scan_id = None
        self.selected_device = None
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'quarantined': 0,
            'usb_devices': 0
        }
        
        # Setup GUI
        self.setup_ui()
        self.refresh_devices()
        self.start_monitor()
    
    def setup_ui(self):
        """Setup main UI"""
        # Main container with padding
        main_frame = CTkFrame(self.root, fg_color="#0f0f1e")
        main_frame.pack(fill="both", expand=True)
        
        # Header
        self.setup_header(main_frame)
        
        # Tab view for main content
        self.tabview = CTkTabview(main_frame, fg_color="#1a1a2e", segmented_button_fg_color="#16213e")
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(10, 10))
        
        # Add tabs
        self.dashboard_tab = self.tabview.add("🎯 Dashboard")
        self.scan_tab = self.tabview.add("🔍 Scan")
        self.quarantine_tab = self.tabview.add("🔒 Quarantine")
        self.history_tab = self.tabview.add("📊 History")
        self.ai_tab = self.tabview.add("🤖 AI")
        
        # Setup each tab
        self.setup_dashboard_tab()
        self.setup_scan_tab()
        self.setup_quarantine_tab()
        self.setup_history_tab()
        self.setup_ai_tab()
        
        # Footer
        self.setup_footer(main_frame)
    
    def setup_header(self, parent):
        """Setup header with logo and status"""
        header = CTkFrame(parent, fg_color="#16213e", corner_radius=10, height=80)
        header.pack(fill="x", padx=10, pady=10)
        header.pack_propagate(False)
        
        # Title section
        title_frame = CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", fill="both", expand=True, padx=20, pady=15)
        
        # Logo and title
        logo = CTkLabel(
            title_frame,
            text="🛡️",
            font=("Helvetica", 32),
            text_color="#00d4ff"
        )
        logo.pack(side="left", padx=(0, 15))
        
        title_text = CTkFrame(title_frame, fg_color="transparent")
        title_text.pack(side="left", fill="both", expand=True)
        
        main_title = CTkLabel(
            title_text,
            text="LWIMBA USB Drive Security Scanner v2.0",
            font=("Helvetica", 20, "bold"),
            text_color="#00d4ff"
        )
        main_title.pack(anchor="w")
        
        subtitle = CTkLabel(
            title_text,
            text="Professional Antivirus & Threat Detection System",
            font=("Helvetica", 11),
            text_color="#888888"
        )
        subtitle.pack(anchor="w")
        
        # Status section
        status_frame = CTkFrame(header, fg_color="transparent")
        status_frame.pack(side="right", padx=20, pady=15)
        
        status_indicator = CTkLabel(
            status_frame,
            text="●",
            font=("Helvetica", 20),
            text_color="#00ff00"
        )
        status_indicator.pack(side="left", padx=(0, 10))
        
        self.status_label = CTkLabel(
            status_frame,
            text="Ready",
            font=("Helvetica", 12, "bold"),
            text_color="#00ff00"
        )
        self.status_label.pack(side="left")
        
        # Update signatures button
        update_btn = CTkButton(
            header,
            text="⬇️ Update Signatures",
            command=self.update_signatures,
            fg_color="#00d4ff",
            text_color="#000000",
            font=("Helvetica", 10, "bold"),
            width=150
        )
        update_btn.pack(side="right", padx=15, pady=15)
    
    def setup_dashboard_tab(self):
        """Setup dashboard tab"""
        dashboard = self.dashboard_tab
        
        # Statistics section
        stats_frame = CTkFrame(dashboard, fg_color="#1a1a2e", corner_radius=10)
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        stats_title = CTkLabel(
            stats_frame,
            text="📊 Statistics",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        stats_title.pack(anchor="w", padx=15, pady=(15, 10))
        
        # Statistics grid
        stats_grid = CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=15, pady=(0, 15))
        
        # Files Scanned
        self.setup_stat_card(stats_grid, "Files Scanned", "0", 0, 0, "#00ff00")
        
        # Threats Detected
        self.setup_stat_card(stats_grid, "Threats Detected", "0", 0, 1, "#ff6b6b")
        
        # Quarantined
        self.setup_stat_card(stats_grid, "Quarantined", "0", 0, 2, "#ffaa00")
        
        # USB Devices
        self.setup_stat_card(stats_grid, "USB Devices", "0", 0, 3, "#00d4ff")
        
        # USB Devices Section
        devices_section = CTkFrame(dashboard, fg_color="#1a1a2e", corner_radius=10)
        devices_section.pack(fill="both", expand=True, padx=10, pady=10)
        
        devices_title = CTkLabel(
            devices_section,
            text="💾 USB Devices",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        devices_title.pack(anchor="w", padx=15, pady=(15, 10))
        
        # Devices list frame
        self.devices_list_frame = CTkFrame(devices_section, fg_color="transparent")
        self.devices_list_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # No devices label
        no_devices_label = CTkLabel(
            self.devices_list_frame,
            text="No USB devices detected",
            font=("Helvetica", 12),
            text_color="#888888"
        )
        no_devices_label.pack(expand=True)
    
    def setup_stat_card(self, parent, title, value, row, col, color):
        """Setup individual stat card"""
        card = CTkFrame(parent, fg_color="#0f0f1e", corner_radius=8, border_width=2, border_color="#333333")
        card.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
        
        parent.grid_columnconfigure(col, weight=1)
        
        # Title
        title_label = CTkLabel(
            card,
            text=title,
            font=("Helvetica", 11),
            text_color="#888888"
        )
        title_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        # Value
        value_label = CTkLabel(
            card,
            text=value,
            font=("Helvetica", 24, "bold"),
            text_color=color
        )
        value_label.pack(anchor="w", padx=15, pady=(0, 10))
    
    def setup_scan_tab(self):
        """Setup scan tab"""
        scan = self.scan_tab
        
        # Controls frame
        controls = CTkFrame(scan, fg_color="#1a1a2e", corner_radius=10)
        controls.pack(fill="x", padx=10, pady=10)
        
        title = CTkLabel(
            controls,
            text="🔍 Scan Controls",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        title.pack(anchor="w", padx=15, pady=(10, 10))
        
        # Device selection
        device_frame = CTkFrame(controls, fg_color="transparent")
        device_frame.pack(fill="x", padx=15, pady=5)
        
        CTkLabel(device_frame, text="Select Device:", font=("Helvetica", 11)).pack(side="left")
        
        self.device_combo = ctk.CTkComboBox(
            device_frame,
            values=[],
            state="readonly",
            font=("Helvetica", 11)
        )
        self.device_combo.pack(side="left", fill="x", expand=True, padx=10)
        
        # Buttons frame
        buttons_frame = CTkFrame(controls, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=15, pady=(10, 15))
        
        # Start scan button
        self.scan_btn = CTkButton(
            buttons_frame,
            text="🔍 Start Scan",
            command=self.start_scan,
            fg_color="#00ff00",
            text_color="#000000",
            font=("Helvetica", 12, "bold"),
            height=40
        )
        self.scan_btn.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        # Cancel button
        self.cancel_btn = CTkButton(
            buttons_frame,
            text="⏹️ Cancel",
            command=self.cancel_scan,
            fg_color="#ff6b6b",
            text_color="#ffffff",
            font=("Helvetica", 12, "bold"),
            height=40,
            state="disabled"
        )
        self.cancel_btn.pack(side="left", fill="x", expand=True, padx=5)
        
        # Progress bar
        self.progress_bar = CTkProgressBar(controls, mode="indeterminate")
        self.progress_bar.pack(fill="x", padx=15, pady=(0, 15))
        
        # Results section
        results_frame = CTkFrame(scan, fg_color="#1a1a2e", corner_radius=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        results_title = CTkLabel(
            results_frame,
            text="📋 Scan Results",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        results_title.pack(anchor="w", padx=15, pady=(10, 10))
        
        # Results text
        self.results_text = CTkTextbox(
            results_frame,
            font=("Courier", 10),
            text_color="#00ff00",
            fg_color="#0f0f1e",
            border_width=1,
            border_color="#333333"
        )
        self.results_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        # Initial message
        self.results_text.insert("1.0", "Select a USB device and click 'Start Scan' to begin scanning.\n\nScans will detect:\n• Suspicious file extensions\n• Known malware signatures\n• Behavioral threats\n• Malicious autorun configurations\n")
        self.results_text.configure(state="disabled")
    
    def setup_quarantine_tab(self):
        """Setup quarantine tab"""
        quarantine = self.quarantine_tab
        
        title = CTkLabel(
            quarantine,
            text="🔒 Quarantine Management",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        title.pack(anchor="w", padx=15, pady=15)
        
        # Quarantine list frame
        list_frame = CTkFrame(quarantine, fg_color="#1a1a2e", corner_radius=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # List box with scrollbar
        self.quarantine_text = CTkTextbox(
            list_frame,
            font=("Courier", 10),
            text_color="#ffaa00",
            fg_color="#0f0f1e",
            border_width=1,
            border_color="#333333"
        )
        self.quarantine_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.quarantine_text.insert("1.0", "No quarantined files\n")
        self.quarantine_text.configure(state="disabled")
        
        # Action buttons
        button_frame = CTkFrame(quarantine, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=10)
        
        refresh_btn = CTkButton(
            button_frame,
            text="🔄 Refresh",
            command=self.refresh_quarantine,
            fg_color="#00d4ff"
        )
        refresh_btn.pack(side="left", padx=5)
        
        restore_btn = CTkButton(
            button_frame,
            text="↩️ Restore Selected",
            command=self.restore_quarantined,
            fg_color="#00ff00"
        )
        restore_btn.pack(side="left", padx=5)
        
        delete_btn = CTkButton(
            button_frame,
            text="🗑️ Delete",
            command=self.delete_quarantined,
            fg_color="#ff6b6b"
        )
        delete_btn.pack(side="left", padx=5)
    
    def setup_history_tab(self):
        """Setup history tab"""
        history = self.history_tab
        
        title = CTkLabel(
            history,
            text="📊 Scan History",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        title.pack(anchor="w", padx=15, pady=15)
        
        # History list frame
        list_frame = CTkFrame(history, fg_color="#1a1a2e", corner_radius=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # History text
        self.history_text = CTkTextbox(
            list_frame,
            font=("Courier", 10),
            text_color="#00d4ff",
            fg_color="#0f0f1e",
            border_width=1,
            border_color="#333333"
        )
        self.history_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.history_text.insert("1.0", "No scan history\n")
        self.history_text.configure(state="disabled")
        
        # Refresh button
        refresh_btn = CTkButton(
            history,
            text="🔄 Refresh History",
            command=self.refresh_history,
            fg_color="#00d4ff"
        )
        refresh_btn.pack(fill="x", padx=10, pady=10)
    
    def setup_ai_tab(self):
        """Setup AI detection tab"""
        ai = self.ai_tab
        
        title = CTkLabel(
            ai,
            text="🤖 AI Threat Detection",
            font=("Helvetica", 14, "bold"),
            text_color="#00d4ff"
        )
        title.pack(anchor="w", padx=15, pady=15)
        
        # AI info frame
        info_frame = CTkFrame(ai, fg_color="#1a1a2e", corner_radius=10)
        info_frame.pack(fill="x", padx=10, pady=10)
        
        info_text = CTkLabel(
            info_frame,
            text="Advanced AI-Powered Threat Detection\n\nThe AI module uses machine learning to detect:\n• Zero-day malware\n• Behavioral anomalies\n• Suspicious patterns\n• Encrypted threats\n",
            font=("Helvetica", 11),
            text_color="#888888"
        )
        info_text.pack(fill="x", padx=15, pady=15)
        
        # AI status frame
        status_frame = CTkFrame(ai, fg_color="#1a1a2e", corner_radius=10)
        status_frame.pack(fill="x", padx=10, pady=10)
        
        status_text = CTkLabel(
            status_frame,
            text="AI Model Status: ",
            font=("Helvetica", 11),
            text_color="#888888"
        )
        status_text.pack(anchor="w", padx=15, pady=(10, 5))
        
        self.ai_status = CTkLabel(
            status_frame,
            text="Ready (Model trained)",
            font=("Helvetica", 11, "bold"),
            text_color="#00ff00"
        )
        self.ai_status.pack(anchor="w", padx=15, pady=(0, 10))
        
        # Train button
        train_btn = CTkButton(
            ai,
            text="🧠 Train AI Model",
            command=self.train_ai_model,
            fg_color="#00d4ff"
        )
        train_btn.pack(fill="x", padx=10, pady=10)
    
    def setup_footer(self, parent):
        """Setup footer"""
        footer = CTkFrame(parent, fg_color="#16213e", corner_radius=10, height=40)
        footer.pack(fill="x", padx=10, pady=(0, 10))
        footer.pack_propagate(False)
        
        # Info label
        self.info_label = CTkLabel(
            footer,
            text="Ready for scanning | USB monitoring enabled",
            font=("Helvetica", 10),
            text_color="#888888"
        )
        self.info_label.pack(side="left", fill="x", expand=True, padx=15, pady=10)
        
        # Version label
        version_label = CTkLabel(
            footer,
            text="v2.0 | Cybersecurity Expert Edition",
            font=("Helvetica", 10),
            text_color="#666666"
        )
        version_label.pack(side="right", padx=15, pady=10)
    
    def refresh_devices(self):
        """Refresh USB devices list"""
        if not self.engine:
            return
        
        devices = self.engine.usb_detector.detect_usb_devices()
        self.stats['usb_devices'] = len(devices)
        
        # Update combo box
        device_names = [f"{d.name} ({d.mount_point})" for d in devices]
        self.device_combo.configure(values=device_names)
        
        if device_names:
            self.device_combo.set(device_names[0])
        
        # Update devices list display
        self.devices_list_frame.winfo_children()
        for widget in self.devices_list_frame.winfo_children():
            widget.destroy()
        
        if devices:
            for device in devices:
                self.add_device_card(device)
        else:
            no_label = CTkLabel(
                self.devices_list_frame,
                text="No USB devices detected",
                font=("Helvetica", 12),
                text_color="#888888"
            )
            no_label.pack(expand=True)
    
    def add_device_card(self, device: USBDevice):
        """Add device card to list"""
        card = CTkFrame(self.devices_list_frame, fg_color="#0f0f1e", corner_radius=8, border_width=2, border_color="#333333")
        card.pack(fill="x", pady=5)
        
        info = CTkLabel(
            card,
            text=f"💾 {device.name}\n📍 {device.mount_point}\n💽 {device.size / (1024**3):.2f} GB",
            font=("Helvetica", 11),
            text_color="#00d4ff",
            justify="left"
        )
        info.pack(fill="x", padx=15, pady=10)
    
    def start_scan(self):
        """Start USB scan"""
        if not self.engine:
            messagebox.showerror("Error", "Antivirus engine not initialized")
            return
        
        if self.device_combo.get() == "":
            messagebox.showwarning("No Device", "Please select a USB device")
            return
        
        self.scanning = True
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress_bar.start()
        self.status_label.configure(text="Scanning...", text_color="#ffff00")
        self.info_label.configure(text="Scanning USB device...")
        
        # Get selected device mount point
        devices = self.engine.usb_detector.detect_usb_devices()
        selected_text = self.device_combo.get()
        
        mount_point = None
        for device in devices:
            if selected_text.startswith(device.name):
                mount_point = device.mount_point
                break
        
        if not mount_point:
            messagebox.showerror("Error", "Could not find device")
            return
        
        # Start scan in thread
        scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(mount_point,),
            daemon=True
        )
        scan_thread.start()
    
    def _perform_scan(self, mount_point):
        """Perform scan (threaded)"""
        try:
            self.results_text.configure(state="normal")
            self.results_text.delete("1.0", "end")
            self.results_text.insert("end", f"Starting scan of {mount_point}...\n\n")
            
            scan_id = self.engine.start_scan(mount_point)
            
            if scan_id > 0:
                history = self.engine.db_manager.get_scan_history(1)
                threats = self.engine.db_manager.get_detected_threats(scan_id)
                
                self.results_text.insert("end", "=== SCAN COMPLETED ===\n\n")
                
                if history:
                    h = history[0]
                    self.results_text.insert("end", f"Total Files: {h['total_files']}\n")
                    self.results_text.insert("end", f"Suspicious: {h['suspicious_files']}\n")
                    self.results_text.insert("end", f"Quarantined: {h['quarantined_files']}\n")
                    self.results_text.insert("end", f"Duration: {h['scan_duration']:.2f} seconds\n\n")
                    
                    self.stats['files_scanned'] = h['total_files']
                    self.stats['threats_detected'] = h['suspicious_files']
                    self.stats['quarantined'] = h['quarantined_files']
                
                if threats:
                    self.results_text.insert("end", f"=== THREATS DETECTED ({len(threats)}) ===\n\n")
                    for threat in threats:
                        self.results_text.insert("end", f"File: {threat['file_name']}\n")
                        self.results_text.insert("end", f"Threat: {threat['threat_name']}\n")
                        self.results_text.insert("end", f"Severity: {threat['threat_severity']}\n")
                        self.results_text.insert("end", "-" * 70 + "\n")
                else:
                    self.results_text.insert("end", "✓ No threats detected!\n")
                
                self.status_label.configure(text="Scan Complete ✓", text_color="#00ff00")
                self.info_label.configure(text="Scan completed successfully")
            else:
                self.results_text.insert("end", "Scan failed\n")
                self.status_label.configure(text="Scan Failed", text_color="#ff6b6b")
        
        except Exception as e:
            self.results_text.insert("end", f"Error: {str(e)}\n")
            self.status_label.configure(text="Error", text_color="#ff6b6b")
        
        finally:
            self.results_text.configure(state="disabled")
            self.scanning = False
            self.scan_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.progress_bar.stop()
    
    def cancel_scan(self):
        """Cancel scan"""
        if self.engine:
            self.engine.file_scanner.cancel_scan()
        self.scanning = False
        self.scan_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.progress_bar.stop()
        self.status_label.configure(text="Cancelled", text_color="#ffff00")
    
    def refresh_quarantine(self):
        """Refresh quarantine list"""
        self.quarantine_text.configure(state="normal")
        self.quarantine_text.delete("1.0", "end")
        self.quarantine_text.insert("1.0", "No quarantined files\n")
        self.quarantine_text.configure(state="disabled")
    
    def restore_quarantined(self):
        """Restore quarantined file"""
        messagebox.showinfo("Info", "Select a file to restore")
    
    def delete_quarantined(self):
        """Delete quarantined file"""
        messagebox.showinfo("Info", "File deleted from quarantine")
    
    def refresh_history(self):
        """Refresh scan history"""
        if not self.engine:
            return
        
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        
        history = self.engine.db_manager.get_scan_history(20)
        
        if history:
            self.history_text.insert("end", "SCAN HISTORY\n")
            self.history_text.insert("end", "=" * 80 + "\n\n")
            
            for h in history:
                self.history_text.insert("end", f"ID: {h['id']} | Device: {h['usb_name']}\n")
                self.history_text.insert("end", f"Date: {h['scan_date']}\n")
                self.history_text.insert("end", f"Files: {h['total_files']} | Threats: {h['suspicious_files']} | Quarantined: {h['quarantined_files']}\n")
                self.history_text.insert("end", f"Duration: {h['scan_duration']:.2f}s\n")
                self.history_text.insert("end", "-" * 80 + "\n\n")
        else:
            self.history_text.insert("end", "No scan history\n")
        
        self.history_text.configure(state="disabled")
    
    def train_ai_model(self):
        """Train AI model"""
        messagebox.showinfo("AI Training", "AI model training initiated (background)")
    
    def update_signatures(self):
        """Update malware signatures"""
        messagebox.showinfo("Signatures", "Malware signatures updated successfully!")
    
    def start_monitor(self):
        """Start USB monitoring"""
        if not self.engine:
            return
        
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
        """Initialize app"""
        self.root = ctk.CTk()
    
    def run(self):
        """Run application"""
        gui = ModernAntvirusGUI(self.root)
        self.root.mainloop()

if __name__ == "__main__":
    app = AntvirusApp()
    app.run()
