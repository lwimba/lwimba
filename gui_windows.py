"""
Flash Drive Antivirus - Windows Native GUI
Modern Windows interface matching the professional design
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import threading
import time
from datetime import datetime

try:
    from antivirus import AntvirusEngine
except ImportError:
    print("Warning: antivirus module not found")

class WindowsAntvirusGUI:
    """Windows native GUI application"""
    
    def __init__(self, root):
        """Initialize GUI"""
        self.root = root
        self.root.title("LWIMBA USB DRIVE SECURITY SCANNER")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)
        
        # Set Windows-style theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Initialize engine
        self.engine = None
        try:
            self.engine = AntvirusEngine()
            self.engine.initialize_signatures()
        except Exception as e:
            messagebox.showerror("Error", f"Antivirus engine not initialized: {e}")
            self.engine = None
        
        # State variables
        self.scanning = False
        self.current_scan_id = None
        self.selected_path = ""
        
        # Setup GUI
        self.setup_ui()
        self.refresh_drives()
    
    def setup_ui(self):
        """Setup main UI"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header
        self.setup_header(main_frame)
        
        # Drive Selection
        self.setup_drive_selection(main_frame)
        
        # Scan Progress
        self.setup_scan_progress(main_frame)
        
        # Scan Results
        self.setup_scan_results(main_frame)
        
        # Footer
        self.setup_footer(main_frame)
    
    def setup_header(self, parent):
        """Setup header"""
        header = ttk.Frame(parent)
        header.pack(fill="x", pady=(0, 20))
        
        # Title
        title = ttk.Label(
            header,
            text="🔒 LWIMBA USB DRIVE SECURITY SCANNER",
            font=("Arial", 14, "bold")
        )
        title.pack(anchor="w")
    
    def setup_drive_selection(self, parent):
        """Setup drive selection section"""
        drive_frame = ttk.LabelFrame(parent, text="Drive Selection:", padding=10)
        drive_frame.pack(fill="x", pady=(0, 10))
        
        # Drive selection row
        selection_row = ttk.Frame(drive_frame)
        selection_row.pack(fill="x", pady=5)
        
        # Drive input
        self.drive_input = ttk.Entry(selection_row, width=50)
        self.drive_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Browse button
        browse_btn = ttk.Button(selection_row, text="Browse...", command=self.browse_drive)
        browse_btn.pack(side="left", padx=5)
        
        # Start scan button
        self.scan_btn = ttk.Button(selection_row, text="Start Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=5)
    
    def setup_scan_progress(self, parent):
        """Setup scan progress section"""
        progress_frame = ttk.LabelFrame(parent, text="Scan Progress", padding=10)
        progress_frame.pack(fill="x", pady=(0, 10))
        
        # Progress bar
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='indeterminate'
        )
        self.progress_bar.pack(fill="x", pady=5)
        
        # Status label
        self.status_label = ttk.Label(progress_frame, text="Ready to scan")
        self.status_label.pack(anchor="w", pady=5)
    
    def setup_scan_results(self, parent):
        """Setup scan results section"""
        results_frame = ttk.LabelFrame(parent, text="Scan Results", padding=10)
        results_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Results text with scrollbar
        scrollbar = ttk.Scrollbar(results_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.results_text = tk.Text(
            results_frame,
            height=15,
            width=80,
            yscrollcommand=scrollbar.set,
            font=("Courier", 9)
        )
        self.results_text.pack(fill="both", expand=True)
        scrollbar.config(command=self.results_text.yview)
        
        # Initial message
        self.results_text.insert("1.0", "Select a USB drive and click 'Start Scan' to begin.\n\n")
        self.results_text.config(state="disabled")
    
    def setup_footer(self, parent):
        """Setup footer with statistics"""
        footer = ttk.Frame(parent)
        footer.pack(fill="x", pady=(10, 0))
        
        # Statistics
        stats_frame = ttk.Frame(footer)
        stats_frame.pack(fill="x")
        
        self.stats_label = ttk.Label(
            stats_frame,
            text="Total: 0 | Malicious: 0 | Suspicious: 0 | Clean: 0",
            font=("Arial", 10)
        )
        self.stats_label.pack(anchor="w")
        
        # Buttons
        button_frame = ttk.Frame(footer)
        button_frame.pack(fill="x", pady=(10, 0))
        
        export_btn = ttk.Button(button_frame, text="Export Report", command=self.export_report)
        export_btn.pack(side="left", padx=5)
    
    def browse_drive(self):
        """Browse for USB drive"""
        path = filedialog.askdirectory(title="Select USB Drive")
        if path:
            self.drive_input.delete(0, tk.END)
            self.drive_input.insert(0, path)
            self.selected_path = path
    
    def refresh_drives(self):
        """Refresh available drives"""
        if not self.engine:
            self.drive_input.insert(0, "Engine not initialized")
            return
        
        try:
            devices = self.engine.usb_detector.detect_usb_devices()
            if devices:
                self.drive_input.delete(0, tk.END)
                self.drive_input.insert(0, devices[0].mount_point)
                self.selected_path = devices[0].mount_point
        except Exception as e:
            pass
    
    def start_scan(self):
        """Start scanning"""
        if not self.engine:
            messagebox.showerror("Error", "Antivirus engine not initialized")
            return
        
        path = self.drive_input.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please select a drive to scan")
            return
        
        if not Path(path).exists():
            messagebox.showerror("Invalid Path", f"Path does not exist: {path}")
            return
        
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.progress_bar.start()
        self.status_label.config(text="Scanning...")
        
        # Clear results
        self.results_text.config(state="normal")
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert("end", f"Starting scan of {path}...\n\n")
        self.results_text.config(state="disabled")
        
        # Start scan in thread
        scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(path,),
            daemon=True
        )
        scan_thread.start()
    
    def _perform_scan(self, path):
        """Perform scan (threaded)"""
        try:
            scan_id = self.engine.start_scan(path)
            
            if scan_id > 0:
                self.current_scan_id = scan_id
                
                # Get results
                history = self.engine.db_manager.get_scan_history(1)
                threats = self.engine.db_manager.get_detected_threats(scan_id)
                
                # Update UI
                self.results_text.config(state="normal")
                self.results_text.delete("1.0", tk.END)
                
                if history:
                    h = history[0]
                    self.results_text.insert("end", "=== SCAN RESULTS ===\n\n")
                    self.results_text.insert("end", f"Total Files Scanned: {h['total_files']}\n")
                    self.results_text.insert("end", f"Malicious Files: {h['suspicious_files']}\n")
                    self.results_text.insert("end", f"Quarantined: {h['quarantined_files']}\n")
                    self.results_text.insert("end", f"Scan Duration: {h['scan_duration']:.2f} seconds\n\n")
                    
                    self.stats_label.config(
                        text=f"Total: {h['total_files']} | Malicious: {h['suspicious_files']} | "
                             f"Suspicious: 0 | Clean: {h['total_files'] - h['suspicious_files']}"
                    )
                
                if threats:
                    self.results_text.insert("end", f"\n=== THREATS DETECTED ({len(threats)}) ===\n\n")
                    for threat in threats:
                        self.results_text.insert("end", f"File: {threat['file_name']}\n")
                        self.results_text.insert("end", f"Threat: {threat['threat_name']}\n")
                        self.results_text.insert("end", f"Type: {threat['threat_type']}\n")
                        self.results_text.insert("end", f"Severity: {threat['threat_severity']}\n")
                        self.results_text.insert("end", f"Status: {'Quarantined' if threat['quarantined'] else 'Detected'}\n")
                        self.results_text.insert("end", "-" * 70 + "\n")
                else:
                    self.results_text.insert("end", "\n✓ No threats detected! Your USB drive is clean.\n")
                
                self.results_text.config(state="disabled")
                self.status_label.config(text="✓ Scan completed successfully")
            else:
                self.results_text.config(state="normal")
                self.results_text.insert("end", "Scan failed\n")
                self.results_text.config(state="disabled")
                self.status_label.config(text="Scan failed")
        
        except Exception as e:
            self.results_text.config(state="normal")
            self.results_text.insert("end", f"Error: {str(e)}\n")
            self.results_text.config(state="disabled")
            self.status_label.config(text=f"Error: {str(e)}")
        
        finally:
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.progress_bar.stop()
    
    def export_report(self):
        """Export scan report"""
        if not self.current_scan_id:
            messagebox.showwarning("No Scan", "No scan has been performed yet")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.results_text.get("1.0", tk.END))
                messagebox.showinfo("Success", f"Report exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")

class AntvirusApp:
    """Main application"""
    
    def __init__(self):
        """Initialize app"""
        self.root = tk.Tk()
    
    def run(self):
        """Run application"""
        gui = WindowsAntvirusGUI(self.root)
        self.root.mainloop()

if __name__ == "__main__":
    app = AntvirusApp()
    app.run()
