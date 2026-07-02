"""
Flash Drive Antivirus - Main Entry Point
Choose between Console, Simple GUI, or Professional Dashboard
"""

import sys
import os
from pathlib import Path

def show_menu():
    """Display main menu"""
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║         LWIMBA USB Drive Security Scanner v2.0                 ║
    ║              Select Your Interface                             ║
    ╚════════════════════════════════════════════════════════════════╝
    
    1️⃣  Console Mode (CLI) - Text-based interface
    2️⃣  Simple GUI - Basic graphical interface
    3️⃣  Professional Dashboard - Full featured UI ⭐ RECOMMENDED
    4️⃣  Exit
    
    """)

def run_console_mode():
    """Run console application"""
    print("\n[*] Starting Console Mode...\n")
    from antivirus import AntvirusEngine
    
    engine = AntvirusEngine()
    engine.initialize_signatures()
    
    # Detect USB devices
    print("[*] Detecting USB devices...")
    devices = engine.usb_detector.detect_usb_devices()
    
    if devices:
        print(f"\n[+] Found {len(devices)} USB device(s):")
        for i, device in enumerate(devices, 1):
            print(f"    {i}. {device.name} ({device.mount_point})")
        
        # Scan first device
        device = devices[0]
        print(f"\n[*] Starting scan of {device.mount_point}...")
        scan_id = engine.start_scan(device.mount_point)
        
        if scan_id > 0:
            print(f"\n[+] Scan completed with ID: {scan_id}")
            
            # Get scan history
            history = engine.db_manager.get_scan_history(1)
            if history:
                h = history[0]
                print(f"\n[+] Scan Summary:")
                print(f"    Total Files: {h['total_files']}")
                print(f"    Suspicious: {h['suspicious_files']}")
                print(f"    Quarantined: {h['quarantined_files']}")
                print(f"    Duration: {h['scan_duration']:.2f} seconds")
            
            # Get detected threats
            threats = engine.db_manager.get_detected_threats(scan_id)
            if threats:
                print(f"\n[!] Detected {len(threats)} threat(s):")
                for threat in threats[:10]:
                    print(f"    - {threat['file_name']}: {threat['threat_name']}")
        else:
            print("\n[-] Scan failed")
    else:
        print("\n[-] No USB devices found")
    
    print("\n[*] Console mode completed")

def run_simple_gui():
    """Run simple GUI"""
    print("\n[*] Starting Simple GUI Mode...\n")
    try:
        from gui import AntvirusApp
        app = AntvirusApp()
        app.run()
    except ImportError as e:
        print(f"[-] Error: Could not import GUI module: {e}")
        print("[*] Make sure customtkinter is installed: pip install customtkinter")
    except Exception as e:
        print(f"[-] Error starting GUI: {e}")

def run_professional_dashboard():
    """Run professional dashboard"""
    print("\n[*] Starting Professional Dashboard...\n")
    try:
        from gui_dashboard import AntvirusApp
        app = AntvirusApp()
        app.run()
    except ImportError as e:
        print(f"[-] Error: Could not import GUI module: {e}")
        print("[*] Make sure customtkinter is installed: pip install customtkinter")
    except Exception as e:
        print(f"[-] Error starting dashboard: {e}")

def main():
    """Main entry point"""
    while True:
        show_menu()
        choice = input("Select option (1-4): ").strip()
        
        if choice == "1":
            run_console_mode()
            print("\nPress Enter to continue...")
            input()
        
        elif choice == "2":
            run_simple_gui()
        
        elif choice == "3":
            run_professional_dashboard()
        
        elif choice == "4":
            print("\n[*] Thank you for using LWIMBA USB Drive Security Scanner!")
            print("[*] Exiting...\n")
            break
        
        else:
            print("\n[-] Invalid option. Please try again.\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        sys.exit(1)
