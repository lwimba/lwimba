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
    2️⃣  Windows GUI - Native Windows interface ⭐ RECOMMENDED
    3️⃣  Professional Dashboard - Full featured modern UI
    4️⃣  Simple GUI - Basic graphical interface
    5️⃣  Exit
    
    """)

def initialize_engine():
    """Initialize and test antivirus engine"""
    try:
        print("[*] Initializing antivirus engine...")
        from antivirus import AntvirusEngine
        
        engine = AntvirusEngine()
        print("[+] Engine initialized successfully")
        
        print("[*] Initializing signatures...")
        engine.initialize_signatures()
        print("[+] Signatures loaded")
        
        print("[*] Detecting USB devices...")
        devices = engine.usb_detector.detect_usb_devices()
        print(f"[+] Found {len(devices)} USB device(s)")
        
        return True
    except Exception as e:
        print(f"[-] Error initializing engine: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_console_mode():
    """Run console application"""
    print("\n[*] Starting Console Mode...\n")
    try:
        from antivirus import AntvirusEngine
        
        engine = AntvirusEngine()
        engine.initialize_signatures()
        
        # Detect USB devices
        print("[*] Detecting USB devices...")
        devices = engine.usb_detector.detect_usb_devices()
        
        if devices:
            print(f"\n[+] Found {len(devices)} USB device(s):")
            for i, device in enumerate(devices, 1):
                print(f"    {i}. {device.name} ({device.mount_point}) - {device.size / (1024**3):.2f} GB")
            
            # Ask which device to scan
            while True:
                try:
                    choice = int(input("\nSelect device number to scan (0 to skip): "))
                    if choice == 0:
                        print("[*] Skipping scan")
                        return
                    if 1 <= choice <= len(devices):
                        device = devices[choice - 1]
                        break
                    print("[-] Invalid choice")
                except ValueError:
                    print("[-] Please enter a number")
            
            # Scan selected device
            print(f"\n[*] Starting scan of {device.mount_point}...")
            scan_id = engine.start_scan(device.mount_point)
            
            if scan_id > 0:
                print(f"[+] Scan completed with ID: {scan_id}")
                
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
                        print(f"    - {threat['file_name']}: {threat['threat_name']} ({threat['threat_severity']})")
                else:
                    print("\n[✓] No threats detected!")
            else:
                print("\n[-] Scan failed")
        else:
            print("\n[-] No USB devices found")
            print("[*] Make sure a USB drive is connected and properly mounted")
    
    except Exception as e:
        print(f"[-] Error in console mode: {e}")
        import traceback
        traceback.print_exc()

def run_windows_gui():
    """Run Windows native GUI"""
    print("\n[*] Starting Windows GUI Mode...\n")
    try:
        from gui_windows import AntvirusApp
        app = AntvirusApp()
        app.run()
    except ImportError as e:
        print(f"[-] Error: Could not import GUI module: {e}")
        print("[*] Make sure tkinter is available (usually included with Python)")
    except Exception as e:
        print(f"[-] Error starting Windows GUI: {e}")
        import traceback
        traceback.print_exc()

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
        import traceback
        traceback.print_exc()

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
        import traceback
        traceback.print_exc()

def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("LWIMBA USB Drive Security Scanner v2.0")
    print("="*70)
    
    # Check if antivirus engine can be initialized
    print("\n[*] Checking system requirements...")
    engine_ok = initialize_engine()
    
    if not engine_ok:
        print("\n[-] Antivirus engine initialization failed!")
        print("[*] Troubleshooting steps:")
        print("    1. Verify all files are in the correct directory")
        print("    2. Check that antivirus.py is not corrupted")
        print("    3. Ensure data/ and logs/ directories exist")
        print("    4. Check file permissions")
        response = input("\nContinue anyway? (y/n): ").lower()
        if response != 'y':
            sys.exit(1)
    
    print("\n")
    
    while True:
        show_menu()
        choice = input("Select option (1-5): ").strip()
        
        if choice == "1":
            run_console_mode()
            print("\nPress Enter to continue...")
            input()
        
        elif choice == "2":
            run_windows_gui()
        
        elif choice == "3":
            run_professional_dashboard()
        
        elif choice == "4":
            run_simple_gui()
        
        elif choice == "5":
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
        import traceback
        traceback.print_exc()
        sys.exit(1)
