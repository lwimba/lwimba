"""
Flash Drive Antivirus - Main Entry Point
Launches Professional Dashboard automatically
"""

import sys
import os
from pathlib import Path

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
        print(f"[+] Found {len(devices)} USB device(s)\n")
        
        return True
    except Exception as e:
        print(f"[-] Error initializing engine: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_professional_dashboard():
    """Run professional dashboard"""
    try:
        from gui_dashboard import AntvirusApp
        app = AntvirusApp()
        app.run()
    except ImportError as e:
        print(f"[-] Error: Could not import GUI module: {e}")
        print("[*] Make sure customtkinter is installed: pip install customtkinter")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error starting dashboard: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("LWIMBA USB Drive Security Scanner v2.0")
    print("Cybersecurity Expert Edition")
    print("="*70 + "\n")
    
    # Check if antivirus engine can be initialized
    print("[*] Checking system requirements...")
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
    
    print("[*] Starting Professional Dashboard...\n")
    run_professional_dashboard()

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
