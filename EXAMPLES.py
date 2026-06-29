"""
Flash Drive Antivirus - Usage Examples and Documentation
Comprehensive guide for all features and API usage
"""

# ============================================================================
# EXAMPLE 1: Basic Console Usage
# ============================================================================

"""
Run the basic console demo:

    python antivirus.py

This will:
1. Detect connected USB devices
2. Scan the first USB device
3. Display results
4. Save to database
"""

# ============================================================================
# EXAMPLE 2: Using the Python API
# ============================================================================

from antivirus import AntvirusEngine

# Initialize engine
engine = AntvirusEngine()

# Example 2.1: Detect USB Devices
print("\n=== USB Device Detection ===")
devices = engine.usb_detector.detect_usb_devices()

for device in devices:
    print(f"Device: {device.name}")
    print(f"  Mount Point: {device.mount_point}")
    print(f"  Size: {device.size / (1024**3):.2f} GB")
    print(f"  ID: {device.device_id}")

# Example 2.2: Manual Scan
print("\n=== Manual USB Scan ===")
if devices:
    device = devices[0]
    print(f"Scanning: {device.mount_point}")
    
    scan_id = engine.start_scan(device.mount_point)
    
    if scan_id > 0:
        # Get scan results
        history = engine.db_manager.get_scan_history(1)
        threats = engine.db_manager.get_detected_threats(scan_id)
        
        if history:
            h = history[0]
            print(f"\nScan Results:")
            print(f"  Total Files: {h['total_files']}")
            print(f"  Suspicious: {h['suspicious_files']}")
            print(f"  Quarantined: {h['quarantined_files']}")
            print(f"  Duration: {h['scan_duration']:.2f} seconds")
        
        if threats:
            print(f"\nThreats Detected: {len(threats)}")
            for threat in threats[:5]:
                print(f"  - {threat['file_name']}: {threat['threat_name']}")

# ============================================================================
# EXAMPLE 3: Real-time USB Monitoring
# ============================================================================

print("\n=== Real-time USB Monitoring ===")

def on_device_change(action, device):
    """Callback for device changes"""
    if action == "connected":
        print(f"[CONNECTED] {device.name} at {device.mount_point}")
        # Auto-scan on connection
        print(f"Auto-scanning {device.mount_point}...")
        scan_id = engine.start_scan(device.mount_point)
        print(f"Scan ID: {scan_id}")
    else:
        print(f"[DISCONNECTED] {device.name}")

# Register callback
engine.usb_detector.register_callback(on_device_change)

# Start monitoring
engine.usb_detector.start_monitoring()
print("Monitoring started - connect/disconnect USB devices...")

# Monitor for 60 seconds
import time
for i in range(60):
    time.sleep(1)
    if i % 10 == 0:
        print(f"  Monitoring... ({i}s)")

# Stop monitoring
engine.usb_detector.stop_monitoring()
print("Monitoring stopped")

# ============================================================================
# EXAMPLE 4: Whitelist Management
# ============================================================================

print("\n=== Whitelist Management ===")

# Add file to whitelist
file_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
engine.db_manager.add_to_whitelist(
    file_hash=file_hash,
    file_name="safe_program.exe",
    file_path="/media/usb/safe_program.exe",
    file_size=1024000,
    reason="Verified safe program"
)

# Check if file is whitelisted
is_safe = engine.db_manager.is_whitelisted(file_hash)
print(f"File is whitelisted: {is_safe}")

# ============================================================================
# EXAMPLE 5: Quarantine Management
# ============================================================================

print("\n=== Quarantine Management ===")

# Quarantine a file
file_to_quarantine = "/media/usb/suspicious_file.exe"
threat_name = "Win32.Trojan.Generic"
file_hash = "cf8bd9fb5d614175c9cf3a2ecc0cf18c40642c44e7ca0efb9ea9e8e8ff47f6d9"

success = engine.quarantine_manager.quarantine_file(
    file_path=file_to_quarantine,
    threat_name=threat_name,
    file_hash=file_hash
)

if success:
    print(f"Successfully quarantined: {file_to_quarantine}")

# Restore a quarantined file
restore_success = engine.quarantine_manager.restore_file(
    quarantine_id=1,
    restore_path="/backup/restored_file.exe"
)

if restore_success:
    print("Successfully restored file")

# ============================================================================
# EXAMPLE 6: Scan History and Reporting
# ============================================================================

print("\n=== Scan History ===")

# Get recent scans
history = engine.db_manager.get_scan_history(limit=10)

print(f"Recent Scans: {len(history)}")
for scan in history:
    print(f"\nScan ID: {scan['id']}")
    print(f"  Device: {scan['usb_name']}")
    print(f"  Date: {scan['scan_date']}")
    print(f"  Files: {scan['total_files']} | Threats: {scan['suspicious_files']}")
    print(f"  Duration: {scan['scan_duration']:.2f}s")

# Get threats from specific scan
scan_id = history[0]['id'] if history else None
if scan_id:
    threats = engine.db_manager.get_detected_threats(scan_id)
    print(f"\nThreats in Scan {scan_id}: {len(threats)}")
    for threat in threats:
        print(f"  - {threat['file_name']}: {threat['threat_name']} ({threat['threat_severity']})")

# ============================================================================
# EXAMPLE 7: AI/ML Detection
# ============================================================================

print("\n=== AI/ML Threat Detection ===")

from ai_detection import MalwareDetector, ThreatAnalyzer

# Initialize AI detector
detector = MalwareDetector()

# Check if model is trained
if detector.is_trained:
    print("AI model is trained and ready")
    
    # Analyze a file
    threat_analyzer = ThreatAnalyzer(detector)
    
    file_path = "/media/usb/program.exe"
    file_size = 1024000
    file_extension = ".exe"
    
    results = threat_analyzer.analyze_file(
        file_path, file_size, file_extension
    )
    
    print(f"AI Analysis Results:")
    print(f"  AI Threat: {results['ai_threat']}")
    print(f"  AI Confidence: {results['ai_confidence']:.2%}")
    print(f"  Behavioral Threats: {results['behavioral_threats']}")
    print(f"  Threat Level: {results['threat_level']}")
else:
    print("AI model not trained - training on sample data...")
    
    # Create sample training data
    training_data = [
        # Benign files
        (detector.extract_features("/path/to/safe1.txt", 5000, ".txt", 0.2), 0),
        (detector.extract_features("/path/to/safe2.doc", 50000, ".doc", 0.3), 0),
        # Malicious files
        (detector.extract_features("/path/to/virus1.exe", 100000, ".exe", 0.8), 1),
        (detector.extract_features("/path/to/virus2.bat", 2000, ".bat", 0.7), 1),
    ]
    
    # Train model
    from pathlib import Path
    model_path = Path("data/ai_model/detector.pkl")
    scaler_path = Path("data/ai_model/scaler.pkl")
    
    detector.train_model(training_data, model_path, scaler_path)
    print("Model trained successfully!")

# ============================================================================
# EXAMPLE 8: GUI Usage
# ============================================================================

print("\n=== GUI Usage ===")

"""
To run the professional GUI:

    python gui.py

Features:
- Real-time USB device detection
- Visual scan progress
- Threat visualization
- One-click scanning
- Scan history viewer
- Settings configuration
"""

# ============================================================================
# EXAMPLE 9: Signature Management
# ============================================================================

print("\n=== Signature Management ===")

# Add custom malware signature
engine.db_manager.insert_malware_signature(
    signature_hash="d41d8cd98f00b204e9800998ecf8427e",
    malware_name="CustomMalware.Generic",
    threat_type="TROJAN",
    threat_severity="HIGH",
    file_extension=".exe",
    source="CUSTOM"
)

# Get signature
sig = engine.db_manager.get_malware_signature(
    "d41d8cd98f00b204e9800998ecf8427e"
)

if sig:
    print(f"Signature: {sig['malware_name']}")
    print(f"Type: {sig['threat_type']}")
    print(f"Severity: {sig['threat_severity']}")

# ============================================================================
# EXAMPLE 10: Custom Scanning with Progress Callback
# ============================================================================

print("\n=== Custom Scanning ===")

def progress_callback(total_scanned, result):
    """Custom progress callback"""
    print(f"Scanned: {total_scanned} files", end="\r")
    
    if result.is_suspicious:
        print(f"\n  [!] Threat found: {result.file_name}")

# Scan directory with custom callback
if devices:
    results = engine.file_scanner.scan_directory(
        devices[0].mount_point,
        on_progress=progress_callback
    )
    
    print(f"\n\nTotal results: {len(results)}")
    suspicious = [r for r in results if r.is_suspicious]
    print(f"Suspicious files: {len(suspicious)}")

# ============================================================================
# EXAMPLE 11: Advanced Threat Analysis
# ============================================================================

print("\n=== Advanced Threat Analysis ===")

from ai_detection import BehavioralAnalyzer

# Behavioral analysis
analyzer = BehavioralAnalyzer()

# Simulate file content analysis
suspicious_content = b"CreateRemoteThread WriteProcessMemory VirtualAllocEx"

behaviors, risk_score = analyzer.analyze_behavior(suspicious_content)

print(f"Detected Behaviors: {behaviors}")
print(f"Risk Score: {risk_score:.2%}")

# ============================================================================
# EXAMPLE 12: Batch Operations
# ============================================================================

print("\n=== Batch Operations ===")

# Scan multiple USB devices
def scan_all_devices():
    """Scan all connected USB devices"""
    devices = engine.usb_detector.detect_usb_devices()
    
    results = {}
    for device in devices:
        print(f"Scanning {device.name}...")
        scan_id = engine.start_scan(device.mount_point)
        results[device.name] = scan_id
    
    return results

all_results = scan_all_devices()
print(f"Scan results: {all_results}")

# ============================================================================
# EXAMPLE 13: Logging and Debugging
# ============================================================================

print("\n=== Logging ===")

import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")

# Check log file
log_file = Path("logs/antivirus.log")
if log_file.exists():
    print(f"Log file: {log_file}")
    with open(log_file, 'r') as f:
        lines = f.readlines()
        print(f"Log entries: {len(lines)}")
        print("Latest entries:")
        for line in lines[-5:]:
            print(f"  {line.strip()}")

# ============================================================================
# EXAMPLE 14: Performance Optimization
# ============================================================================

print("\n=== Performance ===")

import time

# Time a scan
if devices:
    start = time.time()
    engine.start_scan(devices[0].mount_point)
    duration = time.time() - start
    
    print(f"Scan time: {duration:.2f} seconds")
    print(f"Throughput: {len(devices[0].mount_point) / duration:.0f} files/sec")

# ============================================================================
# EXAMPLE 15: Error Handling
# ============================================================================

print("\n=== Error Handling ===")

try:
    # Attempt to scan non-existent directory
    engine.start_scan("/nonexistent/path")
except Exception as e:
    print(f"Error caught: {type(e).__name__}: {e}")

try:
    # Attempt invalid file hash
    sig = engine.db_manager.get_malware_signature("invalid_hash")
    if not sig:
        print("Signature not found (handled gracefully)")
except Exception as e:
    print(f"Error caught: {type(e).__name__}: {e}")

print("\n=== Examples Complete ===")
