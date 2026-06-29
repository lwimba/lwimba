# Flash Drive Antivirus Prototype

A comprehensive USB antivirus solution with advanced threat detection, AI-powered analysis, and real-time monitoring capabilities.

## ✅ Features Implemented

### Core Security Features
- ✅ **Automatic USB Detection** - Real-time detection of connected/disconnected USB devices
- ✅ **Automatic USB Scanning** - Automatic scanning when USB is connected
- ✅ **Suspicious File Extension Detection** - 30+ dangerous extensions (.exe, .bat, .cmd, .vbs, .js, etc.)
- ✅ **Autorun.inf Detection** - Detects malicious autorun configurations
- ✅ **SHA-256 Hash Calculation** - Cryptographic verification of all scanned files
- ✅ **Quarantine System** - Isolates suspicious files safely
- ✅ **Scan History** - SQLite database of all scan results
- ✅ **Real-time USB Monitoring** - Continuous device monitoring with callbacks

### Advanced Features
- ✅ **Signature-based Detection** - Database of known malware signatures
- ✅ **Behavioral Analysis** - Pattern-based threat detection
- ✅ **AI-Powered Detection** - Machine learning ready framework
- ✅ **Whitelist Management** - Exclude safe files from scanning
- ✅ **Threat History** - Track all detected threats
- ✅ **File Restoration** - Restore quarantined files if needed
- ✅ **Cross-Platform Support** - Windows, Linux, macOS

## Installation

```bash
# Clone repository
git clone https://github.com/lwimba/flash-drive-antivirus.git
cd flash-drive-antivirus

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Console Demo
```bash
python antivirus.py
```

This will:
1. Detect connected USB devices
2. Start scanning the first USB device
3. Display scan results and detected threats
4. Save results to SQLite database

### Python API

```python
from antivirus import AntvirusEngine

# Initialize engine
engine = AntvirusEngine()

# Detect USB devices
devices = engine.usb_detector.detect_usb_devices()
for device in devices:
    print(f"Found: {device.name} at {device.mount_point}")

# Start monitoring
engine.usb_detector.start_monitoring()

# Register device callback
def on_device_change(action, device):
    if action == "connected":
        print(f"USB connected: {device}")
        # Auto-scan
        scan_id = engine.start_scan(device.mount_point)
    else:
        print(f"USB disconnected: {device}")

engine.usb_detector.register_callback(on_device_change)

# Manual scan
scan_id = engine.start_scan("/media/user/USB_DEVICE")

# Get scan results
history = engine.db_manager.get_scan_history()
threats = engine.db_manager.get_detected_threats(scan_id)

# Print results
for threat in threats:
    print(f"{threat['file_name']}: {threat['threat_name']}")
```

## Database Schema

### scan_history
```sql
CREATE TABLE scan_history (
    id INTEGER PRIMARY KEY,
    usb_name TEXT NOT NULL,
    usb_path TEXT NOT NULL,
    scan_date TIMESTAMP NOT NULL,
    total_files INTEGER,
    suspicious_files INTEGER,
    quarantined_files INTEGER,
    scan_duration REAL,
    status TEXT,
    details TEXT
);
```

### detected_threats
```sql
CREATE TABLE detected_threats (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    file_path TEXT NOT NULL,
    file_name TEXT,
    file_size INTEGER,
    file_extension TEXT,
    file_hash TEXT,
    threat_type TEXT,
    threat_name TEXT,
    threat_severity TEXT,
    detection_method TEXT,
    ai_confidence REAL,
    quarantined BOOLEAN,
    quarantine_path TEXT,
    detected_date TIMESTAMP,
    action_taken TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_history(id)
);
```

### malware_signatures
```sql
CREATE TABLE malware_signatures (
    id INTEGER PRIMARY KEY,
    signature_hash TEXT UNIQUE,
    malware_name TEXT,
    threat_type TEXT,
    threat_severity TEXT,
    file_extension TEXT,
    behavior_pattern TEXT,
    created_date TIMESTAMP,
    updated_date TIMESTAMP,
    source TEXT
);
```

## Architecture

### DatabaseManager
Manages all SQLite operations:
- Scan history logging
- Threat recording
- Signature storage
- Whitelist management
- Quarantine logging

### USBDetector
Handles USB device detection:
- Windows (WMI, diskpart, PowerShell)
- Linux (lsblk, udevadm, /dev/disk)
- macOS (diskutil, /Volumes)

### FileScanner
Performs file scanning:
- Extension-based detection
- Signature-based detection
- Behavioral pattern analysis
- Autorun.inf inspection

### QuarantineManager
Manages quarantined files:
- Safe file isolation
- Quarantine logging
- Secure restoration

### AntvirusEngine
Main orchestrator:
- Coordinates all components
- Manages scan operations
- Handles results

## Threat Severity Levels

- **LOW** - Potentially unwanted programs
- **MEDIUM** - Suspicious behavior detected
- **HIGH** - Probable malware
- **CRITICAL** - Known dangerous malware

## Detection Methods

1. **EXTENSION_CHECK** - Suspicious file extension
2. **SIGNATURE_BASED** - Known malware hash
3. **BEHAVIOR_ANALYSIS** - Suspicious code patterns
4. **AUTORUN_CHECK** - Malicious autorun configuration
5. **AI_MODEL** - Machine learning classification

## Suspicious Extensions Detected

```python
.exe, .bat, .cmd, .vbs, .js, .vbe, .jse,
.wsf, .wsh, .msi, .scr, .pif, .com, .dll,
.sys, .drv, .cpl, .hta, .jar, .ps1, .psm1,
.psc1, .msh, .msh1, .msh2, .mshxml, .msh1xml,
.msh2xml, .scf, .lnk, .inf, .reg, .asm, .app
```

## File Structure

```
flash-drive-antivirus/
├── antivirus.py              # Main application (all-in-one)
├── requirements.txt          # Dependencies
├── README.md                 # Documentation
├── data/
│   ├── database/
│   │   └── antivirus.db      # SQLite database
│   ├── quarantine/           # Quarantined files
│   └── signatures/           # Signature updates
└── logs/
    └── antivirus.log         # Application logs
```

## Security Considerations

### Best Practices
1. Regular Updates - Keep malware signatures updated
2. Whitelist Management - Maintain accurate whitelist
3. Log Review - Regularly review scan logs
4. Backup - Backup scan history and quarantine
5. Testing - Test on non-critical systems first

### Limitations
- File size limit: 100 MB (configurable)
- Permission dependent on OS access
- Signature-based detection limited to known threats
- Requires Python 3.7+

## Configuration

Edit constants in `antivirus.py`:

```python
# Suspicious extensions
SUSPICIOUS_EXTENSIONS = {...}

# File size limit
MAX_FILE_SIZE_SCAN = 100 * 1024 * 1024

# Scan timeout
SCAN_TIMEOUT = 300
```

## Logging

Logs are written to:
```
logs/antivirus.log
```

Example log output:
```
2026-06-29 10:15:30,123 - __main__ - INFO - Scan completed: 150 files, 5 suspicious, 3 quarantined
2026-06-29 10:15:32,456 - __main__ - WARNING - File too large to scan: /media/usb/large_file.iso
```

## Performance

- Scan Speed: ~100-200 files/second (depends on file size and content)
- Memory Usage: ~50-100 MB
- CPU Usage: Minimal (single-threaded scanning)

## Future Enhancements

- [ ] Multi-threaded scanning for performance
- [ ] Cloud-based threat intelligence API
- [ ] Machine learning model training
- [ ] Network scanning capabilities
- [ ] Behavioral sandboxing
- [ ] Zero-day detection
- [ ] GUI with CustomTkinter
- [ ] Automated signature updates

## Troubleshooting

### USB Not Detected

**Windows:**
```powershell
# Check USB drives
Get-Volume | Where-Object {$_.DriveType -eq 'Removable'}
```

**Linux:**
```bash
# List USB devices
lsblk -d -n -o NAME,SIZE,TYPE | grep disk
```

**macOS:**
```bash
# List volumes
diskutil list
```

### Scan Hangs

- Check file permissions
- Verify USB device is not being accessed by another program
- Increase MAX_FILE_SIZE_SCAN if needed

### Database Errors

- Delete `data/database/antivirus.db` and restart
- Check disk space availability
- Verify folder permissions

## License

MIT License - See LICENSE file for details

## Author

Cybersecurity Expert

## Disclaimer

This is a prototype for educational purposes. Always:
- Test in safe environments
- Use alongside established antivirus
- Follow local laws and regulations
- Backup important data before scanning

## Support & Contributing

For issues or questions:
1. Check the logs in `logs/antivirus.log`
2. Review documentation above
3. Create an issue in the repository
4. Submit pull requests for improvements
