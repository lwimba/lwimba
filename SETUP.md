"""
Flash Drive Antivirus - Installation and Setup Guide
Complete setup instructions for all platforms
"""

# ============================================================================
# INSTALLATION GUIDE
# ============================================================================

"""
STEP 1: Clone Repository
========================

On Windows (Command Prompt):
    git clone https://github.com/lwimba/flash-drive-antivirus.git
    cd flash-drive-antivirus

On Linux/macOS (Terminal):
    git clone https://github.com/lwimba/flash-drive-antivirus.git
    cd flash-drive-antivirus


STEP 2: Install Python
======================

Minimum: Python 3.7+
Recommended: Python 3.9+

Windows:
    Download from https://www.python.org/downloads/
    Run installer, check "Add Python to PATH"

Linux (Ubuntu/Debian):
    sudo apt-get update
    sudo apt-get install python3 python3-pip

macOS:
    brew install python@3.9


STEP 3: Install Dependencies
=============================

pip install -r requirements.txt

This installs:
    - customtkinter (Modern GUI)
    - pillow (Image processing)
    - psutil (System info)
    - requests (HTTP library)
    - numpy (Numerical computing)
    - scikit-learn (ML library)
    - joblib (Serialization)
    - watchdog (File monitoring)


STEP 4: Verify Installation
============================

Test with:
    python antivirus.py

Expected output:
    [+] Found X USB device(s)
    [+] Scan completed with ID: 1
    [+] Scan Summary:
        Total Files: XXX
        Suspicious: X
        Quarantined: X
        Duration: X.XX seconds


STEP 5: First Run Setup
=======================

Console Mode:
    python antivirus.py
    
GUI Mode:
    python gui.py

Database will be automatically created at:
    data/database/antivirus.db

Log files will be created at:
    logs/antivirus.log
"""

# ============================================================================
# PLATFORM-SPECIFIC SETUP
# ============================================================================

"""
WINDOWS SETUP
=============

1. Administrator Privileges (Optional but Recommended)
   Right-click Command Prompt → Run as Administrator
   
2. USB Detection
   Windows 10/11 automatically recognizes USB drives
   No additional drivers needed
   
3. Firewall (If Enabled)
   Windows Defender may flag app
   Add to Exclusions or disable warnings
   
4. Example Command:
   python antivirus.py

Detected drives typically appear as D:\, E:\, F:\, etc.


LINUX SETUP
===========

1. Install Required Packages
   sudo apt-get install python3-dev
   sudo apt-get install libffi-dev
   sudo apt-get install libssl-dev
   
2. USB Access Permissions
   sudo usermod -a -G dialout $USER
   sudo usermod -a -G plugdev $USER
   
3. Reload Groups
   newgrp dialout
   newgrp plugdev
   
4. Verify USB Detection
   lsblk -d -n -o NAME,SIZE,TYPE
   
5. Run Antivirus
   python3 antivirus.py

USB devices typically mount at /media/username/USB_NAME


MACOS SETUP
===========

1. Install Xcode Command Line Tools
   xcode-select --install
   
2. Install Python 3.9+
   brew install python@3.9
   
3. USB Access
   macOS automatically handles USB access
   No special permissions needed
   
4. Run Antivirus
   python3 antivirus.py

USB drives appear in /Volumes/USB_NAME
"""

# ============================================================================
# COMMON ISSUES AND TROUBLESHOOTING
# ============================================================================

"""
ISSUE 1: "ModuleNotFoundError: No module named 'customtkinter'"
==============================================================

Solution:
    pip install --upgrade customtkinter
    
Or reinstall all dependencies:
    pip install -r requirements.txt --force-reinstall


ISSUE 2: USB Device Not Detected
=================================

Windows:
    Check Disk Management (diskmgmt.msc)
    Ensure drive has assigned letter (D:, E:, etc.)
    Try different USB port
    
Linux:
    Check with: lsblk
    Verify mount: mount | grep usb
    Check permissions: groups
    
macOS:
    Check System Report → USB
    Verify in Finder
    Try different USB port


ISSUE 3: Permission Denied Error
=================================

Windows:
    Run as Administrator
    
Linux:
    sudo python3 antivirus.py
    Or: sudo usermod -a -G dialout $USER
    
macOS:
    sudo python3 antivirus.py


ISSUE 4: Slow Scanning
======================

Causes:
    - Large files (>100MB)
    - Many files
    - Slow USB drive
    - Anti-virus interference

Solutions:
    - Disable other anti-virus temporarily
    - Use faster USB 3.0 drive
    - Exclude large files from scan
    - Run on less busy system


ISSUE 5: GUI Not Opening / Blank Window
========================================

Solutions:
    - Update CustomTkinter: pip install -U customtkinter
    - Clear cache: rm -rf ~/.cache/pip
    - Reinstall all packages: pip install -r requirements.txt --force-reinstall
    - Try console mode: python antivirus.py
    
Check logs:
    tail -f logs/antivirus.log


ISSUE 6: Database Locked Error
===============================

Solution 1 (Simple):
    Delete database and restart:
    rm data/database/antivirus.db
    python antivirus.py
    
Solution 2 (Keep data):
    Wait 30 seconds and retry
    Only one scan at a time
    
Solution 3 (Detailed):
    Check if scan is running
    Stop any background processes
    Verify disk space


ISSUE 7: AI Detection Not Working
==================================

Check if scikit-learn is installed:
    python -c "import sklearn; print(sklearn.__version__)"

If not installed:
    pip install scikit-learn numpy

Train the model:
    from ai_detection import MalwareDetector
    detector = MalwareDetector()
    detector.train_model(training_data)


ISSUE 8: High CPU Usage During Scan
====================================

Normal behavior during initial scan
Reduces after first run (signatures cached)

To reduce CPU usage:
    - Reduce scan complexity
    - Disable behavioral analysis
    - Increase file size threshold
    - Use console mode (GUI intensive)


ISSUE 9: "Cannot find pyudev" on Linux
======================================

Solution:
    pip install pyudev
    
Or for system-wide:
    sudo apt-get install python3-pyudev


ISSUE 10: Scanned Files Deleted/Missing
========================================

The antivirus:
    - Never deletes files by default
    - Only moves suspicious files to quarantine
    
Restore files:
    Check: data/quarantine/ directory
    Use: gui.py → View History → Restore
"""

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

"""
OPTIMIZE SCAN SPEED
===================

1. Exclude Large Directories
   Modify scan path to exclude:
   /media/usb/ (except specific folders)

2. Increase File Size Limit
   In antivirus.py:
   MAX_FILE_SIZE_SCAN = 200 * 1024 * 1024  # 200MB instead of 100MB

3. Disable Behavioral Analysis
   Comment out: self._analyze_behavior(result)

4. Enable Multi-threading (Future)
   Use ThreadPoolExecutor for parallel scanning

5. Cache Signatures
   Pre-load all signatures at startup


OPTIMIZE MEMORY USAGE
=====================

1. Stream File Processing
   Process files in chunks instead of fully loading

2. Limit History Retention
   Delete old scan records

3. Clear Logs Regularly
   logs/antivirus.log can grow large

4. Reduce Feature Extraction
   Disable entropy calculation


OPTIMIZE DATABASE
=================

1. Regular Maintenance
   VACUUM antivirus.db
   ANALYZE antivirus.db

2. Index Key Columns
   CREATE INDEX idx_hash ON detected_threats(file_hash)

3. Archive Old Scans
   Move old records to archive database
"""

# ============================================================================
# SECURITY BEST PRACTICES
# ============================================================================

"""
SECURE USAGE
============

1. Use Strong Hashes
   - Always verify SHA-256 hashes
   - Never trust file names alone
   - Keep signature database updated

2. Whitelist Management
   - Only whitelist known-safe files
   - Periodically review whitelist
   - Document reason for each entry

3. Quarantine Safety
   - Never restore unknown files
   - Verify origin before restoration
   - Keep quarantine backups

4. Regular Updates
   - Update malware signatures monthly
   - Update Python packages regularly
   - Keep OS security patches current

5. Access Control
   - Run with minimal privileges needed
   - Restrict database access
   - Secure quarantine directory

6. Logging and Auditing
   - Review logs regularly
   - Archive log files
   - Monitor for suspicious patterns

7. False Positives
   - Never whitelist malware
   - Verify detections independently
   - Report false positives


DATA PRIVACY
============

This antivirus:
    ✓ Runs completely locally
    ✓ No cloud uploads required
    ✓ No data collection
    ✓ No phone-home functions
    ✓ Fully open source
    ✓ No telemetry


QUARANTINE SAFETY
=================

Quarantined files are:
    - Copied (original not deleted)
    - Renamed with hash prefix
    - Stored in isolated directory
    - Never executed
    - Can be restored if needed
"""

# ============================================================================
# CONFIGURATION OPTIONS
# ============================================================================

"""
EDIT antivirus.py FOR CUSTOM CONFIGURATION
============================================

1. Suspicious Extensions
   SUSPICIOUS_EXTENSIONS = {
       '.exe', '.bat', '.cmd', '.vbs', '.js', ...
   }

2. File Size Limit
   MAX_FILE_SIZE_SCAN = 100 * 1024 * 1024  # 100 MB

3. Scan Timeout
   SCAN_TIMEOUT = 300  # 5 minutes

4. USB Monitor Interval
   USB_MONITOR_INTERVAL = 2000  # 2 seconds

5. Database Path
   DATABASE_PATH = DATABASE_DIR / "antivirus.db"

6. Quarantine Directory
   QUARANTINE_DIR = DATA_DIR / "quarantine"

7. Logging Level
   logging.basicConfig(level=logging.INFO)
   # DEBUG, INFO, WARNING, ERROR, CRITICAL

8. AI Detection
   ENABLE_AI_DETECTION = True
   ENABLE_BEHAVIORAL_ANALYSIS = True
"""

# ============================================================================
# DEVELOPER SETUP
# ============================================================================

"""
FOR DEVELOPERS
==============

1. Clone and Setup
   git clone https://github.com/lwimba/flash-drive-antivirus.git
   cd flash-drive-antivirus
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\\Scripts\\activate.bat  # Windows
   pip install -r requirements.txt

2. Install Dev Tools
   pip install pytest black flake8 pylint

3. Run Tests
   pytest tests/

4. Code Style
   black *.py
   flake8 *.py
   pylint *.py

5. Generate Documentation
   pdoc --html antivirus.py

6. Create Distribution
   python setup.py sdist bdist_wheel


CONTRIBUTING
============

1. Fork repository
2. Create feature branch
3. Make changes
4. Run tests
5. Submit pull request

Code Guidelines:
    - PEP 8 style
    - Type hints
    - Docstrings
    - Comments for complex logic
"""

# ============================================================================
# UNINSTALLATION
# ============================================================================

"""
TO REMOVE ANTIVIRUS
===================

1. Remove Directory
   rm -r flash-drive-antivirus  # Linux/macOS
   rmdir /s flash-drive-antivirus  # Windows

2. Uninstall Python Packages
   pip uninstall -r requirements.txt

3. Remove Virtual Environment (if used)
   rm -r venv  # Linux/macOS
   rmdir venv  # Windows

4. Remove Log Files (optional)
   rm -r logs/

5. Remove Data (optional)
   rm -r data/


BACKUP IMPORTANT DATA
=====================

Before uninstalling, backup:
    - Scan history database
    - Quarantine directory
    - Custom signatures
    - Configuration files

Commands:
    cp -r data/ ~/antivirus_backup/  # Linux/macOS
    xcopy data \\backup\\antivirus_backup /E  # Windows
"""

# ============================================================================
# GETTING HELP
# ============================================================================

"""
RESOURCES
=========

1. Documentation
   - README.md - Quick start
   - EXAMPLES.py - Code examples
   - SETUP.md - This file
   - Inline code comments

2. Logs
   - logs/antivirus.log - Application logs
   - Check for error messages

3. GitHub
   - Repository: github.com/lwimba/flash-drive-antivirus
   - Issues: Report bugs
   - Discussions: Ask questions
   - Wiki: Community knowledge

4. Community
   - StackOverflow: Tag with "antivirus" + "python"
   - Reddit: r/cybersecurity
   - GitHub Discussions: Direct repository

5. Professional Support
   - For commercial deployment
   - Custom development
   - Enterprise features
   - Contact: [email address]


REPORTING BUGS
==============

Include:
    1. Python version: python --version
    2. OS: Windows/Linux/macOS version
    3. Antivirus version
    4. Error message (full traceback)
    5. Steps to reproduce
    6. Relevant log entries
    7. System specifications
    8. USB device information


FEATURE REQUESTS
================

Suggest:
    1. Description of feature
    2. Why it's useful
    3. How it should work
    4. Examples of usage
    5. Priority level
"""

print("""
╔════════════════════════════════════════════════════════════════╗
║         Flash Drive Antivirus - Setup Guide                    ║
║              v1.0.0 - Cybersecurity Expert Edition              ║
╚════════════════════════════════════════════════════════════════╝

To get started:
    1. pip install -r requirements.txt
    2. python antivirus.py          (console mode)
    3. python gui.py                (GUI mode)

For help:
    - Check README.md
    - See EXAMPLES.py for code samples
    - Review logs/antivirus.log
    - Visit github.com/lwimba/flash-drive-antivirus

Happy scanning! 🛡️
""")
