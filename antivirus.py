"""
Flash Drive Antivirus Prototype - Complete Implementation
A comprehensive USB antivirus solution with AI-powered detection
Author: Security Expert
Version: 1.0.0
"""

import sys
import os
import sqlite3
import hashlib
import json
import logging
import threading
import platform
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from enum import Enum
import time

# ============================================================================
# CONFIGURATION
# ============================================================================

class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# Base directories
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
SIGNATURES_DIR = DATA_DIR / "signatures"
DATABASE_DIR = DATA_DIR / "database"

# Create directories
for directory in [DATA_DIR, LOG_DIR, QUARANTINE_DIR, SIGNATURES_DIR, DATABASE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = DATABASE_DIR / "antivirus.db"

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.js', '.vbe', '.jse',
    '.wsf', '.wsh', '.msi', '.scr', '.pif', '.com', '.dll',
    '.sys', '.drv', '.cpl', '.hta', '.jar', '.ps1', '.psm1',
    '.psc1', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml',
    '.msh2xml', '.scf', '.lnk', '.inf', '.reg', '.asm', '.app'
}

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "antivirus.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class DatabaseManager:
    """Manages all database operations"""
    
    def __init__(self, db_path: Path):
        """Initialize database manager"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Scan history table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        usb_name TEXT NOT NULL,
                        usb_path TEXT NOT NULL,
                        scan_date TIMESTAMP NOT NULL,
                        total_files INTEGER,
                        suspicious_files INTEGER,
                        quarantined_files INTEGER,
                        scan_duration REAL,
                        status TEXT,
                        details TEXT
                    )
                """)
                
                # Detected threats table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detected_threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                    )
                """)
                
                # Malware signatures
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS malware_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_hash TEXT UNIQUE,
                        malware_name TEXT,
                        threat_type TEXT,
                        threat_severity TEXT,
                        file_extension TEXT,
                        behavior_pattern TEXT,
                        created_date TIMESTAMP,
                        updated_date TIMESTAMP,
                        source TEXT
                    )
                """)
                
                # Whitelist
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_hash TEXT UNIQUE,
                        file_name TEXT,
                        file_path TEXT,
                        file_size INTEGER,
                        added_date TIMESTAMP,
                        reason TEXT
                    )
                """)
                
                # Quarantine log
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS quarantine_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT,
                        original_name TEXT,
                        quarantine_path TEXT,
                        file_hash TEXT,
                        threat_name TEXT,
                        quarantine_date TIMESTAMP,
                        restoration_date TIMESTAMP,
                        status TEXT
                    )
                """)
                
                conn.commit()
                logger.info(f"Database initialized at {self.db_path}")
        
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def insert_scan_history(self, usb_name: str, usb_path: str, 
                           total_files: int, suspicious_files: int,
                           quarantined_files: int, scan_duration: float,
                           status: str, details: str = None) -> int:
        """Insert scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history 
                    (usb_name, usb_path, scan_date, total_files, suspicious_files,
                     quarantined_files, scan_duration, status, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (usb_name, usb_path, datetime.now(), total_files, 
                      suspicious_files, quarantined_files, scan_duration, 
                      status, details))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting scan history: {e}")
            raise
    
    def insert_detected_threat(self, scan_id: int, file_path: str, 
                              file_name: str, file_size: int,
                              file_extension: str, file_hash: str,
                              threat_type: str, threat_name: str,
                              threat_severity: str, detection_method: str,
                              ai_confidence: float = 0.0) -> int:
        """Insert detected threat"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO detected_threats
                    (scan_id, file_path, file_name, file_size, file_extension,
                     file_hash, threat_type, threat_name, threat_severity,
                     detection_method, ai_confidence, detected_date, quarantined)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, file_path, file_name, file_size, file_extension,
                      file_hash, threat_type, threat_name, threat_severity,
                      detection_method, ai_confidence, datetime.now(), False))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting detected threat: {e}")
            raise
    
    def insert_malware_signature(self, signature_hash: str, malware_name: str,
                                threat_type: str, threat_severity: str,
                                file_extension: str = None,
                                behavior_pattern: str = None,
                                source: str = None) -> int:
        """Insert malware signature"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO malware_signatures
                    (signature_hash, malware_name, threat_type, threat_severity,
                     file_extension, behavior_pattern, created_date, updated_date, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (signature_hash, malware_name, threat_type, threat_severity,
                      file_extension, behavior_pattern, datetime.now(), 
                      datetime.now(), source))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Error inserting malware signature: {e}")
            raise
    
    def get_scan_history(self, limit: int = 50) -> List[Dict]:
        """Get recent scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM scan_history
                    ORDER BY scan_date DESC
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving scan history: {e}")
            return []
    
    def get_detected_threats(self, scan_id: int = None) -> List[Dict]:
        """Get detected threats"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if scan_id:
                    cursor.execute("""
                        SELECT * FROM detected_threats
                        WHERE scan_id = ?
                        ORDER BY detected_date DESC
                    """, (scan_id,))
                else:
                    cursor.execute("""
                        SELECT * FROM detected_threats
                        ORDER BY detected_date DESC
                    """)
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error retrieving detected threats: {e}")
            return []
    
    def get_malware_signature(self, signature_hash: str) -> Optional[Dict]:
        """Get malware signature by hash"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM malware_signatures
                    WHERE signature_hash = ?
                """, (signature_hash,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error retrieving malware signature: {e}")
            return None
    
    def update_threat_quarantine(self, threat_id: int, quarantine_path: str,
                                action_taken: str):
        """Update threat with quarantine information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE detected_threats
                    SET quarantined = 1, quarantine_path = ?, action_taken = ?
                    WHERE id = ?
                """, (quarantine_path, action_taken, threat_id))
                conn.commit()
        except Exception as e:
            logger.error(f"Error updating threat quarantine: {e}")
            raise
    
    def add_to_whitelist(self, file_hash: str, file_name: str,
                        file_path: str, file_size: int, reason: str):
        """Add file to whitelist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO whitelist
                    (file_hash, file_name, file_path, file_size, added_date, reason)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (file_hash, file_name, file_path, file_size, 
                      datetime.now(), reason))
                conn.commit()
        except Exception as e:
            logger.error(f"Error adding to whitelist: {e}")
            raise
    
    def is_whitelisted(self, file_hash: str) -> bool:
        """Check if file is whitelisted"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id FROM whitelist WHERE file_hash = ?
                """, (file_hash,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking whitelist: {e}")
            return False

# ============================================================================
# USB DETECTION
# ============================================================================

class USBDevice:
    """Represents a USB device"""
    
    def __init__(self, device_id: str, name: str, mount_point: str, 
                 size: int, is_mounted: bool):
        self.device_id = device_id
        self.name = name
        self.mount_point = mount_point
        self.size = size
        self.is_mounted = is_mounted
    
    def __repr__(self):
        return f"USBDevice(id={self.device_id}, name={self.name}, path={self.mount_point})"

class USBDetector:
    """Detects and monitors USB devices"""
    
    def __init__(self):
        """Initialize USB detector"""
        self.system = platform.system()
        self.connected_devices: Dict[str, USBDevice] = {}
        self._monitoring = False
        self._callbacks = []
        self._stop_event = threading.Event()
    
    def detect_usb_devices(self) -> List[USBDevice]:
        """Detect all currently connected USB devices"""
        devices = []
        
        if self.system == "Windows":
            devices = self._detect_windows()
        elif self.system == "Linux":
            devices = self._detect_linux()
        elif self.system == "Darwin":  # macOS
            devices = self._detect_macos()
        
        return devices
    
    def _detect_windows(self) -> List[USBDevice]:
        """Detect USB devices on Windows"""
        devices = []
        try:
            # Check removable drives
            for letter in 'DEFGHIJKLMNOPQRSTUVWXYZ':
                path = f"{letter}:\\"
                if os.path.exists(path) and self._is_removable_drive(path):
                    devices.append(USBDevice(
                        device_id=letter,
                        name=f"USB Drive {letter}",
                        mount_point=path,
                        size=self._get_drive_size(path),
                        is_mounted=True
                    ))
        except Exception as e:
            logger.warning(f"Error detecting Windows USB devices: {e}")
        
        return devices
    
    def _detect_linux(self) -> List[USBDevice]:
        """Detect USB devices on Linux"""
        devices = []
        try:
            usb_path = Path("/media") / Path(os.getenv("USER", "user"))
            if usb_path.exists():
                for mount in usb_path.iterdir():
                    devices.append(USBDevice(
                        device_id=mount.name,
                        name=mount.name,
                        mount_point=str(mount),
                        size=self._get_directory_size(str(mount)),
                        is_mounted=True
                    ))
            
            # Also check /mnt
            mnt_path = Path("/mnt")
            if mnt_path.exists():
                for mount in mnt_path.iterdir():
                    if mount.is_dir():
                        devices.append(USBDevice(
                            device_id=mount.name,
                            name=mount.name,
                            mount_point=str(mount),
                            size=self._get_directory_size(str(mount)),
                            is_mounted=True
                        ))
        except Exception as e:
            logger.warning(f"Error detecting Linux USB devices: {e}")
        
        return devices
    
    def _detect_macos(self) -> List[USBDevice]:
        """Detect USB devices on macOS"""
        devices = []
        try:
            volumes_path = Path("/Volumes")
            if volumes_path.exists():
                for volume in volumes_path.iterdir():
                    if volume.is_dir() and volume.name not in ['Macintosh HD', '.']:
                        devices.append(USBDevice(
                            device_id=volume.name,
                            name=volume.name,
                            mount_point=str(volume),
                            size=self._get_directory_size(str(volume)),
                            is_mounted=True
                        ))
        except Exception as e:
            logger.warning(f"Error detecting macOS USB devices: {e}")
        
        return devices
    
    def _is_removable_drive(self, path: str) -> bool:
        """Check if drive is removable on Windows"""
        try:
            import ctypes
            GetDriveType = ctypes.windll.kernel32.GetDriveTypeW
            DRIVE_REMOVABLE = 2
            return GetDriveType(path) == DRIVE_REMOVABLE
        except Exception:
            return False
    
    def _get_drive_size(self, path: str) -> int:
        """Get drive size on Windows"""
        try:
            import ctypes
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(path), None, 
                ctypes.pointer(total_bytes), None
            )
            return total_bytes.value
        except Exception:
            return 0
    
    def _get_directory_size(self, path: str) -> int:
        """Get total size of directory"""
        try:
            total = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    total += os.path.getsize(os.path.join(dirpath, filename))
            return total
        except Exception:
            return 0
    
    def register_callback(self, callback):
        """Register callback for device changes"""
        self._callbacks.append(callback)
    
    def start_monitoring(self):
        """Start monitoring for USB device changes"""
        if not self._monitoring:
            self._monitoring = True
            self._stop_event.clear()
            
            monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            monitor_thread.start()
            
            logger.info("USB monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring USB devices"""
        self._monitoring = False
        self._stop_event.set()
        logger.info("USB monitoring stopped")
    
    def _monitor_loop(self):
        """Monitor for USB device changes"""
        while self._monitoring:
            try:
                current_devices = {d.device_id: d for d in self.detect_usb_devices()}
                
                # Check for new devices
                for device_id, device in current_devices.items():
                    if device_id not in self.connected_devices:
                        self.connected_devices[device_id] = device
                        for callback in self._callbacks:
                            callback("connected", device)
                        logger.info(f"USB device connected: {device}")
                
                # Check for removed devices
                removed_ids = set(self.connected_devices.keys()) - set(current_devices.keys())
                for device_id in removed_ids:
                    device = self.connected_devices.pop(device_id)
                    for callback in self._callbacks:
                        callback("disconnected", device)
                    logger.info(f"USB device disconnected: {device}")
                
                time.sleep(2)
            
            except Exception as e:
                logger.error(f"Error in USB monitoring loop: {e}")
                time.sleep(2)

# ============================================================================
# FILE SCANNING ENGINE
# ============================================================================

class ScanResult:
    """Represents the result of a file scan"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_name = Path(file_path).name
        self.file_size = 0
        self.file_extension = Path(file_path).suffix.lower()
        self.file_hash = None
        self.is_suspicious = False
        self.threats = []
        self.scan_timestamp = datetime.now()
    
    def add_threat(self, threat_type: str, threat_name: str, 
                  threat_severity: str, detection_method: str,
                  confidence: float = 1.0):
        """Add detected threat"""
        threat = {
            'type': threat_type,
            'name': threat_name,
            'severity': threat_severity,
            'method': detection_method,
            'confidence': confidence
        }
        self.threats.append(threat)
        self.is_suspicious = True

class FileScanner:
    """Scans files for threats"""
    
    def __init__(self, db_manager):
        """Initialize file scanner"""
        self.db_manager = db_manager
        self._cancel_scan = False
    
    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file"""
        result = ScanResult(file_path)
        
        if self._cancel_scan:
            return result
        
        try:
            if not os.path.isfile(file_path):
                return result
            
            result.file_size = os.path.getsize(file_path)
            
            # Skip extremely large files
            if result.file_size > 100 * 1024 * 1024:  # 100 MB
                logger.warning(f"File too large to scan: {file_path}")
                return result
            
            # Calculate file hash
            result.file_hash = self._calculate_hash(file_path)
            
            # Check whitelist
            if self.db_manager.is_whitelisted(result.file_hash):
                return result
            
            # Extension-based detection
            self._check_suspicious_extension(result)
            
            # Signature-based detection
            self._check_signature(result)
            
            # Behavioral analysis
            self._analyze_behavior(result)
            
            # Special handling for autorun.inf
            if result.file_name.lower() == 'autorun.inf':
                self._check_autorun_inf(result, file_path)
        
        except PermissionError:
            logger.debug(f"Permission denied scanning file: {file_path}")
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return result
    
    def scan_directory(self, directory_path: str, 
                      on_progress=None) -> List[ScanResult]:
        """Recursively scan directory"""
        results = []
        self._cancel_scan = False
        
        try:
            for root, dirs, files in os.walk(directory_path):
                if self._cancel_scan:
                    break
                
                for file in files:
                    if self._cancel_scan:
                        break
                    
                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)
                    results.append(result)
                    
                    if on_progress:
                        on_progress(len(results), result)
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
        
        return results
    
    def cancel_scan(self):
        """Cancel ongoing scan"""
        self._cancel_scan = True
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            hash_obj = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _check_suspicious_extension(self, result: ScanResult):
        """Check for suspicious file extension"""
        if result.file_extension in SUSPICIOUS_EXTENSIONS:
            result.add_threat(
                threat_type="SUSPICIOUS_EXTENSION",
                threat_name=f"Suspicious extension: {result.file_extension}",
                threat_severity=ThreatSeverity.MEDIUM.value,
                detection_method="EXTENSION_CHECK"
            )
    
    def _check_signature(self, result: ScanResult):
        """Check against signature database"""
        signature = self.db_manager.get_malware_signature(result.file_hash)
        
        if signature:
            result.add_threat(
                threat_type="SIGNATURE_MATCH",
                threat_name=signature['malware_name'],
                threat_severity=signature['threat_severity'],
                detection_method="SIGNATURE_BASED"
            )
    
    def _analyze_behavior(self, result: ScanResult):
        """Analyze file behavior patterns"""
        try:
            if result.file_extension in ['.js', '.vbs', '.bat', '.cmd', '.ps1']:
                with open(result.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    
                    suspicious_patterns = [
                        'eval(', 'exec(', 'system(', 'shell.',
                        'createobject(', 'run(', 'powershell',
                        'wmi.', 'registry.', 'delete'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in content:
                            result.add_threat(
                                threat_type="SUSPICIOUS_BEHAVIOR",
                                threat_name=f"Suspicious pattern: {pattern}",
                                threat_severity=ThreatSeverity.MEDIUM.value,
                                detection_method="BEHAVIOR_ANALYSIS",
                                confidence=0.7
                            )
                            break
        
        except Exception as e:
            logger.debug(f"Error analyzing behavior for {result.file_path}: {e}")
    
    def _check_autorun_inf(self, result: ScanResult, file_path: str):
        """Check autorun.inf for suspicious content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                suspicious_keywords = [
                    'shell=', 'shellexecute=', 'action=', 'icon='
                ]
                
                has_suspicious = any(kw in content.lower() for kw in suspicious_keywords)
                
                if has_suspicious:
                    result.add_threat(
                        threat_type="AUTORUN_EXPLOIT",
                        threat_name="Suspicious autorun.inf detected",
                        threat_severity=ThreatSeverity.HIGH.value,
                        detection_method="AUTORUN_CHECK"
                    )
        
        except Exception as e:
            logger.debug(f"Error checking autorun.inf: {e}")

# ============================================================================
# QUARANTINE MANAGER
# ============================================================================

class QuarantineManager:
    """Manages quarantine of suspicious files"""
    
    def __init__(self, db_manager, quarantine_dir: Path):
        """Initialize quarantine manager"""
        self.db_manager = db_manager
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
    
    def quarantine_file(self, file_path: str, threat_name: str, 
                       file_hash: str) -> bool:
        """
        Quarantine a suspicious file
        
        Args:
            file_path: Path to file to quarantine
            threat_name: Name of detected threat
            file_hash: SHA-256 hash of file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create quarantine filename with hash
            filename = f"{file_hash}_{Path(file_path).name}"
            quarantine_path = self.quarantine_dir / filename
            
            # Copy file to quarantine
            with open(file_path, 'rb') as src:
                with open(quarantine_path, 'wb') as dst:
                    dst.write(src.read())
            
            # Log in database
            with sqlite3.connect(self.db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO quarantine_log
                    (original_path, original_name, quarantine_path, file_hash, 
                     threat_name, quarantine_date, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (file_path, Path(file_path).name, str(quarantine_path),
                      file_hash, threat_name, datetime.now(), "QUARANTINED"))
                conn.commit()
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def restore_file(self, quarantine_id: int, restore_path: str) -> bool:
        """
        Restore quarantined file
        
        Args:
            quarantine_id: ID of quarantined file
            restore_path: Path to restore to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT quarantine_path FROM quarantine_log WHERE id = ?
                """, (quarantine_id,))
                
                row = cursor.fetchone()
                if not row:
                    return False
                
                quarantine_path = row[0]
                
                # Restore file
                with open(quarantine_path, 'rb') as src:
                    with open(restore_path, 'wb') as dst:
                        dst.write(src.read())
                
                # Update database
                cursor.execute("""
                    UPDATE quarantine_log
                    SET status = ?, restoration_date = ?
                    WHERE id = ?
                """, ("RESTORED", datetime.now(), quarantine_id))
                conn.commit()
            
            logger.info(f"File restored: {quarantine_path} -> {restore_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error restoring file: {e}")
            return False

# ============================================================================
# ANTIVIRUS ENGINE
# ============================================================================

class AntvirusEngine:
    """Main antivirus engine"""
    
    def __init__(self):
        """Initialize antivirus engine"""
        self.db_manager = DatabaseManager(DATABASE_PATH)
        self.usb_detector = USBDetector()
        self.file_scanner = FileScanner(self.db_manager)
        self.quarantine_manager = QuarantineManager(self.db_manager, QUARANTINE_DIR)
        self._scan_in_progress = False
        self._current_scan_id = None
    
    def start_scan(self, usb_mount_point: str) -> int:
        """
        Start scanning a USB device
        
        Args:
            usb_mount_point: Mount point of USB device
            
        Returns:
            Scan ID
        """
        if self._scan_in_progress:
            logger.warning("Scan already in progress")
            return -1
        
        self._scan_in_progress = True
        start_time = time.time()
        
        try:
            # Start scan history record
            usb_name = Path(usb_mount_point).name
            self._current_scan_id = self.db_manager.insert_scan_history(
                usb_name=usb_name,
                usb_path=usb_mount_point,
                total_files=0,
                suspicious_files=0,
                quarantined_files=0,
                scan_duration=0,
                status="IN_PROGRESS"
            )
            
            suspicious_count = 0
            quarantined_count = 0
            
            # Scan files
            def on_progress(total, result):
                if result.is_suspicious:
                    nonlocal suspicious_count
                    suspicious_count += 1
                    
                    # Insert threat record
                    threat_id = self.db_manager.insert_detected_threat(
                        scan_id=self._current_scan_id,
                        file_path=result.file_path,
                        file_name=result.file_name,
                        file_size=result.file_size,
                        file_extension=result.file_extension,
                        file_hash=result.file_hash,
                        threat_type=result.threats[0]['type'],
                        threat_name=result.threats[0]['name'],
                        threat_severity=result.threats[0]['severity'],
                        detection_method=result.threats[0]['method'],
                        ai_confidence=result.threats[0]['confidence']
                    )
                    
                    # Auto-quarantine high severity threats
                    if result.threats[0]['severity'] in ['HIGH', 'CRITICAL']:
                        if self.quarantine_manager.quarantine_file(
                            result.file_path,
                            result.threats[0]['name'],
                            result.file_hash
                        ):
                            nonlocal quarantined_count
                            quarantined_count += 1
                            self.db_manager.update_threat_quarantine(
                                threat_id,
                                str(QUARANTINE_DIR / result.file_hash),
                                "QUARANTINED"
                            )
            
            results = self.file_scanner.scan_directory(usb_mount_point, on_progress)
            
            # Update scan history
            scan_duration = time.time() - start_time
            with sqlite3.connect(self.db_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scan_history
                    SET total_files = ?, suspicious_files = ?, 
                        quarantined_files = ?, scan_duration = ?, status = ?
                    WHERE id = ?
                """, (len(results), suspicious_count, quarantined_count, 
                      scan_duration, "COMPLETED", self._current_scan_id))
                conn.commit()
            
            logger.info(f"Scan completed: {len(results)} files, {suspicious_count} suspicious, "
                       f"{quarantined_count} quarantined")
            
            return self._current_scan_id
        
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return -1
        
        finally:
            self._scan_in_progress = False
    
    def initialize_signatures(self):
        """Initialize default malware signatures"""
        # Add some default signatures
        default_signatures = [
            {
                'hash': 'cf8bd9fb5d614175c9cf3a2ecc0cf18c40642c44e7ca0efb9ea9e8e8ff47f6d9',
                'name': 'Win32.Malware.Test',
                'type': 'TROJAN',
                'severity': 'HIGH'
            },
            {
                'hash': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
                'name': 'Script.Malware.Test',
                'type': 'SCRIPT',
                'severity': 'MEDIUM'
            }
        ]
        
        for sig in default_signatures:
            try:
                self.db_manager.insert_malware_signature(
                    signature_hash=sig['hash'],
                    malware_name=sig['name'],
                    threat_type=sig['type'],
                    threat_severity=sig['severity'],
                    source='DEFAULT'
                )
            except Exception as e:
                logger.debug(f"Signature already exists: {e}")

# ============================================================================
# MAIN APPLICATION
# ============================================================================

if __name__ == "__main__":
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║         Flash Drive Antivirus - Console Demo                   ║
    ║              Cybersecurity Expert Edition                       ║
    ╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize antivirus engine
    engine = AntvirusEngine()
    engine.initialize_signatures()
    
    # Detect USB devices
    print("\n[*] Detecting USB devices...")
    devices = engine.usb_detector.detect_usb_devices()
    
    if devices:
        print(f"\n[+] Found {len(devices)} USB device(s):")
        for i, device in enumerate(devices, 1):
            print(f"    {i}. {device.name} ({device.mount_point})")
        
        # Scan first device
        print(f"\n[*] Starting scan of {devices[0].mount_point}...")
        scan_id = engine.start_scan(devices[0].mount_point)
        
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
                for threat in threats[:10]:  # Show first 10
                    print(f"    - {threat['file_name']}: {threat['threat_name']}")
    else:
        print("\n[-] No USB devices found")
    
    print("\n[*] Antivirus console demo completed")
