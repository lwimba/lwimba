"""
AI-Powered Malware Detection Module
Machine learning-based threat analysis and classification
"""

import numpy as np
import logging
from pathlib import Path
from typing import List, Tuple, Optional
import pickle
import os

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - AI detection disabled")

class MalwareDetector:
    """AI-based malware detection using machine learning"""
    
    def __init__(self, model_path: Path = None, scaler_path: Path = None):
        """
        Initialize malware detector
        
        Args:
            model_path: Path to trained model
            scaler_path: Path to feature scaler
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.is_trained = False
        
        if SKLEARN_AVAILABLE:
            self.load_model()
    
    def load_model(self):
        """Load pre-trained model and scaler"""
        try:
            if self.model_path and os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info("Model loaded successfully")
            
            if self.scaler_path and os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Scaler loaded successfully")
            
            if self.model and self.scaler:
                self.is_trained = True
        
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
            self.model = None
            self.scaler = None
            self.is_trained = False
    
    def extract_features(self, file_path: str, file_size: int, 
                        file_extension: str, entropy: float) -> np.ndarray:
        """
        Extract features from file for ML model
        
        Args:
            file_path: Path to file
            file_size: File size in bytes
            file_extension: File extension
            entropy: Shannon entropy of file
            
        Returns:
            Feature vector
        """
        features = []
        
        try:
            # 1. File size features
            features.append(min(file_size / (1024 * 1024), 100))  # Size in MB, capped
            
            # 2. Extension risk score
            extension_risk = self._get_extension_risk(file_extension)
            features.append(extension_risk)
            
            # 3. Entropy
            features.append(entropy)
            
            # 4. Content analysis
            null_bytes_ratio, high_entropy_ratio, printable_ratio = self._analyze_content(file_path)
            features.append(null_bytes_ratio)
            features.append(high_entropy_ratio)
            features.append(printable_ratio)
            
            # 7. String indicators
            suspicious_string_count = self._count_suspicious_strings(file_path)
            features.append(suspicious_string_count)
            
            # 8. PE header indicators
            is_pe_file = self._check_pe_header(file_path)
            features.append(1 if is_pe_file else 0)
            
            # 9. File name characteristics
            features.append(len(Path(file_path).name))
            
            # 10. Nested archive depth
            nested_depth = self._check_nested_archives(file_path)
            features.append(nested_depth)
        
        except Exception as e:
            logger.debug(f"Error extracting features: {e}")
            features = [0] * 10
        
        return np.array(features, dtype=np.float32)
    
    def predict(self, features: np.ndarray) -> Tuple[bool, float]:
        """
        Predict if file is malware
        
        Args:
            features: Feature vector
            
        Returns:
            Tuple of (is_malware, confidence)
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            return False, 0.0
        
        try:
            # Scale features
            scaled_features = self.scaler.transform([features])
            
            # Predict
            prediction = self.model.predict(scaled_features)[0]
            
            # Get probability
            probabilities = self.model.predict_proba(scaled_features)[0]
            confidence = probabilities[1]  # Probability of malware class
            
            return bool(prediction), float(confidence)
        
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return False, 0.0
    
    def train_model(self, training_data: List[Tuple[np.ndarray, int]], 
                   save_path: Path = None, scaler_save_path: Path = None):
        """
        Train malware detection model
        
        Args:
            training_data: List of (features, label) tuples
            save_path: Path to save trained model
            scaler_save_path: Path to save scaler
        """
        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn not available for training")
            return False
        
        try:
            # Prepare data
            X = np.array([x[0] for x in training_data])
            y = np.array([x[1] for x in training_data])
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            logger.info(f"Model trained - Accuracy: {accuracy:.2%}, Precision: {precision:.2%}, "
                       f"Recall: {recall:.2%}, F1: {f1:.2%}")
            
            # Save model
            if save_path:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                with open(save_path, 'wb') as f:
                    pickle.dump(self.model, f)
                logger.info(f"Model saved to {save_path}")
            
            # Save scaler
            if scaler_save_path:
                scaler_save_path.parent.mkdir(parents=True, exist_ok=True)
                with open(scaler_save_path, 'wb') as f:
                    pickle.dump(self.scaler, f)
                logger.info(f"Scaler saved to {scaler_save_path}")
            
            self.is_trained = True
            return True
        
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def _get_extension_risk(self, extension: str) -> float:
        """Get risk score for file extension"""
        risk_scores = {
            '.exe': 10.0, '.dll': 9.0, '.bat': 8.5, '.cmd': 8.5,
            '.js': 7.0, '.vbs': 8.5, '.ps1': 8.0, '.psm1': 8.0,
            '.scr': 9.5, '.msi': 7.5, '.com': 8.5, '.sys': 9.0,
            '.drv': 9.0, '.cpl': 8.0, '.hta': 8.5, '.jar': 6.0,
            '.vbe': 9.0, '.jse': 9.0, '.wsf': 8.5, '.wsh': 8.5,
            '.pif': 8.0, '.lnk': 7.5, '.reg': 6.5, '.inf': 5.0
        }
        return risk_scores.get(extension.lower(), 1.0)
    
    def _analyze_content(self, file_path: str) -> Tuple[float, float, float]:
        """
        Analyze file content
        
        Returns:
            Tuple of (null_bytes_ratio, high_entropy_ratio, printable_ratio)
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(50000, os.path.getsize(file_path)))
            
            if not content:
                return 0.0, 0.0, 0.0
            
            # Null bytes ratio
            null_bytes = content.count(b'\x00')
            null_ratio = null_bytes / len(content)
            
            # High entropy bytes (> 127)
            high_entropy = sum(1 for b in content if b > 127)
            high_entropy_ratio = high_entropy / len(content)
            
            # Printable ASCII ratio
            printable = sum(1 for b in content if 32 <= b < 127)
            printable_ratio = printable / len(content)
            
            return null_ratio, high_entropy_ratio, printable_ratio
        
        except Exception:
            return 0.0, 0.0, 0.0
    
    def _count_suspicious_strings(self, file_path: str) -> int:
        """Count suspicious strings in file"""
        suspicious_patterns = [
            b'eval', b'exec', b'system', b'shell',
            b'CreateObject', b'WScript', b'ActiveXObject',
            b'GetObject', b'CreateProcessA', b'CreateProcessW',
            b'ShellExecute', b'WinExec', b'RegOpenKey',
            b'RegSetValue', b'cmd.exe', b'powershell'
        ]
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(50000, os.path.getsize(file_path)))
            
            count = 0
            for pattern in suspicious_patterns:
                count += content.count(pattern)
            
            return count
        
        except Exception:
            return 0
    
    def _check_pe_header(self, file_path: str) -> bool:
        """Check if file has PE (Portable Executable) header"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
            return header == b'MZ'
        except Exception:
            return False
    
    def _check_nested_archives(self, file_path: str) -> int:
        """Check for nested archive depth"""
        archive_extensions = {'.zip', '.rar', '.7z', '.tar', '.gz', '.iso'}
        
        depth = 0
        current_path = Path(file_path)
        
        while depth < 3:
            if current_path.suffix.lower() in archive_extensions:
                depth += 1
            current_path = current_path.parent
        
        return depth

class BehavioralAnalyzer:
    """Behavioral threat analysis"""
    
    def __init__(self):
        """Initialize behavioral analyzer"""
        self.suspicious_behaviors = {
            'process_injection': ['CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx'],
            'registry_modification': ['RegSetValue', 'RegSetValueEx', 'RegDeleteValue'],
            'file_system_manipulation': ['DeleteFile', 'MoveFile', 'CopyFile'],
            'network_activity': ['connect', 'send', 'recv', 'WSASocket'],
            'persistence': ['Run', 'RunOnce', 'Startup', 'Schedule'],
            'privilege_escalation': ['CreateProcessWithToken', 'DuplicateToken'],
            'anti_analysis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetTickCount']
        }
    
    def analyze_behavior(self, file_content: bytes) -> Tuple[List[str], float]:
        """
        Analyze file behavior patterns
        
        Args:
            file_content: Binary file content
            
        Returns:
            Tuple of (detected_behaviors, risk_score)
        """
        detected = []
        
        try:
            for behavior, indicators in self.suspicious_behaviors.items():
                for indicator in indicators:
                    if indicator.encode() in file_content or indicator.lower().encode() in file_content.lower():
                        detected.append(behavior)
                        break
            
            # Calculate risk score
            risk_score = min(len(detected) * 0.15, 1.0)
            
            return detected, risk_score
        
        except Exception as e:
            logger.debug(f"Error analyzing behavior: {e}")
            return [], 0.0

class ThreatAnalyzer:
    """Comprehensive threat analysis"""
    
    def __init__(self, malware_detector: MalwareDetector = None):
        """
        Initialize threat analyzer
        
        Args:
            malware_detector: Malware detection model
        """
        self.detector = malware_detector or MalwareDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
    
    def analyze_file(self, file_path: str, file_size: int, 
                    file_extension: str) -> dict:
        """
        Perform comprehensive threat analysis
        
        Args:
            file_path: Path to file
            file_size: File size
            file_extension: File extension
            
        Returns:
            Analysis results dictionary
        """
        results = {
            'ai_threat': False,
            'ai_confidence': 0.0,
            'behavioral_threats': [],
            'behavioral_risk': 0.0,
            'overall_threat': False,
            'threat_level': 'LOW'
        }
        
        try:
            # Calculate entropy
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(min(50000, file_size))
                entropy = self._calculate_entropy(content)
            except:
                entropy = 0.0
            
            # ML-based detection
            if self.detector.is_trained:
                features = self.detector.extract_features(
                    file_path, file_size, file_extension, entropy
                )
                is_malware, confidence = self.detector.predict(features)
                results['ai_threat'] = is_malware
                results['ai_confidence'] = confidence
            
            # Behavioral analysis
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(min(100000, file_size))
                behaviors, behavior_risk = self.behavioral_analyzer.analyze_behavior(content)
                results['behavioral_threats'] = behaviors
                results['behavioral_risk'] = behavior_risk
            except:
                pass
            
            # Overall threat assessment
            ai_score = results['ai_confidence'] if results['ai_threat'] else 0
            behavior_score = results['behavioral_risk']
            
            overall_score = max(ai_score, behavior_score)
            
            results['overall_threat'] = overall_score > 0.5
            
            if overall_score > 0.8:
                results['threat_level'] = 'CRITICAL'
            elif overall_score > 0.6:
                results['threat_level'] = 'HIGH'
            elif overall_score > 0.4:
                results['threat_level'] = 'MEDIUM'
            elif overall_score > 0.2:
                results['threat_level'] = 'LOW'
            
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
        
        return results
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in frequency.values():
            probability = count / data_len
            entropy -= probability * np.log2(probability)
        
        return entropy / 8.0  # Normalize to 0-1

class SignatureUpdater:
    """Handles automatic signature updates"""
    
    def __init__(self, signature_db_manager):
        """
        Initialize signature updater
        
        Args:
            signature_db_manager: Database manager instance
        """
        self.db_manager = signature_db_manager
        self.last_update = None
    
    def check_for_updates(self) -> bool:
        """Check for signature updates"""
        # This would connect to a remote server
        logger.info("Checking for signature updates...")
        return False
    
    def update_signatures(self, new_signatures: List[dict]) -> int:
        """
        Update malware signatures
        
        Args:
            new_signatures: List of signature dictionaries
            
        Returns:
            Number of signatures added
        """
        added = 0
        try:
            for sig in new_signatures:
                try:
                    self.db_manager.insert_malware_signature(
                        signature_hash=sig['hash'],
                        malware_name=sig['name'],
                        threat_type=sig['type'],
                        threat_severity=sig['severity'],
                        source='UPDATE'
                    )
                    added += 1
                except Exception as e:
                    logger.debug(f"Signature already exists: {e}")
            
            logger.info(f"Added {added} new signatures")
            self.last_update = datetime.now()
            return added
        
        except Exception as e:
            logger.error(f"Error updating signatures: {e}")
            return 0

from datetime import datetime
