import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogProcessor:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.log_buffer = []
        self.feature_buffer = []
        self.is_trained = False
        self.anomaly_threshold = 0.1
        
    def extract_features(self, log_entry: Dict[str, Any]) -> List[float]:
        """Extract numerical features from log entry for anomaly detection"""
        features = []
        
        # Response time (if available)
        features.append(log_entry.get('response_time', 0.0))
        
        # Status code
        features.append(float(log_entry.get('status_code', 200)))
        
        # Hour of day
        try:
            timestamp = datetime.fromisoformat(log_entry.get('asctime', '').replace('Z', '+00:00'))
            features.append(float(timestamp.hour))
            features.append(float(timestamp.minute))
        except:
            features.extend([0.0, 0.0])
        
        # Request count (if available)
        features.append(float(log_entry.get('request_count', 0)))
        
        # Log level (convert to numeric)
        level_map = {'DEBUG': 1, 'INFO': 2, 'WARNING': 3, 'ERROR': 4, 'CRITICAL': 5}
        features.append(float(level_map.get(log_entry.get('levelname', 'INFO'), 2)))
        
        return features
    
    def infer_attack_type(self, log_entry: Dict[str, Any], features: List[float]) -> str:
        """Heuristically infer the type of attack based on log data"""
        status_code = log_entry.get('status_code', 200)
        response_time = log_entry.get('response_time', 0.0)
        request_count = log_entry.get('request_count', 0)
        level = log_entry.get('levelname', 'INFO').upper()
        message = log_entry.get('message', '')

        # Heuristic-based inference
        if request_count > 100:
            return "DoS attack"
        elif status_code in [401, 403, 429] and "login" in message.lower():
            return "Brute force attempt"
        elif status_code >= 500 and response_time > 3.0:
            return "Service disruption"
        elif "bot" in message.lower() or "scraper" in message.lower():
            return "Scraping activity"
        elif "sql" in message.lower() or "injection" in message.lower():
            return "SQL injection"
        elif status_code == 404 and request_count > 50:
            return "Scanning/probing"
        else:
            return "Unknown anomaly"

    
    def process_log_entry(self, log_entry: Dict[str, Any]):
        """Process a single log entry"""
        self.log_buffer.append(log_entry)
        
        # Extract features
        features = self.extract_features(log_entry)
        self.feature_buffer.append(features)
        
        # Train model if we have enough data
        if len(self.feature_buffer) >= 100 and not self.is_trained:
            self.train_model()
        
        # Detect anomalies if model is trained
        if self.is_trained:
            is_anomaly = self.detect_anomaly(features)
            if is_anomaly:
                self.handle_anomaly(log_entry, features)
    
    def train_model(self):
        """Train the Isolation Forest model"""
        try:
            df = pd.DataFrame(self.feature_buffer)
            df = df.fillna(0)  # Handle any NaN values
            
            # Scale features
            scaled_features = self.scaler.fit_transform(df)
            
            # Train Isolation Forest
            self.isolation_forest.fit(scaled_features)
            self.is_trained = True
            
            print(f"Isolation Forest model trained with {len(self.feature_buffer)} samples")
            
        except Exception as e:
            print(f"Error training model: {e}")
    
    def detect_anomaly(self, features: List[float]) -> bool:
        """Detect if a log entry is anomalous"""
        try:
            # Reshape for single prediction
            features_array = np.array(features).reshape(1, -1)
            
            # Handle any missing values
            features_array = np.nan_to_num(features_array)
            
            # Scale features
            scaled_features = self.scaler.transform(features_array)
            
            # Predict anomaly (-1 for anomaly, 1 for normal)
            prediction = self.isolation_forest.predict(scaled_features)[0]
            
            return prediction == -1
            
        except Exception as e:
            print(f"Error detecting anomaly: {e}")
            return False
    
    def handle_anomaly(self, log_entry: Dict[str, Any], features: List[float]):
        """Handle detected anomaly"""
        scaled = self.scaler.transform(np.array(features).reshape(1, -1))
        anomaly_score = self.isolation_forest.decision_function(scaled)[0]
        
        # Detect attack type
        attack_type = self.infer_attack_type(log_entry, features)
        
        print(f"---ANOMALY DETECTED! Score: {anomaly_score:.3f}")
        print(f"   Type: {attack_type}")
        print(f"   Timestamp: {log_entry.get('asctime', 'N/A')}")
        print(f"   Message: {log_entry.get('message', 'N/A')}")
        print(f"   Level: {log_entry.get('levelname', 'N/A')}")
        print(f"   Response Time: {log_entry.get('response_time', 'N/A')}")
        print(f"   Status Code: {log_entry.get('status_code', 'N/A')}")
        print(f"   Features: {features}")
        print("-" * 60)
        
        self.send_alert(log_entry, anomaly_score, attack_type)

    
    def send_alert(self, log_entry: Dict[str, Any], anomaly_score: float, attack_type: str):
        """Send alert for anomaly"""
        alert_data = {
            "type": "anomaly_detected",
            "attack_type": attack_type,
            "timestamp": datetime.now().isoformat(),
            "log_entry": log_entry,
            "anomaly_score": anomaly_score,
            "severity": "high" if anomaly_score < -0.5 else "medium"
        }
        
        with open("alerts.json", "a") as f:
            f.write(json.dumps(alert_data) + "\n")


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, processor: LogProcessor):
        self.processor = processor
        self.file_position = 0
        
    def on_modified(self, event):
        if event.src_path.endswith('app.log'):
            self.read_new_logs()
    
    def read_new_logs(self):
        """Read new log entries from the file"""
        try:
            with open('app.log', 'r') as f:
                f.seek(self.file_position)
                new_lines = f.readlines()
                self.file_position = f.tell()
                
                for line in new_lines:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            print(f"Processing log: {log_entry.get('message', 'N/A')}")
                            self.processor.process_log_entry(log_entry)
                        except json.JSONDecodeError:
                            print(f"Invalid JSON in log: {line}")
                            
        except FileNotFoundError:
            print("Log file not found, waiting...")
        except Exception as e:
            print(f"Error reading logs: {e}")

class LogStreamingAgent:
    def __init__(self):
        self.processor = LogProcessor()
        self.observer = Observer()
        
    def start(self):
        """Start the log streaming agent"""
        print("Starting Log Streaming Agent with Anomaly Detection...")
        
        # Set up file monitoring
        event_handler = LogFileHandler(self.processor)
        self.observer.schedule(event_handler, path='.', recursive=False)
        self.observer.start()
        
        try:
            # Read existing logs first
            event_handler.read_new_logs()
            
            print("Monitoring logs for anomalies...")
            print("Model will train automatically after collecting 100 samples")
            print("Press Ctrl+C to stop")
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping Log Streaming Agent...")
            self.observer.stop()
        
        self.observer.join()

if __name__ == "__main__":
    agent = LogStreamingAgent()
    agent.start()

