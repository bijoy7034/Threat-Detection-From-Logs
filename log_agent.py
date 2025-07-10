import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, DefaultDict
from collections import defaultdict, deque
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class DoSDetector:
    def __init__(self):
        self.request_rate_threshold = 100  
        self.error_rate_threshold = 0.5  
        self.response_time_threshold = 5.0
        self.time_window = 5
        
  
        self.alert_cooldown = 20
        self.alerted_ips = {}
        
        self.ip_requests = defaultdict(lambda: deque())
        self.ip_errors = defaultdict(lambda: deque())
        self.ip_response_times = defaultdict(lambda: deque())
        self.user_agent_requests = defaultdict(lambda: deque())
        self.endpoint_requests = defaultdict(lambda: deque())
        
    def clean_old_entries(self, data_deque: deque, current_time: datetime):
        """Remove entries older than time window"""
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        while data_deque and data_deque[0]['timestamp'] < cutoff_time:
            data_deque.popleft()
    
    def should_alert_for_ip(self, ip: str, current_time: datetime) -> bool:
        """Check if we should send an alert for this IP based on cooldown"""
        if ip not in self.alerted_ips:
            self.alerted_ips[ip] = current_time
            return True
        
        time_since_last_alert = (current_time - self.alerted_ips[ip]).total_seconds()
        
        if time_since_last_alert >= self.alert_cooldown:
            self.alerted_ips[ip] = current_time
            return True
        
        return False
    
    def get_time_until_next_alert(self, ip: str, current_time: datetime) -> int:
        """Get remaining cooldown time in seconds"""
        if ip not in self.alerted_ips:
            return 0
        
        time_since_last = (current_time - self.alerted_ips[ip]).total_seconds()
        remaining = self.alert_cooldown - time_since_last
        return max(0, int(remaining))
    
    def detect_high_request_rate(self, ip: str, current_time: datetime) -> bool:
        """Detect high request rate from single IP"""
        self.clean_old_entries(self.ip_requests[ip], current_time)
        requests_per_minute = len(self.ip_requests[ip]) * (60 / self.time_window)
        return requests_per_minute > self.request_rate_threshold
    
    def detect_high_error_rate(self, ip: str, current_time: datetime) -> bool:
        """Detect high error rate from single IP"""
        self.clean_old_entries(self.ip_requests[ip], current_time)
        self.clean_old_entries(self.ip_errors[ip], current_time)
        
        total_requests = len(self.ip_requests[ip])
        error_requests = len(self.ip_errors[ip])
        
        if total_requests < 10:
            return False
            
        error_rate = error_requests / total_requests
        return error_rate > self.error_rate_threshold
    
    def detect_slow_response_pattern(self, ip: str, current_time: datetime) -> bool:
        """Detect pattern of slow responses"""
        self.clean_old_entries(self.ip_response_times[ip], current_time)
        
        if len(self.ip_response_times[ip]) < 5:
            return False
            
        avg_response_time = sum(entry['response_time'] for entry in self.ip_response_times[ip]) / len(self.ip_response_times[ip])
        return avg_response_time > self.response_time_threshold
    
    def detect_suspicious_user_agent(self, user_agent: str, current_time: datetime) -> bool:
        """Detect suspicious user agents"""
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'scanner',
            'nikto', 'sqlmap', 'nmap', 'masscan', 'zap',
            'burp', 'curl', 'wget', 'python-requests',
            'go-http-client', 'java/', 'apache-httpclient'
        ]
        
        if not user_agent:
            return True
            
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                self.clean_old_entries(self.user_agent_requests[user_agent], current_time)
                requests_per_minute = len(self.user_agent_requests[user_agent]) * (60 / self.time_window)
                return requests_per_minute > 20
        
        return False
    
    def detect_endpoint_flooding(self, endpoint: str, current_time: datetime) -> bool:
        """Detect flooding of specific endpoints"""
        self.clean_old_entries(self.endpoint_requests[endpoint], current_time)
        requests_per_minute = len(self.endpoint_requests[endpoint]) * (60 / self.time_window)
        return requests_per_minute > 200
    
    def update_tracking_data(self, log_entry: Dict[str, Any]):
        """Update tracking data structures"""
        try:
            current_time = datetime.fromisoformat(log_entry.get('asctime', '').replace('Z', '+00:00'))
        except:
            current_time = datetime.now()
        
        ip = log_entry.get('client_ip', log_entry.get('remote_addr', 'unknown'))
        user_agent = log_entry.get('user_agent', '')
        endpoint = log_entry.get('endpoint', log_entry.get('path', '/'))
        status_code = log_entry.get('status_code', 200)
        response_time = log_entry.get('response_time', 0.0)
        

        self.ip_requests[ip].append({
            'timestamp': current_time,
            'status_code': status_code,
            'response_time': response_time
        })
        

        if status_code >= 400:
            self.ip_errors[ip].append({
                'timestamp': current_time,
                'status_code': status_code
            })
        
    
        if response_time > 0:
            self.ip_response_times[ip].append({
                'timestamp': current_time,
                'response_time': response_time
            })
   
        if user_agent:
            self.user_agent_requests[user_agent].append({
                'timestamp': current_time,
                'ip': ip
            })

        self.endpoint_requests[endpoint].append({
            'timestamp': current_time,
            'ip': ip
        })
    
    def analyze_dos_patterns(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze log entry for DoS patterns - returns alert only if cooldown allows"""
        self.update_tracking_data(log_entry)
        
        try:
            current_time = datetime.fromisoformat(log_entry.get('asctime', '').replace('Z', '+00:00'))
        except:
            current_time = datetime.now()
        
        ip = log_entry.get('client_ip', log_entry.get('remote_addr', 'unknown'))
        user_agent = log_entry.get('user_agent', '')
        endpoint = log_entry.get('endpoint', log_entry.get('path', '/'))
        
   
        dos_detected = False
        detection_details = []

        if self.detect_high_request_rate(ip, current_time):
            dos_detected = True
            detection_details.append({
                'type': 'high_request_rate',
                'severity': 'high',
                'details': {
                    'requests_in_window': len(self.ip_requests[ip]),
                    'rate_per_minute': len(self.ip_requests[ip]) * (60 / self.time_window)
                }
            })
        
    
        if self.detect_high_error_rate(ip, current_time):
            dos_detected = True
            error_rate = len(self.ip_errors[ip]) / len(self.ip_requests[ip]) if self.ip_requests[ip] else 0
            detection_details.append({
                'type': 'high_error_rate',
                'severity': 'medium',
                'details': {
                    'error_rate': error_rate,
                    'total_requests': len(self.ip_requests[ip]),
                    'error_requests': len(self.ip_errors[ip])
                }
            })
        
       
        if self.detect_slow_response_pattern(ip, current_time):
            dos_detected = True
            avg_response_time = sum(entry['response_time'] for entry in self.ip_response_times[ip]) / len(self.ip_response_times[ip])
            detection_details.append({
                'type': 'slow_response_pattern',
                'severity': 'medium',
                'details': {
                    'avg_response_time': avg_response_time,
                    'requests_analyzed': len(self.ip_response_times[ip])
                }
            })
        
        if self.detect_suspicious_user_agent(user_agent, current_time):
            dos_detected = True
            detection_details.append({
                'type': 'suspicious_user_agent',
                'severity': 'high',
                'details': {
                    'user_agent': user_agent,
                    'requests_from_ua': len(self.user_agent_requests[user_agent])
                }
            })
        

        if self.detect_endpoint_flooding(endpoint, current_time):
            dos_detected = True
            detection_details.append({
                'type': 'endpoint_flooding',
                'severity': 'high',
                'details': {
                    'endpoint': endpoint,
                    'requests_in_window': len(self.endpoint_requests[endpoint]),
                    'rate_per_minute': len(self.endpoint_requests[endpoint]) * (60 / self.time_window)
                }
            })
        

        if dos_detected:
            if self.should_alert_for_ip(ip, current_time):
                return {
                    'should_alert': True,
                    'ip': ip,
                    'detection_details': detection_details,
                    'timestamp': current_time
                }
            else:

                remaining_cooldown = self.get_time_until_next_alert(ip, current_time)
                print(f"=> DoS activity detected from {ip} but in cooldown period. Next alert in {remaining_cooldown//60}m {remaining_cooldown%60}s")
                return {'should_alert': False}
        
        return {'should_alert': False}

class LogProcessor:
    def __init__(self):
        self.dos_detector = DoSDetector()
        
    def process_log_entry(self, log_entry: Dict[str, Any]):
        """Process a single log entry for DoS detection"""

        dos_result = self.dos_detector.analyze_dos_patterns(log_entry)
        
        if dos_result.get('should_alert'):
            self.handle_dos_alert(log_entry, dos_result)
    
    def handle_dos_alert(self, log_entry: Dict[str, Any], dos_result: Dict):
        """Handle a single DoS alert per IP with cooldown"""
        ip = dos_result['ip']
        detection_details = dos_result['detection_details']
        
        # Create combined alert message
        attack_types = [detail['type'] for detail in detection_details]
        highest_severity = max([detail['severity'] for detail in detection_details], 
                              key=lambda x: {'medium': 1, 'high': 2}[x])
        
        print("-" * 20)
        print(f"DoS ATTACK DETECTED FROM IP: {ip}")
        print(f"Attack Types: {', '.join(attack_types).upper()}")
        print(f"Severity: {highest_severity.upper()}")
        print(f"Timestamp: {log_entry.get('asctime', 'N/A')}")
        print(f"Cooldown: Next alert in {self.dos_detector.alert_cooldown//60} minutes")
        print("-" * 20)
        
        # Print detailed information
        for detail in detection_details:
            print(f"   {detail['type'].replace('_', ' ').title()}:")
            for key, value in detail['details'].items():
                if isinstance(value, float):
                    print(f"      {key}: {value:.2f}")
                else:
                    print(f"      {key}: {value}")
        
        print("-" * 60)
        
        # Save consolidated alert
        alert_data = {
            "type": "dos_attack_consolidated",
            "ip": ip,
            "attack_types": attack_types,
            "severity": highest_severity,
            "timestamp": datetime.now().isoformat(),
            "log_entry": log_entry,
            "detection_details": detection_details,
            "cooldown_period": self.dos_detector.alert_cooldown
        }
        
        with open("dos_alerts.json", "a") as f:
            f.write(json.dumps(alert_data) + "\n")

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, processor: LogProcessor):
        self.processor = processor
        self.file_position = 0
        
    def on_modified(self, event):
        if event.src_path.endswith('app.log'):
            self.read_new_logs()
    
    def read_new_logs(self):
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
        """Start the DoS detection agent with cooldown"""
        print("Starting DoS Detection Agent with Smart Alerting...")
        print("Configuration:")
        print(f"   - Request Rate Threshold: {self.processor.dos_detector.request_rate_threshold} req/min")
        print(f"   - Error Rate Threshold: {self.processor.dos_detector.error_rate_threshold * 100}%")
        print(f"   - Response Time Threshold: {self.processor.dos_detector.response_time_threshold}s")
        print(f"   - Alert Cooldown: {self.processor.dos_detector.alert_cooldown // 60} minutes per IP")
        print("Monitoring for:")
        print("   - High request rates")
        print("   - High error rates") 
        print("   - Slow response patterns")
        print("   - Suspicious user agents")
        print("   - Endpoint flooding")
        print("ONE ALERT PER IP PER 10 MINUTES")
        
        event_handler = LogFileHandler(self.processor)
        self.observer.schedule(event_handler, path='.', recursive=False)
        self.observer.start()
        
        try:
            event_handler.read_new_logs()
            print("\nActive DoS monitoring started...")
            print("Press Ctrl+C to stop")
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping DoS Detection Agent...")
            self.observer.stop()
        
        self.observer.join()

if __name__ == "__main__":
    agent = LogStreamingAgent()
    agent.start()
