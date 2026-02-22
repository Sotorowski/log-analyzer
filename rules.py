from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any
from parser import LogEntry


class DetectionRules:
    """Security detection rules for Apache log analysis."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize detection rules with configuration.
        
        Args:
            config: Dictionary containing detection thresholds
        """
        self.config = config or {
            'brute_force_threshold': 5,   # attempts per IP (düşürüldü)
            'brute_force_endpoint': '/login',
            '404_threshold': 10,          # 404 responses per IP (düşürüldü)
            'rate_limit_threshold': 20,    # requests per minute per IP (düşürüldü)
            'time_window_minutes': 5
        }
    
    def detect_brute_force(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """
        Detect brute force attacks on login endpoints.
        
        Args:
            entries: List of log entries
            
        Returns:
            List of brute force detection results
        """
        results = []
        login_attempts = defaultdict(list)
        
        # Count login attempts per IP
        for entry in entries:
            if self.config['brute_force_endpoint'] in entry.endpoint:
                login_attempts[entry.ip].append(entry)
        
        # Check for IPs exceeding threshold
        for ip, attempts in login_attempts.items():
            if len(attempts) > self.config['brute_force_threshold']:
                # Get unique timestamps for time-based analysis
                timestamps = [entry.timestamp for entry in attempts]
                time_span = max(timestamps) - min(timestamps) if timestamps else timedelta(0)
                
                results.append({
                    "ip": ip,
                    "type": "brute_force",
                    "details": {
                        "attempts": len(attempts),
                        "endpoint": self.config['brute_force_endpoint'],
                        "time_span_minutes": time_span.total_seconds() / 60,
                        "first_attempt": min(timestamps).isoformat() if timestamps else None,
                        "last_attempt": max(timestamps).isoformat() if timestamps else None
                    }
                })
        
        return results
    
    def detect_404_flood(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """
        Detect 404 flood attacks.
        
        Args:
            entries: List of log entries
            
        Returns:
            List of 404 flood detection results
        """
        results = []
        not_found_requests = defaultdict(list)
        
        # Count 404 responses per IP
        for entry in entries:
            if entry.status_code == 404:
                not_found_requests[entry.ip].append(entry)
        
        # Check for IPs exceeding threshold
        for ip, requests in not_found_requests.items():
            if len(requests) > self.config['404_threshold']:
                # Get unique endpoints accessed
                endpoints = [req.endpoint for req in requests]
                unique_endpoints = len(set(endpoints))
                
                timestamps = [req.timestamp for req in requests]
                time_span = max(timestamps) - min(timestamps) if timestamps else timedelta(0)
                
                results.append({
                    "ip": ip,
                    "type": "404_flood",
                    "details": {
                        "not_found_count": len(requests),
                        "unique_endpoints": unique_endpoints,
                        "time_span_minutes": time_span.total_seconds() / 60,
                        "first_request": min(timestamps).isoformat() if timestamps else None,
                        "last_request": max(timestamps).isoformat() if timestamps else None,
                        "top_endpoints": Counter(endpoints).most_common(5)
                    }
                })
        
        return results
    
    def detect_rate_limiting(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """
        Detect rate limiting violations.
        
        Args:
            entries: List of log entries
            
        Returns:
            List of rate limiting detection results
        """
        results = []
        time_window = timedelta(minutes=self.config['time_window_minutes'])
        
        # Group entries by IP
        ip_entries = defaultdict(list)
        for entry in entries:
            ip_entries[entry.ip].append(entry)
        
        # Check each IP for rate limiting violations
        for ip, ip_log_entries in ip_entries.items():
            # Sort entries by timestamp
            ip_log_entries.sort(key=lambda x: x.timestamp)
            
            # Sliding window analysis
            for i in range(len(ip_log_entries)):
                window_start = ip_log_entries[i].timestamp
                window_end = window_start + time_window
                
                # Count requests in the time window
                window_requests = [
                    entry for entry in ip_log_entries[i:]
                    if window_start <= entry.timestamp <= window_end
                ]
                
                if len(window_requests) > self.config['rate_limit_threshold']:
                    # Get methods and endpoints in the window
                    methods = [req.method for req in window_requests]
                    endpoints = [req.endpoint for req in window_requests]
                    
                    results.append({
                        "ip": ip,
                        "type": "rate_limiting",
                        "details": {
                            "requests_per_window": len(window_requests),
                            "time_window_minutes": self.config['time_window_minutes'],
                            "window_start": window_start.isoformat(),
                            "window_end": window_end.isoformat(),
                            "methods": Counter(methods).most_common(),
                            "top_endpoints": Counter(endpoints).most_common(5)
                        }
                    })
                    break  # Only report once per IP
        
        return results
    
    def detect_all(self, entries: List[LogEntry]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Apply all detection rules.
        
        Args:
            entries: List of log entries
            
        Returns:
            Dictionary containing all detection results
        """
        return {
            "brute_force": self.detect_brute_force(entries),
            "404_flood": self.detect_404_flood(entries),
            "rate_limiting": self.detect_rate_limiting(entries)
        }
    
    def get_suspicious_ips(self, entries: List[LogEntry]) -> Dict[str, Dict[str, Any]]:
        """
        Aggregate all suspicious activities by IP.
        
        Args:
            entries: List of log entries
            
        Returns:
            Dictionary mapping IPs to their suspicious activities
        """
        all_detections = self.detect_all(entries)
        suspicious_ips = defaultdict(dict)
        
        for detection_type, detections in all_detections.items():
            for detection in detections:
                ip = detection["ip"]
                suspicious_ips[ip][detection_type] = detection["details"]
        
        return dict(suspicious_ips)
