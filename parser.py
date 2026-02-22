import re
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class LogEntry:
    """Structured representation of an Apache log entry."""
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    status_code: int
    raw_line: str


class ApacheLogParser:
    """Parser for Apache access logs."""
    
    def __init__(self):
        # Apache Common Log Format pattern
        self.common_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/[0-9\.]+" '
            r'(?P<status_code>\d{3})'
        )
        
        # Extended Apache Log Format (with User-Agent, Referer)
        self.extended_pattern = re.compile(
            r'(?:\d+,)?"?(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] '
            r'""?(?P<method>\w+) (?P<endpoint>[^\s]+)(?: HTTP/[0-9\.]+)?""? '
            r'(?P<status_code>\d{3})'
        )
        
        # Timestamp format for Apache logs
        self.timestamp_format = "%d/%b/%Y:%H:%M:%S %z"
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single Apache log line.
        
        Args:
            line: Raw log line
            
        Returns:
            LogEntry object or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None
        
        # Remove leading numbers if present
        line = re.sub(r'^\d+,', '', line)
        
        # Try common pattern first
        match = self.common_pattern.match(line)
        if not match:
            # Try extended pattern
            match = self.extended_pattern.match(line)
        
        if not match:
            return None
        
        try:
            # Extract and parse timestamp
            timestamp_str = match.group('timestamp')
            # Handle timezone if present, otherwise assume UTC
            if '+' in timestamp_str:
                timestamp = datetime.strptime(timestamp_str, self.timestamp_format)
            else:
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
            
            return LogEntry(
                ip=match.group('ip'),
                timestamp=timestamp,
                method=match.group('method'),
                endpoint=match.group('endpoint'),
                status_code=int(match.group('status_code')),
                raw_line=line
            )
            
        except (ValueError, AttributeError) as e:
            print(f"Error parsing line: {line} - {e}")
            return None
    
    def parse_file(self, file_path: str) -> list[LogEntry]:
        """
        Parse an entire log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of LogEntry objects
        """
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                for line_num, line in enumerate(file, 1):
                    entry = self.parse_line(line)
                    if entry:
                        entries.append(entry)
                    elif line.strip():  # Skip empty lines
                        print(f"Warning: Could not parse line {line_num}: {line.strip()}")
                        
        except FileNotFoundError:
            print(f"Error: Log file not found: {file_path}")
            return []
        except Exception as e:
            print(f"Error reading log file: {e}")
            return []
        
        return entries
    
    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        """
        Parse a list of log lines.
        
        Args:
            lines: List of raw log lines
            
        Returns:
            List of LogEntry objects
        """
        entries = []
        for line in lines:
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        return entries
