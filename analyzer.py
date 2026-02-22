import os
from datetime import datetime
from typing import List, Dict, Any
from flask import Flask, request, render_template_string, redirect, url_for
from parser import ApacheLogParser, LogEntry
from rules import DetectionRules


class LogAnalyzer:
    """Main log analyzer class."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the log analyzer.
        
        Args:
            config: Configuration dictionary for detection rules
        """
        self.parser = ApacheLogParser()
        self.rules = DetectionRules(config)
        self.config = config or {}
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a log file for suspicious activities.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Analysis results dictionary
        """
        print(f"[*] Analyzing log file: {file_path}")
        
        # Parse log entries
        entries = self.parser.parse_file(file_path)
        if not entries:
            return {"error": "No valid log entries found"}
        
        print(f"[*] Parsed {len(entries)} log entries")
        
        # Apply detection rules
        suspicious_ips = self.rules.get_suspicious_ips(entries)
        all_detections = self.rules.detect_all(entries)
        
        # Generate statistics
        stats = self._generate_statistics(entries, all_detections)
        
        results = {
            "file_path": file_path,
            "total_entries": len(entries),
            "suspicious_ips": suspicious_ips,
            "all_detections": all_detections,
            "statistics": stats,
            "analysis_time": datetime.now().isoformat()
        }
        
        return results
    
    def analyze_lines(self, lines: List[str]) -> Dict[str, Any]:
        """
        Analyze log lines directly.
        
        Args:
            lines: List of log lines
            
        Returns:
            Analysis results dictionary
        """
        entries = self.parser.parse_lines(lines)
        if not entries:
            return {"error": "No valid log entries found"}
        
        suspicious_ips = self.rules.get_suspicious_ips(entries)
        all_detections = self.rules.detect_all(entries)
        stats = self._generate_statistics(entries, all_detections)
        
        return {
            "total_entries": len(entries),
            "suspicious_ips": suspicious_ips,
            "all_detections": all_detections,
            "statistics": stats,
            "analysis_time": datetime.now().isoformat()
        }
    
    def _generate_statistics(self, entries: List[LogEntry], detections: Dict[str, List]) -> Dict[str, Any]:
        """Generate analysis statistics."""
        if not entries:
            return {}
        
        # Basic stats
        unique_ips = len(set(entry.ip for entry in entries))
        status_codes = {}
        methods = {}
        
        for entry in entries:
            status_codes[entry.status_code] = status_codes.get(entry.status_code, 0) + 1
            methods[entry.method] = methods.get(entry.method, 0) + 1
        
        # Time range
        timestamps = [entry.timestamp for entry in entries]
        time_range = {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_minutes": (max(timestamps) - min(timestamps)).total_seconds() / 60
        }
        
        # Detection stats
        detection_stats = {}
        for detection_type, detection_list in detections.items():
            detection_stats[detection_type] = len(detection_list)
        
        return {
            "unique_ips": unique_ips,
            "status_codes": status_codes,
            "methods": methods,
            "time_range": time_range,
            "detection_stats": detection_stats
        }
    
    def print_results(self, results: Dict[str, Any]):
        """Print analysis results to terminal."""
        if "error" in results:
            print(f"[!] Error: {results['error']}")
            return
        
        print(f"\n[*] Log Analysis Results")
        print(f"=" * 50)
        print(f"Total entries analyzed: {results['total_entries']}")
        print(f"Analysis time: {results['analysis_time']}")
        
        # Print statistics
        stats = results.get('statistics', {})
        if stats:
            print(f"\n[*] Statistics:")
            print(f"  - Unique IPs: {stats.get('unique_ips', 0)}")
            print(f"  - Time span: {stats.get('time_range', {}).get('duration_minutes', 0):.1f} minutes")
            
            detection_stats = stats.get('detection_stats', {})
            if detection_stats:
                print(f"  - Detections:")
                for det_type, count in detection_stats.items():
                    print(f"    * {det_type}: {count}")
        
        # Print suspicious IPs
        suspicious_ips = results.get('suspicious_ips', {})
        if suspicious_ips:
            print(f"\n[!] Suspicious IPs Found:")
            for ip, activities in suspicious_ips.items():
                print(f"  - IP: {ip}")
                for activity_type, details in activities.items():
                    if activity_type == "brute_force":
                        print(f"    * Brute Force: {details['attempts']} attempts on {details['endpoint']}")
                    elif activity_type == "404_flood":
                        print(f"    * 404 Flood: {details['not_found_count']} 404 responses")
                    elif activity_type == "rate_limiting":
                        print(f"    * Rate Limiting: {details['requests_per_window']} requests in {details['time_window_minutes']} minutes")
        else:
            print(f"\n[*] No suspicious activities detected.")
    
    def generate_html_report(self, results: Dict[str, Any], output_file: str = "report.html"):
        """Generate HTML report."""
        if "error" in results:
            html_content = f"""
            <html>
            <head><title>Log Analysis Error</title></head>
            <body>
                <h1>Analysis Error</h1>
                <p>{results['error']}</p>
            </body>
            </html>
            """
        else:
            html_content = self._generate_html_content(results)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[*] HTML report generated: {output_file}")
            print(f"[*] Report size: {len(html_content)} characters")
        except Exception as e:
            print(f"[!] Error generating report: {e}")
    
    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """Generate HTML content for the report."""
        suspicious_ips = results.get('suspicious_ips', {})
        stats = results.get('statistics', {})
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Log Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .suspicious {{ background-color: #ffe6e6; }}
                .stats {{ background-color: #e6f3ff; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .alert {{ color: #d32f2f; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Log Analysis Report</h1>
                <p><strong>File:</strong> {results.get('file_path', 'Uploaded file')}</p>
                <p><strong>Analysis Time:</strong> {results['analysis_time']}</p>
                <p><strong>Total Entries:</strong> {results['total_entries']}</p>
            </div>
            
            <div class="section stats">
                <h2>Statistics</h2>
                <p><strong>Unique IPs:</strong> {stats.get('unique_ips', 0)}</p>
                <p><strong>Time Span:</strong> {stats.get('time_range', {}).get('duration_minutes', 0):.1f} minutes</p>
                
                <h3>Status Codes</h3>
                <table>
                    <tr><th>Status Code</th><th>Count</th></tr>
                    {''.join([f'<tr><td>{code}</td><td>{count}</td></tr>' for code, count in stats.get('status_codes', {}).items()])}
                </table>
                
                <h3>HTTP Methods</h3>
                <table>
                    <tr><th>Method</th><th>Count</th></tr>
                    {''.join([f'<tr><td>{method}</td><td>{count}</td></tr>' for method, count in stats.get('methods', {}).items()])}
                </table>
            </div>
            
            <div class="section suspicious">
                <h2>Suspicious Activities</h2>
                {self._generate_suspicious_ips_html(suspicious_ips)}
            </div>
        </body>
        </html>
        """
    
    def _generate_suspicious_ips_html(self, suspicious_ips: Dict[str, Dict]) -> str:
        """Generate HTML for suspicious IPs section."""
        if not suspicious_ips:
            return "<p class='alert'>No suspicious activities detected.</p>"
        
        html = ""
        for ip, activities in suspicious_ips.items():
            html += f"<div style='margin: 15px 0; padding: 10px; border-left: 4px solid #d32f2f;'>"
            html += f"<h3 class='alert'>Suspicious IP: {ip}</h3>"
            
            for activity_type, details in activities.items():
                if activity_type == "brute_force":
                    html += f"<p><strong>Brute Force Attack:</strong> {details['attempts']} attempts on {details['endpoint']}</p>"
                elif activity_type == "404_flood":
                    html += f"<p><strong>404 Flood:</strong> {details['not_found_count']} 404 responses</p>"
                elif activity_type == "rate_limiting":
                    html += f"<p><strong>Rate Limiting Violation:</strong> {details['requests_per_window']} requests in {details['time_window_minutes']} minutes</p>"
            
            html += "</div>"
        
        return html


# Flask Web Interface
FLASK_AVAILABLE = False
app = None
analyzer = None

try:
    from flask import Flask, request, render_template_string, redirect, url_for
    FLASK_AVAILABLE = True
    app = Flask(__name__)
    analyzer = LogAnalyzer()
except ImportError:
    print("Warning: Flask not available. Web interface disabled.")
except Exception as e:
    print(f"Warning: Flask initialization failed: {e}")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Log Analyzer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .upload-area { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; border-radius: 5px; }
        .upload-area:hover { border-color: #007bff; background-color: #f8f9fa; }
        .btn { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
        .results { margin-top: 20px; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .stats { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .suspicious { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Apache Log Analyzer</h1>
        
        <form method="post" enctype="multipart/form-data">
            <div class="upload-area">
                <input type="file" name="log_file" accept=".log,.txt" required>
                <p>Upload your Apache log file to analyze for suspicious activities</p>
                <button type="submit" class="btn">Analyze Log</button>
            </div>
        </form>
        
        {% if results %}
        <div class="results">
            {% if results.error %}
            <div class="alert alert-danger">
                <strong>Error:</strong> {{ results.error }}
            </div>
            {% else %}
            <div class="alert alert-success">
                <strong>Analysis Complete!</strong> Processed {{ results.total_entries }} log entries.
            </div>
            
            <div class="stats">
                <h3>📊 Statistics</h3>
                <p><strong>Unique IPs:</strong> {{ results.statistics.unique_ips }}</p>
                <p><strong>Time Span:</strong> {{ "%.1f"|format(results.statistics.time_range.duration_minutes) }} minutes</p>
                
                {% if results.statistics.detection_stats %}
                <h4>Detection Results:</h4>
                <ul>
                    {% for det_type, count in results.statistics.detection_stats.items() %}
                    <li><strong>{{ det_type.replace('_', ' ').title() }}:</strong> {{ count }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            
            {% if results.suspicious_ips %}
            <div class="suspicious">
                <h3>🚨 Suspicious Activities Detected</h3>
                {% for ip, activities in results.suspicious_ips.items() %}
                <div style="margin: 15px 0; padding: 10px; border-left: 4px solid #d32f2f; background-color: white;">
                    <h4 style="color: #d32f2f;">IP: {{ ip }}</h4>
                    {% for activity_type, details in activities.items() %}
                    {% if activity_type == 'brute_force' %}
                    <p><strong>Brute Force Attack:</strong> {{ details.attempts }} attempts on {{ details.endpoint }}</p>
                    {% elif activity_type == '404_flood' %}
                    <p><strong>404 Flood:</strong> {{ details.not_found_count }} 404 responses</p>
                    {% elif activity_type == 'rate_limiting' %}
                    <p><strong>Rate Limiting Violation:</strong> {{ details.requests_per_window }} requests in {{ details.time_window_minutes }} minutes</p>
                    {% endif %}
                    {% endfor %}
                </div>
                {% endfor %}
            </div>
            {% else %}
            <div class="alert alert-success">
                <strong>✅ No suspicious activities detected.</strong>
            </div>
            {% endif %}
            {% endif %}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

if FLASK_AVAILABLE and app:
    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method == 'POST':
            if 'log_file' not in request.files:
                return redirect(request.url)
            
            file = request.files['log_file']
            if file.filename == '':
                return redirect(request.url)
            
            if file:
                # Read file content
                lines = file.read().decode('utf-8').splitlines()
                results = analyzer.analyze_lines(lines)
                return render_template_string(HTML_TEMPLATE, results=results)
        
        return render_template_string(HTML_TEMPLATE, results=None)


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Apache Log Analyzer')
    parser.add_argument('file', nargs='?', help='Path to log file')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('--port', type=int, default=5000, help='Web interface port')
    parser.add_argument('--output', '-o', default='report.html', help='Output HTML report file')
    
    args = parser.parse_args()
    
    if args.web:
        if not FLASK_AVAILABLE:
            print("Error: Flask is not available. Install it with: pip install Flask")
            return
        print(f"[*] Starting web interface on http://localhost:{args.port}")
        app.run(host='0.0.0.0', port=args.port, debug=False)
    elif args.file:
        analyzer = LogAnalyzer()
        results = analyzer.analyze_file(args.file)
        analyzer.print_results(results)
        analyzer.generate_html_report(results, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
