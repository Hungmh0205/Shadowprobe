import os
import sys
import subprocess
import requests
import json
import re
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils import normalize_url, is_noise_line

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a09_logging_results"
NUCLEI_TEMPLATES = r"C:\Users\Dell\nuclei-templates"
KATANA_IMAGE = "projectdiscovery/katana:latest"
console = Console()

# Tạo thư mục output ngay từ đầu
try:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
except Exception as e:
    console.print(f"[red]Error creating output directory: {e}[/red]")
    sys.exit(1)

# ===================== CVSS SEVERITY STANDARD =====================
CVSS_METRICS = {
    "Attack Vector": {
        "Network": 0.85,
        "Adjacent": 0.62,
        "Local": 0.55,
        "Physical": 0.2
    },
    "Attack Complexity": {
        "Low": 0.77,
        "High": 0.44
    },
    "Privileges Required": {
        "None": 0.85,
        "Low": 0.62,
        "High": 0.27
    },
    "User Interaction": {
        "None": 0.85,
        "Required": 0.62
    },
    "Scope": {
        "Unchanged": 6.42,
        "Changed": 7.52
    },
    "Confidentiality": {
        "None": 0,
        "Low": 0.22,
        "High": 0.56
    },
    "Integrity": {
        "None": 0,
        "Low": 0.22,
        "High": 0.56
    },
    "Availability": {
        "None": 0,
        "Low": 0.22,
        "High": 0.56
    }
}

# A09 Vulnerability Mappings với CVSS
A09_VULNERABILITY_MAPPINGS = {
    "LOG_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Log injection allows malicious data insertion into logs"
    },
    "LOG_TAMPERING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
        "score": 8.5,
        "description": "Log tampering allows unauthorized modification of audit trails"
    },
    "LOG_STORAGE_EXPOSURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Log storage exposure reveals sensitive information"
    },
    "MONITORING_BYPASS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 6.5,
        "description": "Monitoring bypass allows undetected malicious activities"
    },
    "ALERT_FATIGUE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Alert fatigue reduces security team responsiveness"
    },
    "LOG_RETENTION_FAILURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Log retention failure prevents proper audit trails"
    },
    "SIEM_INTEGRATION_FAILURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "SIEM integration failure reduces security visibility"
    }
}

# OWASP A09:2021 - Security Logging and Monitoring Failures Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical logging failures - immediate remediation required",
                 "keywords": ["log injection", "log tampering", "critical", "breach", "unauthorized", "malicious", "compromise", "backdoor", "rootkit", "malware"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity logging vulnerabilities",
             "keywords": ["log exposure", "log storage", "monitoring bypass", "log manipulation", "unauthorized", "access", "sensitive", "data", "exposure", "leak"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - logging improvements needed",
               "keywords": ["alert fatigue", "log retention", "siem integration", "monitoring gap", "medium", "warning", "notice", "info", "misconfiguration"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["low", "info", "note", "debug", "development", "test", "sample", "non-critical", "minor", "cosmetic", "display issue", "enumeration"]}
}

# ================== UTIL ==================
def sanitize_filename(url):
    return urlparse(url).netloc.replace(":", "_")

def save_output(filename, data, append=False):
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except Exception as e:
        console.print(f"[red]Error creating output directory: {e}[/red]")
        return
    
    mode = "a" if append else "w"
    try:
        with open(os.path.join(OUTPUT_DIR, filename), mode, encoding="utf-8") as f:
            f.write(data)
    except Exception as e:
        console.print(f"[red]Error saving {filename}: {e}[/red]")

def run_command(cmd_list):
    try:
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(cmd_list)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            if result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                return "Command blocked for security reasons"
        except ImportError:
            # Fallback to direct subprocess with timeout
            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300)
        return result.stdout + "\n" + result.stderr
    except Exception as e:
        return f"Command error: {str(e)}\n"

def check_tool_available(tool_name):
    try:
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join([tool_name, "--version"])
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            if result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                return False
        except ImportError:
            # Fallback to direct subprocess with timeout
            result = subprocess.run([tool_name, "--version"], capture_output=True, text=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A09_VULNERABILITY_MAPPINGS:
        return A09_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A09_VULNERABILITY_MAPPINGS:
        mapping = A09_VULNERABILITY_MAPPINGS[vulnerability_type]
        score = mapping["score"]
        severity = mapping["severity"]
        color = SEVERITY_LEVELS[severity]["color"]
        return severity, color, score, mapping["cvss_vector"]
    
    # Fallback: phân tích theo keywords
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for kw in SEVERITY_LEVELS[level]["keywords"]:
            if kw.lower() in f_lower:
                if level == "CRITICAL":
                    score = 9.8
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                elif level == "HIGH":
                    score = 7.5
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
                elif level == "MEDIUM":
                    score = 5.3
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                else:
                    score = 3.1
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    
    score = 3.1
    return "LOW", "blue", score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

# ================== A09 ADVANCED FEATURES ==================

# 1. LOG INJECTION DETECTION
def detect_log_injection(target):
    """Detect log injection vulnerabilities"""
    console.print("[cyan][*] Running Log Injection Detection...[/cyan]")
    findings = []
    
    # Log injection payloads
    injection_payloads = [
        "'; DROP TABLE logs; --",
        "'; INSERT INTO logs VALUES ('injected'); --",
        "'; UPDATE logs SET data='injected'; --",
        "'; DELETE FROM logs; --",
        "'; EXEC xp_cmdshell('dir'); --",
        "'; SELECT * FROM users; --",
        "'; UNION SELECT 1,2,3,4,5; --",
        "'; WAITFOR DELAY '00:00:05'; --",
        "'; IF 1=1 WAITFOR DELAY '00:00:05'; --",
        "'; DECLARE @x INT; SET @x=1; --"
    ]
    
    # Test endpoints for log injection
    test_endpoints = [
        "/login", "/search", "/comment", "/feedback", "/contact",
        "/api/user", "/api/search", "/api/comment", "/admin/login"
    ]
    
    for endpoint in test_endpoints:
        url = target.rstrip("/") + endpoint
        for payload in injection_payloads:
            try:
                # Test GET request
                r = requests.get(url, params={"q": payload}, timeout=5)
                if r.status_code == 200:
                    findings.append(f"[LOG_INJECTION] Potential log injection via GET {endpoint} with payload: {payload}")
                
                # Test POST request
                r = requests.post(url, data={"input": payload}, timeout=5)
                if r.status_code == 200:
                    findings.append(f"[LOG_INJECTION] Potential log injection via POST {endpoint} with payload: {payload}")
                    
            except Exception as e:
                findings.append(f"[ERROR] Error testing log injection on {endpoint}: {e}")
    
    save_output("log_injection_detection.txt", "\n".join(findings))
    return findings

# 2. LOG TAMPERING DETECTION
def detect_log_tampering(target):
    """Detect log tampering vulnerabilities"""
    console.print("[cyan][*] Running Log Tampering Detection...[/cyan]")
    findings = []
    
    # Common log file paths
    log_paths = [
        "/var/log/", "/logs/", "/log/", "/tmp/", "/temp/",
        "access.log", "error.log", "debug.log", "system.log",
        "application.log", "web.log", "security.log", "audit.log"
    ]
    
    # Check for writable log files
    for log_path in log_paths:
        url = target.rstrip("/") + "/" + log_path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[LOG_TAMPERING] Log file accessible and potentially writable: {log_path}")
                
                # Check for log rotation patterns
                if "log" in log_path.lower():
                    findings.append(f"[LOG_TAMPERING] Log file may be subject to tampering: {log_path}")
                    
        except Exception as e:
            findings.append(f"[ERROR] Error checking log tampering for {log_path}: {e}")
    
    # Check for log manipulation endpoints
    manipulation_endpoints = [
        "/admin/logs", "/admin/clear-logs", "/admin/delete-logs",
        "/api/logs", "/api/clear-logs", "/api/delete-logs",
        "/logs/clear", "/logs/delete", "/logs/truncate"
    ]
    
    for endpoint in manipulation_endpoints:
        url = target.rstrip("/") + endpoint
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[LOG_TAMPERING] Log manipulation endpoint accessible: {endpoint}")
        except:
            pass
    
    save_output("log_tampering_detection.txt", "\n".join(findings))
    return findings

# 3. LOG STORAGE SECURITY ANALYSIS
def analyze_log_storage_security(target):
    """Analyze log storage security"""
    console.print("[cyan][*] Running Log Storage Security Analysis...[/cyan]")
    findings = []
    
    # Check for exposed log storage
    storage_paths = [
        "/logs/", "/var/log/", "/tmp/logs/", "/temp/logs/",
        "/backup/logs/", "/archive/logs/", "/old/logs/",
        "/database/logs/", "/db/logs/", "/sql/logs/"
    ]
    
    for path in storage_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[LOG_STORAGE_EXPOSURE] Log storage directory accessible: {path}")
                
                # Check for directory listing
                if "Index of" in r.text or "Directory listing" in r.text:
                    findings.append(f"[LOG_STORAGE_EXPOSURE] Directory listing enabled for log storage: {path}")
                    
        except Exception as e:
            findings.append(f"[ERROR] Error checking log storage {path}: {e}")
    
    # Check for log backup exposure
    backup_patterns = [
        "*.log.bak", "*.log.old", "*.log.backup", "*.log.gz", "*.log.tar.gz",
        "logs.zip", "logs.tar", "logs.tar.gz", "backup.log", "archive.log"
    ]
    
    for pattern in backup_patterns:
        url = target.rstrip("/") + "/" + pattern
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[LOG_STORAGE_EXPOSURE] Log backup file accessible: {pattern}")
        except:
            pass
    
    save_output("log_storage_security.txt", "\n".join(findings))
    return findings

# 4. MONITORING BYPASS DETECTION
def detect_monitoring_bypass(target):
    """Detect monitoring bypass techniques"""
    console.print("[cyan][*] Running Monitoring Bypass Detection...[/cyan]")
    findings = []
    
    # Check for monitoring bypass techniques
    bypass_techniques = [
        # User-Agent bypass
        {"header": "User-Agent", "value": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"header": "User-Agent", "value": "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
        
        # Referer bypass
        {"header": "Referer", "value": "https://www.google.com/"},
        {"header": "Referer", "value": "https://www.bing.com/"},
        
        # X-Forwarded-For bypass
        {"header": "X-Forwarded-For", "value": "127.0.0.1"},
        {"header": "X-Forwarded-For", "value": "10.0.0.1"},
        
        # Custom headers that might bypass monitoring
        {"header": "X-Requested-With", "value": "XMLHttpRequest"},
        {"header": "X-Real-IP", "value": "192.168.1.1"}
    ]
    
    test_endpoints = ["/admin", "/api/admin", "/admin/login", "/api/user"]
    
    for endpoint in test_endpoints:
        url = target.rstrip("/") + endpoint
        for technique in bypass_techniques:
            try:
                headers = {technique["header"]: technique["value"]}
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code in [200, 403, 401]:
                    findings.append(f"[MONITORING_BYPASS] Potential monitoring bypass via {technique['header']}: {technique['value']} on {endpoint}")
            except Exception as e:
                findings.append(f"[ERROR] Error testing monitoring bypass on {endpoint}: {e}")
    
    save_output("monitoring_bypass_detection.txt", "\n".join(findings))
    return findings

# 5. ALERT FATIGUE ANALYSIS
def analyze_alert_fatigue(target):
    """Analyze potential alert fatigue issues"""
    console.print("[cyan][*] Running Alert Fatigue Analysis...[/cyan]")
    findings = []
    
    # Check for excessive logging/alerting
    excessive_patterns = [
        "/debug", "/verbose", "/trace", "/detailed",
        "/api/debug", "/api/verbose", "/api/trace"
    ]
    
    for pattern in excessive_patterns:
        url = target.rstrip("/") + pattern
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[ALERT_FATIGUE] Excessive logging endpoint accessible: {pattern}")
        except:
            pass
    
    # Check for log verbosity settings
    verbosity_endpoints = [
        "/config/logging", "/settings/logging", "/admin/logging",
        "/api/config/logging", "/api/settings/logging"
    ]
    
    for endpoint in verbosity_endpoints:
        url = target.rstrip("/") + endpoint
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[ALERT_FATIGUE] Log verbosity configuration accessible: {endpoint}")
        except:
            pass
    
    save_output("alert_fatigue_analysis.txt", "\n".join(findings))
    return findings

# 6. LOG RETENTION ANALYSIS
def analyze_log_retention(target):
    """Analyze log retention policies"""
    console.print("[cyan][*] Running Log Retention Analysis...[/cyan]")
    findings = []
    
    # Check for log retention configuration
    retention_paths = [
        "/config/retention", "/settings/retention", "/admin/retention",
        "/api/config/retention", "/api/settings/retention",
        "/logs/retention", "/log/retention"
    ]
    
    for path in retention_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[LOG_RETENTION_FAILURE] Log retention configuration accessible: {path}")
        except:
            pass
    
    # Check for old log files that should be rotated
    old_log_patterns = [
        "*.log.2020", "*.log.2021", "*.log.2022", "*.log.2023",
        "*.log.old", "*.log.backup", "*.log.archive"
    ]
    
    for pattern in old_log_patterns:
        url = target.rstrip("/") + "/" + pattern
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[LOG_RETENTION_FAILURE] Old log file accessible (potential retention issue): {pattern}")
        except:
            pass
    
    save_output("log_retention_analysis.txt", "\n".join(findings))
    return findings

# 7. SIEM INTEGRATION TESTING
def test_siem_integration(target):
    """Test SIEM integration capabilities"""
    console.print("[cyan][*] Running SIEM Integration Testing...[/cyan]")
    findings = []
    
    # Check for SIEM integration endpoints
    siem_endpoints = [
        "/api/siem", "/api/logs/siem", "/api/events/siem",
        "/logs/siem", "/events/siem", "/monitoring/siem",
        "/api/alerts", "/api/events", "/api/logs/export"
    ]
    
    for endpoint in siem_endpoints:
        url = target.rstrip("/") + endpoint
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[SIEM_INTEGRATION_FAILURE] SIEM integration endpoint accessible: {endpoint}")
        except:
            pass
    
    # Check for log export capabilities
    export_formats = [
        "/api/logs/export?format=json",
        "/api/logs/export?format=xml",
        "/api/logs/export?format=csv",
        "/api/events/export?format=json"
    ]
    
    for export_url in export_formats:
        url = target.rstrip("/") + export_url
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[SIEM_INTEGRATION_FAILURE] Log export endpoint accessible: {export_url}")
        except:
            pass
    
    save_output("siem_integration_testing.txt", "\n".join(findings))
    return findings

# ================== A09 BASIC SCAN ==================
def check_log_related_headers(target):
    """Check logging-related HTTP headers"""
    console.print("[cyan][*] Checking Logging-related HTTP Headers...[/cyan]")
    findings = []
    
    try:
        r = requests.get(target, timeout=10)
        headers = r.headers
        
        for header in headers:
            if "log" in header.lower() or "report" in header.lower():
                findings.append(f"[LOG_HEADER] Logging header found: {header}: {headers[header]}")
        
        if "Content-Security-Policy-Report-Only" in headers:
            findings.append("[LOG_HEADER] CSP Reporting Header found - may leak logging endpoints")
        
        if not any("log" in h.lower() for h in headers):
            findings.append("[LOG_HEADER] No obvious logging/reporting headers found")
            
    except Exception as e:
        findings.append(f"[ERROR] Header check failed: {e}")
    
    save_output("log_headers_check.txt", "\n".join(findings))
    return findings

def find_exposed_logs(target):
    """Find exposed log files"""
    console.print("[cyan][*] Scanning for exposed logs...[/cyan]")
    findings = []
    
    log_paths = [
        "/log.txt", "/logs.txt", "/debug.log", "/server.log", "/access.log",
        "/error.log", "/app.log", "/php.log", "/web.log", "/system.log",
        "/.env", "/.log", "/logfile", "/logfile.txt", "/logs/access.log",
        "/logs/error.log", "/logs/debug.log", "/var/log/access.log",
        "/var/log/error.log", "/tmp/logs/", "/temp/logs/"
    ]
    
    for path in log_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[LOG_EXPOSURE] Log file accessible: {path}")
        except Exception as e:
            findings.append(f"[ERROR] Error checking {path}: {e}")
    
    save_output("exposed_logs.txt", "\n".join(findings))
    return findings

def run_nuclei_log_templates(target):
    """Run Nuclei log-related templates"""
    console.print("[cyan][*] Running Nuclei log exposure templates...[/cyan]")
    output = ""
    
    if not check_tool_available("nuclei"):
        output += "[!] Nuclei not found. Skipping Nuclei scans.\n"
        return output
    
    try:
        cmd = [
            "nuclei", "-u", target,
            "-t", "exposures/",
            "-tags", "log,exposure,debug",
            "-severity", "critical,high,medium",
            "-silent"
        ]
        result = run_command(cmd)
        if result.strip():
            output += result
    except Exception as e:
        output += f"[!] Error running Nuclei: {str(e)}\n"
    
    save_output("nuclei_log_templates.txt", output)
    return output

def run_katana_scan(target):
    """Run Katana for endpoint discovery"""
    console.print("[cyan][*] Running Katana for endpoint discovery...[/cyan]")
    cmd = [
        "docker", "run", "--rm",
        KATANA_IMAGE, "-u", target, "-silent"
    ]
    result = run_command(cmd)
    save_output("katana_output.txt", result)
    return result

# ================== ANALYSIS ==================
def analyze_results():
    console.print("[magenta][*] Analyzing A09 scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("log_injection_detection.txt", "LOG_INJECTION"),
        ("log_tampering_detection.txt", "LOG_TAMPERING"),
        ("log_storage_security.txt", "LOG_STORAGE_EXPOSURE"),
        ("monitoring_bypass_detection.txt", "MONITORING_BYPASS"),
        ("alert_fatigue_analysis.txt", "ALERT_FATIGUE"),
        ("log_retention_analysis.txt", "LOG_RETENTION_FAILURE"),
        ("siem_integration_testing.txt", "SIEM_INTEGRATION_FAILURE"),
        ("log_headers_check.txt", None),
        ("exposed_logs.txt", None),
        ("nuclei_log_templates.txt", None),
        ("katana_output.txt", None)
    ]

    for file, vuln_type in finding_files:
        file_path = os.path.join(OUTPUT_DIR, file)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip() and not is_noise_line(line):
                            severity, color, score, cvss_vector = classify_severity_advanced(line, vuln_type)
                            categorized[severity].append({"source": file, "finding": line.strip()})
                            findings.append(line.strip())
                            cvss_scores.append(score)
                            
                            # Store vulnerability details
                            if vuln_type and vuln_type in A09_VULNERABILITY_MAPPINGS:
                                mapping = A09_VULNERABILITY_MAPPINGS[vuln_type]
                                vulnerability_details.append({
                                    "type": vuln_type,
                                    "finding": line.strip(),
                                    "cvss_score": score,
                                    "cvss_vector": cvss_vector,
                                    "severity": severity,
                                    "description": mapping["description"]
                                })
            except Exception as e:
                console.print(f"[red]Error reading {file}: {e}[/red]")

    display_results(categorized, cvss_scores)
    save_summary(findings, categorized, vulnerability_details, cvss_scores)

def display_results(categorized, cvss_scores):
    table = Table(title="📊 A09 Security Logging & Monitoring Failures - CVSS Standard Overview", header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("CVSS Score", style="green", justify="center")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", style="green", justify="center")
    table.add_column("Description", style="white")
    table.add_column("A09 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Log Injection, Log Tampering",
        "HIGH": "Log Storage Exposure, Monitoring Bypass",
        "MEDIUM": "Alert Fatigue, Log Retention, SIEM Integration", 
        "LOW": "Info Disclosure, Reconnaissance"
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(categorized[sev])
        avg_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        table.add_row(
            f"[{SEVERITY_LEVELS[sev]['color']}]{sev}[/{SEVERITY_LEVELS[sev]['color']}]",
            f"{avg_score:.1f}" if avg_score > 0 else "N/A",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if sev == "CRITICAL" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            str(count),
            SEVERITY_LEVELS[sev]["description"],
            coverage_info[sev]
        )
    console.print(table)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if categorized[sev]:
            console.print(f"\n[{SEVERITY_LEVELS[sev]['color']}]{sev} FINDINGS[/]:")
            for item in categorized[sev]:
                console.print(f"  - {item['source']}: {item['finding']}")

def save_summary(findings, categorized, vulnerability_details, cvss_scores):
    with open(os.path.join(OUTPUT_DIR, "summary.txt"), "w", encoding="utf-8") as f:
        for sev in categorized:
            f.write(f"{sev}: {len(categorized[sev])} findings\n")
        f.write("\n=== DETAILS ===\n")
        for file, items in categorized.items():
            f.write(f"\n[{file}]\n")
            for item in items:
                sev, _, _, _ = classify_severity_advanced(item['finding'])
                f.write(f"[{sev}] {item['finding']}\n")
    
    # Save detailed report with CVSS
    report = f"""
A09 Security Logging & Monitoring Failures Scan Report - CVSS Standard
Generated: {datetime.now()}
Total Findings: {len(findings)}
Average CVSS Score: {sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0:.1f}

=== CRITICAL FINDINGS (CVSS 9.0-10.0) ===
{chr(10).join([item['finding'] for item in categorized['CRITICAL']])}

=== HIGH FINDINGS (CVSS 7.0-8.9) ===  
{chr(10).join([item['finding'] for item in categorized['HIGH']])}

=== MEDIUM FINDINGS (CVSS 4.0-6.9) ===
{chr(10).join([item['finding'] for item in categorized['MEDIUM']])}

=== LOW FINDINGS (CVSS 0.1-3.9) ===
{chr(10).join([item['finding'] for item in categorized['LOW']])}

=== VULNERABILITY DETAILS ===
"""
    
    for detail in vulnerability_details:
        report += f"""
Type: {detail['type']}
CVSS Score: {detail['cvss_score']}
CVSS Vector: {detail['cvss_vector']}
Severity: {detail['severity']}
Description: {detail['description']}
Finding: {detail['finding']}
"""

    report += """
=== A09 COVERAGE ===
✅ Log Injection Detection (CVSS 7.5)
✅ Log Tampering Detection (CVSS 8.5)
✅ Log Storage Security Analysis (CVSS 7.5)
✅ Monitoring Bypass Detection (CVSS 6.5)
✅ Alert Fatigue Analysis (CVSS 5.3)
✅ Log Retention Analysis (CVSS 5.3)
✅ SIEM Integration Testing (CVSS 5.3)
✅ Advanced Logging Security Testing
"""
    save_output("a09_detailed_report.txt", report)
    console.print("[green]💾 Summary saved[/green]")

# ================== MAIN ==================
def main(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = sanitize_filename(target)
    start = datetime.now()
    
    console.print(f"\n[bold yellow][*] Starting Advanced A09 Security Logging & Monitoring Scan for {target}[/bold yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Basic scans
        task1 = progress.add_task("Running basic logging checks...", total=None)
        header_findings = check_log_related_headers(target)
        exposed_logs = find_exposed_logs(target)
        nuclei_output = run_nuclei_log_templates(target)
        katana_output = run_katana_scan(target)
        progress.update(task1, completed=True)
        
        # Step 2: Advanced A09 scans
        task2 = progress.add_task("Running log injection detection...", total=None)
        injection_findings = detect_log_injection(target)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Running log tampering detection...", total=None)
        tampering_findings = detect_log_tampering(target)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Running log storage security analysis...", total=None)
        storage_findings = analyze_log_storage_security(target)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Running monitoring bypass detection...", total=None)
        bypass_findings = detect_monitoring_bypass(target)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Running alert fatigue analysis...", total=None)
        fatigue_findings = analyze_alert_fatigue(target)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Running log retention analysis...", total=None)
        retention_findings = analyze_log_retention(target)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Running SIEM integration testing...", total=None)
        siem_findings = test_siem_integration(target)
        progress.update(task8, completed=True)

        # Step 3: Analysis
        task9 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task9, completed=True)

    console.print(f"[green][*] Advanced A09 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a09_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python A09.py <target_url>[/red]")
        sys.exit(1)
    main(normalize_url(sys.argv[1]))
