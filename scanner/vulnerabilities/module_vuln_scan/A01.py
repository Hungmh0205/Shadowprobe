import os
import subprocess
import json
import re
import base64
import requests
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils import normalize_url, is_noise_line

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core'))  

# ================== CONFIG ==================
OUTPUT_DIR = "reports/a01_scan_results"
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

# A01 Vulnerability Mappings với CVSS
A01_VULNERABILITY_MAPPINGS = {
    "AUTH_BYPASS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Authentication bypass allows unauthorized access"
    },
    "PRIVILEGE_ESCALATION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 8.8,
        "description": "Privilege escalation allows elevated access"
    },
    "IDOR": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Insecure Direct Object Reference allows data access"
    },
    "FORCE_BROWSING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Force browsing allows unauthorized resource access"
    },
    "JWT_BYPASS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "JWT bypass allows token manipulation"
    },
    "PARAMETER_POLLUTION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Parameter pollution allows request manipulation"
    },
    "HORIZONTAL_ACCESS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Horizontal access control bypass"
    },
    "VERTICAL_ACCESS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
        "score": 8.1,
        "description": "Vertical access control bypass"
    }
}

# OWASP A01:2021 - Broken Access Control Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical broken access control - immediate remediation required",
                 "keywords": ["auth bypass", "authentication bypass", "privilege escalation", "role bypass", "admin bypass", "rce", "remote code execution", "command injection", "sql injection", "idor", "insecure direct object reference", "ssrf", "server side request forgery", "jwt bypass", "jwt tampering", "jwt none", "critical", "crash", "buffer overflow", "xxe", "xml external entity"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity broken access control vulnerabilities",
             "keywords": ["broken access control", "access control", "authorization bypass", "access denied bypass", "forbidden bypass", "csrf", "cross-site request forgery", "session riding", "security misconfiguration", "known vulnerabilities", "outdated software", "nuclei", "zap", "role change", "role escalation", "jwt", "idor", "insecure direct object reference", "force browsing", "parameter pollution", "horizontal access", "vertical access"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - access control improvements needed",
               "keywords": ["missing", "absence", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "information disclosure", "version disclosure", "weak", "insecure", "deprecated", "outdated protocol", "medium", "warning", "notice", "info"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["low", "info", "note", "debug", "development", "test", "sample", "non-critical", "minor", "cosmetic", "display issue", "enumeration"]}
}

# A01 Specific Test Cases
A01_TEST_CASES = {
    "auth_bypass": {
        "techniques": ["admin", "admin/admin", "admin:admin", "guest", "test", "user", "demo", "temp", "backup", "root", "administrator"],
        "description": "Authentication bypass techniques"
    },
    "privilege_escalation": {
        "methods": ["role=admin", "isadmin=true", "accesslevel=admin", "privilege=admin", "type=admin", "level=admin", "group=admin", "role=superuser", "isadmin=1", "admin=1"],
        "description": "Privilege escalation methods"
    },
    "idor": {
        "parameters": ["id", "uid", "userid", "accountid", "orderid", "fileid", "docid", "itemid", "productid", "customerid", "patientid", "studentid"],
        "description": "IDOR vulnerable parameters"
    },
    "force_browsing": {
        "paths": ["/admin", "/api/admin", "/internal", "/private", "/dashboard", "/panel", "/console", "/management", "/control", "/settings", "/config", "/system", "/backup", "/logs", "/debug", "/test", "/dev", "/staging"],
        "description": "Force browsing paths"
    },
    "jwt_attacks": {
        "techniques": ["none", "null", "empty", "weak", "predictable", "tampering", "forgery"],
        "description": "JWT attack techniques"
    },
    "parameter_pollution": {
        "parameters": ["id", "user", "role", "type", "level", "access", "privilege", "group", "category"],
        "description": "Parameter pollution vulnerable parameters"
    }
}

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A01_VULNERABILITY_MAPPINGS:
        return A01_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A01_VULNERABILITY_MAPPINGS:
        mapping = A01_VULNERABILITY_MAPPINGS[vulnerability_type]
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

def save_output(filename, data, append=False):
    mode = "a" if append else "w"
    with open(os.path.join(OUTPUT_DIR, filename), mode, encoding="utf-8") as f:
        f.write(data)

def run_cmd(cmd_list, output_file):
    """Safely run command using security utilities"""
    try:
        # Import security utils using proper relative import
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

# ===================== A01 SPECIFIC TESTS =====================
def test_auth_bypass(target, endpoints):
    """Test authentication bypass techniques"""
    console.print("[cyan][*] Testing authentication bypass...[/cyan]")
    findings = []
    
    auth_bypass_techniques = A01_TEST_CASES["auth_bypass"]["techniques"]
    
    for endpoint in endpoints:
        for technique in auth_bypass_techniques:
            try:
                # Test different auth bypass techniques
                test_urls = [
                    f"{endpoint}?user={technique}",
                    f"{endpoint}?username={technique}",
                    f"{endpoint}?admin={technique}",
                    f"{endpoint}?auth={technique}",
                    f"{endpoint}?login={technique}"
                ]
                
                for test_url in test_urls:
                    r = requests.get(test_url, timeout=5)
                    
                    # Check for successful bypass indicators
                    bypass_indicators = [
                        "welcome", "dashboard", "admin", "panel", "console",
                        "logged in", "authenticated", "authorized", "access granted"
                    ]
                    
                    if any(indicator in r.text.lower() for indicator in bypass_indicators):
                        finding = f"[AUTH_BYPASS] {test_url} - Authentication bypass detected with technique: {technique}"
                        findings.append(finding)
                        
            except Exception as e:
                findings.append(f"[ERROR] Testing auth bypass for {endpoint}: {str(e)}")
    
    save_output("auth_bypass_findings.txt", "\n".join(findings))
    return findings

def test_privilege_escalation(target, endpoints):
    """Test privilege escalation methods"""
    console.print("[cyan][*] Testing privilege escalation...[/cyan]")
    findings = []
    
    escalation_methods = A01_TEST_CASES["privilege_escalation"]["methods"]
    
    for endpoint in endpoints:
        for method in escalation_methods:
            try:
                # Test POST with privilege escalation
                data = {method.split('=')[0]: method.split('=')[1]}
                r = requests.post(endpoint, data=data, timeout=5)
                
                # Check for privilege escalation indicators
                escalation_indicators = [
                    "admin", "administrator", "superuser", "privileged", "elevated",
                    "access granted", "authorized", "role changed", "privilege escalated"
                ]
                
                if any(indicator in r.text.lower() for indicator in escalation_indicators):
                    finding = f"[PRIVILEGE_ESCALATION] {endpoint} - Privilege escalation detected with method: {method}"
                    findings.append(finding)
                    
            except Exception as e:
                findings.append(f"[ERROR] Testing privilege escalation for {endpoint}: {str(e)}")
    
    save_output("privilege_escalation_findings.txt", "\n".join(findings))
    return findings

def test_horizontal_access_control(target, endpoints):
    """Test horizontal access control bypass"""
    console.print("[cyan][*] Testing horizontal access control...[/cyan]")
    findings = []
    
    id_params = A01_TEST_CASES["idor"]["parameters"]
    
    for endpoint in endpoints:
        for param in id_params:
            try:
                # Test horizontal access control
                test_urls = [
                    f"{endpoint}?{param}=1",
                    f"{endpoint}?{param}=2",
                    f"{endpoint}?{param}=admin",
                    f"{endpoint}?{param}=other"
                ]
                
                responses = []
                for test_url in test_urls:
                    r = requests.get(test_url, timeout=5)
                    responses.append((test_url, r.status_code, len(r.text)))
                
                # Check for horizontal access control bypass
                if len(responses) >= 2:
                    for i in range(len(responses)-1):
                        for j in range(i+1, len(responses)):
                            if (responses[i][1] == 200 and responses[j][1] == 200 and
                                abs(responses[i][2] - responses[j][2]) >= 50):
                                finding = f"[HORIZONTAL_ACCESS] {endpoint} - Horizontal access control bypass detected with parameter: {param}"
                                findings.append(finding)
                                break
                        
            except Exception as e:
                findings.append(f"[ERROR] Testing horizontal access control for {endpoint}: {str(e)}")
    
    save_output("horizontal_access_findings.txt", "\n".join(findings))
    return findings

def test_vertical_access_control(target, endpoints):
    """Test vertical access control bypass"""
    console.print("[cyan][*] Testing vertical access control...[/cyan]")
    findings = []
    
    admin_paths = A01_TEST_CASES["force_browsing"]["paths"]
    
    for endpoint in endpoints:
        base_url = endpoint.split('?')[0] if '?' in endpoint else endpoint
        
        for admin_path in admin_paths:
            try:
                test_url = f"{base_url}{admin_path}"
                r = requests.get(test_url, timeout=5)
                
                # Check for vertical access control bypass
                if r.status_code == 200:
                    admin_indicators = [
                        "admin", "administrator", "dashboard", "panel", "console",
                        "management", "control", "settings", "config", "system"
                    ]
                    
                    if any(indicator in r.text.lower() for indicator in admin_indicators):
                        finding = f"[VERTICAL_ACCESS] {test_url} - Vertical access control bypass detected"
                        findings.append(finding)
                        
            except Exception as e:
                findings.append(f"[ERROR] Testing vertical access control for {endpoint}: {str(e)}")
    
    save_output("vertical_access_findings.txt", "\n".join(findings))
    return findings

def test_force_browsing(target, endpoints):
    """Test force browsing vulnerabilities"""
    console.print("[cyan][*] Testing force browsing...[/cyan]")
    findings = []
    
    force_browsing_paths = A01_TEST_CASES["force_browsing"]["paths"]
    
    for endpoint in endpoints:
        base_url = endpoint.split('?')[0] if '?' in endpoint else endpoint
        
        for path in force_browsing_paths:
            try:
                test_url = f"{base_url}{path}"
                r = requests.get(test_url, timeout=5)
                
                # Check for force browsing success
                if r.status_code == 200:
                    sensitive_indicators = [
                        "internal", "private", "admin", "backup", "logs", "debug",
                        "test", "dev", "staging", "config", "system", "management"
                    ]
                    
                    if any(indicator in r.text.lower() for indicator in sensitive_indicators):
                        finding = f"[FORCE_BROWSING] {test_url} - Force browsing vulnerability detected"
                        findings.append(finding)
                        
            except Exception as e:
                findings.append(f"[ERROR] Testing force browsing for {endpoint}: {str(e)}")
    
    save_output("force_browsing_findings.txt", "\n".join(findings))
    return findings

def test_parameter_pollution(target, endpoints):
    """Test parameter pollution attacks"""
    console.print("[cyan][*] Testing parameter pollution...[/cyan]")
    findings = []
    
    pollution_params = A01_TEST_CASES["parameter_pollution"]["parameters"]
    
    for endpoint in endpoints:
        if '?' in endpoint:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            for param in pollution_params:
                if param in params:
                    try:
                        # Test parameter pollution
                        original_value = params[param][0]
                        polluted_url = endpoint.replace(f"{param}={original_value}", f"{param}={original_value}&{param}=admin")
                        
                        r1 = requests.get(endpoint, timeout=5)
                        r2 = requests.get(polluted_url, timeout=5)
                        
                        # Check for parameter pollution effect
                        if r1.status_code != r2.status_code or abs(len(r1.text) - len(r2.text)) >= 30:
                            finding = f"[PARAMETER_POLLUTION] {polluted_url} - Parameter pollution detected with parameter: {param}"
                            findings.append(finding)
                            
                    except Exception as e:
                        findings.append(f"[ERROR] Testing parameter pollution for {endpoint}: {str(e)}")
    
    save_output("parameter_pollution_findings.txt", "\n".join(findings))
    return findings

def test_jwt_vulnerabilities(target):
    """Test JWT vulnerabilities"""
    console.print("[cyan][*] Testing JWT vulnerabilities...[/cyan]")
    findings = []
    
    try:
        # Find JWT tokens
        r = requests.get(target, timeout=5)
        jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'
        tokens = re.findall(jwt_pattern, r.text)
        
        for token in tokens:
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                    
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
                
                # Test JWT none algorithm attack
                header["alg"] = "none"
                new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().strip("=")
                new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().strip("=")
                forged_token = f"{new_header}.{new_payload}."
                
                r = requests.get(target, headers={"Authorization": f"Bearer {forged_token}"}, timeout=5)
                if r.status_code == 200:
                    finding = f"[JWT_BYPASS] {target} - JWT none algorithm attack successful"
                    findings.append(finding)
                    
            except Exception as e:
                findings.append(f"[ERROR] Testing JWT for {target}: {str(e)}")
                
    except Exception as e:
        findings.append(f"[ERROR] Testing JWT vulnerabilities for {target}: {str(e)}")
    
    save_output("jwt_vulnerabilities_findings.txt", "\n".join(findings))
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

def run_nuclei_advanced(url):
    """Chạy Nuclei với nhiều template A01 hơn"""
    console.print(f"[yellow][*] Running Advanced Nuclei for {url}[/yellow]")
    
    # Thêm nhiều template A01
    templates = [
        "cves/",
        "vulnerabilities/",
        "vulnerabilities/generic/",
        "vulnerabilities/auth-bypass",
        "vulnerabilities/idor",
        "vulnerabilities/privilege-escalation",
        "vulnerabilities/force-browsing",
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
            
            if result and result.stdout:
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

def run_zap_advanced(target):
    console.print(f"[yellow][*] Running OWASP ZAP Advanced Scan for {target}[/yellow]")
    zap_out_dir = os.path.abspath(OUTPUT_DIR)
    
    # Sử dụng zap-baseline.py thay vì zap-full-scan.py để tránh lỗi
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{zap_out_dir}:/zap/wrk:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t", target,
        "-J", "zap_report.json",
        "-m", "3"
    ]
    
    try:
        run_cmd(cmd, "zap_output.txt")
    except Exception as e:
        console.print(f"[red]ZAP scan failed: {e}[/red]")
        # Fallback: sử dụng zap-cli nếu có
        fallback_cmd = [
            "zap-cli", "quick-scan", target,
            "--self-contained", "--start-options", "-config api.disablekey=true"
        ]
        try:
            run_cmd(fallback_cmd, "zap_output.txt")
        except Exception as e2:
            console.print(f"[red]ZAP fallback also failed: {e2}[/red]")
            save_output("zap_output.txt", f"ZAP scan failed: {e}\nFallback failed: {e2}")

# ================== ANALYSIS ==================
def analyze_results():
    console.print("[magenta][*] Analyzing scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("auth_bypass_findings.txt", "AUTH_BYPASS"),
        ("privilege_escalation_findings.txt", "PRIVILEGE_ESCALATION"),
        ("horizontal_access_findings.txt", "HORIZONTAL_ACCESS"),
        ("vertical_access_findings.txt", "VERTICAL_ACCESS"),
        ("force_browsing_findings.txt", "FORCE_BROWSING"),
        ("parameter_pollution_findings.txt", "PARAMETER_POLLUTION"),
        ("jwt_vulnerabilities_findings.txt", "JWT_BYPASS"),
        ("nuclei_output.txt", None),
        ("zap_output.txt", None)
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
                            if vuln_type and vuln_type in A01_VULNERABILITY_MAPPINGS:
                                mapping = A01_VULNERABILITY_MAPPINGS[vuln_type]
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
    table = Table(title="📊 A01 Broken Access Control - CVSS Standard Overview", header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("CVSS Score", style="green", justify="center")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", style="green", justify="center")
    table.add_column("Description", style="white")
    table.add_column("A01 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Auth Bypass, Privilege Escalation",
        "HIGH": "IDOR, Force Browsing, JWT Bypass, Access Control",
        "MEDIUM": "Parameter Pollution, Info Disclosure", 
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
A01 Broken Access Control Scan Report - CVSS Standard
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
=== A01 COVERAGE ===
✅ Authentication Bypass Testing (CVSS 9.8)
✅ Privilege Escalation Testing (CVSS 8.8)
✅ IDOR Testing (CVSS 7.5)
✅ Force Browsing Testing (CVSS 7.5)
✅ JWT Bypass Testing (CVSS 7.5)
✅ Parameter Pollution Testing (CVSS 5.3)
✅ Horizontal Access Control Testing (CVSS 7.5)
✅ Vertical Access Control Testing (CVSS 8.1)
✅ Advanced Access Control Testing
"""
    save_output("a01_detailed_report.txt", report)
    console.print("[green]💾 Summary saved[/green]")

# ================== MAIN ==================
def main(target):
    """Main function for A01 module - only callable from OWASP_MASTER_SCANNER"""
    if not target:
        console.print("[red]Target is required[/red]")
        return
    
    start = datetime.now()
    console.print(f"[cyan][*] Starting Advanced A01 Broken Access Control Scan for {target}[/cyan]")

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

        # Step 2: Advanced A01 Tests
        task2 = progress.add_task("Testing authentication bypass...", total=None)
        auth_bypass_findings = test_auth_bypass(target, endpoints)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Testing privilege escalation...", total=None)
        privilege_escalation_findings = test_privilege_escalation(target, endpoints)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Testing horizontal access control...", total=None)
        horizontal_access_findings = test_horizontal_access_control(target, endpoints)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Testing vertical access control...", total=None)
        vertical_access_findings = test_vertical_access_control(target, endpoints)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Testing force browsing...", total=None)
        force_browsing_findings = test_force_browsing(target, endpoints)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Testing parameter pollution...", total=None)
        parameter_pollution_findings = test_parameter_pollution(target, endpoints)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Testing JWT vulnerabilities...", total=None)
        jwt_vulnerabilities_findings = test_jwt_vulnerabilities(target)
        progress.update(task8, completed=True)

        # Step 3: Traditional Tools
        task9 = progress.add_task("Running Advanced Nuclei scans...", total=len(endpoints))
        for ep in endpoints:
            run_nuclei_advanced(ep)
            progress.update(task9, advance=1)

        task10 = progress.add_task("Running OWASP ZAP scan...", total=None)
        run_zap_advanced(target)
        progress.update(task10, completed=True)

        # Step 4: Analysis
        task11 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task11, completed=True)

    console.print(f"[green][*] Advanced A01 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a01_detailed_report.txt for comprehensive results[/bold yellow]")
