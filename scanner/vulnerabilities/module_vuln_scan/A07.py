import os
import requests
import re
import json
import base64
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from utils import normalize_url, is_noise_line
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a07_scan_results"
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

# A07 Vulnerability Mappings với CVSS
A07_VULNERABILITY_MAPPINGS = {
    "AUTH_BYPASS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Authentication bypass allows unauthorized access"
    },
    "WEAK_PASSWORDS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Weak passwords are easily guessable"
    },
    "CREDENTIAL_STUFFING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Credential stuffing attacks use leaked credentials"
    },
    "ACCOUNT_ENUMERATION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Account enumeration reveals valid usernames"
    },
    "SESSION_MANAGEMENT": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Weak session management allows session hijacking"
    },
    "MFA_BYPASS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
        "score": 8.1,
        "description": "MFA bypass allows unauthorized access"
    },
    "TOKEN_LEAKAGE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Token leakage exposes authentication tokens"
    },
    "DEFAULT_CREDENTIALS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Default credentials are easily guessable"
    }
}

# OWASP A07:2021 - Identification and Authentication Failures Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical authentication failures - immediate remediation required",
                 "keywords": ["auth bypass", "authentication bypass", "login bypass", "admin bypass", "root bypass", "privilege escalation", "session hijacking", "token hijacking", "credential theft", "password cracking", "brute force", "dictionary attack"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity authentication vulnerabilities",
             "keywords": ["weak password", "default password", "common password", "credential stuffing", "account enumeration", "session fixation", "session prediction", "mfa bypass", "2fa bypass", "token leakage", "jwt leakage", "session leakage"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - authentication improvements needed",
               "keywords": ["password policy", "session timeout", "session management", "login form", "authentication mechanism", "weak session", "predictable session", "no session expiry", "missing mfa", "weak 2fa"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["info disclosure", "debug information", "test endpoint", "enumeration", "information gathering", "login page", "auth page"]}
}

# A07 Specific Test Cases
A07_TEST_CASES = {
    "weak_passwords": {
        "passwords": ["password", "123456", "admin", "root", "test", "guest", "user", "demo", "temp", "backup", "default", "changeme", "secret", "qwerty", "abc123", "letmein", "welcome", "login", "pass", "pwd"],
        "description": "Weak password testing"
    },
    "auth_bypass": {
        "techniques": ["admin", "admin/admin", "admin:admin", "guest", "test", "user", "demo", "temp", "backup", "root", "administrator", "null", "empty", "none"],
        "description": "Authentication bypass techniques"
    },
    "default_credentials": {
        "credentials": [("admin", "admin"), ("root", "root"), ("admin", "password"), ("admin", "123456"), ("user", "user"), ("guest", "guest"), ("test", "test"), ("demo", "demo")],
        "description": "Default credential testing"
    },
    "session_issues": {
        "issues": ["predictable", "weak", "insecure", "no_expiry", "long_session", "session_fixation", "session_prediction"],
        "description": "Session management issues"
    },
    "mfa_bypass": {
        "techniques": ["skip_mfa", "disable_mfa", "bypass_2fa", "mfa_none", "2fa_none", "mfa_disabled", "2fa_disabled"],
        "description": "MFA bypass techniques"
    },
    "account_enumeration": {
        "techniques": ["user_exists", "user_not_found", "email_exists", "username_exists", "account_exists"],
        "description": "Account enumeration techniques"
    }
}

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A07_VULNERABILITY_MAPPINGS:
        return A07_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A07_VULNERABILITY_MAPPINGS:
        mapping = A07_VULNERABILITY_MAPPINGS[vulnerability_type]
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

# ===================== A07 SPECIFIC TESTS =====================
def test_weak_passwords(target, login_urls):
    """Test for weak password policies"""
    console.print("[cyan][*] Testing weak passwords...[/cyan]")
    findings = []
    
    weak_passwords = A07_TEST_CASES["weak_passwords"]["passwords"]
    
    if login_urls:
        for login_url in login_urls:
            for password in weak_passwords:
                try:
                    test_credentials = [
                        ("admin", password),
                        ("root", password),
                        ("user", password),
                        ("test", password),
                        ("guest", password)
                    ]
                    for username, pwd in test_credentials:
                        data = {"username": username, "password": pwd}
                        r = requests.post(login_url, data=data, timeout=5)
                        success_indicators = [
                            "welcome", "dashboard", "logged in", "successful",
                            "admin", "panel", "console", "authenticated"
                        ]
                        if any(indicator in r.text.lower() for indicator in success_indicators):
                            finding = f"[WEAK_PASSWORDS] {login_url} - Weak password accepted: {username}:{pwd}"
                            findings.append(finding)
                except Exception as e:
                    findings.append(f"[ERROR] Testing weak passwords for {login_url}: {str(e)}")
    
    save_output("weak_passwords_findings.txt", "\n".join(findings))
    return findings

def test_auth_bypass(target, login_urls):
    """Test authentication bypass techniques"""
    console.print("[cyan][*] Testing authentication bypass...[/cyan]")
    findings = []
    
    bypass_techniques = A07_TEST_CASES["auth_bypass"]["techniques"]
    
    if login_urls:
        for login_url in login_urls:
            for technique in bypass_techniques:
                try:
                    test_data = [
                        {"username": technique, "password": ""},
                        {"username": technique, "password": technique},
                        {"username": "", "password": technique},
                        {"username": technique, "password": "admin"},
                        {"username": "admin", "password": technique}
                    ]
                    for data in test_data:
                        r = requests.post(login_url, data=data, timeout=5)
                        bypass_indicators = [
                            "welcome", "dashboard", "logged in", "successful",
                            "admin", "panel", "console", "authenticated"
                        ]
                        if any(indicator in r.text.lower() for indicator in bypass_indicators):
                            finding = f"[AUTH_BYPASS] {login_url} - Authentication bypass detected with technique: {data}"
                            findings.append(finding)
                except Exception as e:
                    findings.append(f"[ERROR] Testing auth bypass for {login_url}: {str(e)}")
    
    save_output("auth_bypass_findings.txt", "\n".join(findings))
    return findings

def test_default_credentials(target, login_urls):
    """Test default credentials"""
    console.print("[cyan][*] Testing default credentials...[/cyan]")
    findings = []
    
    default_creds = A07_TEST_CASES["default_credentials"]["credentials"]
    
    if login_urls:
        for login_url in login_urls:
            for username, password in default_creds:
                try:
                    data = {"username": username, "password": password}
                    r = requests.post(login_url, data=data, timeout=5)
                    success_indicators = [
                        "welcome", "dashboard", "logged in", "successful",
                        "admin", "panel", "console", "authenticated"
                    ]
                    if any(indicator in r.text.lower() for indicator in success_indicators):
                        finding = f"[DEFAULT_CREDENTIALS] {login_url} - Default credentials accepted: {username}:{password}"
                        findings.append(finding)
                except Exception as e:
                    findings.append(f"[ERROR] Testing default credentials for {login_url}: {str(e)}")
    
    save_output("default_credentials_findings.txt", "\n".join(findings))
    return findings

def test_session_management(target):
    """Test session management vulnerabilities"""
    console.print("[cyan][*] Testing session management...[/cyan]")
    findings = []
    
    try:
        # Test session-related headers
        r = requests.get(target, timeout=5)
        headers = r.headers
        
        session_issues = []
        
        # Check for session-related headers
        session_headers = ["set-cookie", "session", "auth", "token"]
        for header in session_headers:
            if header in str(headers).lower():
                # Check for weak session indicators
                if "httponly" not in str(headers).lower():
                    session_issues.append("Missing HttpOnly flag")
                if "secure" not in str(headers).lower():
                    session_issues.append("Missing Secure flag")
                if "samesite" not in str(headers).lower():
                    session_issues.append("Missing SameSite flag")
                    
        if session_issues:
            finding = f"[SESSION_MANAGEMENT] {target} - Session management issues: {', '.join(session_issues)}"
            findings.append(finding)
            
    except Exception as e:
        findings.append(f"[ERROR] Testing session management for {target}: {str(e)}")
    
    save_output("session_management_findings.txt", "\n".join(findings))
    return findings

def test_account_enumeration(target, login_urls):
    """Test account enumeration vulnerabilities"""
    console.print("[cyan][*] Testing account enumeration...[/cyan]")
    findings = []
    
    if login_urls:
        common_usernames = ["admin", "root", "user", "test", "guest", "demo", "backup", "support", "info", "webmaster"]
        for login_url in login_urls:
            for username in common_usernames:
                try:
                    data = {"username": username, "password": "invalid_password_12345"}
                    r = requests.post(login_url, data=data, timeout=5)
                    enumeration_indicators = [
                        "user exists", "user not found", "account exists", "account not found",
                        "username exists", "username not found", "email exists", "email not found"
                    ]
                    if any(indicator in r.text.lower() for indicator in enumeration_indicators):
                        finding = f"[ACCOUNT_ENUMERATION] {login_url} - Account enumeration detected for username: {username}"
                        findings.append(finding)
                except Exception as e:
                    findings.append(f"[ERROR] Testing account enumeration for {login_url}: {str(e)}")
    
    save_output("account_enumeration_findings.txt", "\n".join(findings))
    return findings

def test_mfa_bypass(target, login_urls):
    """Test MFA bypass techniques"""
    console.print("[cyan][*] Testing MFA bypass...[/cyan]")
    findings = []
    
    mfa_bypass_techniques = A07_TEST_CASES["mfa_bypass"]["techniques"]
    
    if login_urls:
        for login_url in login_urls:
            for technique in mfa_bypass_techniques:
                try:
                    test_data = [
                        {"username": "admin", "password": "admin", "mfa": technique},
                        {"username": "admin", "password": "admin", "2fa": technique},
                        {"username": "admin", "password": "admin", "otp": technique},
                        {"username": "admin", "password": "admin", "code": technique}
                    ]
                    for data in test_data:
                        r = requests.post(login_url, data=data, timeout=5)
                        bypass_indicators = [
                            "welcome", "dashboard", "logged in", "successful",
                            "admin", "panel", "console", "authenticated"
                        ]
                        if any(indicator in r.text.lower() for indicator in bypass_indicators):
                            finding = f"[MFA_BYPASS] {login_url} - MFA bypass detected with technique: {technique}"
                            findings.append(finding)
                except Exception as e:
                    findings.append(f"[ERROR] Testing MFA bypass for {login_url}: {str(e)}")
    
    save_output("mfa_bypass_findings.txt", "\n".join(findings))
    return findings

def test_token_leakage(target):
    """Test for token leakage in responses"""
    console.print("[cyan][*] Testing token leakage...[/cyan]")
    findings = []
    
    try:
        r = requests.get(target, timeout=5)
        response_text = r.text.lower()
        
        # Check for token patterns
        token_patterns = [
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}',  # JWT
            r'[a-f0-9]{32}',  # MD5 hash
            r'[a-f0-9]{40}',  # SHA1 hash
            r'[a-f0-9]{64}',  # SHA256 hash
            r'[a-zA-Z0-9]{20,}',  # Generic token
        ]
        
        for pattern in token_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                finding = f"[TOKEN_LEAKAGE] {target} - Token leakage detected: {len(matches)} tokens found"
                findings.append(finding)
                break
                
    except Exception as e:
        findings.append(f"[ERROR] Testing token leakage for {target}: {str(e)}")
    
    save_output("token_leakage_findings.txt", "\n".join(findings))
    return findings

# ================== SCANNERS ==================
def detect_login_form(url):
    """Detect login forms on the target"""
    console.print("[yellow][*] Detecting login forms...[/yellow]")
    findings = []
    
    try:
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        
        login_urls = []
        for form in forms:
            inputs = form.find_all("input")
            has_password = any(inp.get("type") == "password" for inp in inputs)
            
            if has_password:
                action = form.get("action")
                if action:
                    login_url = urljoin(url, action)
                    login_urls.append(login_url)
                    finding = f"[LOGIN_FORM] {login_url} - Login form detected"
                    findings.append(finding)
                    
    except Exception as e:
        findings.append(f"[ERROR] Login form detection failed: {str(e)}")
    
    save_output("login_form_findings.txt", "\n".join(findings))
    return login_urls

def run_hydra_advanced(target, login_urls):
    """Run advanced Hydra brute force"""
    console.print("[yellow][*] Running Hydra brute force...[/yellow]")
    
    for login_url in login_urls:
        try:
            hydra_cmd = [
                "hydra",
                "-L", "common-usernames.txt",
                "-P", "common-passwords.txt",
                login_url,
                "http-post-form",
                f"/login.php:user=^USER^&pass=^PASS^:F=incorrect",
                "-t", "4",
                "-V"
            ]
            run_cmd(hydra_cmd, f"hydra_{urlparse(login_url).hostname}.txt")
            
        except Exception as e:
            console.print(f"[red]Hydra error for {login_url}: {e}[/red]")

def run_nmap_auth(target):
    """Run Nmap authentication scripts"""
    console.print("[yellow][*] Running Nmap authentication scripts...[/yellow]")
    host = urlparse(target).hostname
    
    cmd = [
    "nmap",
        "-p", "21,22,23,80,443,8080,8443",
        "--script", "ftp-brute,ssh-brute,http-brute,http-auth-finder",
        host
    ]
    run_cmd(cmd, f"nmap_auth_{host}.txt")

def run_nuclei_auth(target):
    """Run Nuclei with authentication templates"""
    console.print("[yellow][*] Running Nuclei authentication templates...[/yellow]")
    
    templates = [
        "vulnerabilities/authentication/",
        "vulnerabilities/jwt/",
        "vulnerabilities/token-leakage/",
        "vulnerabilities/auth-bypass/",
        "vulnerabilities/default-login/",
        "vulnerabilities/weak-password/",
        "exposures/",
        "misconfiguration/"
    ]
    
    for template in templates:
        try:
            cmd = ["nuclei", "-u", target, "-t", template, "-severity", "critical,high,medium", "-silent"]
            try:
                from core.security_utils import SecurityUtils
                cmd_str = " ".join(cmd)
                result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
                if result is None:
                    console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                    continue
            except ImportError:
                # Fallback to direct subprocess with timeout
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                save_output("nuclei_auth_output.txt", f"\n{'-'*60}\nNuclei {template} scan for: {target}\n{'-'*60}\n\n{result.stdout}\n")
                
        except Exception as e:
            console.print(f"[red]Nuclei error: {e}[/red]")

# ================== ANALYSIS ==================
def save_summary(findings, categorized, vulnerability_details, cvss_scores):
    with open(os.path.join(OUTPUT_DIR, "summary.txt"), "w", encoding="utf-8") as f:
        for sev in categorized:
            f.write(f"{sev}: {len(categorized[sev])} findings\n")
        f.write("\n=== DETAILS ===\n")
        for file, items in categorized.items():
            f.write(f"\n[{file}]\n")
            for item in items:
                sev = classify_severity_advanced(item['finding'])[0]
                f.write(f"[{sev}] {item['finding']}\n")

def analyze_results():
    console.print("[magenta][*] Analyzing scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("weak_passwords_findings.txt", "WEAK_PASSWORDS"),
        ("auth_bypass_findings.txt", "AUTH_BYPASS"),
        ("default_credentials_findings.txt", "DEFAULT_CREDENTIALS"),
        ("session_management_findings.txt", "SESSION_MANAGEMENT"),
        ("account_enumeration_findings.txt", "ACCOUNT_ENUMERATION"),
        ("mfa_bypass_findings.txt", "MFA_BYPASS"),
        ("token_leakage_findings.txt", "TOKEN_LEAKAGE"),
        ("login_form_findings.txt", None),
        ("nuclei_auth_output.txt", None),
        ("hydra_*.txt", None),
        ("nmap_auth_*.txt", None)
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
                            if vuln_type and vuln_type in A07_VULNERABILITY_MAPPINGS:
                                mapping = A07_VULNERABILITY_MAPPINGS[vuln_type]
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
    console.print("[bold magenta]📊 A07 IDENTIFICATION AND AUTHENTICATION FAILURES - CVSS STANDARD OVERVIEW[/bold magenta]")
    console.print("="*80)
    
    table = Table(title="📊 A07 Identification and Authentication Failures - CVSS Standard Overview", header_style="bold magenta", border_style="magenta")
    table.add_column("Severity", style="cyan", width=12)
    table.add_column("CVSS Score", style="green", justify="center", width=12)
    table.add_column("CVSS Vector", style="blue", width=35)
    table.add_column("Count", style="green", justify="center", width=8)
    table.add_column("Description", style="white", width=25)
    table.add_column("A07 Coverage", style="yellow", width=30)

    coverage_info = {
        "CRITICAL": "Auth Bypass, Privilege Escalation",
        "HIGH": "Weak Passwords, Credential Stuffing, Session Management, MFA Bypass",
        "MEDIUM": "Account Enumeration, Token Leakage", 
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
    console.print("[bold red]🎯 A07 AUTHENTICATION VULNERABILITY TYPES[/bold red]")
    console.print("="*80)
    
    vuln_table = Table(title="🎯 A07 Authentication Vulnerability Types", header_style="bold red", border_style="red")
    vuln_table.add_column("Type", style="cyan", width=25)
    vuln_table.add_column("CVSS Score", style="green", justify="center", width=12)
    vuln_table.add_column("CVSS Vector", style="blue", width=35)
    vuln_table.add_column("Description", style="white", width=40)
    
    for vuln_type, mapping in A07_VULNERABILITY_MAPPINGS.items():
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
        console.print("[green]✅ No authentication vulnerabilities detected in the scan.[/green]")
        console.print("[green]✅ Target appears to be secure against authentication attacks.[/green]")
        console.print("[yellow]💡 This could mean:[/yellow]")
        console.print("  • Strong authentication mechanisms in place")
        console.print("  • Proper session management")
        console.print("  • MFA is properly configured")
        console.print("  • No weak credentials detected")
    else:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if categorized[sev]:
                console.print(f"\n[{SEVERITY_LEVELS[sev]['color']}]{sev} FINDINGS[/]:")
                for item in categorized[sev]:
                    console.print(f"  - {item['source']}: {item['finding']}")

# ================== MAIN ==================
def main(target):
    """Main function for A07 module - only callable from OWASP_MASTER_SCANNER"""
    if not target:
        console.print("[red]Target is required[/red]")
        return
    
    target = normalize_url(target)
    start = datetime.now()

    console.print(f"[cyan][*] Starting Advanced A07 Identification and Authentication Failures Scan for {target}[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Login Form Detection
        task1 = progress.add_task("Detecting login forms...", total=None)
        login_urls = detect_login_form(target)
        progress.update(task1, completed=True)

        # Chuẩn hóa URL và Advanced A07 Tests
        target = normalize_url(target)
        task2 = progress.add_task("Testing weak passwords...", total=None)
        weak_passwords_findings = test_weak_passwords(target, login_urls)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Testing authentication bypass...", total=None)
        auth_bypass_findings = test_auth_bypass(target, login_urls)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Testing default credentials...", total=None)
        default_credentials_findings = test_default_credentials(target, login_urls)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Testing session management...", total=None)
        session_management_findings = test_session_management(target)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Testing account enumeration...", total=None)
        account_enumeration_findings = test_account_enumeration(target, login_urls)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Testing MFA bypass...", total=None)
        mfa_bypass_findings = test_mfa_bypass(target, login_urls)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Testing token leakage...", total=None)
        token_leakage_findings = test_token_leakage(target)
        progress.update(task8, completed=True)

        # Step 3: Traditional Tools
        task9 = progress.add_task("Running Hydra brute force...", total=None)
        run_hydra_advanced(target, login_urls)
        progress.update(task9, completed=True)

        task10 = progress.add_task("Running Nmap authentication scripts...", total=None)
        run_nmap_auth(target)
        progress.update(task10, completed=True)

        task11 = progress.add_task("Running Nuclei authentication templates...", total=None)
        run_nuclei_auth(target)
        progress.update(task11, completed=True)

        # Step 4: Analysis
        task12 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task12, completed=True)

    console.print(f"[green][*] Advanced A07 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a07_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_url>")
        sys.exit(1)

    main(sys.argv[1])
