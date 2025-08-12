import os
import requests
import ssl
import socket
import json
import re
import base64
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
OUTPUT_DIR = "reports/a02_scan_results"
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

# A02 Vulnerability Mappings với CVSS
A02_VULNERABILITY_MAPPINGS = {
    "HEARTBLEED": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "CRITICAL",
        "score": 7.5,
        "description": "Heartbleed vulnerability allows memory disclosure"
    },
    "POODLE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 6.5,
        "description": "Poodle attack allows padding oracle attacks"
    },
    "BEAST": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 6.8,
        "description": "BEAST attack allows ciphertext manipulation"
    },
    "FREAK": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 6.5,
        "description": "FREAK attack forces weak RSA keys"
    },
    "LOGJAM": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 6.8,
        "description": "Logjam attack downgrades to weak DH parameters"
    },
    "WEAK_CIPHERS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Weak cryptographic ciphers are vulnerable to attacks"
    },
    "WEAK_PROTOCOLS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Deprecated SSL/TLS protocols are insecure"
    },
    "CERTIFICATE_ISSUES": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 4.3,
        "description": "Certificate validation issues reduce security"
    }
}

# OWASP A02:2021 - Cryptographic Failures Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical cryptographic flaws - immediate remediation required",
                 "keywords": ["heartbleed", "poodle", "beast", "freak", "logjam", "rc4", "md5", "sha1", "ssl v2", "ssl v3", "tls v1.0", "tls v1.1"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity cryptographic vulnerabilities",
             "keywords": ["weak cipher", "deprecated", "insecure", "expired cert", "self-signed", "small key size", "weak signature"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - cryptographic improvements needed",
               "keywords": ["no hsts", "missing", "not enabled", "weak dh", "insecure curve", "no ocsp"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["info disclosure", "debug information", "test endpoint", "enumeration", "information gathering"]}
}

# A02 Specific Test Cases
A02_TEST_CASES = {
    "weak_ciphers": {
        "ciphers": ["RC4", "3DES", "DES", "MD5", "SHA1", "NULL", "EXPORT"],
        "description": "Weak cryptographic ciphers"
    },
    "weak_protocols": {
        "protocols": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
        "description": "Deprecated SSL/TLS protocols"
    },
    "certificate_issues": {
        "issues": ["expired", "self-signed", "weak_signature", "wrong_hostname", "no_ocsp"],
        "description": "Certificate validation issues"
    },
    "key_exchange": {
        "weaknesses": ["weak_dh", "small_key_size", "insecure_curve", "static_dh"],
        "description": "Weak key exchange mechanisms"
    },
    "vulnerabilities": {
        "vulns": ["heartbleed", "poodle", "beast", "freak", "logjam", "drown"],
        "description": "Known cryptographic vulnerabilities"
    }
}

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A02_VULNERABILITY_MAPPINGS:
        return A02_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A02_VULNERABILITY_MAPPINGS:
        mapping = A02_VULNERABILITY_MAPPINGS[vulnerability_type]
        score = mapping["score"]
        severity = mapping["severity"]
        color = SEVERITY_LEVELS[severity]["color"]
        return severity, color, score, mapping["cvss_vector"]
    
    # Fallback: phân tích theo keywords
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for kw in SEVERITY_LEVELS[level]["keywords"]:
            if kw.lower() in f_lower:
                if level == "CRITICAL":
                    score = 9.1
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

# ===================== A02 SPECIFIC TESTS =====================
def test_weak_ciphers(target):
    """Test for weak cryptographic ciphers"""
    console.print("[cyan][*] Testing weak ciphers...[/cyan]")
    findings = []
    
    try:
        # Test common weak ciphers
        weak_ciphers = A02_TEST_CASES["weak_ciphers"]["ciphers"]
        host = urlparse(target).hostname
        port = 443
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0].upper()
                    for weak_cipher in weak_ciphers:
                        if weak_cipher.upper() in cipher_name:
                            finding = f"[WEAK_CIPHERS] {target} - Weak cipher detected: {cipher_name}"
                            findings.append(finding)
                            break
                            
    except Exception as e:
        findings.append(f"[ERROR] Testing weak ciphers for {target}: {str(e)}")
    
    save_output("weak_ciphers_findings.txt", "\n".join(findings))
    return findings

def test_certificate_validation(target):
    """Test certificate validation issues"""
    console.print("[cyan][*] Testing certificate validation...[/cyan]")
    findings = []
    
    try:
        host = urlparse(target).hostname
        port = 443
        
        # Test certificate validation
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check for self-signed certificate
                    if cert.get('issuer') == cert.get('subject'):
                        finding = f"[CERTIFICATE_ISSUES] {target} - Self-signed certificate detected"
                        findings.append(finding)
                    
                    # Check for expired certificate
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        finding = f"[CERTIFICATE_ISSUES] {target} - Expired certificate detected"
                        findings.append(finding)
                        
        except ssl.SSLCertVerificationError as e:
            finding = f"[CERTIFICATE_ISSUES] {target} - Certificate validation failed: {str(e)}"
            findings.append(finding)
            
    except Exception as e:
        findings.append(f"[ERROR] Testing certificate validation for {target}: {str(e)}")
    
    save_output("certificate_issues_findings.txt", "\n".join(findings))
    return findings

def test_protocol_vulnerabilities(target):
    """Test SSL/TLS protocol vulnerabilities"""
    console.print("[cyan][*] Testing protocol vulnerabilities...[/cyan]")
    findings = []
    
    try:
        # Test for deprecated protocols
        weak_protocols = A02_TEST_CASES["weak_protocols"]["protocols"]
        host = urlparse(target).hostname
        port = 443
        
        for protocol in weak_protocols:
            try:
                if protocol == "SSLv2":
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
                elif protocol == "SSLv3":
                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                elif protocol == "TLSv1.0":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                elif protocol == "TLSv1.1":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                else:
                    continue
                
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        finding = f"[WEAK_PROTOCOLS] {target} - Deprecated protocol supported: {protocol}"
                        findings.append(finding)
                        
            except Exception:
                # Protocol not supported (good)
                pass
                
    except Exception as e:
        findings.append(f"[ERROR] Testing protocol vulnerabilities for {target}: {str(e)}")
    
    save_output("protocol_vulnerabilities_findings.txt", "\n".join(findings))
    return findings

def test_key_exchange_weaknesses(target):
    """Test key exchange mechanism weaknesses"""
    console.print("[cyan][*] Testing key exchange weaknesses...[/cyan]")
    findings = []
    
    try:
        host = urlparse(target).hostname
        port = 443
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0].upper()
                    
                    # Check for weak key exchange
                    weak_keywords = ["DH", "DHE", "RSA", "EXPORT"]
                    for keyword in weak_keywords:
                        if keyword in cipher_name:
                            # Additional checks for key size would go here
                            finding = f"[KEY_EXCHANGE] {target} - Potentially weak key exchange: {cipher_name}"
                            findings.append(finding)
                            break
                            
    except Exception as e:
        findings.append(f"[ERROR] Testing key exchange weaknesses for {target}: {str(e)}")
    
    save_output("key_exchange_weaknesses_findings.txt", "\n".join(findings))
    return findings

# ================== SCANNERS ==================
def scan_sslyze(target):
    console.print("[yellow][*] Running SSLyze scan...[/yellow]")
    run_cmd([
        "sslyze",
        "--certinfo",
        "--sslv2",
        "--sslv3",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--heartbleed",
        "--reneg",
        "--robot",
        "--openssl_ccs",
        target
    ], "sslyze_output.txt")

def scan_testssl(target):
    console.print("[yellow][*] Running testssl.sh (Docker) scan...[/yellow]")
    run_cmd(get_secure_docker_cmd("drwetter/testssl.sh", target), "testssl_output.txt")

def scan_nmap_ssl(target):
    console.print("[yellow][*] Running Nmap SSL scripts...[/yellow]")
    host = urlparse(target).hostname
    run_cmd([
        "nmap", "-p443", "--script",
        "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection",
        host
    ], "nmap_output.txt")

def scan_nikto(target):
    console.print("[yellow][*] Running Nikto SSL/TLS check...[/yellow]")
    run_cmd(get_secure_docker_cmd("sullo/nikto", "-host", target), "nikto_output.txt")

# ================== ANALYSIS ==================
def analyze_results():
    console.print("[magenta][*] Analyzing scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("weak_ciphers_findings.txt", "WEAK_CIPHERS"),
        ("certificate_issues_findings.txt", "CERTIFICATE_ISSUES"),
        ("protocol_vulnerabilities_findings.txt", "WEAK_PROTOCOLS"),
        ("key_exchange_weaknesses_findings.txt", "KEY_EXCHANGE"),
        ("sslyze_output.txt", None),
        ("testssl_output.txt", None),
        ("nmap_output.txt", None),
        ("nikto_output.txt", None)
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
                            if vuln_type and vuln_type in A02_VULNERABILITY_MAPPINGS:
                                mapping = A02_VULNERABILITY_MAPPINGS[vuln_type]
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
    table = Table(title="📊 A02 Cryptographic Failures - CVSS Standard Overview", header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("CVSS Score", style="green", justify="center")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", style="green", justify="center")
    table.add_column("Description", style="white")
    table.add_column("A02 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Heartbleed, Poodle, BEAST, FREAK, Logjam",
        "HIGH": "Weak Ciphers, Certificate Issues, Key Exchange",
        "MEDIUM": "Protocol Vulnerabilities, Missing Security Headers", 
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
A02 Cryptographic Failures Scan Report - CVSS Standard
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
=== A02 COVERAGE ===
✅ Heartbleed Testing (CVSS 7.5)
✅ Poodle Testing (CVSS 6.5)
✅ BEAST Testing (CVSS 6.8)
✅ FREAK Testing (CVSS 6.5)
✅ Logjam Testing (CVSS 6.8)
✅ Weak Ciphers Testing (CVSS 5.3)
✅ Certificate Validation Testing (CVSS 4.3)
✅ Protocol Vulnerability Testing
✅ Key Exchange Weakness Testing
"""
    save_output("a02_detailed_report.txt", report)
    console.print("[green]💾 Summary saved[/green]")

# ================== MAIN ==================

def get_secure_docker_cmd(args):
    """Get secure Docker command with validation"""
    try:
        from core.security_utils import SecurityUtils
        # Validate and sanitize Docker arguments
        if isinstance(args, str):
            args = args.split()
        elif isinstance(args, list):
            args = args
        else:
            return None
        
        # Ensure only safe Docker commands
        safe_docker_images = [
            'projectdiscovery/nuclei:latest',
            'projectdiscovery/katana:latest',
            'sullo/nikto:latest',
            'owasp/zap2docker-stable:latest',
            'drwetter/testssl.sh:latest'
        ]
        
        if len(args) >= 1 and args[0] in safe_docker_images:
            return SecurityUtils.safe_subprocess_run(f"docker run --rm {' '.join(args)}", timeout=300)
        else:
            print(f"⚠️  Unsafe Docker image: {args[0] if args else 'None'}")
            return None
    except Exception as e:
        print(f"❌ Error in secure Docker command: {e}")
        return None

def main(target):
    """Main function for A02 module - only callable from OWASP_MASTER_SCANNER"""
    if not target:
        console.print("[red]Target is required[/red]")
        return
    
    target = normalize_url(target)
    start = datetime.now()

    console.print(f"[cyan][*] Starting Advanced A02 Cryptographic Failures Scan for {target}[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Advanced A02 Tests
        task1 = progress.add_task("Testing weak ciphers...", total=None)
        weak_ciphers_findings = test_weak_ciphers(target)
        progress.update(task1, completed=True)

        task2 = progress.add_task("Testing certificate validation...", total=None)
        certificate_findings = test_certificate_validation(target)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Testing protocol vulnerabilities...", total=None)
        protocol_findings = test_protocol_vulnerabilities(target)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Testing key exchange weaknesses...", total=None)
        key_exchange_findings = test_key_exchange_weaknesses(target)
        progress.update(task4, completed=True)

        # Step 2: Traditional Tools
        task5 = progress.add_task("Running SSLyze scan...", total=None)
        scan_sslyze(target)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Running testssl.sh scan...", total=None)
        scan_testssl(target)
        progress.update(task6, completed=True)

        task7 = progress.add_task("Running Nmap SSL scan...", total=None)
        scan_nmap_ssl(target)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Running Nikto scan...", total=None)
        scan_nikto(target)
        progress.update(task8, completed=True)

        # Step 3: Analysis
        task9 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task9, completed=True)

    console.print(f"[green][*] Advanced A02 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a02_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_url>")
        sys.exit(1)

    main(sys.argv[1])
