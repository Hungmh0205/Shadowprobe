#!/usr/bin/env python3
"""
A04 - Broken Access Control
OWASP Top 10 2021 - A04:2021
"""

import os
import re
import requests
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
OUTPUT_DIR = "reports/a04_scan_results"
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

# A04 Vulnerability Mappings với CVSS
A04_VULNERABILITY_MAPPINGS = {
    "IDOR": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Insecure Direct Object Reference allows unauthorized access"
    },
    "PRIVILEGE_ESCALATION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Privilege escalation allows unauthorized access"
    },
    "HORIZONTAL_ACCESS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Horizontal access control bypass"
    },
    "VERTICAL_ACCESS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Vertical access control bypass"
    },
    "MASS_ASSIGNMENT": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Mass assignment allows unauthorized field modification"
    },
    "FORCE_BROWSING": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Force browsing allows unauthorized resource access"
    },
    "NO_AUTH": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "No authentication required for sensitive resources"
    }
}

# ===================== SEVERITY LEVELS =====================
SEVERITY_LEVELS = {
    "CRITICAL": {
        "color": "red",
        "keywords": ["critical", "severe", "exploit", "rce", "remote code execution", "privilege escalation", "business logic"]
    },
    "HIGH": {
        "color": "red",
        "keywords": ["high", "idor", "mass assignment", "horizontal access", "vertical access", "unauthorized access"]
    },
    "MEDIUM": {
        "color": "yellow",
        "keywords": ["medium", "force browsing", "no auth", "parameter pollution", "access control"]
    },
    "LOW": {
        "color": "blue",
        "keywords": ["low", "info", "information disclosure", "basic check"]
    }
}

# ===================== TEST CASES =====================
A04_TEST_CASES = {
    "idor": {
        "parameters": ["id", "user", "account", "order", "invoice", "document", "file"],
        "values": ["1", "2", "10", "100", "999", "admin", "test"],
        "description": "IDOR vulnerable parameters"
    },
    "privilege_escalation": {
        "parameters": ["role", "level", "access", "privilege", "permission", "group"],
        "values": ["admin", "superuser", "root", "manager", "supervisor"],
        "description": "Privilege escalation parameters"
    },
    "mass_assignment": {
        "parameters": ["role", "admin", "is_admin", "is_superuser", "permissions"],
        "values": ["true", "1", "admin", "superuser"],
        "description": "Mass assignment vulnerable parameters"
    },
    "force_browsing": {
        "paths": ["/admin", "/dashboard", "/panel", "/console", "/management", "/config", "/settings"],
        "description": "Force browsing vulnerable paths"
    }
}

# ===================== TOOLS =====================
KATANA_IMAGE = "ghcr.io/projectdiscovery/katana:latest"
NUCLEI_TEMPLATES = "nuclei-templates"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A04_VULNERABILITY_MAPPINGS:
        return A04_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A04_VULNERABILITY_MAPPINGS:
        mapping = A04_VULNERABILITY_MAPPINGS[vulnerability_type]
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
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:L/I:L/A:N"
                else:
                    score = 3.1
                    return level, SEVERITY_LEVELS[level]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:L/I:N/A:N"
    
    score = 3.1
    return "LOW", "blue", score, "CVSS:3.1/AV:N/AC:L/PR:L/I:N/A:N"

def save_output(filename, data, append=False):
    mode = "a" if append else "w"
    with open(os.path.join(OUTPUT_DIR, filename), mode, encoding="utf-8") as f:
        f.write(data)

def sanitize_filename(filename):
    """Sanitize filename for safe file operations"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def run_cmd(cmd_list, output_file):
    """Safely run command using security utilities"""
    try:
        # Import security utils
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

# ===================== SCANS =====================
def run_katana(target):
    console.print("[cyan][*] Running Katana to discover endpoints...[/cyan]")
    cmd = get_secure_docker_cmd(KATANA_IMAGE, "-u", target, "-jc")
    
    # Use SecurityUtils for secure execution
    try:
        from core.security_utils import SecurityUtils
        cmd_str = " ".join(cmd)
        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
        if result is None:
            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
            return []
    except ImportError:
        # Fallback to direct subprocess with timeout
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    endpoints = set()
    for line in result.stdout.splitlines():
        if line.startswith("http") and not line.endswith((".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg")):
            endpoints.add(line.strip())
    return list(endpoints)

def check_no_auth_access(url):
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        if r.status_code == 200:
            for kw in SENSITIVE_KEYWORDS:
                if kw in url.lower():
                    return f"[NO_AUTH] {url} (Status {r.status_code})"
    except requests.RequestException:
        pass
    return None

def run_nuclei_advanced(target):
    """Chạy Nuclei với nhiều template A04 hơn"""
    console.print(f"[yellow][*] Running Advanced Nuclei for {target}[/yellow]")
    
    # Thêm nhiều template A04
    templates = [
        "vulnerabilities/idor",
        "vulnerabilities/broken-access-control", 
        "vulnerabilities/privilege-escalation",
        "vulnerabilities/business-logic",
        "vulnerabilities/mass-assignment",
        "vulnerabilities/force-browsing"
    ]
    
    for template in templates:
        template_path = os.path.join(NUCLEI_TEMPLATES, template)
        if os.path.exists(template_path):
            cmd = ["nuclei", "-u", target, "-t", template_path, "-silent"]
            
            # Use SecurityUtils for secure execution
            try:
                from core.security_utils import SecurityUtils
                cmd_str = " ".join(cmd)
                result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
                if result is None:
                    console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                    continue
            except ImportError:
                # Fallback to direct subprocess with timeout
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.stdout:
                save_output(f"nuclei_{template.replace('/', '_')}_{sanitize_filename(target)}.txt", result.stdout)
                save_output("nuclei_advanced_output.txt", f"\n{'='*80}\n[Nuclei {template}] {target}\n{'='*80}\n{result.stdout}\n", append=True)

def run_zap(target):
    console.print(f"[yellow][*] Running OWASP ZAP for {target}[/yellow]")
    zap_out_dir = os.path.abspath(OUTPUT_DIR)
    
    # Sử dụng zap-baseline.py với error handling
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{zap_out_dir}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py", "-t", target, "-J", "zap_report.json"
    ]
    
    try:
        # Use SecurityUtils for secure execution
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(cmd)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
            if result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                return
        except ImportError:
            # Fallback to direct subprocess with timeout
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result and result.stdout:
            save_output("zap_output.txt", result.stdout + "\n" + result.stderr)
    except subprocess.TimeoutExpired:
        console.print("[red]ZAP scan timed out[/red]")
        save_output("zap_output.txt", "ZAP scan timed out after 5 minutes")
    except Exception as e:
        console.print(f"[red]ZAP scan failed: {e}[/red]")
        save_output("zap_output.txt", f"ZAP scan failed: {e}")

# ===================== ANALYSIS =====================
def analyze_results():
    categorized = {lvl: [] for lvl in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("noauth_findings.txt", "NO_AUTH"),
        ("business_logic_findings.txt", None),  # Will be classified by content
        ("mass_assignment_findings.txt", "MASS_ASSIGNMENT"),
        ("idor_findings.txt", "IDOR"),
        ("force_browsing_findings.txt", "FORCE_BROWSING"),
        ("parameter_pollution_findings.txt", "PARAM_POLLUTION"),
        ("nuclei_advanced_output.txt", None)
    ]

    for file, vuln_type in finding_files:
        file_path = os.path.join(OUTPUT_DIR, file)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not is_noise_line(line):
                        # Classify based on content if no specific type
                        if vuln_type is None:
                            if "PRIVILEGE_ESCALATION" in line:
                                vuln_type = "PRIVILEGE_ESCALATION"
                            elif "HORIZONTAL_ACCESS" in line:
                                vuln_type = "HORIZONTAL_ACCESS"
                            else:
                                vuln_type = None
                        
                        severity, color, score, cvss_vector = classify_severity_advanced(line, vuln_type)
                        categorized[severity].append(line.strip())
                        findings.append(line.strip())
                        cvss_scores.append(score)
                        
                        # Store vulnerability details
                        if vuln_type and vuln_type in A04_VULNERABILITY_MAPPINGS:
                            mapping = A04_VULNERABILITY_MAPPINGS[vuln_type]
                            vulnerability_details.append({
                                "type": vuln_type,
                                "finding": line.strip(),
                                "cvss_score": score,
                                "cvss_vector": cvss_vector,
                                "severity": severity,
                                "description": mapping["description"]
                            })

    # Display comprehensive table with CVSS
    table = Table(title="A04 Insecure Design - CVSS Standard Scan Results", header_style="bold magenta")
    table.add_column("Severity", style="cyan", no_wrap=True)
    table.add_column("CVSS Score", style="green")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", justify="center", style="green")
    table.add_column("Description", style="white")
    table.add_column("A04 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Business Logic Flaws, Privilege Escalation",
        "HIGH": "IDOR, Mass Assignment, Horizontal Access",
        "MEDIUM": "Force Browsing, Parameter Pollution", 
        "LOW": "No-Auth Access, Basic Checks"
    }

    for lvl in SEVERITY_LEVELS:
        count = len(categorized[lvl])
        avg_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        table.add_row(
            f"[{SEVERITY_LEVELS[lvl]['color']}]{lvl}[/{SEVERITY_LEVELS[lvl]['color']}]",
            f"{avg_score:.1f}" if avg_score > 0 else "N/A",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" if lvl == "CRITICAL" else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            str(count),
            coverage_info.get(lvl, "Access Control Issues"),
            f"{count}/{len(findings)}" if findings else "0/0"
        )

    console.print(table)
    
    # Save detailed results
    save_output("a04_analysis_results.txt", f"""
A04 - Broken Access Control Analysis Results
Generated: {datetime.now()}
Total Findings: {len(findings)}
CVSS Scores: {cvss_scores}

Detailed Findings:
{chr(10).join(findings)}

Vulnerability Details:
{chr(10).join([f"{v['type']}: {v['finding']} (CVSS: {v['cvss_score']})" for v in vulnerability_details])}
""")

    return categorized, findings, cvss_scores, vulnerability_details


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

def main():
    """Main function for A04 scanning"""
    console.print("[bold magenta]A04 - Broken Access Control Scanner[/bold magenta]")
    console.print("OWASP Top 10 2021 - A04:2021\n")
    
    # Get target from user
    target = input("Enter target URL: ").strip()
    if not target:
        console.print("[red]No target specified[/red]")
        return
    
    target = normalize_url(target)
    console.print(f"[green]Target: {target}[/green]\n")
    
    # Run scans
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Katana scan
        task = progress.add_task("Running Katana...", total=None)
        endpoints = run_katana(target)
        progress.update(task, completed=True)
        
        # Nuclei scan
        task = progress.add_task("Running Nuclei...", total=None)
        run_nuclei_advanced(target)
        progress.update(task, completed=True)
        
        # ZAP scan
        task = progress.add_task("Running ZAP...", total=None)
        run_zap(target)
        progress.update(task, completed=True)
    
    # Analyze results
    console.print("\n[bold cyan]Analyzing results...[/bold cyan]")
    categorized, findings, cvss_scores, vulnerability_details = analyze_results()
    
    # Summary
    console.print(f"\n[bold green]Scan completed![/bold green]")
    console.print(f"Total findings: {len(findings)}")
    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        console.print(f"Average CVSS Score: {avg_cvss:.1f}")
    
    console.print(f"Results saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
