#!/usr/bin/env python3
"""
A05 - Security Misconfiguration
OWASP Top 10 2021 - A05:2021
"""

import os
import re
import requests
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
OUTPUT_DIR = "reports/a05_scan_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

console = Console()

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

# A05 Vulnerability Mappings với CVSS
A05_VULNERABILITY_MAPPINGS = {
    "SECURITY_MISCONFIGURATION": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Security misconfiguration allows unauthorized access"
    },
    "DEFAULT_CREDENTIALS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Default credentials allow unauthorized access"
    },
    "EXPOSED_CONFIGS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Exposed configuration files reveal sensitive information"
    },
    "WEAK_SECURITY_HEADERS": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Weak security headers allow various attacks"
    }
}

# ===================== SEVERITY LEVELS =====================
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "keywords": ["critical", "severe", "exploit", "rce", "remote code execution"]},
    "HIGH": {"color": "red", "keywords": ["high", "default credentials", "admin", "root", "unauthorized access"]},
    "MEDIUM": {"color": "yellow", "keywords": ["medium", "exposed", "config", "headers", "information disclosure"]},
    "LOW": {"color": "blue", "keywords": ["low", "info", "basic check", "version disclosure"]}
}

# ===================== TOOLS ==================
KATANA_IMAGE = "ghcr.io/projectdiscovery/katana:latest"
NUCLEI_TEMPLATES = "nuclei-templates"

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A05_VULNERABILITY_MAPPINGS:
        return A05_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    if vulnerability_type and vulnerability_type in A05_VULNERABILITY_MAPPINGS:
        mapping = A05_VULNERABILITY_MAPPINGS[vulnerability_type]
        score = mapping["score"]
        severity = mapping["severity"]
        color = SEVERITY_LEVELS[severity]["color"]
        return severity, color, score, mapping["cvss_vector"]
    
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
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(cmd_list)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            
            if result is None:
                console.print(f"[red]ERROR: Command execution blocked for security: {cmd_str}[/red]")
                save_output(output_file, f"Error: Command execution blocked for security reasons")
                return
            
            save_output(output_file, result.stdout + "\n" + result.stderr)
            console.print(result.stdout, style="dim")
            
        except ImportError:
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
    cmd = get_secure_docker_cmd(KATANA_IMAGE, "-u", target)
    
    try:
        from core.security_utils import SecurityUtils
        cmd_str = " ".join(cmd)
        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
        if result is None:
            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
            return []
    except ImportError:
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    endpoints = set()
    for line in result.stdout.splitlines():
        if line.startswith("http") and not line.endswith((".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg")):
            endpoints.add(line.strip())
    return list(endpoints)

def run_nmap(host):
    console.print(f"[yellow][*] Running Nmap for {host}[/yellow]")
    cmd = ["nmap", "-p80,443,8080,8443", "-sV", "--script", "http-enum,http-config-backup,http-headers,http-methods,http-passwd,vulners", host]
    
    try:
        from core.security_utils import SecurityUtils
        cmd_str = " ".join(cmd)
        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
        if result is None:
            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
            return
    except ImportError:
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    if result and result.stdout:
        save_output(f"nmap_{host}.txt", result.stdout + "\n" + result.stderr)
        save_output("nmap_output.txt", f"\n{'='*80}\n[Nmap] {host}\n{'='*80}\n{result.stdout}\n", append=True)

def run_nuclei_advanced(url):
    console.print(f"[yellow][*] Running Advanced Nuclei for {url}[/yellow]")
    
    templates = ["misconfiguration", "exposures/configs", "security-misconfiguration", "security-headers", "exposures/default-logins"]
    
    for template in templates:
        cmd = ["nuclei", "-u", url, "-t", template, "-silent"]
        
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(cmd)
            result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=300)
            if result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                continue
        except ImportError:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.stdout:
            save_output(f"nuclei_{template.replace('/', '_')}_{sanitize_filename(url)}.txt", result.stdout)
            save_output("nuclei_advanced_output.txt", f"\n{'='*80}\n[Nuclei {template}] {url}\n{'='*80}\n{result.stdout}\n", append=True)


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
    console.print("[bold magenta]A05 - Security Misconfiguration Scanner[/bold magenta]")
    console.print("OWASP Top 10 2021 - A05:2021\n")
    
    target = input("Enter target URL: ").strip()
    if not target:
        console.print("[red]No target specified[/red]")
        return
    
    target = normalize_url(target)
    console.print(f"[green]Target: {target}[/green]\n")
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Running Katana...", total=None)
        endpoints = run_katana(target)
        progress.update(task, completed=True)
        
        task = progress.add_task("Running Nmap...", total=None)
        run_nmap(urlparse(target).hostname)
        progress.update(task, completed=True)
        
        task = progress.add_task("Running Nuclei...", total=None)
        run_nuclei_advanced(target)
        progress.update(task, completed=True)
    
    console.print("\n[bold green]Scan completed![/bold green]")
    console.print(f"Results saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
