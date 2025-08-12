import os
import sys
import subprocess
import requests
import json
import re
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from bs4 import BeautifulSoup
from utils import normalize_url, is_noise_line

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a06_scan_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)
NUCLEI_TEMPLATES = r"C:\Users\Dell\nuclei-templates"
KATANA_IMAGE = "projectdiscovery/katana:latest"
WHATWEB_IMAGE = "wappalyzer/whatweb"

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

# A06 Vulnerability Mappings với CVSS
A06_VULNERABILITY_MAPPINGS = {
    "CRITICAL_CVE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Critical CVE with high impact"
    },
    "HIGH_CVE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "High severity CVE detected"
    },
    "OUTDATED_COMPONENT": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "Outdated component with known vulnerabilities"
    },
    "VERSION_DISCLOSURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "LOW",
        "score": 3.1,
        "description": "Version information disclosed"
    }
}

SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical CVE or severe outdated component"},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity vulnerable component"},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Moderate outdated component"},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational"},
}

VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# A06 Specific Test Cases
A06_TEST_CASES = {
    "package_files": [
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/requirements.txt", "/Pipfile", "/poetry.lock",
        "/pom.xml", "/build.gradle", "/composer.json",
        "/Gemfile", "/Gemfile.lock", "/Cargo.toml",
        "/go.mod", "/go.sum", "/Dockerfile"
    ],
    "framework_patterns": {
        "django": r"django[^\d]*(\d+\.\d+\.\d+)",
        "rails": r"rails[^\d]*(\d+\.\d+\.\d+)",
        "laravel": r"laravel[^\d]*(\d+\.\d+\.\d+)",
        "spring": r"spring[^\d]*(\d+\.\d+\.\d+)",
        "express": r"express[^\d]*(\d+\.\d+\.\d+)",
        "angular": r"angular[^\d]*(\d+\.\d+\.\d+)",
        "react": r"react[^\d]*(\d+\.\d+\.\d+)",
        "vue": r"vue[^\d]*(\d+\.\d+\.\d+)"
    },
    "vulnerable_versions": {
        "django": ["1.11", "2.0", "2.1", "2.2"],
        "rails": ["5.0", "5.1", "5.2"],
        "laravel": ["5.8", "6.0", "7.0"],
        "spring": ["4.3", "5.0", "5.1"],
        "express": ["4.16", "4.17"],
        "angular": ["1.x", "2.x", "4.x", "5.x"],
        "react": ["16.x", "17.x"],
        "vue": ["2.x"]
    }
}

console = Console()
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ================== UTIL ==================
def sanitize_filename(url):
    return re.sub(r'[\\/*?:"<>|]', "_", url)

def save_output(filename, data, append=False):
    mode = "a" if append else "w"
    with open(os.path.join(OUTPUT_DIR, filename), mode, encoding="utf-8") as f:
        f.write(data)

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A06_VULNERABILITY_MAPPINGS:
        return A06_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(text, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    text_low = text.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A06_VULNERABILITY_MAPPINGS:
        mapping = A06_VULNERABILITY_MAPPINGS[vulnerability_type]
        score = mapping["score"]
        severity = mapping["severity"]
        color = SEVERITY_LEVELS[severity]["color"]
        return severity, color, score, mapping["cvss_vector"]
    
    # Fallback: phân tích theo keywords và CVSS scores
    if "cvss" in text_low:
        try:
            score = float(re.findall(r"(\d+\.\d+)", text)[0])
            if score >= 9.0:
                return "CRITICAL", SEVERITY_LEVELS["CRITICAL"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            elif score >= 7.0:
                return "HIGH", SEVERITY_LEVELS["HIGH"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
            elif score >= 4.0:
                return "MEDIUM", SEVERITY_LEVELS["MEDIUM"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            else:
                return "LOW", SEVERITY_LEVELS["LOW"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        except:
            pass
    
    if any(k in text_low for k in ["rce", "remote code execution", "critical", "cve-2021", "cve-2022", "cve-2023"]):
        score = 9.8
        return "CRITICAL", SEVERITY_LEVELS["CRITICAL"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    elif any(k in text_low for k in ["high", "sql injection", "xss", "outdated", "vulnerable"]):
        score = 7.5
        return "HIGH", SEVERITY_LEVELS["HIGH"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
    elif any(k in text_low for k in ["medium", "deprecated", "insecure", "version"]):
        score = 5.3
        return "MEDIUM", SEVERITY_LEVELS["MEDIUM"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    
    score = 3.1
    return "LOW", SEVERITY_LEVELS["LOW"]["color"], score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"

# ===================== A06 SPECIFIC TESTS =====================
def test_package_files(target):
    """Test Package Manager Files - core của A06"""
    console.print("[cyan][*] Testing Package Manager Files...[/cyan]")
    findings = []
    
    for package_file in A06_TEST_CASES["package_files"]:
        try:
            r = requests.get(f"{target}{package_file}", timeout=5)
            if r.status_code == 200:
                finding = f"[PACKAGE_FILE] {package_file} - Accessible"
                findings.append(finding)
                
                # Parse package file content
                if package_file.endswith(".json"):
                    try:
                        data = json.loads(r.text)
                        if "dependencies" in data:
                            for dep, version in data["dependencies"].items():
                                if version.startswith("^") or version.startswith("~"):
                                    finding = f"[VULNERABLE_DEP] {dep}@{version} - Version range allows vulnerable versions"
                                    findings.append(finding)
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            findings.append(f"[ERROR] Testing {package_file}: {str(e)}")
    
    save_output("package_files_findings.txt", "\n".join(findings))
    return findings

def test_framework_versions(target):
    """Test Framework Version Detection"""
    console.print("[cyan][*] Testing Framework Versions...[/cyan]")
    findings = []
    
    try:
        r = requests.get(target, timeout=5)
        content = r.text.lower()
        headers = str(r.headers).lower()
        
        for framework, pattern in A06_TEST_CASES["framework_patterns"].items():
            # Check in HTML content
            matches = re.findall(pattern, content)
            if matches:
                version = matches[0]
                finding = f"[FRAMEWORK_VERSION] {framework} {version} detected"
                findings.append(finding)
                
                # Check if version is vulnerable
                if framework in A06_TEST_CASES["vulnerable_versions"]:
                    vulnerable_versions = A06_TEST_CASES["vulnerable_versions"][framework]
                    for vuln_ver in vulnerable_versions:
                        if version.startswith(vuln_ver):
                            finding = f"[VULNERABLE_FRAMEWORK] {framework} {version} - Known vulnerable version"
                            findings.append(finding)
                            break
            
            # Check in headers
            header_matches = re.findall(pattern, headers)
            if header_matches:
                version = header_matches[0]
                finding = f"[FRAMEWORK_VERSION] {framework} {version} in headers"
                findings.append(finding)
                
    except Exception as e:
        findings.append(f"[ERROR] Testing framework versions: {str(e)}")
    
    save_output("framework_versions_findings.txt", "\n".join(findings))
    return findings

def test_api_versions(target):
    """Test API Version Detection"""
    console.print("[cyan][*] Testing API Versions...[/cyan]")
    findings = []
    
    # Common API version patterns
    api_patterns = [
        r"/api/v(\d+)",
        r"/v(\d+)/api",
        r"version=(\d+)",
        r"api-version=(\d+)"
    ]
    
    try:
        r = requests.get(target, timeout=5)
        content = r.text
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            if matches:
                version = matches[0]
                finding = f"[API_VERSION] API version {version} detected"
                findings.append(finding)
                
                # Check for deprecated API versions
                if int(version) < 2:
                    finding = f"[DEPRECATED_API] API version {version} - Deprecated version"
                    findings.append(finding)
                    
    except Exception as e:
        findings.append(f"[ERROR] Testing API versions: {str(e)}")
    
    save_output("api_versions_findings.txt", "\n".join(findings))
    return findings

def test_docker_components(target):
    """Test Docker and Container Components"""
    console.print("[cyan][*] Testing Docker Components...[/cyan]")
    findings = []
    
    docker_paths = [
        "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
        "/.dockerignore", "/dockerfile", "/docker-compose.override.yml"
    ]
    
    for path in docker_paths:
        try:
            r = requests.get(f"{target}{path}", timeout=5)
            if r.status_code == 200:
                finding = f"[DOCKER_FILE] {path} - Accessible"
                findings.append(finding)
                
                # Check for vulnerable base images
                content = r.text.lower()
                vulnerable_images = ["alpine:3.8", "ubuntu:16.04", "debian:stretch", "centos:7"]
                for img in vulnerable_images:
                    if img in content:
                        finding = f"[VULNERABLE_IMAGE] {img} - Known vulnerable base image"
                        findings.append(finding)
                        
        except Exception as e:
            findings.append(f"[ERROR] Testing {path}: {str(e)}")
    
    save_output("docker_components_findings.txt", "\n".join(findings))
    return findings

def test_library_versions(target):
    """Test JavaScript and CSS Library Versions"""
    console.print("[cyan][*] Testing Library Versions...[/cyan]")
    findings = []
    
    try:
        r = requests.get(target, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        
        # Check script tags
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if any(lib in src.lower() for lib in ["jquery", "bootstrap", "angular", "react", "vue"]):
                # Extract version from URL
                version_match = re.search(r"(\d+\.\d+\.\d+)", src)
                if version_match:
                    version = version_match.group(1)
                    lib_name = next(lib for lib in ["jquery", "bootstrap", "angular", "react", "vue"] if lib in src.lower())
                    finding = f"[LIBRARY_VERSION] {lib_name} {version} - {src}"
                    findings.append(finding)
                    
                    # Check for vulnerable versions
                    if lib_name == "jquery" and version.startswith("1."):
                        finding = f"[VULNERABLE_LIBRARY] jQuery {version} - Known vulnerable version"
                        findings.append(finding)
                    elif lib_name == "bootstrap" and version.startswith("3."):
                        finding = f"[VULNERABLE_LIBRARY] Bootstrap {version} - Known vulnerable version"
                        findings.append(finding)
        
        # Check CSS files
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if any(lib in href.lower() for lib in ["bootstrap", "foundation", "semantic"]):
                version_match = re.search(r"(\d+\.\d+\.\d+)", href)
                if version_match:
                    version = version_match.group(1)
                    lib_name = next(lib for lib in ["bootstrap", "foundation", "semantic"] if lib in href.lower())
                    finding = f"[LIBRARY_VERSION] {lib_name} {version} - {href}"
                    findings.append(finding)
                    
    except Exception as e:
        findings.append(f"[ERROR] Testing library versions: {str(e)}")
    
    save_output("library_versions_findings.txt", "\n".join(findings))
    return findings

# ================== SCAN FUNCTIONS ==================
def run_katana(target):
    console.print("[cyan][*] Running Smart Katana Discovery...[/cyan]")
    # Chiến lược 2 giai đoạn: Quick discovery + Deep scan
    console.print("[cyan][*] Phase 1: Quick endpoint discovery...[/cyan]")
    quick_cmd = get_secure_docker_cmd(KATANA_IMAGE, "-u", target, "-d", "1", "-jc", "-silent", "-timeout", "60")
    try:
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(quick_cmd)
            quick_result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            if quick_result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                return []
        except ImportError:
            # Fallback to direct subprocess with timeout
            quick_result = subprocess.run(quick_cmd, capture_output=True, text=True, timeout=300)
        
        quick_endpoints = set()
        for line in quick_result.stdout.splitlines():
            if line.startswith("http"):
                if not line.endswith((".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg")):
                    quick_endpoints.add(line.strip())
        
        console.print(f"[green][+] Quick discovery found {len(quick_endpoints)} endpoints[/green]")
        
        # Phase 2: Deep scan nếu có ít endpoints
        if len(quick_endpoints) < 20:
            console.print("[cyan][*] Phase 2: Deep discovery for better coverage...[/cyan]")
            deep_cmd = get_secure_docker_cmd(KATANA_IMAGE, "-u", target, "-d", "2", "-jc", "-silent", "-timeout", "120")
            try:
                try:
                    from core.security_utils import SecurityUtils
                    cmd_str = " ".join(deep_cmd)
                    deep_result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
                    if deep_result is None:
                        console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                        return list(quick_endpoints)
                except ImportError:
                    # Fallback to direct subprocess with timeout
                    deep_result = subprocess.run(deep_cmd, capture_output=True, text=True, timeout=300)
                
                for line in deep_result.stdout.splitlines():
                    if line.startswith("http"):
                        if not line.endswith((".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg")):
                            quick_endpoints.add(line.strip())
            except subprocess.TimeoutExpired:
                console.print("[yellow]Deep discovery timeout - using quick results[/yellow]")
        
        return list(quick_endpoints)
        
    except subprocess.TimeoutExpired:
        console.print("[red]Katana timeout - using basic endpoint discovery[/red]")
        # Fallback: basic endpoint discovery
        basic_endpoints = [
            f"{target}/",
            f"{target}/admin",
            f"{target}/api",
            f"{target}/login",
            f"{target}/test",
            f"{target}/dashboard",
            f"{target}/user",
            f"{target}/config",
            f"{target}/debug",
            f"{target}/status"
        ]
        return basic_endpoints

def run_nmap(host):
    console.print(f"[yellow][*] Running Smart Nmap for {host}[/yellow]")
    # Chiến lược 2 giai đoạn: Quick scan trước, chi tiết sau
    console.print("[cyan][*] Phase 1: Quick port discovery...[/cyan]")
    quick_cmd = ["nmap", "-p-", "--min-rate", "1000", "--max-retries", "1", "--host-timeout", "120s", host]
    try:
        try:
            from core.security_utils import SecurityUtils
            cmd_str = " ".join(quick_cmd)
            quick_result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
            if quick_result is None:
                console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                return []
        except ImportError:
            # Fallback to direct subprocess with timeout
            quick_result = subprocess.run(quick_cmd, capture_output=True, text=True, timeout=300)
        open_ports = []
        for line in quick_result.stdout.splitlines():
            if "open" in line:
                port = line.split("/")[0]
                open_ports.append(port)
        
        if open_ports:
            console.print(f"[green][+] Found {len(open_ports)} open ports: {', '.join(open_ports[:10])}[/green]")
            # Phase 2: Detailed scan on open ports only
            console.print("[cyan][*] Phase 2: Detailed vulnerability scan...[/cyan]")
            ports_str = ",".join(open_ports[:20])  # Giới hạn 20 ports để tránh quá chậm
            detail_cmd = ["nmap", "-p", ports_str, "-sV", "--script", "vulners", "--script-args", "vulnerscheckall", "--max-retries", "2", "--host-timeout", "300s", host]
            try:
                from core.security_utils import SecurityUtils
                cmd_str = " ".join(detail_cmd)
                detail_result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
                if detail_result is None:
                    console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                    return
            except ImportError:
                # Fallback to direct subprocess with timeout
                detail_result = subprocess.run(detail_cmd, capture_output=True, text=True, timeout=300)
            save_output("nmap_output.txt", detail_result.stdout + "\n" + detail_result.stderr, append=True)
        else:
            # Fallback: scan ports phổ biến
            common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080,8443"
            fallback_cmd = ["nmap", "-p", common_ports, "-sV", "--script", "vulners", "--max-retries", "2", "--host-timeout", "300s", host]
            try:
                from core.security_utils import SecurityUtils
                cmd_str = " ".join(fallback_cmd)
                fallback_result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
                if fallback_result is None:
                    console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                    return
            except ImportError:
                # Fallback to direct subprocess with timeout
                fallback_result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=300)
            save_output("nmap_output.txt", fallback_result.stdout + "\n" + fallback_result.stderr, append=True)
            
    except subprocess.TimeoutExpired:
        console.print("[red]Nmap timeout - saving partial results[/red]")
        save_output("nmap_output.txt", quick_result.stdout + "\n" + quick_result.stderr, append=True)

def run_nikto(host):
    console.print(f"[yellow][*] Running Nikto for {host}[/yellow]")
    cmd = get_secure_docker_cmd("sullo/nikto", "-host", host)
    try:
        from core.security_utils import SecurityUtils
        cmd_str = " ".join(cmd)
        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
        if result is None:
            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
            return
    except ImportError:
        # Fallback to direct subprocess with timeout
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    save_output("nikto_output.txt", result.stdout + "\n" + result.stderr, append=True)

def run_whatweb(url):
    console.print(f"[yellow][*] Running WhatWeb for {url}[/yellow]")
    cmd = get_secure_docker_cmd(WHATWEB_IMAGE, url)
    try:
        from core.security_utils import SecurityUtils
        cmd_str = " ".join(cmd)
        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=120)
        if result is None:
            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
            return
    except ImportError:
        # Fallback to direct subprocess with timeout
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    save_output("fingerprint_output.txt", f"[WhatWeb] {url}\n{result.stdout}\n", append=True)

def run_nuclei_advanced(url):
    """Chạy Nuclei với chiến lược thông minh - TỐI ƯU NHƯNG ĐẦY ĐỦ"""
    console.print(f"[yellow][*] Running Smart Nuclei for {url}[/yellow]")
    
    # Chiến lược 3 giai đoạn: Critical → High → Medium
    scan_phases = [
        {
            "name": "Critical CVEs",
            "templates": ["cves"],
            "timeout": 120,
            "rate_limit": 200
        },
        {
            "name": "High Priority Vulnerabilities", 
            "templates": ["vulnerabilities", "exposures/version"],
            "timeout": 180,
            "rate_limit": 150
        },
        {
            "name": "Technology Fingerprinting",
            "templates": ["technologies", "exposures/configs", "exposures/files"],
            "timeout": 240,
            "rate_limit": 100
        }
    ]
    
    for phase in scan_phases:
        console.print(f"[cyan][*] Phase: {phase['name']}...[/cyan]")
        for template in phase["templates"]:
            template_path = os.path.join(NUCLEI_TEMPLATES, template)
            if os.path.exists(template_path):
                cmd = [
                    "nuclei", "-u", url, "-t", template_path, 
                    "-silent", "-rate-limit", str(phase["rate_limit"]),
                    "-bulk-size", "25", "-concurrency", "10"
                ]
                try:
                    try:
                        from core.security_utils import SecurityUtils
                        cmd_str = " ".join(cmd)
                        result = SecurityUtils.safe_subprocess_run(cmd_str, timeout=phase["timeout"])
                        if result is None:
                            console.print(f"[red]ERROR: Command blocked for security: {cmd_str}[/red]")
                            continue
                    except ImportError:
                        # Fallback to direct subprocess with timeout
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=phase["timeout"])
                    if result.stdout:
                        save_output(f"nuclei_{template.replace('/', '_')}_{sanitize_filename(url)}.txt", result.stdout)
                        save_output("nuclei_advanced_output.txt", f"\n{'='*80}\n[Nuclei {template}] {url}\n{'='*80}\n{result.stdout}\n", append=True)
                except subprocess.TimeoutExpired:
                    console.print(f"[red]Nuclei timeout for {url} - {template}[/red]")
                    continue

def check_headers(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, verify=False)
        for header in VERSION_HEADERS:
            if header in r.headers:
                finding = f"[VERSION_HEADER] {header}: {r.headers[header]} on {url}"
                findings.append(finding)
    except requests.RequestException:
        pass
    if findings:
        save_output("headers_output.txt", "\n".join(findings) + "\n", append=True)

def fingerprint_html_js(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        findings = []
        
        # Meta tags
        for meta in soup.find_all("meta"):
            content = " ".join(meta.attrs.values())
            if re.search(r"\d+\.\d+", content):
                finding = f"[META_VERSION] {content} on {url}"
                findings.append(finding)
        
        # Comments
        for comment in soup.find_all(string=lambda text:isinstance(text, type(soup.string))):
            if re.search(r"\d+\.\d+", comment):
                finding = f"[COMMENT_VERSION] {comment.strip()} on {url}"
                findings.append(finding)
        
        # JS files
        for script in soup.find_all("script", src=True):
            if re.search(r"\d+\.\d+", script['src']):
                finding = f"[JS_VERSION] {script['src']} on {url}"
                findings.append(finding)
                
        if findings:
            save_output("fingerprint_output.txt", "\n".join(findings) + "\n", append=True)
    except:
        pass

# ================== ANALYSIS ==================
def analyze_results():
    categorized = {lvl: [] for lvl in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("package_files_findings.txt", "OUTDATED_COMPONENT"),
        ("framework_versions_findings.txt", "OUTDATED_COMPONENT"),
        ("api_versions_findings.txt", "VERSION_DISCLOSURE"),
        ("docker_components_findings.txt", "OUTDATED_COMPONENT"),
        ("library_versions_findings.txt", "OUTDATED_COMPONENT"),
        ("headers_output.txt", "VERSION_DISCLOSURE"),
        ("fingerprint_output.txt", "VERSION_DISCLOSURE"),
        ("nmap_output.txt", None),
        ("nikto_output.txt", None),
        ("nuclei_advanced_output.txt", None)
    ]

    for file, vuln_type in finding_files:
        file_path = os.path.join(OUTPUT_DIR, file)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not is_noise_line(line):
                        severity, color, score, cvss_vector = classify_severity_advanced(line, vuln_type)
                        categorized[severity].append(line.strip())
                        findings.append(line.strip())
                        cvss_scores.append(score)
                        
                        # Store vulnerability details
                        if vuln_type and vuln_type in A06_VULNERABILITY_MAPPINGS:
                            mapping = A06_VULNERABILITY_MAPPINGS[vuln_type]
                            vulnerability_details.append({
                                "type": vuln_type,
                                "finding": line.strip(),
                                "cvss_score": score,
                                "cvss_vector": cvss_vector,
                                "severity": severity,
                                "description": mapping["description"]
                            })

    # Display comprehensive table with CVSS
    table = Table(title="A06 Vulnerable & Outdated Components - CVSS Standard Scan Results", header_style="bold magenta")
    table.add_column("Severity", style="cyan", no_wrap=True)
    table.add_column("CVSS Score", style="green")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", justify="center", style="green")
    table.add_column("Description", style="white")
    table.add_column("A06 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Critical CVEs, RCE Vulnerabilities",
        "HIGH": "High CVEs, SQL Injection, XSS",
        "MEDIUM": "Outdated Components, Deprecated Versions", 
        "LOW": "Version Disclosure, Info Leakage"
    }

    for lvl in SEVERITY_LEVELS:
        count = len(categorized[lvl])
        avg_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        table.add_row(
            f"[{SEVERITY_LEVELS[lvl]['color']}]{lvl}[/{SEVERITY_LEVELS[lvl]['color']}]",
            f"{avg_score:.1f}" if avg_score > 0 else "N/A",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if lvl == "CRITICAL" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            str(count),
            SEVERITY_LEVELS[lvl]["description"],
            coverage_info[lvl]
        )
    console.print(table)

    # Save detailed report with CVSS
    report = f"""
A06 Vulnerable & Outdated Components Scan Report - CVSS Standard
Generated: {datetime.now()}
Total Findings: {len(findings)}
Average CVSS Score: {sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0:.1f}

=== CRITICAL FINDINGS (CVSS 9.0-10.0) ===
{chr(10).join(categorized['CRITICAL'])}

=== HIGH FINDINGS (CVSS 7.0-8.9) ===  
{chr(10).join(categorized['HIGH'])}

=== MEDIUM FINDINGS (CVSS 4.0-6.9) ===
{chr(10).join(categorized['MEDIUM'])}

=== LOW FINDINGS (CVSS 0.1-3.9) ===
{chr(10).join(categorized['LOW'])}

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
=== A06 COVERAGE ===
✅ Package Manager Files Testing (CVSS 5.3)
✅ Framework Version Detection (CVSS 5.3)
✅ API Version Analysis (CVSS 3.1)
✅ Docker Components Testing (CVSS 5.3)
✅ Library Version Detection (CVSS 5.3)
✅ CVE Scanning (CVSS 9.8)
✅ Technology Fingerprinting (CVSS 3.1)
✅ Version Disclosure Testing (CVSS 3.1)
"""
    save_output("a06_detailed_report.txt", report)

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
            return SecurityUtils.safe_subprocess_run(f"get_secure_docker_cmd(args)", timeout=300)
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

def main(target):
    """Main function for A06 module - only callable from OWASP_MASTER_SCANNER"""
    if not target:
        console.print("[red]Target is required[/red]")
        return
    
    target_url = normalize_url(target)
    parsed = urlparse(target_url)
    host = parsed.hostname

    console.print(f"[bold cyan][*] Starting Advanced A06 Vulnerable & Outdated Components Scan for {target_url}[/bold cyan]")
    start = datetime.now()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Katana Discovery
        task1 = progress.add_task("Discovering endpoints...", total=None)
        endpoints = run_katana(target_url)
        save_output("katana_endpoints.txt", "\n".join(endpoints))
        console.print(f"[green][+] Found {len(endpoints)} endpoints[/green]")
        progress.update(task1, completed=True)

        # Step 2: Advanced A06 Tests
        task2 = progress.add_task("Testing Package Manager Files...", total=None)
        package_files_findings = test_package_files(target_url)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Testing Framework Versions...", total=None)
        framework_versions_findings = test_framework_versions(target_url)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Testing API Versions...", total=None)
        api_versions_findings = test_api_versions(target_url)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Testing Docker Components...", total=None)
        docker_components_findings = test_docker_components(target_url)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Testing Library Versions...", total=None)
        library_versions_findings = test_library_versions(target_url)
        progress.update(task6, completed=True)

        # Step 3: Nmap & Nikto on host
        task7 = progress.add_task("Running Nmap scan...", total=None)
        run_nmap(host)
        progress.update(task7, completed=True)

        task8 = progress.add_task("Running Nikto scan...", total=None)
        run_nikto(host)
        progress.update(task8, completed=True)

        # Step 4: Smart Nuclei & Fingerprinting - CHIẾN LƯỢC THÔNG MINH
        task9 = progress.add_task("Running Smart Nuclei scans...", total=min(len(endpoints), 15))
        
        # Phân loại endpoints theo priority
        priority_endpoints = []
        secondary_endpoints = []
        
        for ep in endpoints:
            if any(keyword in ep.lower() for keyword in ["admin", "api", "login", "test", "dev", "stage"]):
                priority_endpoints.append(ep)
            else:
                secondary_endpoints.append(ep)
        
        # Scan priority endpoints trước (đầy đủ)
        for ep in priority_endpoints[:10]:  # Tối đa 10 priority endpoints
            try:
                run_nuclei_advanced(ep)
                check_headers(ep)
                fingerprint_html_js(ep)
                progress.update(task9, advance=1)
            except Exception as e:
                console.print(f"[red]Error scanning priority {ep}: {e}[/red]")
                progress.update(task9, advance=1)
                continue
        
        # Scan secondary endpoints (rút gọn)
        for ep in secondary_endpoints[:5]:  # Chỉ 5 secondary endpoints
            try:
                # Chỉ scan critical CVEs cho secondary
                console.print(f"[cyan][*] Quick scan for {ep}[/cyan]")
                template_path = os.path.join(NUCLEI_TEMPLATES, "cves")
                if os.path.exists(template_path):
                    cmd = ["nuclei", "-u", ep, "-t", template_path, "-silent", "-rate-limit", "300", "-timeout", "60"]
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
                        save_output("nuclei_quick_output.txt", f"\n{'='*40}\n[Quick Nuclei] {ep}\n{'='*40}\n{result.stdout}\n", append=True)
                progress.update(task9, advance=1)
            except Exception as e:
                console.print(f"[red]Error scanning secondary {ep}: {e}[/red]")
                progress.update(task9, advance=1)
                continue

        # Step 5: Analysis
        task10 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task10, completed=True)

    elapsed = datetime.now() - start
    console.print(f"[bold green][*] Advanced A06 Scan completed in {elapsed}[/bold green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a06_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print(f"[red]Usage: python {sys.argv[0]} <target_url>[/red]")
        sys.exit(1)

    main(sys.argv[1])
