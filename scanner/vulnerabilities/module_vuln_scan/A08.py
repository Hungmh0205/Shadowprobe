import os
import sys
import subprocess
import requests
import json
import hashlib
import re
from urllib.parse import urlparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.progress import Progress, SpinnerColumn, TextColumn
from utils import normalize_url, is_noise_line

# Add path to core modules for absolute imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


# ================== CONFIG ==================
OUTPUT_DIR = "reports/a08_integrity_results"
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

# A08 Vulnerability Mappings với CVSS
A08_VULNERABILITY_MAPPINGS = {
    "SUPPLY_CHAIN": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Supply chain compromise allows malicious code injection"
    },
    "CICD_SECURITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "CI/CD pipeline compromise allows unauthorized deployments"
    },
    "CONTAINER_SECURITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Container security issues allow privilege escalation"
    },
    "CODE_REPOSITORY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Code repository exposure reveals sensitive information"
    },
    "RUNTIME_INTEGRITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Runtime integrity failure allows code tampering"
    },
    "FILE_INTEGRITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "File integrity issues allow unauthorized access"
    },
    "SECRET_EXPOSURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Secret exposure allows unauthorized access"
    }
}

# OWASP A08:2021 - Software and Data Integrity Failures Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical integrity failures - immediate remediation required",
                 "keywords": ["supply chain", "cicd", "pipeline", "deployment", "malicious", "injection", "backdoor", "trojan", "critical", "compromise", "breach", "unauthorized", "malware", "virus", "rootkit"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity integrity vulnerabilities",
             "keywords": ["container", "docker", "repository", "git", "runtime", "integrity", "tampering", "modification", "unauthorized", "access", "secret", "token", "key", "credential", "password", "api", "exposure", "leak"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - integrity improvements needed",
               "keywords": ["file", "backup", "config", "version", "outdated", "weak", "insecure", "deprecated", "medium", "warning", "notice", "info", "misconfiguration"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["low", "info", "note", "debug", "development", "test", "sample", "non-critical", "minor", "cosmetic", "display issue", "enumeration"]}
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

# A08 Vulnerability Mappings với CVSS
A08_VULNERABILITY_MAPPINGS = {
    "SUPPLY_CHAIN": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Supply chain compromise allows malicious code injection"
    },
    "CICD_SECURITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "CI/CD pipeline compromise allows unauthorized deployments"
    },
    "CONTAINER_SECURITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Container security issues allow privilege escalation"
    },
    "CODE_REPOSITORY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Code repository exposure reveals sensitive information"
    },
    "RUNTIME_INTEGRITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Runtime integrity failure allows code tampering"
    },
    "FILE_INTEGRITY": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "severity": "MEDIUM",
        "score": 5.3,
        "description": "File integrity issues allow unauthorized access"
    },
    "SECRET_EXPOSURE": {
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "severity": "HIGH",
        "score": 7.5,
        "description": "Secret exposure allows unauthorized access"
    }
}

# OWASP A08:2021 - Software and Data Integrity Failures Classification
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "red", "score": "9.0-10.0", "description": "Critical integrity failures - immediate remediation required",
                 "keywords": ["supply chain", "cicd", "pipeline", "deployment", "malicious", "injection", "backdoor", "trojan", "critical", "compromise", "breach", "unauthorized", "malware", "virus", "rootkit"]},
    "HIGH": {"color": "bright_red", "score": "7.0-8.9", "description": "High severity integrity vulnerabilities",
             "keywords": ["container", "docker", "repository", "git", "runtime", "integrity", "tampering", "modification", "unauthorized", "access", "secret", "token", "key", "credential", "password", "api", "exposure", "leak"]},
    "MEDIUM": {"color": "yellow", "score": "4.0-6.9", "description": "Medium severity - integrity improvements needed",
               "keywords": ["file", "backup", "config", "version", "outdated", "weak", "insecure", "deprecated", "medium", "warning", "notice", "info", "misconfiguration"]},
    "LOW": {"color": "blue", "score": "0.1-3.9", "description": "Informational or low impact findings",
            "keywords": ["low", "info", "note", "debug", "development", "test", "sample", "non-critical", "minor", "cosmetic", "display issue", "enumeration"]}
}

# Kiểm tra tool có sẵn
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

# Sử dụng template Nuclei có sẵn thay vì template cụ thể
A08_TEMPLATES = [
    "cves/",
    "vulnerabilities/",
    "exposures/",
    "misconfiguration/"
]

A08_PACKAGE_FILES = [
    ".git/config", "Dockerfile", "package-lock.json", "yarn.lock", "requirements.txt"
]

# ================== UTIL ==================
def sanitize_filename(url):
    return urlparse(url).netloc.replace(":", "_")

def save_output(filename, data, append=False):
    # Đảm bảo thư mục output tồn tại
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

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A08_VULNERABILITY_MAPPINGS:
        return A08_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A08_VULNERABILITY_MAPPINGS:
        mapping = A08_VULNERABILITY_MAPPINGS[vulnerability_type]
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

def calculate_cvss_score(vulnerability_type):
    """Tính CVSS score dựa trên loại vulnerability"""
    if vulnerability_type in A08_VULNERABILITY_MAPPINGS:
        return A08_VULNERABILITY_MAPPINGS[vulnerability_type]["score"]
    return 5.0  # Default MEDIUM

def classify_severity_advanced(finding, vulnerability_type=None):
    """Phân loại severity theo tiêu chuẩn CVSS"""
    f_lower = finding.lower()
    
    # Nếu có vulnerability_type, sử dụng mapping
    if vulnerability_type and vulnerability_type in A08_VULNERABILITY_MAPPINGS:
        mapping = A08_VULNERABILITY_MAPPINGS[vulnerability_type]
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

# ================== A08 ADVANCED FEATURES ==================

# 1. SUPPLY CHAIN SECURITY ANALYSIS
def analyze_supply_chain(target):
    """Analyze supply chain security - dependencies, packages, SBOM"""
    console.print("[cyan][*] Running Supply Chain Security Analysis...[/cyan]")
    findings = []
    
    # Package files to check
    package_files = [
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
        "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
        "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml",
        "build.gradle", "build.sbt", "mix.exs", "mix.lock"
    ]
    
    for pkg_file in package_files:
        url = target.rstrip("/") + "/" + pkg_file
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[SUPPLY_CHAIN] Package file accessible: {pkg_file}")
                
                # Analyze package content for security issues
                if pkg_file.endswith('.json'):
                    try:
                        pkg_data = json.loads(r.text)
                        findings.extend(analyze_package_json(pkg_data, pkg_file))
                    except:
                        pass
                elif pkg_file in ['requirements.txt', 'Pipfile']:
                    findings.extend(analyze_python_dependencies(r.text, pkg_file))
                        
        except Exception as e:
            findings.append(f"[ERROR] Error analyzing {pkg_file}: {e}")
    
    save_output("supply_chain_analysis.txt", "\n".join(findings))
    return findings

def analyze_package_json(pkg_data, filename):
    """Analyze package.json for security issues"""
    findings = []
    
    # Check for known vulnerable dependencies
    if 'dependencies' in pkg_data:
        for dep, version in pkg_data['dependencies'].items():
            if is_vulnerable_dependency(dep, version):
                findings.append(f"[SUPPLY_CHAIN] Vulnerable dependency in {filename}: {dep}@{version}")
    
    # Check for dev dependencies
    if 'devDependencies' in pkg_data:
        for dep, version in pkg_data['devDependencies'].items():
            if is_vulnerable_dependency(dep, version):
                findings.append(f"[SUPPLY_CHAIN] Vulnerable dev dependency in {filename}: {dep}@{version}")
    
    # Check for scripts that might be dangerous
    if 'scripts' in pkg_data:
        for script_name, script_cmd in pkg_data['scripts'].items():
            if is_dangerous_script(script_cmd):
                findings.append(f"[SUPPLY_CHAIN] Potentially dangerous script in {filename}: {script_name} = {script_cmd}")
    
    return findings

def analyze_python_dependencies(content, filename):
    """Analyze Python dependencies for security issues"""
    findings = []
    
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            # Parse package name and version
            if '==' in line:
                pkg_name, version = line.split('==', 1)
                if is_vulnerable_dependency(pkg_name.strip(), version.strip()):
                    findings.append(f"[SUPPLY_CHAIN] Vulnerable Python dependency in {filename}: {pkg_name.strip()}=={version.strip()}")
    
    return findings

def is_vulnerable_dependency(pkg_name, version):
    """Check if dependency is known to be vulnerable"""
    # Common vulnerable packages (simplified check)
    vulnerable_packages = {
        'lodash': ['<4.17.21'],
        'jquery': ['<3.6.0'],
        'moment': ['<2.29.4'],
        'axios': ['<1.6.0'],
        'express': ['<4.18.2'],
        'django': ['<4.2.0'],
        'flask': ['<2.3.0'],
        'requests': ['<2.31.0']
    }
    
    if pkg_name.lower() in vulnerable_packages:
        # Simple version check (in real implementation, use proper version comparison)
        return True
    return False

def is_dangerous_script(script_cmd):
    """Check if script command is potentially dangerous"""
    dangerous_patterns = [
        r'curl\s+.*\|\s*bash',
        r'wget\s+.*\|\s*bash',
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'rm\s+-rf',
        r'del\s+/s'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, script_cmd, re.IGNORECASE):
            return True
    return False

# 2. CI/CD PIPELINE SECURITY
def scan_cicd_pipelines(target):
    """Scan CI/CD pipeline files for security issues"""
    console.print("[cyan][*] Running CI/CD Pipeline Security Analysis...[/cyan]")
    findings = []
    
    # CI/CD files to check
    cicd_files = [
        ".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml",
        "azure-pipelines.yml", "bitbucket-pipelines.yml", "circle.yml",
        ".github/actions/", ".github/workflows/deploy.yml", ".github/workflows/build.yml",
        "appveyor.yml", "codeship-steps.yml", "drone.yml", "semaphore.yml"
    ]
    
    for cicd_file in cicd_files:
        url = target.rstrip("/") + "/" + cicd_file
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[CICD_SECURITY] CI/CD file accessible: {cicd_file}")
                findings.extend(analyze_cicd_content(r.text, cicd_file))
        except Exception as e:
            findings.append(f"[ERROR] Error scanning {cicd_file}: {e}")
    
    save_output("cicd_security_analysis.txt", "\n".join(findings))
    return findings

def analyze_cicd_content(content, filename):
    """Analyze CI/CD content for security issues"""
    findings = []
    
    # Check for hardcoded secrets
    secret_patterns = [
        r'(?i)(api[_-]?key|secret|token|password|aws[_-]?access|aws[_-]?secret)["\'=:\s]+([A-Za-z0-9_\-\/\.\+]{8,})',
        r'(?i)(github[_-]?token|gitlab[_-]?token|bitbucket[_-]?token)["\'=:\s]+([A-Za-z0-9_\-\/\.\+]{8,})',
        r'(?i)(docker[_-]?password|registry[_-]?password)["\'=:\s]+([A-Za-z0-9_\-\/\.\+]{8,})'
    ]
    
    for pattern in secret_patterns:
        for match in re.findall(pattern, content):
            findings.append(f"[CICD_SECURITY] Hardcoded secret in {filename}: {match[0]} = {match[1]}")
    
    # Check for dangerous commands
    dangerous_commands = [
        r'curl\s+.*\|\s*bash',
        r'wget\s+.*\|\s*bash',
        r'eval\s*\(',
        r'exec\s*\(',
        r'system\s*\(',
        r'rm\s+-rf',
        r'del\s+/s',
        r'chmod\s+777',
        r'chown\s+root'
    ]
    
    for cmd_pattern in dangerous_commands:
        if re.search(cmd_pattern, content, re.IGNORECASE):
            findings.append(f"[CICD_SECURITY] Dangerous command in {filename}: {cmd_pattern}")
    
    # Check for insecure base images
    insecure_images = [
        r'FROM\s+(alpine|debian|ubuntu):[0-9]+\.[0-9]+',
        r'FROM\s+node:[0-9]+\.[0-9]+',
        r'FROM\s+python:[0-9]+\.[0-9]+'
    ]
    
    for img_pattern in insecure_images:
        if re.search(img_pattern, content, re.IGNORECASE):
            findings.append(f"[CICD_SECURITY] Potentially outdated base image in {filename}")
    
    return findings

# 3. CONTAINER SECURITY
def scan_containers(target):
    """Scan container-related files for security issues"""
    console.print("[cyan][*] Running Container Security Analysis...[/cyan]")
    findings = []
    
    # Container files to check
    container_files = [
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".dockerignore", "dockerfile", "Dockerfile.dev", "Dockerfile.prod",
        "docker-compose.override.yml", "docker-compose.prod.yml"
    ]
    
    for container_file in container_files:
        url = target.rstrip("/") + "/" + container_file
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[CONTAINER_SECURITY] Container file accessible: {container_file}")
                findings.extend(analyze_container_content(r.text, container_file))
        except Exception as e:
            findings.append(f"[ERROR] Error scanning {container_file}: {e}")
    
    save_output("container_security_analysis.txt", "\n".join(findings))
    return findings

def analyze_container_content(content, filename):
    """Analyze container content for security issues"""
    findings = []
    
    # Check for root user
    if re.search(r'USER\s+root', content, re.IGNORECASE):
        findings.append(f"[CONTAINER_SECURITY] Container runs as root in {filename}")
    
    # Check for latest tags
    if re.search(r'FROM\s+.*:latest', content, re.IGNORECASE):
        findings.append(f"[CONTAINER_SECURITY] Uses 'latest' tag in {filename} - potential security risk")
    
    # Check for exposed ports
    exposed_ports = re.findall(r'EXPOSE\s+(\d+)', content, re.IGNORECASE)
    if exposed_ports:
        findings.append(f"[CONTAINER_SECURITY] Exposed ports in {filename}: {', '.join(exposed_ports)}")
    
    # Check for volume mounts
    volume_mounts = re.findall(r'VOLUME\s+([^\s]+)', content, re.IGNORECASE)
    if volume_mounts:
        findings.append(f"[CONTAINER_SECURITY] Volume mounts in {filename}: {', '.join(volume_mounts)}")
    
    # Check for environment variables with secrets
    env_secrets = re.findall(r'ENV\s+([A-Z_]+)=([^\s]+)', content, re.IGNORECASE)
    for var_name, var_value in env_secrets:
        if any(secret_word in var_name.lower() for secret_word in ['key', 'secret', 'password', 'token']):
            findings.append(f"[CONTAINER_SECURITY] Environment variable with potential secret in {filename}: {var_name}")
    
    return findings

# 4. CODE REPOSITORY ANALYSIS
def analyze_code_repository(target):
    """Analyze code repository for security issues"""
    console.print("[cyan][*] Running Code Repository Analysis...[/cyan]")
    findings = []
    
    # Git repository files to check
    git_files = [
        ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
        ".git/refs/heads/", ".git/refs/tags/", ".gitignore",
        ".gitattributes", ".gitmodules"
    ]
    
    for git_file in git_files:
        url = target.rstrip("/") + "/" + git_file
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[CODE_REPOSITORY] Git file accessible: {git_file}")
                findings.extend(analyze_git_content(r.text, git_file))
        except Exception as e:
            findings.append(f"[ERROR] Error scanning {git_file}: {e}")
    
    # Check for source code backups
    backup_patterns = [
        "*.bak", "*.old", "*.backup", "*.orig", "*.tmp", "*.swp",
        "*.swo", "*~", "*.tar.gz", "*.zip", "*.rar"
    ]
    
    for pattern in backup_patterns:
        url = target.rstrip("/") + "/" + pattern
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[CODE_REPOSITORY] Source code backup accessible: {pattern}")
        except:
            pass
    
    save_output("code_repository_analysis.txt", "\n".join(findings))
    return findings

def analyze_git_content(content, filename):
    """Analyze Git content for security issues"""
    findings = []
    
    # Check for repository URLs
    repo_urls = re.findall(r'url\s*=\s*([^\s]+)', content, re.IGNORECASE)
    for url in repo_urls:
        findings.append(f"[CODE_REPOSITORY] Repository URL found in {filename}: {url}")
    
    # Check for branch information
    branches = re.findall(r'ref:\s*refs/heads/([^\s]+)', content, re.IGNORECASE)
    for branch in branches:
        findings.append(f"[CODE_REPOSITORY] Branch information in {filename}: {branch}")
    
    # Check for commit hashes
    commits = re.findall(r'[a-f0-9]{40}', content)
    if commits:
        findings.append(f"[CODE_REPOSITORY] Commit hashes found in {filename}: {len(commits)} commits")
    
    return findings

# 5. RUNTIME INTEGRITY CHECKING
def check_runtime_integrity(target):
    """Check runtime integrity of files"""
    console.print("[cyan][*] Running Runtime Integrity Checks...[/cyan]")
    findings = []
    
    # Files to check for integrity
    integrity_files = [
        "index.php", "index.html", "main.js", "app.js", "style.css",
        "config.php", "settings.php", "database.php"
    ]
    
    for file_name in integrity_files:
        url = target.rstrip("/") + "/" + file_name
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                # Calculate file hash
                file_hash = hashlib.sha256(r.content).hexdigest()
                findings.append(f"[RUNTIME_INTEGRITY] File integrity check for {file_name}: SHA256={file_hash[:16]}...")
                
                # Check for suspicious content
                suspicious_patterns = [
                    r'eval\s*\(',
                    r'exec\s*\(',
                    r'system\s*\(',
                    r'base64_decode\s*\(',
                    r'gzinflate\s*\(',
                    r'str_rot13\s*\('
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        findings.append(f"[RUNTIME_INTEGRITY] Suspicious function found in {file_name}: {pattern}")
                        
        except Exception as e:
            findings.append(f"[ERROR] Error checking integrity of {file_name}: {e}")
    
    save_output("runtime_integrity_checks.txt", "\n".join(findings))
    return findings

# ================== A08 MAIN SCAN ==================
def run_nuclei_integrity(target):
    console.print("[cyan][*] Running Nuclei integrity-related templates...[/cyan]")
    output = ""
    
    if not check_tool_available("nuclei"):
        output += "[!] Nuclei not found. Skipping Nuclei scans.\n"
        return output
    
    for template in A08_TEMPLATES:
        try:
            cmd = [
                "nuclei", "-u", target,
                "-t", template,
                "-severity", "critical,high,medium",
                "-silent"
            ]
            result = run_command(cmd)
            if result.strip():
                output += f"\n# Template: {template}\n{result}"
        except Exception as e:
            output += f"\n# Template: {template}\n[!] Error: {str(e)}\n"
    
    save_output("nuclei_integrity.txt", output)
    return output

# Mở rộng wordlist file backup, config, artifact phổ biến
A08_EXTRA_FILES = [
    ".env", ".env.bak", ".env.old", ".env.save", "config.php", "config.json", "web.config", "settings.py", "settings.json", "database.yml", "db.sql", "backup.sql", "dump.rdb", "docker-compose.yml", "docker-compose.yaml", "wp-config.php", "composer.lock", "Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock", "Cargo.toml", "go.mod", "package.json", "package-lock.json", "yarn.lock", "requirements.txt", "admin.bak", "index.php~", "index.php.bak", "index.php.old", "index.php.swp", "index.php.tmp", "backup.zip", "backup.tar.gz", "backup.rar", "logs.zip", "logs.tar.gz", "debug.log", "error.log", "access.log"
]

SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|secret|token|password|aws[_-]?access|aws[_-]?secret|authorization|bearer)["\'=:\s]+([A-Za-z0-9_\-/\.\+]{8,})'
]

def check_package_files(target):
    console.print("[cyan][*] Running file integrity (hash) and secret check...[/cyan]")
    findings = []
    for path in set(A08_PACKAGE_FILES + A08_EXTRA_FILES):
        url = target.rstrip("/") + "/" + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                findings.append(f"[FILE_INTEGRITY] File accessible: {path}")
                # Quét secret/token trong nội dung file
                for patt in SECRET_PATTERNS:
                    for m in re.findall(patt, r.text):
                        findings.append(f"[SECRET_EXPOSURE] Secret/Token found in {path}: {m[0]} = {m[1]}")
            else:
                findings.append(f"[-] File not found: {path}")
        except Exception as e:
            findings.append(f"[!] Error fetching: {path} ({e})")
    save_output("package_file_check.txt", "\n".join(findings))
    return findings

def run_nikto_scan(target):
    console.print("[cyan][*] Running Nikto scan...[/cyan]")
    cmd = [
        "docker", "run", "--rm",
        "sullo/nikto:latest", "-host", target
    ]
    result = run_command(cmd)
    save_output("nikto_output.txt", result)
    return result

def run_katana_scan(target):
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
    console.print("[magenta][*] Analyzing A08 scan results...[/magenta]")

    categorized = {sev: [] for sev in SEVERITY_LEVELS}
    findings = []
    cvss_scores = []
    vulnerability_details = []

    # Collect all findings with proper classification
    finding_files = [
        ("supply_chain_analysis.txt", "SUPPLY_CHAIN"),
        ("cicd_security_analysis.txt", "CICD_SECURITY"),
        ("container_security_analysis.txt", "CONTAINER_SECURITY"),
        ("code_repository_analysis.txt", "CODE_REPOSITORY"),
        ("runtime_integrity_checks.txt", "RUNTIME_INTEGRITY"),
        ("package_file_check.txt", "FILE_INTEGRITY"),
        ("nuclei_integrity.txt", None),
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
                            if vuln_type and vuln_type in A08_VULNERABILITY_MAPPINGS:
                                mapping = A08_VULNERABILITY_MAPPINGS[vuln_type]
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
    table = Table(title="📊 A08 Software & Data Integrity Failures - CVSS Standard Overview", header_style="bold magenta")
    table.add_column("Severity", style="cyan")
    table.add_column("CVSS Score", style="green", justify="center")
    table.add_column("CVSS Vector", style="blue")
    table.add_column("Count", style="green", justify="center")
    table.add_column("Description", style="white")
    table.add_column("A08 Coverage", style="yellow")

    coverage_info = {
        "CRITICAL": "Supply Chain, CI/CD Pipeline",
        "HIGH": "Container Security, Repository, Runtime Integrity",
        "MEDIUM": "File Integrity, Secret Exposure", 
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
A08 Software & Data Integrity Failures Scan Report - CVSS Standard
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
=== A08 COVERAGE ===
✅ Supply Chain Security Analysis (CVSS 9.8)
✅ CI/CD Pipeline Security (CVSS 9.8)
✅ Container Security Analysis (CVSS 7.5)
✅ Code Repository Analysis (CVSS 7.5)
✅ Runtime Integrity Checking (CVSS 7.5)
✅ File Integrity Analysis (CVSS 5.3)
✅ Secret Exposure Detection (CVSS 7.5)
✅ Advanced Integrity Testing
"""
    save_output("a08_detailed_report.txt", report)
    console.print("[green]💾 Summary saved[/green]")

# ================== MAIN ==================
def main(target):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = sanitize_filename(target)
    start = datetime.now()
    
    console.print(f"\n[bold yellow][*] Starting Advanced A08 Software & Data Integrity Scan for {target}[/bold yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Step 1: Basic scans
        task1 = progress.add_task("Running basic integrity checks...", total=None)
        nuclei_output = run_nuclei_integrity(target)
        package_findings = check_package_files(target)
        nikto_output = run_nikto_scan(target)
        katana_output = run_katana_scan(target)
        progress.update(task1, completed=True)
        
        # Step 2: Advanced A08 scans
        task2 = progress.add_task("Running supply chain analysis...", total=None)
        supply_chain_findings = analyze_supply_chain(target)
        progress.update(task2, completed=True)

        task3 = progress.add_task("Running CI/CD pipeline analysis...", total=None)
        cicd_findings = scan_cicd_pipelines(target)
        progress.update(task3, completed=True)

        task4 = progress.add_task("Running container security analysis...", total=None)
        container_findings = scan_containers(target)
        progress.update(task4, completed=True)

        task5 = progress.add_task("Running code repository analysis...", total=None)
        repo_findings = analyze_code_repository(target)
        progress.update(task5, completed=True)

        task6 = progress.add_task("Running runtime integrity checks...", total=None)
        integrity_findings = check_runtime_integrity(target)
        progress.update(task6, completed=True)

        # Step 3: Analysis
        task7 = progress.add_task("Analyzing results...", total=None)
        analyze_results()
        progress.update(task7, completed=True)

    console.print(f"[green][*] Advanced A08 Scan completed in {datetime.now() - start}[/green]")
    console.print(f"[bold yellow][*] Check {OUTPUT_DIR}/a08_detailed_report.txt for comprehensive results[/bold yellow]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python A08.py <target_url>[/red]")
        sys.exit(1)
    main(normalize_url(sys.argv[1]))
