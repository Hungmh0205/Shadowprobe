#!/usr/bin/env python3
"""
OWASP Result Aggregator
Tổng hợp kết quả từ tất cả các module A01-A10 với CVSS classification
Tạo output tổng hợp cho database và frontend
"""

import os
import json
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFinding:
    """Cấu trúc dữ liệu cho một vulnerability finding"""
    id: str
    owasp_module: str
    severity: str
    cvss_score: float
    cvss_vector: str
    title: str
    description: str
    location: str
    evidence: Dict[str, Any]
    recommendation: str
    tags: List[str]
    timestamp: str
    source_file: str
    risk_level: str

@dataclass
class AggregatedResult:
    """Cấu trúc dữ liệu cho kết quả tổng hợp"""
    scan_id: str
    target: str
    scan_timestamp: str
    total_findings: int
    risk_score: float
    risk_level: str
    
    # Phân loại theo severity
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Phân loại theo module
    module_breakdown: Dict[str, int]
    
    # Danh sách findings
    findings: List[VulnerabilityFinding]
    
    # Metadata
    scan_duration: float
    modules_scanned: List[str]

class OWASPResultAggregator:
    """Tổng hợp kết quả từ tất cả các module OWASP"""
    
    def __init__(self, target: str):
        self.target = target
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.base_reports_dir = "reports"
        
        # CVSS Severity Mapping
        self.cvss_mapping = {
            'CRITICAL': {'score': 9.0, 'color': '🔴', 'priority': 1},
            'HIGH': {'score': 7.0, 'color': '🟠', 'priority': 2},
            'MEDIUM': {'score': 4.0, 'color': '🟡', 'priority': 3},
            'LOW': {'score': 0.1, 'color': '🟢', 'priority': 4}
        }
        
        # Module mapping
        self.module_mapping = {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures', 
            'A03': 'Injection',
            'A04': 'Insecure Design',
            'A05': 'Security Misconfiguration',
            'A06': 'Vulnerable Components',
            'A07': 'Authentication Failures',
            'A08': 'Software and Data Integrity Failures',
            'A09': 'Security Logging Failures',
            'A10': 'Server-Side Request Forgery'
        }
    
    def collect_module_results(self) -> List[VulnerabilityFinding]:
        """Thu thập kết quả từ tất cả các module"""
        all_findings = []
        
        for module_code in self.module_mapping.keys():
            module_findings = self._parse_module_output(module_code)
            all_findings.extend(module_findings)
        
        return all_findings
    
    def _parse_module_output(self, module_code: str) -> List[VulnerabilityFinding]:
        """Parse output từ một module cụ thể"""
        findings = []
        module_dir = os.path.join(self.base_reports_dir, f"{module_code.lower()}_scan_results")
        
        if not os.path.exists(module_dir):
            logger.warning(f"Module directory not found: {module_dir}")
            return findings
        
        # Các file cần parse
        files_to_parse = [
            f"{module_code.lower()}_detailed_report.txt",
            "summary.txt"
        ]
        
        # Thêm các file findings cụ thể
        if module_code == 'A01':
            files_to_parse.extend([
                "auth_bypass_findings.txt",
                "privilege_escalation_findings.txt",
                "horizontal_access_findings.txt",
                "vertical_access_findings.txt",
                "force_browsing_findings.txt",
                "parameter_pollution_findings.txt",
                "jwt_vulnerabilities_findings.txt"
            ])
        elif module_code == 'A02':
            files_to_parse.extend([
                "weak_ciphers_findings.txt",
                "certificate_issues_findings.txt",
                "protocol_vulnerabilities_findings.txt",
                "key_exchange_weaknesses_findings.txt"
            ])
        elif module_code == 'A03':
            files_to_parse.extend([
                "sql_injection_findings.txt",
                "nosql_injection_findings.txt",
                "command_injection_findings.txt",
                "xxe_injection_findings.txt",
                "ldap_injection_findings.txt",
                "template_injection_findings.txt",
                "crlf_injection_findings.txt"
            ])
        elif module_code == 'A04':
            files_to_parse.extend([
                "business_logic_findings.txt",
                "mass_assignment_findings.txt",
                "idor_findings.txt",
                "force_browsing_findings.txt",
                "parameter_pollution_findings.txt"
            ])
        elif module_code == 'A05':
            files_to_parse.extend([
                "default_credentials_findings.txt",
                "directory_listing_findings.txt",
                "config_exposure_findings.txt",
                "debug_mode_findings.txt",
                "ssl_misconfiguration_findings.txt",
                "version_disclosure_findings.txt"
            ])
        elif module_code == 'A06':
            files_to_parse.extend([
                "vulnerable_components_findings.txt",
                "outdated_versions_findings.txt",
                "package_vulnerabilities_findings.txt",
                "framework_vulnerabilities_findings.txt"
            ])
        elif module_code == 'A07':
            files_to_parse.extend([
                "auth_failures_findings.txt",
                "weak_passwords_findings.txt",
                "session_management_findings.txt",
                "account_enumeration_findings.txt",
                "mfa_bypass_findings.txt",
                "token_leakage_findings.txt"
            ])
        elif module_code == 'A08':
            files_to_parse.extend([
                "integrity_failures_findings.txt",
                "supply_chain_findings.txt",
                "cicd_vulnerabilities_findings.txt",
                "container_vulnerabilities_findings.txt"
            ])
        elif module_code == 'A09':
            files_to_parse.extend([
                "logging_failures_findings.txt",
                "monitoring_failures_findings.txt",
                "log_injection_findings.txt",
                "log_tampering_findings.txt"
            ])
        elif module_code == 'A10':
            files_to_parse.extend([
                "ssrf_findings.txt",
                "internal_network_findings.txt",
                "cloud_metadata_findings.txt",
                "information_disclosure_findings.txt"
            ])
        
        # Parse từng file
        for filename in files_to_parse:
            file_path = os.path.join(module_dir, filename)
            if os.path.exists(file_path):
                file_findings = self._parse_findings_file(file_path, module_code)
                findings.extend(file_findings)
        
        return findings
    
    def _parse_findings_file(self, file_path: str, module_code: str) -> List[VulnerabilityFinding]:
        """Parse một file findings cụ thể"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Parse từng line
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('==='):
                    continue
                
                # Parse finding từ line
                finding = self._parse_finding_line(line, module_code, file_path, line_num)
                if finding:
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
        
        return findings
    
    def _parse_finding_line(self, line: str, module_code: str, source_file: str, line_num: int) -> Optional[VulnerabilityFinding]:
        """Parse một line thành VulnerabilityFinding"""
        
        # Extract severity từ line
        severity = self._extract_severity(line)
        cvss_score = self._get_cvss_score(severity)
        cvss_vector = self._get_cvss_vector(severity)
        
        # Extract title và description
        title = self._extract_title(line, module_code)
        description = line[:200] + "..." if len(line) > 200 else line
        
        # Generate unique ID
        finding_id = f"{self.scan_id}_{module_code}_{line_num}"
        
        # Extract location
        location = self._extract_location(line)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(module_code, severity)
        
        # Generate tags
        tags = self._generate_tags(module_code, severity)
        
        return VulnerabilityFinding(
            id=finding_id,
            owasp_module=module_code,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            title=title,
            description=description,
            location=location or self.target,
            evidence={'source_file': source_file, 'line': line_num, 'content': line},
            recommendation=recommendation,
            tags=tags,
            timestamp=datetime.now().isoformat(),
            source_file=os.path.basename(source_file),
            risk_level=self._get_risk_level(cvss_score)
        )
    
    def _extract_severity(self, line: str) -> str:
        """Extract severity từ line"""
        line_lower = line.lower()
        
        # Check for explicit severity indicators
        if any(keyword in line_lower for keyword in ['critical', 'crash', 'rce', 'remote code execution']):
            return 'CRITICAL'
        elif any(keyword in line_lower for keyword in ['high', 'severe', 'dangerous']):
            return 'HIGH'
        elif any(keyword in line_lower for keyword in ['medium', 'moderate']):
            return 'MEDIUM'
        elif any(keyword in line_lower for keyword in ['low', 'minor', 'info']):
            return 'LOW'
        
        # Check for vulnerability type keywords
        critical_keywords = ['auth bypass', 'authentication bypass', 'privilege escalation', 'sql injection', 'xxe', 'ssrf']
        high_keywords = ['idor', 'csrf', 'xss', 'weak cipher', 'expired cert', 'self-signed']
        medium_keywords = ['missing', 'not enabled', 'weak', 'deprecated', 'outdated']
        
        if any(keyword in line_lower for keyword in critical_keywords):
            return 'CRITICAL'
        elif any(keyword in line_lower for keyword in high_keywords):
            return 'HIGH'
        elif any(keyword in line_lower for keyword in medium_keywords):
            return 'MEDIUM'
        
        return 'LOW'  # Default
    
    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score từ severity"""
        return self.cvss_mapping.get(severity, self.cvss_mapping['LOW'])['score']
    
    def _get_cvss_vector(self, severity: str) -> str:
        """Get CVSS vector từ severity"""
        vectors = {
            'CRITICAL': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'HIGH': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
            'MEDIUM': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            'LOW': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
        }
        return vectors.get(severity, vectors['LOW'])
    
    def _extract_title(self, line: str, module_code: str) -> str:
        """Extract title từ line"""
        # Remove common prefixes
        prefixes_to_remove = ['[ERROR]', '[CRITICAL]', '[HIGH]', '[MEDIUM]', '[LOW]', '[INFO]']
        title = line
        
        for prefix in prefixes_to_remove:
            if title.startswith(prefix):
                title = title[len(prefix):].strip()
                break
        
        # If no meaningful title, create one
        if len(title) < 10:
            title = f"{module_code} - {self.module_mapping[module_code]} Vulnerability"
        
        return title[:100]  # Limit length
    
    def _extract_location(self, line: str) -> str:
        """Extract location từ line"""
        # Look for URLs or IPs
        url_pattern = r'https?://[^\s]+'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        urls = re.findall(url_pattern, line)
        if urls:
            return urls[0]
        
        ips = re.findall(ip_pattern, line)
        if ips:
            return ips[0]
        
        return self.target
    
    def _generate_recommendation(self, module_code: str, severity: str) -> str:
        """Generate recommendation dựa trên module và severity"""
        recommendations = {
            'A01': {
                'CRITICAL': 'Implement proper authentication and authorization controls. Use role-based access control (RBAC).',
                'HIGH': 'Review and fix access control mechanisms. Implement proper session management.',
                'MEDIUM': 'Enhance access control policies and implement security headers.',
                'LOW': 'Consider implementing additional security measures.'
            },
            'A02': {
                'CRITICAL': 'Immediately upgrade to strong cryptographic algorithms. Disable weak ciphers and protocols.',
                'HIGH': 'Update SSL/TLS configuration. Use strong certificates and key exchange methods.',
                'MEDIUM': 'Configure proper SSL/TLS settings and security headers.',
                'LOW': 'Review cryptographic configuration and consider improvements.'
            },
            'A03': {
                'CRITICAL': 'Implement input validation and use parameterized queries. Use WAF protection.',
                'HIGH': 'Sanitize all user inputs and implement proper error handling.',
                'MEDIUM': 'Use prepared statements and input validation libraries.',
                'LOW': 'Review input handling and consider additional validation.'
            }
        }
        
        module_recs = recommendations.get(module_code, recommendations['A01'])
        return module_recs.get(severity, 'Review and implement appropriate security measures.')
    
    def _generate_tags(self, module_code: str, severity: str) -> List[str]:
        """Generate tags cho finding"""
        tags = [module_code, severity.lower(), 'owasp', 'automated_scan']
        
        # Add module-specific tags
        module_tags = {
            'A01': ['access_control', 'authentication', 'authorization'],
            'A02': ['cryptography', 'ssl', 'tls', 'certificates'],
            'A03': ['injection', 'input_validation', 'sql'],
            'A04': ['design', 'business_logic', 'architecture'],
            'A05': ['configuration', 'misconfiguration', 'security_headers'],
            'A06': ['dependencies', 'components', 'versions'],
            'A07': ['authentication', 'session', 'password'],
            'A08': ['integrity', 'supply_chain', 'cicd'],
            'A09': ['logging', 'monitoring', 'audit'],
            'A10': ['ssrf', 'network', 'internal']
        }
        
        tags.extend(module_tags.get(module_code, []))
        return tags
    
    def _get_risk_level(self, cvss_score: float) -> str:
        """Get risk level từ CVSS score"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def aggregate_results(self, findings: List[VulnerabilityFinding], scan_duration: float = 0.0) -> AggregatedResult:
        """Tổng hợp kết quả thành AggregatedResult"""
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        module_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            module_counts[finding.owasp_module] = module_counts.get(finding.owasp_module, 0) + 1
        
        # Calculate overall risk score
        total_score = sum(finding.cvss_score for finding in findings)
        avg_risk_score = total_score / len(findings) if findings else 0.0
        
        # Determine overall risk level
        overall_risk_level = self._get_risk_level(avg_risk_score)
        
        return AggregatedResult(
            scan_id=self.scan_id,
            target=self.target,
            scan_timestamp=datetime.now().isoformat(),
            total_findings=len(findings),
            risk_score=round(avg_risk_score, 2),
            risk_level=overall_risk_level,
            critical_count=severity_counts['CRITICAL'],
            high_count=severity_counts['HIGH'],
            medium_count=severity_counts['MEDIUM'],
            low_count=severity_counts['LOW'],
            module_breakdown=module_counts,
            findings=findings,
            scan_duration=scan_duration,
            modules_scanned=list(self.module_mapping.keys())
        )
    
    def save_to_database_format(self, aggregated_result: AggregatedResult, output_dir: str = "owasp_master_output"):
        """Lưu kết quả theo format phù hợp cho database"""
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Convert to dictionary format
        result_dict = asdict(aggregated_result)
        
        # Convert findings to list of dicts
        result_dict['findings'] = [asdict(finding) for finding in aggregated_result.findings]
        
        # Save as JSON
        json_file = os.path.join(output_dir, f"owasp_master_report_{self.scan_id}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False)
        
        # Save summary report
        summary_file = os.path.join(output_dir, f"owasp_master_summary_{self.scan_id}.txt")
        self._save_summary_report(aggregated_result, summary_file)
        
        # Save findings for database import
        db_file = os.path.join(output_dir, f"owasp_findings_db_{self.scan_id}.json")
        self._save_database_format(aggregated_result, db_file)
        
        return {
            'json_report': json_file,
            'summary_report': summary_file,
            'database_format': db_file
        }
    
    def _save_summary_report(self, result: AggregatedResult, filepath: str):
        """Lưu báo cáo tổng hợp"""
        
        report = f"""
🔍 OWASP Master Vulnerability Scan Report
{'='*60}

🎯 Target: {result.target}
📅 Scan Date: {datetime.fromisoformat(result.scan_timestamp).strftime('%Y-%m-%d %H:%M:%S')}
⏱️  Duration: {result.scan_duration:.2f} seconds
⚠️  Overall Risk Score: {result.risk_score}/10.0 ({result.risk_level})

📊 FINDINGS SUMMARY
{'-'*30}
🔴 Critical: {result.critical_count} findings
🟠 High: {result.high_count} findings  
🟡 Medium: {result.medium_count} findings
🟢 Low: {result.low_count} findings
📈 Total: {result.total_findings} vulnerabilities

🔧 MODULE BREAKDOWN
{'-'*20}
"""
        
        for module, count in result.module_breakdown.items():
            module_name = self.module_mapping.get(module, module)
            report += f"• {module} ({module_name}): {count} findings\n"
        
        # Critical and High findings
        critical_high = [f for f in result.findings if f.severity in ['CRITICAL', 'HIGH']]
        if critical_high:
            report += f"\n🚨 CRITICAL & HIGH FINDINGS\n{'-'*30}\n"
            for i, finding in enumerate(critical_high[:10], 1):  # Show top 10
                report += f"{i}. {finding.title}\n"
                report += f"   📍 {finding.location}\n"
                report += f"   📝 {finding.description[:100]}...\n\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
    
    def _save_database_format(self, result: AggregatedResult, filepath: str):
        """Lưu theo format phù hợp cho database import"""
        
        db_data = {
            'scan_metadata': {
                'scan_id': result.scan_id,
                'target': result.target,
                'scan_timestamp': result.scan_timestamp,
                'scan_duration': result.scan_duration,
                'total_findings': result.total_findings,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level
            },
            'severity_breakdown': {
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count
            },
            'module_breakdown': result.module_breakdown,
            'findings': []
        }
        
        # Convert findings to database-friendly format
        for finding in result.findings:
            db_finding = {
                'id': finding.id,
                'owasp_module': finding.owasp_module,
                'module_name': self.module_mapping.get(finding.owasp_module, finding.owasp_module),
                'severity': finding.severity,
                'cvss_score': finding.cvss_score,
                'cvss_vector': finding.cvss_vector,
                'title': finding.title,
                'description': finding.description,
                'location': finding.location,
                'evidence': finding.evidence,
                'recommendation': finding.recommendation,
                'tags': finding.tags,
                'timestamp': finding.timestamp,
                'source_file': finding.source_file,
                'risk_level': finding.risk_level
            }
            db_data['findings'].append(db_finding)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(db_data, f, indent=2, ensure_ascii=False)

def aggregate_owasp_results(target: str, scan_duration: float = 0.0) -> Dict[str, Any]:
    """
    Main function để tổng hợp kết quả OWASP
    
    Args:
        target: Target URL/IP
        scan_duration: Thời gian scan (seconds)
    
    Returns:
        Dictionary chứa thông tin về các file output
    """
    
    print(f"🔍 Aggregating OWASP results for target: {target}")
    
    # Tạo aggregator
    aggregator = OWASPResultAggregator(target)
    
    # Thu thập kết quả từ tất cả modules
    print("📊 Collecting results from all modules...")
    findings = aggregator.collect_module_results()
    
    print(f"✅ Collected {len(findings)} findings from all modules")
    
    # Tổng hợp kết quả
    print("🔧 Aggregating results...")
    aggregated_result = aggregator.aggregate_results(findings, scan_duration)
    
    # Lưu kết quả
    print("💾 Saving aggregated results...")
    output_files = aggregator.save_to_database_format(aggregated_result)
    
    print(f"🎉 Aggregation completed!")
    print(f"📄 JSON Report: {output_files['json_report']}")
    print(f"📋 Summary Report: {output_files['summary_report']}")
    print(f"🗄️  Database Format: {output_files['database_format']}")
    
    return {
        'aggregated_result': aggregated_result,
        'output_files': output_files,
        'statistics': {
            'total_findings': aggregated_result.total_findings,
            'risk_score': aggregated_result.risk_score,
            'risk_level': aggregated_result.risk_level,
            'critical_count': aggregated_result.critical_count,
            'high_count': aggregated_result.high_count,
            'medium_count': aggregated_result.medium_count,
            'low_count': aggregated_result.low_count
        }
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python owasp_result_aggregator.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    result = aggregate_owasp_results(target)
    
    print(f"\n📊 Final Statistics:")
    print(f"   Total Findings: {result['statistics']['total_findings']}")
    print(f"   Risk Score: {result['statistics']['risk_score']}/10.0")
    print(f"   Risk Level: {result['statistics']['risk_level']}")
    print(f"   Critical: {result['statistics']['critical_count']}")
    print(f"   High: {result['statistics']['high_count']}")
    print(f"   Medium: {result['statistics']['medium_count']}")
    print(f"   Low: {result['statistics']['low_count']}")
