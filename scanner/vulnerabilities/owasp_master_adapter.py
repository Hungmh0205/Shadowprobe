"""
OWASP Master Vulnerability Adapter
Single adapter for all OWASP Top 10 2021 vulnerability scanning.
Replaces individual A01-A10 adapters with a unified interface.
"""

from typing import List, Dict, Any, Optional
import logging
import os
import sys
from datetime import datetime

# Add module_vuln_scan to path
current_dir = os.path.dirname(os.path.abspath(__file__))
module_vuln_scan_path = os.path.join(current_dir, 'module_vuln_scan')
sys.path.insert(0, module_vuln_scan_path)

try:
    from .module_vuln_scan.OWASP_MASTER_SCANNER import scan_target, get_available_modules, get_module_info
    MASTER_SCANNER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"OWASP Master Scanner not available: {e}")
    MASTER_SCANNER_AVAILABLE = False

logger = logging.getLogger(__name__)

class VulnerabilityResultAggregator:
    """Aggregates and categorizes vulnerability findings with CVSS scoring"""
    
    def __init__(self):
        self.cvss_severity_mapping = {
            'critical': {'score': 9.0, 'color': '🔴', 'priority': 1},
            'high': {'score': 7.0, 'color': '🟠', 'priority': 2},
            'medium': {'score': 4.0, 'color': '🟡', 'priority': 3},
            'low': {'score': 0.1, 'color': '🟢', 'priority': 4},
            'info': {'score': 0.0, 'color': '🔵', 'priority': 5}
        }
    
    def aggregate_findings(self, findings: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """Aggregate findings with CVSS categorization and summary"""
        
        # Categorize by severity
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        # Categorize by OWASP module
        by_module = {}
        
        # Categorize by vulnerability type
        by_type = {}
        
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            module = finding.get('owasp', 'Unknown')
            vuln_type = finding.get('title', 'Unknown').split(' - ')[-1] if ' - ' in finding.get('title', '') else 'General'
            
            # Add to severity category
            if severity in categorized:
                categorized[severity].append(finding)
            
            # Add to module category
            if module not in by_module:
                by_module[module] = []
            by_module[module].append(finding)
            
            # Add to type category
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(finding)
        
        # Calculate statistics
        stats = {
            'total_findings': len(findings),
            'by_severity': {sev: len(findings) for sev, findings in categorized.items()},
            'by_module': {module: len(findings) for module, findings in by_module.items()},
            'by_type': {vuln_type: len(findings) for vuln_type, findings in by_type.items()},
            'risk_score': self._calculate_risk_score(findings),
            'scan_timestamp': datetime.now().isoformat()
        }
        
        return {
            'target': target,
            'summary': stats,
            'categorized': categorized,
            'by_module': by_module,
            'by_type': by_type,
            'all_findings': findings
        }
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score based on CVSS severity"""
        if not findings:
            return 0.0
        
        total_score = 0.0
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            cvss_info = self.cvss_severity_mapping.get(severity, self.cvss_severity_mapping['medium'])
            total_score += cvss_info['score']
        
        return round(total_score / len(findings), 2)
    
    def generate_cvss_report(self, aggregated_results: Dict[str, Any]) -> str:
        """Generate detailed CVSS report"""
        
        report = f"""
🔍 OWASP Vulnerability Scan Report - CVSS Analysis
{'='*60}

🎯 Target: {aggregated_results['target']}
📅 Scan Date: {datetime.fromisoformat(aggregated_results['summary']['scan_timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
⚠️  Overall Risk Score: {aggregated_results['summary']['risk_score']}/10.0

📊 FINDINGS SUMMARY
{'-'*30}
"""
        
        # Severity breakdown
        for severity, findings in aggregated_results['categorized'].items():
            if findings:
                cvss_info = self.cvss_severity_mapping[severity]
                report += f"{cvss_info['color']} {severity.upper()}: {len(findings)} findings (CVSS: {cvss_info['score']}+)\n"
        
        report += f"\n📈 TOTAL: {aggregated_results['summary']['total_findings']} vulnerabilities found\n"
        
        # Module breakdown
        report += f"\n🔧 BY OWASP MODULE\n{'-'*20}\n"
        for module, findings in aggregated_results['by_module'].items():
            if findings:
                report += f"• {module}: {len(findings)} findings\n"
        
        # Critical and High findings details
        critical_high = aggregated_results['categorized']['critical'] + aggregated_results['categorized']['high']
        if critical_high:
            report += f"\n🚨 CRITICAL & HIGH FINDINGS\n{'-'*30}\n"
            for i, finding in enumerate(critical_high[:5], 1):  # Show top 5
                severity = finding.get('severity', 'medium')
                cvss_info = self.cvss_severity_mapping[severity]
                report += f"{i}. {cvss_info['color']} {finding.get('title', 'Unknown')}\n"
                report += f"   📍 {finding.get('location', 'Unknown')}\n"
                report += f"   📝 {finding.get('description', 'No description')[:100]}...\n\n"
        
        return report
    
    def export_cvss_json(self, aggregated_results: Dict[str, Any], filename: str = None) -> str:
        """Export aggregated results to JSON with CVSS data"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cvss_report_{aggregated_results['target'].replace('.', '_')}_{timestamp}.json"
        
        # Add CVSS metadata
        cvss_report = {
            'metadata': {
                'target': aggregated_results['target'],
                'scan_timestamp': aggregated_results['summary']['scan_timestamp'],
                'report_version': '1.0',
                'cvss_version': '3.1',
                'generator': 'OWASP Master Adapter'
            },
            'risk_assessment': {
                'overall_risk_score': aggregated_results['summary']['risk_score'],
                'risk_level': self._get_risk_level(aggregated_results['summary']['risk_score']),
                'total_vulnerabilities': aggregated_results['summary']['total_findings']
            },
            'findings_summary': aggregated_results['summary'],
            'detailed_findings': aggregated_results['all_findings'],
            'categorized_findings': aggregated_results['categorized']
        }
        
        # Save to file
        os.makedirs('cvss_reports', exist_ok=True)
        filepath = os.path.join('cvss_reports', filename)
        
        import json
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cvss_report, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on CVSS score"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        elif score >= 0.1:
            return 'Low'
        else:
            return 'Info'

class OWASPMasterAdapter:
    """Master adapter for OWASP Top 10 2021 vulnerability scanning"""
    
    def __init__(self):
        self.available_modules = get_available_modules() if MASTER_SCANNER_AVAILABLE else []
        self.module_info = {}
        self.aggregator = VulnerabilityResultAggregator()
        
        # Cache module information
        for module_code in self.available_modules:
            info = get_module_info(module_code)
            if info:
                self.module_info[module_code] = info
    
    def get_available_modules(self) -> List[str]:
        """Get list of available OWASP modules"""
        return self.available_modules.copy()
    
    def get_module_info(self, module_code: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific module"""
        return self.module_info.get(module_code)
    
    def scan_single_module(self, target: str, module_code: str) -> List[Dict[str, Any]]:
        """Scan target with a single OWASP module"""
        if not MASTER_SCANNER_AVAILABLE:
            logger.error("OWASP Master Scanner not available")
            return []
        
        if module_code not in self.available_modules:
            logger.error(f"Module {module_code} not available")
            return []
        
        try:
            logger.info(f"Running single module scan: {module_code} for target: {target}")
            result = scan_target(target, [module_code])
            
            if result['status'] == 'completed':
                # Extract findings from the specific module
                module_result = result['results'].get(module_code, {})
                findings = module_result.get('findings', [])
                logger.info(f"Module {module_code} completed with {len(findings)} findings")
                return findings
            else:
                logger.error(f"Module {module_code} failed: {result.get('error', 'Unknown error')}")
                return []
                
        except Exception as e:
            logger.error(f"Error running module {module_code}: {e}")
            return []
    
    def scan_multiple_modules(self, target: str, module_codes: List[str]) -> List[Dict[str, Any]]:
        """Scan target with multiple OWASP modules"""
        if not MASTER_SCANNER_AVAILABLE:
            logger.error("OWASP Master Scanner not available")
            return []
        
        # Validate module codes
        valid_modules = [m for m in module_codes if m in self.available_modules]
        if not valid_modules:
            logger.error(f"No valid modules specified: {module_codes}")
            return []
        
        try:
            logger.info(f"Running multi-module scan: {', '.join(valid_modules)} for target: {target}")
            result = scan_target(target, valid_modules)
            
            if result['status'] == 'completed':
                # Combine findings from all modules
                all_findings = []
                for module_code in valid_modules:
                    module_result = result['results'].get(module_code, {})
                    findings = module_result.get('findings', [])
                    all_findings.extend(findings)
                
                logger.info(f"Multi-module scan completed with {len(all_findings)} total findings")
                return all_findings
            else:
                logger.error(f"Multi-module scan failed: {result.get('error', 'Unknown error')}")
                return []
                
        except Exception as e:
            logger.error(f"Error running multi-module scan: {e}")
            return []
    
    def scan_all_modules(self, target: str) -> List[Dict[str, Any]]:
        """Scan target with all available OWASP modules"""
        return self.scan_multiple_modules(target, self.available_modules)
    
    def scan_with_cvss_analysis(self, target: str, module_codes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan target and return aggregated results with CVSS analysis"""
        
        # Run scan
        if module_codes:
            findings = self.scan_multiple_modules(target, module_codes)
        else:
            findings = self.scan_all_modules(target)
        
        # Aggregate results
        aggregated = self.aggregator.aggregate_findings(findings, target)
        
        # Generate CVSS report
        cvss_report = self.aggregator.generate_cvss_report(aggregated)
        
        # Export JSON
        json_file = self.aggregator.export_cvss_json(aggregated)
        
        return {
            'target': target,
            'findings': findings,
            'aggregated': aggregated,
            'cvss_report': cvss_report,
            'json_file': json_file
        }
    
    def get_scan_summary(self, target: str, module_codes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get scan summary without running the scan"""
        if not MASTER_SCANNER_AVAILABLE:
            return {
                'status': 'error',
                'error': 'OWASP Master Scanner not available',
                'available_modules': [],
                'target': target
            }
        
        modules_to_scan = module_codes if module_codes else self.available_modules
        valid_modules = [m for m in modules_to_scan if m in self.available_modules]
        
        return {
            'status': 'ready',
            'target': target,
            'modules_requested': module_codes,
            'modules_available': valid_modules,
            'total_modules': len(valid_modules),
            'available_modules': self.available_modules
        }

# Global adapter instance
_master_adapter = None

def get_master_adapter() -> OWASPMasterAdapter:
    """Get the global master adapter instance"""
    global _master_adapter
    if _master_adapter is None:
        _master_adapter = OWASPMasterAdapter()
    return _master_adapter

# Convenience functions for backward compatibility
def run(target: str, context: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    """
    Main entry point for vulnerability scanning.
    This replaces all individual adapter run() functions.
    
    Args:
        target: Target URL or IP to scan
        context: Optional context dictionary with scan parameters:
                - modules: List of module codes to run (e.g., ['A01', 'A03', 'A05'])
                - profile: Scan profile ('quick', 'full', 'custom')
                - timeout: Scan timeout in seconds
    
    Returns:
        List of vulnerability findings
    """
    adapter = get_master_adapter()
    
    if not MASTER_SCANNER_AVAILABLE:
        logger.error("OWASP Master Scanner not available")
        return []
    
    # Extract scan parameters from context
    modules = None
    if context:
        modules = context.get('modules')
        profile = context.get('profile', 'full')
        
        # Map profile to modules if not specified
        if not modules and profile == 'quick':
            # Quick scan: most critical modules
            modules = ['A01', 'A03', 'A05']
        elif not modules and profile == 'custom':
            # Custom scan: user can specify modules in context
            modules = context.get('custom_modules', ['A01', 'A02', 'A03'])
    
    try:
        if modules:
            logger.info(f"Running targeted scan with modules: {', '.join(modules)}")
            return adapter.scan_multiple_modules(target, modules)
        else:
            logger.info("Running full scan with all available modules")
            return adapter.scan_all_modules(target)
            
    except Exception as e:
        logger.error(f"Error in vulnerability scan: {e}")
        return []

def run_with_cvss_analysis(target: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    Run vulnerability scan with CVSS analysis and aggregation
    
    Args:
        target: Target URL or IP to scan
        context: Optional context dictionary with scan parameters
    
    Returns:
        Dictionary containing findings, aggregated results, CVSS report, and JSON file
    """
    adapter = get_master_adapter()
    
    if not MASTER_SCANNER_AVAILABLE:
        logger.error("OWASP Master Scanner not available")
        return {'error': 'OWASP Master Scanner not available'}
    
    # Extract scan parameters from context
    modules = None
    if context:
        modules = context.get('modules')
        profile = context.get('profile', 'full')
        
        # Map profile to modules if not specified
        if not modules and profile == 'quick':
            modules = ['A01', 'A03', 'A05']
        elif not modules and profile == 'custom':
            modules = context.get('custom_modules', ['A01', 'A02', 'A03'])
    
    try:
        logger.info(f"Running CVSS analysis scan for target: {target}")
        return adapter.scan_with_cvss_analysis(target, modules)
            
    except Exception as e:
        logger.error(f"Error in CVSS analysis scan: {e}")
        return {'error': str(e)}

def aggregate_existing_results(target: str, scan_duration: float = 0.0) -> Dict[str, Any]:
    """
    Tổng hợp kết quả từ các module đã có sẵn output
    
    Args:
        target: Target URL/IP
        scan_duration: Thời gian scan (seconds)
    
    Returns:
        Dictionary chứa kết quả tổng hợp
    """
    try:
        from .owasp_result_aggregator import aggregate_owasp_results
        return aggregate_owasp_results(target, scan_duration)
    except ImportError as e:
        logger.error(f"Failed to import owasp_result_aggregator: {e}")
        return {'error': f'Failed to import aggregator: {e}'}
    except Exception as e:
        logger.error(f"Error aggregating results: {e}")
        return {'error': str(e)}

def get_available_modules() -> List[str]:
    """Get list of available OWASP modules"""
    if not MASTER_SCANNER_AVAILABLE:
        return []
    # Direct call to OWASP_MASTER_SCANNER to avoid recursion
    try:
        from .module_vuln_scan.OWASP_MASTER_SCANNER import get_available_modules as master_get_modules
        return master_get_modules()
    except:
        # Fallback to adapter
        adapter = get_master_adapter()
        return adapter.get_available_modules()

def get_module_info(module_code: str) -> Optional[Dict[str, Any]]:
    """Get information about a specific module"""
    if not MASTER_SCANNER_AVAILABLE:
        return None
    # Direct call to OWASP_MASTER_SCANNER to avoid recursion
    try:
        from .module_vuln_scan.OWASP_MASTER_SCANNER import get_module_info as master_get_info
        return master_get_info(module_code)
    except:
        # Fallback to adapter
        adapter = get_master_adapter()
        return adapter.get_module_info(module_code)

def scan_single_module(target: str, module_code: str) -> List[Dict[str, Any]]:
    """Scan target with a single OWASP module"""
    adapter = get_master_adapter()
    return adapter.scan_single_module(target, module_code)

def scan_multiple_modules(target: str, module_codes: List[str]) -> List[Dict[str, Any]]:
    """Scan target with multiple OWASP modules"""
    adapter = get_master_adapter()
    return adapter.scan_multiple_modules(target, module_codes)

def scan_all_modules(target: str) -> List[Dict[str, Any]]:
    """Scan target with all available OWASP modules"""
    adapter = get_master_adapter()
    return adapter.scan_all_modules(target)

# Legacy adapter compatibility functions
def run_a01_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A01 scan"""
    return scan_single_module(target, 'A01')

def run_a02_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A02 scan"""
    return scan_single_module(target, 'A02')

def run_a03_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A03 scan"""
    return scan_single_module(target, 'A03')

def run_a04_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A04 scan"""
    return scan_single_module(target, 'A04')

def run_a05_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A05 scan"""
    return scan_single_module(target, 'A05')

def run_a06_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A06 scan"""
    return scan_single_module(target, 'A06')

def run_a07_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A07 scan"""
    return scan_single_module(target, 'A07')

def run_a08_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A08 scan"""
    return scan_single_module(target, 'A08')

def run_a09_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A09 scan"""
    return scan_single_module(target, 'A09')

def run_a10_scan(target: str) -> List[Dict[str, Any]]:
    """Legacy function for A10 scan"""
    return scan_single_module(target, 'A10')

