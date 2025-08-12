"""
OWASP Master Scanner API
Main entry point for vulnerability scanning in ShadowProbe Web.
This replaces the CLI interface with a proper API for integration.
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Configure logging
def setup_logging():
    """Setup logging with better structure"""
    try:
        # Try to use enhanced logging if available
        from core.enhanced_logging import get_enhanced_logger
        logger = get_enhanced_logger()
        if logger and hasattr(logger, 'info'):
            logger.info("Using enhanced logging system")
        else:
            raise ImportError("Enhanced logger not properly initialized")
    except ImportError:
        # Fallback to basic logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('owasp_master_scanner.log')
            ]
        )
        logger = logging.getLogger(__name__)
        logger.info("Using basic logging system")
    
    return logger

logger = setup_logging()

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import all vulnerability modules
try:
    import A01
    import A02
    import A03
    import A04
    import A05
    import A06
    import A07
    import A08
    import A09
    import A10
    MODULES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Some modules not available: {e}")
    MODULES_AVAILABLE = False

# ================== CONFIG ==================
def get_master_output_dir():
    """Get master output directory with fallback"""
    try:
        # Try environment variable first
        base_dir = os.getenv('SHADOWPROBE_OUTPUT_DIR', 'reports')
        
        # Ensure base directory exists
        if not os.path.exists(base_dir):
            os.makedirs(base_dir, exist_ok=True)
        
        master_dir = os.path.join(base_dir, 'owasp_master_results')
        os.makedirs(master_dir, exist_ok=True)
        
        # Verify write permissions
        test_file = os.path.join(master_dir, '.test_write')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except (IOError, OSError):
            # Fallback to current directory if no write permissions
            master_dir = os.path.join(os.getcwd(), 'owasp_master_results')
            os.makedirs(master_dir, exist_ok=True)
        
        return master_dir
        
    except Exception as e:
        # Ultimate fallback to current directory
        fallback_dir = os.path.join(os.getcwd(), 'owasp_master_results')
        os.makedirs(fallback_dir, exist_ok=True)
        return fallback_dir

MASTER_OUTPUT_DIR = get_master_output_dir()

# Module registry
VULNERABILITY_MODULES = {
    'A01': {
        'name': 'Broken Access Control',
        'module': A01 if 'A01' in globals() else None,
        'enabled': True
    },
    'A02': {
        'name': 'Cryptographic Failures',
        'module': A02 if 'A02' in globals() else None,
        'enabled': True
    },
    'A03': {
        'name': 'Injection',
        'module': A03 if 'A03' in globals() else None,
        'enabled': True
    },
    'A04': {
        'name': 'Insecure Design',
        'module': A04 if 'A04' in globals() else None,
        'enabled': True
    },
    'A05': {
        'name': 'Security Misconfiguration',
        'module': A05 if 'A05' in globals() else None,
        'enabled': True
    },
    'A06': {
        'name': 'Vulnerable and Outdated Components',
        'module': A06 if 'A06' in globals() else None,
        'enabled': True
    },
    'A07': {
        'name': 'Identification and Authentication Failures',
        'module': A07 if 'A07' in globals() else None,
        'enabled': True
    },
    'A08': {
        'name': 'Software and Data Integrity Failures',
        'module': A08 if 'A08' in globals() else None,
        'enabled': True
    },
    'A09': {
        'name': 'Security Logging and Monitoring Failures',
        'module': A09 if 'A09' in globals() else None,
        'enabled': True
    },
    'A10': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'module': A10 if 'A10' in globals() else None,
        'enabled': True
    }
}

def create_master_output_dir():
    """Create master output directory"""
    try:
        os.makedirs(MASTER_OUTPUT_DIR, exist_ok=True)
        logger.info(f"Master output directory ready: {MASTER_OUTPUT_DIR}")
    except Exception as e:
        logger.error(f"Failed to create master output directory: {e}")
        # Fallback to current directory
        fallback_dir = "owasp_master_results"
        os.makedirs(fallback_dir, exist_ok=True)
        logger.info(f"Using fallback directory: {fallback_dir}")
        return fallback_dir
    return MASTER_OUTPUT_DIR

def check_module_exists(module_code: str) -> bool:
    """Check if a vulnerability module exists and is available"""
    if not MODULES_AVAILABLE:
        return False
    
    module_info = VULNERABILITY_MODULES.get(module_code)
    if not module_info:
        return False
    
    return module_info['module'] is not None and module_info['enabled']

def run_module(module_code: str, target: str) -> Dict[str, Any]:
    """Run a specific vulnerability module and return results"""
    if not check_module_exists(module_code):
        logger.error(f"Module {module_code} not available")
        return {
            'module': module_code,
            'status': 'error',
            'error': f'Module {module_code} not available',
            'findings': [],
            'execution_time': 0,
            'target': target
        }
    
    module_info = VULNERABILITY_MODULES[module_code]
    module = module_info['module']
    
    start_time = time.time()
    findings = []
    
    try:
        logger.info(f"Running {module_code} module for target: {target}")
        
        # Call the module's main function if it exists
        if hasattr(module, 'main'):
            try:
                # Store original sys.argv to restore later
                original_argv = sys.argv.copy()
                
                # Set up sys.argv for the module
                sys.argv = [f"{module_code}.py", target]
                
                # Call the module's main function with enhanced error handling
                try:
                    module.main(target)
                except TypeError as te:
                    # Handle case where main() doesn't take arguments
                    if "main() takes 0 positional arguments" in str(te):
                        logger.info(f"Module {module_code} main() called without arguments")
                        module.main()
                    else:
                        raise
                
                # Restore original sys.argv
                sys.argv = original_argv
                
                # Parse results from module's output files
                findings = parse_module_results(module_code, target)
                logger.info(f"Module {module_code} completed successfully with {len(findings)} findings")
                
            except Exception as module_error:
                logger.error(f"Error in module {module_code} execution: {module_error}")
                logger.error(f"Module type: {type(module)}")
                logger.error(f"Module attributes: {dir(module)}")
                findings = []
                
        else:
            logger.warning(f"Module {module_code} does not have a main function")
            # Try to call the module directly as a fallback
            try:
                if callable(module):
                    module(target)
                    findings = parse_module_results(module_code, target)
                    logger.info(f"Module {module_code} called directly, found {len(findings)} findings")
                else:
                    logger.error(f"Module {module_code} is not callable")
            except Exception as fallback_error:
                logger.error(f"Fallback execution failed for {module_code}: {fallback_error}")
                findings = []
            findings = []
        
        execution_time = time.time() - start_time
        
        return {
            'module': module_code,
            'status': 'completed',
            'findings': findings,
            'execution_time': execution_time,
            'target': target
        }
        
    except Exception as e:
        execution_time = time.time() - start_time
        logger.error(f"Error running {module_code} module: {e}")
        
        return {
            'module': module_code,
            'status': 'error',
            'error': str(e),
            'findings': [],
            'execution_time': execution_time,
            'target': target
        }

def parse_module_results(module_code: str, target: str) -> List[Dict[str, Any]]:
    """Parse results from module output files with secure path handling"""
    findings = []
    
    # Define output file patterns for each module
    output_patterns = {
        'A01': ['a01_detailed_report.txt', 'auth_bypass_findings.txt', 'privilege_escalation_findings.txt'],
        'A02': ['a02_detailed_report.txt', 'weak_ciphers_findings.txt', 'certificate_issues_findings.txt'],
        'A03': ['a03_detailed_report.txt', 'sql_injection_findings.txt', 'sqlmap_output.txt'],
        'A04': ['a04_detailed_report.txt', 'business_logic_findings.txt', 'idor_findings.txt'],
        'A05': ['a05_detailed_report.txt', 'default_credentials_findings.txt', 'directory_listing_findings.txt'],
        'A06': ['a06_detailed_report.txt', 'vulnerable_components_findings.txt', 'outdated_versions_findings.txt'],
        'A07': ['a07_detailed_report.txt', 'auth_failures_findings.txt', 'weak_passwords_findings.txt'],
        'A08': ['a08_detailed_report.txt', 'integrity_failures_findings.txt', 'supply_chain_findings.txt'],
        'A09': ['a09_detailed_report.txt', 'logging_failures_findings.txt', 'monitoring_failures_findings.txt'],
        'A10': ['a10_detailed_report.txt', 'ssrf_findings.txt', 'internal_network_findings.txt']
    }
    
    patterns = output_patterns.get(module_code, [])
    
    # Secure path construction to prevent path traversal
    try:
        # Use absolute path and ensure it's within allowed directories
        base_dir = os.path.abspath(os.getcwd())
        reports_dir = os.path.join(base_dir, 'reports')
        
        # Ensure reports directory exists and is within base_dir
        if not os.path.commonpath([reports_dir, base_dir]) == base_dir:
            logger.error(f"Reports directory path traversal detected: {reports_dir}")
            return findings
        
        module_output_dir = os.path.join(reports_dir, f"{module_code.lower()}_scan_results")
        
        # Ensure module output directory is within reports directory
        if not os.path.commonpath([module_output_dir, reports_dir]) == reports_dir:
            logger.error(f"Module output directory path traversal detected: {module_output_dir}")
            return findings
        
        # Create directory if it doesn't exist
        os.makedirs(module_output_dir, exist_ok=True)
        
    except Exception as e:
        logger.error(f"Error setting up secure paths: {e}")
        return findings
    
    for pattern in patterns:
        # Validate filename pattern to prevent path traversal
        if '..' in pattern or '/' in pattern or '\\' in pattern:
            logger.warning(f"Skipping suspicious filename pattern: {pattern}")
            continue
            
        file_path = os.path.join(module_output_dir, pattern)
        
        # Final security check - ensure file path is within module output directory
        try:
            file_path = os.path.abspath(file_path)
            if not os.path.commonpath([file_path, module_output_dir]) == module_output_dir:
                logger.error(f"File path traversal detected: {file_path}")
                continue
        except Exception as e:
            logger.error(f"Error validating file path: {e}")
            continue
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Extract findings from content
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('===') and not line.startswith('#'):
                            # Create a finding object
                            finding = {
                                'owasp': module_code,
                                'severity': 'medium',  # Default severity
                                'title': f'{module_code} - {pattern.replace("_findings.txt", "").replace("_", " ").title()}',
                                'description': line,
                                'recommendation': f'Review and fix {module_code} vulnerabilities',
                                'location': target,
                                'evidence': {'file': pattern, 'content': line[:200]},
                                'tags': [module_code, 'automated_scan']
                            }
                            
                            # Try to extract severity from line
                            if any(keyword in line.lower() for keyword in ['critical', 'high', 'medium', 'low']):
                                if 'critical' in line.lower():
                                    finding['severity'] = 'critical'
                                elif 'high' in line.lower():
                                    finding['severity'] = 'high'
                                elif 'low' in line.lower():
                                    finding['severity'] = 'low'
                            
                            findings.append(finding)
                            
            except Exception as e:
                logger.error(f"Error parsing {file_path}: {e}")
    
    return findings

def collect_results() -> Dict[str, Any]:
    """Collect results from all module output directories"""
    all_results = {}
    
    for module_code in VULNERABILITY_MODULES.keys():
        module_output_dir = f"reports/{module_code.lower()}_scan_results"
        if os.path.exists(module_output_dir):
            all_results[module_code] = {
                'output_dir': module_output_dir,
                'files': os.listdir(module_output_dir) if os.path.exists(module_output_dir) else []
            }
    
    return all_results

def generate_master_report(target: str, results: Dict[str, Any], execution_stats: Dict[str, Any]) -> str:
    """Generate a comprehensive master report"""
    report = f"""
OWASP Master Vulnerability Scan Report
=====================================

Target: {target}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Modules: {len(results)}
Completed Modules: {len([r for r in results.values() if r.get('status') == 'completed'])}
Failed Modules: {len([r for r in results.values() if r.get('status') == 'error'])}

Execution Statistics:
"""
    
    total_time = 0
    total_findings = 0
    
    for module_code, result in results.items():
        if result.get('status') == 'completed':
            execution_time = result.get('execution_time', 0)
            findings_count = len(result.get('findings', []))
            total_time += execution_time
            total_findings += findings_count
            
            report += f"""
{module_code} - {VULNERABILITY_MODULES[module_code]['name']}:
  Status: {result.get('status', 'unknown')}
  Execution Time: {execution_time:.2f}s
  Findings: {findings_count}
"""
        else:
            report += f"""
{module_code} - {VULNERABILITY_MODULES[module_code]['name']}:
  Status: {result.get('status', 'unknown')}
  Error: {result.get('error', 'Unknown error')}
"""
    
    report += f"""
Summary:
  Total Execution Time: {total_time:.2f}s
  Total Findings: {total_findings}
  Average Time per Module: {total_time / len(results):.2f}s
"""
    
    return report

def display_master_results(results: Dict[str, Any], execution_stats: Dict[str, Any]):
    """Display master scan results"""
    logger.info("=== OWASP Master Scan Results ===")
    
    completed = 0
    failed = 0
    total_findings = 0
    
    for module_code, result in results.items():
        status = result.get('status', 'unknown')
        if status == 'completed':
            completed += 1
            findings_count = len(result.get('findings', []))
            total_findings += findings_count
            logger.info(f"✅ {module_code}: {findings_count} findings")
        else:
            failed += 1
            error = result.get('error', 'Unknown error')
            logger.error(f"❌ {module_code}: {error}")
    
    logger.info(f"\nSummary: {completed} completed, {failed} failed, {total_findings} total findings")

# ================== MAIN API FUNCTIONS ==================

def scan_target(target: str, modules: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Main API function to scan a target with specified OWASP modules.
    
    Args:
        target: The target URL or IP to scan
        modules: List of module codes to run (e.g., ['A01', 'A03', 'A05'])
                If None, runs all available modules
    
    Returns:
        Dictionary containing scan results and metadata
    """
    if not MODULES_AVAILABLE:
        return {
            'status': 'error',
            'error': 'Vulnerability modules not available',
            'results': {},
            'summary': {}
        }
    
    # Validate target
    if not target or not isinstance(target, str):
        return {
            'status': 'error',
            'error': 'Invalid target provided',
            'results': {},
            'summary': {}
        }
    
    # Determine which modules to run
    if modules is None:
        modules_to_run = list(VULNERABILITY_MODULES.keys())
    else:
        modules_to_run = [m for m in modules if m in VULNERABILITY_MODULES]
    
    if not modules_to_run:
        return {
            'status': 'error',
            'error': 'No valid modules specified',
            'results': {},
            'summary': {}
        }
    
    logger.info(f"Starting OWASP master scan for target: {target}")
    logger.info(f"Modules to run: {', '.join(modules_to_run)}")
    
    # Create output directory
    create_master_output_dir()
    
    # Run modules
    results = {}
    start_time = time.time()
    
    for module_code in modules_to_run:
        logger.info(f"Running module {module_code}...")
        result = run_module(module_code, target)
        results[module_code] = result
    
    total_time = time.time() - start_time
    
    # Generate summary
    summary = {
        'target': target,
        'modules_requested': modules,
        'modules_run': modules_to_run,
        'total_execution_time': total_time,
        'completed_modules': len([r for r in results.values() if r.get('status') == 'completed']),
        'failed_modules': len([r for r in results.values() if r.get('status') == 'error']),
        'total_findings': sum(len(r.get('findings', [])) for r in results.values() if r.get('status') == 'completed')
    }
    
    # Generate master report
    master_report = generate_master_report(target, results, summary)
    report_path = os.path.join(MASTER_OUTPUT_DIR, f"master_report_{target.replace('://', '_').replace('/', '_')}.txt")
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(master_report)
    except Exception as e:
        logger.error(f"Error saving master report: {e}")
    
    # Display results
    display_master_results(results, summary)
    
    return {
        'status': 'completed',
        'results': results,
        'summary': summary,
        'report_path': report_path
    }

def get_available_modules() -> List[str]:
    """Get list of available vulnerability modules"""
    return [code for code, info in VULNERABILITY_MODULES.items() 
            if check_module_exists(code)]

def get_module_info(module_code: str) -> Optional[Dict[str, Any]]:
    """Get information about a specific module"""
    if module_code not in VULNERABILITY_MODULES:
        return None
    
    module_info = VULNERABILITY_MODULES[module_code]
    return {
        'code': module_code,
        'name': module_info['name'],
        'available': check_module_exists(module_code),
        'enabled': module_info['enabled']
    }

# Legacy CLI support (for backward compatibility)
def main():
    """Legacy CLI entry point for backward compatibility"""
    if len(sys.argv) < 2:
        print("Usage: python OWASP_MASTER_SCANNER.py <target_url> [module1,module2,...]")
        sys.exit(1)
    
    target = sys.argv[1]
    modules = None
    
    if len(sys.argv) > 2:
        modules = sys.argv[2].split(',')
    
    result = scan_target(target, modules)
    
    if result['status'] == 'completed':
        print(f"\n✅ Scan completed successfully!")
        print(f"📊 Total findings: {result['summary']['total_findings']}")
        print(f"⏱️  Total time: {result['summary']['total_execution_time']:.2f}s")
    else:
        print(f"\n❌ Scan failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
