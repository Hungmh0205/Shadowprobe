import sys
import asyncio
import socket # Added for fallback port scanning
import ast

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.set_event_loop(asyncio.SelectorEventLoop())

from flask import Flask, request, jsonify, render_template, session, send_file
from flask_cors import CORS
import logging
import time
import threading
from datetime import datetime
import json
from pathlib import Path
import tempfile
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Import ShadowProbe components
from core.models import ScanResult, ScanType, Service, HostInfo
from scanner.port_scanner import PortScanner
from scanner.host_resolver import HostResolver
from core.reporter import ReportGenerator
from core.db_sqlite import add_scan, history_scan, get_scan_by_id, get_scan_by_target, get_scan_by_scan_type, init_db
from core.db_sqlite import save_scan_results, get_scan_results
from core.db_sqlite import SessionLocal, ScanHistory
from core.db_sqlite import add_website, get_all_websites, delete_website_by_id, update_website_by_id
from core.db_sqlite import Website
# Thay thế import SubdomainScanner
# from scanner.Subdomain.engine import SubdomainScanner

from scanner.knock import knockpy
import asyncio

from scanner.knock.knockpy import KNOCKPY
from scanner.knock.knockpy import scan_subdomains_cli
from core.async_scan_manager import get_scan_manager, start_scan as async_start_scan, get_scan_status as async_get_scan_status
from scanner.knock.knockpy import get_subdomains_advanced

app = Flask(__name__)
app.secret_key = 'shadowprobe_web_secret_key_2024'
CORS(app)
init_db()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize ShadowProbe components
port_scanner = PortScanner()
host_resolver = HostResolver()
report_generator = ReportGenerator()

# Global scan status
scan_status = {}
scan_results = {}

from flask import request, jsonify
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=10)

def validate_input(target):
    """Validate IP address or domain name (accepts common formats)"""
    import re
    target = target.strip().lower()
    
    # IPv4
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}" \
                 r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    
    # Domain (supports subdomains & TLDs)
    domain_pattern = r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
    
    return re.match(ip_pattern, target) or re.match(domain_pattern, target)

def is_domain(target):
    """Check if target is a domain"""
    import re
    ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return not re.match(ip_pattern, target)

# Sửa to_subdomain_entry_list để nhận tuple (subdomain, valid)
def to_subdomain_entry_list(subdomains, http_alive):
    result = []
    for s in subdomains or []:
        if isinstance(s, tuple) and len(s) == 2:
            sub, valid = s
            result.append({"subdomain": sub, "valid": valid})
        # Nếu là string dạng dict, parse lại thành dict
        if isinstance(s, str) and s.strip().startswith('{') and s.strip().endswith('}'):
            try:
                s = ast.literal_eval(s)
            except Exception:
                pass
        if isinstance(s, dict):
            if "domain" in s:
                domain_val = s.get("domain")
                if isinstance(domain_val, list) and domain_val:
                    domain_val = domain_val[0]
                if not isinstance(domain_val, str):
                    domain_val = str(domain_val)
                # valid: True nếu có ip hợp lệ, False nếu ip là None hoặc rỗng
                ip_val = s.get("ip")
                is_valid = bool(ip_val and ((isinstance(ip_val, list) and len(ip_val) > 0) or (isinstance(ip_val, str) and ip_val)))
                result.append({
                    "subdomain": domain_val,
                    "valid": is_valid,
                    "ip": s.get("ip"),
                    "http": s.get("http"),
                    "https": s.get("https"),
                    "cert": s.get("cert")
                })
            elif "subdomain" in s and "valid" in s:
                sub_val = s["subdomain"]
                if isinstance(sub_val, list) and sub_val:
                    sub_val = sub_val[0]
                if not isinstance(sub_val, str):
                    sub_val = str(sub_val)
                result.append({"subdomain": sub_val, "valid": bool(s["valid"])})
        elif isinstance(s, str):
            result.append({"subdomain": s, "valid": s in (http_alive or {})})
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scans')
def scans():
    return render_template('scans.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')  # Dashboard sử dụng template index.html

@app.route('/favicon.ico')
def favicon():
    """Serve favicon to prevent 404 errors"""
    return '', 204  # No content response

@app.route('/api/scan', methods=['POST'])
def start_scan():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        target = data.get('target', '').strip()
        website_id = data.get('website_id')  # Thêm website_id
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not validate_input(target):
            return jsonify({'error': 'Invalid IP or domain format'}), 400
        
        # Generate scan ID
        scan_id = f"scan_{int(time.time())}_{target.replace('.', '_')}"
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Initializing scan...',
            'start_time': datetime.now().isoformat(),
            'target': target,
            'scan_type': 'full',
            'website_id': website_id  # Lưu website_id vào status
        }
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan,
            args=(scan_id, target, website_id)  # Truyền website_id
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scan_v2', methods=['POST'])
async def start_scan_v2():
    """New async scan endpoint using AsyncScanManager"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'full')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        if not validate_input(target):
            return jsonify({'error': 'Invalid IP or domain format'}), 400
        
        # Start scan using AsyncScanManager
        scan_id = await async_start_scan(target, scan_type)
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started successfully',
            'scan_type': scan_type
        })
    except Exception as e:
        logger.error(f"Error starting scan v2: {e}")
        return jsonify({'error': 'Internal server error'}), 500


def run_scan(scan_id, target, website_id=None):
    start_time = time.time()
    try:
        logger.info(f"Starting scan {scan_id} for target {target}")
        scan_status[scan_id]['message'] = 'Resolving host information...'
        scan_status[scan_id]['progress'] = 10
        
        # Resolve host information (sync)
        logger.info(f"Resolving host information for {target}")
        
        # Fix host resolution - resolve domain to multiple IPs
        import socket
        try:
            if is_domain(target):
                # Resolve domain to multiple IPs
                resolved_ips = socket.gethostbyname_ex(target)[2]
                host_info_data = {
                    'ips': resolved_ips, 
                    'hostnames': [target], 
                    'primary_ip': resolved_ips[0] if resolved_ips else None, 
                    'primary_hostname': target
                }
                logger.info(f"Resolved domain {target} to IPs: {resolved_ips}")
            else:
                # Target is already an IP
                host_info_data = {
                    'ips': [target], 
                    'hostnames': [], 
                    'primary_ip': target, 
                    'primary_hostname': None
                }
        except Exception as e:
            logger.warning(f"Failed to resolve {target}: {e}, using target as IP")
            host_info_data = {
                'ips': [target], 
                'hostnames': [], 
                'primary_ip': target, 
                'primary_hostname': None
            }
        
        logger.info(f"Host info result: {host_info_data}")
        
        # Convert lists to strings for HostInfo fields
        primary_ip = host_info_data.get('primary_ip', None)
        primary_hostname = host_info_data.get('primary_hostname', None)
        # Ensure primary_ip and primary_hostname are strings, not lists
        if isinstance(primary_ip, list) and primary_ip:
            primary_ip = str(primary_ip[0])
        elif primary_ip is not None:
            primary_ip = str(primary_ip)
        if isinstance(primary_hostname, list) and primary_hostname:
            primary_hostname = str(primary_hostname[0])
        elif primary_hostname is not None:
            primary_hostname = str(primary_hostname)
        # Ensure ips and hostnames are lists
        raw_ips = host_info_data.get('ips', [])
        raw_hostnames = host_info_data.get('hostnames', [])
        ips_list = raw_ips if isinstance(raw_ips, list) else []
        hostnames_list = raw_hostnames if isinstance(raw_hostnames, list) else []
        
        logger.info(f"Resolved IPs: {ips_list}")
        logger.info(f"Resolved hostnames: {hostnames_list}")
        
        host_info = HostInfo(
            ips=ips_list,
            hostnames=hostnames_list,
            primary_ip=primary_ip,
            primary_hostname=primary_hostname
        )
        scan_status[scan_id]['message'] = 'Starting port scan...'
        scan_status[scan_id]['progress'] = 20
        
        # Multi-IP scan logic (CLI style):
        all_open_ports = set()
        all_services = []
        seen_services = set()
        
        logger.info(f"Starting port scan for {len(ips_list)} IPs")
        for ip in host_info.ips:
            try:
                logger.info(f"Scanning ports for IP: {ip}")
                # Use the available method from legacy PortScanner
                _, services = port_scanner.scan_ports_and_services(ip)
                logger.info(f"Found {len(services)} services for IP {ip}")
                for service in services:
                    # Ensure IP is properly set
                    if not service.ip_address:
                        service.ip_address = ip
                    service_key = (service.port, service.ip_address)
                    if service_key not in seen_services:
                        seen_services.add(service_key)
                        all_services.append(service)
                all_open_ports.update([service.port for service in services])
            except Exception as e:
                logger.error(f"Failed to scan {ip}: {e}")
                # Fallback: try common ports manually
                logger.info(f"Trying fallback scan for common ports on {ip}")
                try:
                    common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 3306, 3389, 8080]
                    for port in common_ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip, port))
                            if result == 0:
                                logger.info(f"Found open port {port} on {ip}")
                                service = Service(
                                    port=port,
                                    protocol="tcp",
                                    service_name="unknown",
                                    version=None,
                                    server_name=None,
                                    ip_address=ip
                                )
                                service_key = (port, ip)
                                if service_key not in seen_services:
                                    seen_services.add(service_key)
                                    all_services.append(service)
                                all_open_ports.add(port)
                            sock.close()
                        except Exception as port_e:
                            logger.debug(f"Port {port} check failed: {port_e}")
                except Exception as fallback_e:
                    logger.error(f"Fallback scan also failed: {fallback_e}")
        
        open_ports = list(all_open_ports)
        services = all_services
        logger.info(f"Total open ports found: {open_ports}")
        logger.info(f"Total services found: {len(services)}")
        
        scan_status[scan_id]['message'] = 'Scanning for subdomains...'
        scan_status[scan_id]['progress'] = 70
        subdomains = []
        subdomain_details = {}
        if is_domain(target):
            logger.info(f"Starting advanced subdomain scan for domain: {target}")
            try:
                subdomain_details = asyncio.run(get_subdomains_advanced(target))
                all_subdomains = subdomain_details.get('all_subdomains', [])
                logger.info(f"Advanced scan found {len(all_subdomains)} subdomains: {all_subdomains}")
                
                # Extract subdomain names from dictionaries
                subdomain_names = []
                for sd in all_subdomains:
                    if isinstance(sd, dict):
                        subdomain_names.append(sd.get('subdomain', ''))
                    else:
                        subdomain_names.append(str(sd))
                
                import aiodns
                import asyncio as _asyncio
                async def get_dns_valid_map(subdomains):
                    resolver = aiodns.DNSResolver()
                    async def resolve_one(sd):
                        try:
                            await resolver.gethostbyname(sd, socket.AF_INET)
                            return sd, True
                        except Exception:
                            return sd, False
                    tasks = [_asyncio.create_task(resolve_one(sd)) for sd in subdomains]
                    results = await _asyncio.gather(*tasks)
                    return dict(results)
                dns_valid_map = _asyncio.run(get_dns_valid_map(subdomain_names))
                # Truyền vào to_subdomain_entry_list
                subdomains = [(sd, dns_valid_map.get(sd, False)) for sd in subdomain_names]
                logger.info(f"DNS valid map: {dns_valid_map}")
            except Exception as e:
                logger.error(f"Advanced subdomain scan failed: {e}")
                subdomains = []
                subdomain_details = {}
        else:
            logger.info(f"Skipping subdomain scan for IP target: {target}")
        
        scan_status[scan_id]['message'] = 'Finalizing results...'
        scan_status[scan_id]['progress'] = 90
        scan_duration = time.time() - start_time
        
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Final results - Ports: {open_ports}, Services: {len(services)}, Subdomains: {len(subdomains)}")
        
        # Defensive fix for ScanResult construction
        flat_subdomains = []
        if subdomains and isinstance(subdomains, dict) and "subdomains" in subdomains and isinstance(subdomains["subdomains"], list):
            for s in subdomains["subdomains"]:
                if isinstance(s, str):
                    flat_subdomains.append(s)
                elif isinstance(s, (list, tuple)):
                    flat_subdomains.extend([x for x in s if isinstance(x, str)])
        try:
            scan_result = ScanResult(
                target=target,
                scan_type=ScanType.PORT_SCAN if hasattr(ScanType, "PORT_SCAN") else "port_scan",
                open_ports=list(open_ports) if open_ports else [],
                services=[s.dict() if hasattr(s, 'dict') else s for s in services] if services else [],
                subdomains=to_subdomain_entry_list(subdomains, None),
                host_info=host_info.dict() if hasattr(host_info, 'dict') else (host_info if host_info else {}),
                scan_duration=scan_duration
            )
        except Exception as e:
            logger.error(f"Error constructing ScanResult: {e}")
            scan_result = ScanResult(
                target=target,
                scan_type="port_scan",
                open_ports=list(open_ports) if open_ports else [],
                services=[s.dict() if hasattr(s, 'dict') else s for s in services] if services else [],
                subdomains=to_subdomain_entry_list(subdomains, None),
                host_info=host_info.dict() if hasattr(host_info, 'dict') else (host_info if host_info else {}),
                scan_duration=scan_duration
            )
        try:
            scan_results[scan_id] = scan_result.dict()
            # Save to database with website_id
            save_scan_results(scan_id, scan_results[scan_id], website_id)
            # Save scan history to database
            add_scan(scan_id, target, 'full', datetime.now(), datetime.now(), scan_duration, 'completed', website_id)
            logger.info(f"Scan results and history saved to database")
        except Exception as e:
            logger.error(f"Error serializing scan result: {e}")
            scan_results[scan_id] = {
                'target': target,
                'scan_type': 'full',
                'open_ports': open_ports,
                'services': [s.dict() if hasattr(s, 'dict') else s for s in services],
                'subdomains': to_subdomain_entry_list(subdomains, None),
                'host_info': host_info.dict() if host_info else None,
                'scan_duration': scan_duration
            }
            # Save to database with website_id
            save_scan_results(scan_id, scan_results[scan_id], website_id)
            # Save scan history to database
            add_scan(scan_id, target, 'full', datetime.now(), datetime.now(), scan_duration, 'completed', website_id)
            logger.info(f"Scan results and history saved to database (fallback)")
        
        scan_status[scan_id]['status'] = 'completed'
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['message'] = 'Scan completed successfully'
        scan_status[scan_id]['end_time'] = datetime.now().isoformat()
        logger.info(f"Scan {scan_id} completed successfully in {scan_duration:.2f} seconds")
        
        # Clean up completed scan from memory after a delay
        def cleanup_scan():
            import time
            time.sleep(5)  # Wait 5 seconds before cleanup
            if scan_id in scan_status:
                del scan_status[scan_id]
            if scan_id in scan_results:
                del scan_results[scan_id]
            logger.info(f"Cleaned up scan {scan_id} from memory")
        
        import threading
        cleanup_thread = threading.Thread(target=cleanup_scan)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        scan_status[scan_id]['status'] = 'failed'
        scan_status[scan_id]['message'] = f'Scan failed: {str(e)}'
        
        # Clean up failed scan from memory after a delay
        def cleanup_failed_scan():
            import time
            time.sleep(5)  # Wait 5 seconds before cleanup
            if scan_id in scan_status:
                del scan_status[scan_id]
            if scan_id in scan_results:
                del scan_results[scan_id]
            logger.info(f"Cleaned up failed scan {scan_id} from memory")
        
        import threading
        cleanup_thread = threading.Thread(target=cleanup_failed_scan)
        cleanup_thread.daemon = True
        cleanup_thread.start()

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status from memory or database"""
    try:
        # First try to get from memory (for active scans)
        if scan_id in scan_status:
            return jsonify(scan_status[scan_id])
        
        # Try to get from database
        scan_record = get_scan_by_id(scan_id)
        if scan_record:
            status_data = {
                'scan_id': scan_record.scan_id,
                'target': scan_record.target,
                'scan_type': scan_record.scan_type,
                'status': scan_record.status,
                'start_time': scan_record.start_time.isoformat() if scan_record.start_time is not None else None,
                'end_time': scan_record.end_time.isoformat() if scan_record.end_time is not None else None,
                'duration': scan_record.duration,
                "progress": 100 if str(scan_record.status) == 'completed' else 0, 
                'message': f"Scan {scan_record.status}" if scan_record.status is not None else "Unknown status"
            }
            return jsonify(status_data)
        
        return jsonify({'error': 'Scan not found'}), 404
        
    except Exception as e:
        logger.error(f"Error getting scan status for {scan_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scan/<scan_id>/results')
def get_scan_results_endpoint(scan_id):
    """Get scan results from database or memory"""
    try:
        logger.info(f"Requesting results for scan_id: {scan_id}")
        # First try to get from memory (for active scans)
        if scan_id in scan_results:
            logger.info(f"Found results in memory for scan_id: {scan_id}")
            if scan_status.get(scan_id, {}).get('status') != 'completed':
                logger.warning(f"Scan {scan_id} not completed yet. Status: {scan_status.get(scan_id, {}).get('status')}")
                return jsonify({'error': 'Scan not completed'}), 400
            results = scan_results[scan_id]
        else:
            # Try to get from database
            logger.info(f"Results not in memory, checking database for scan_id: {scan_id}")
            results = get_scan_results(scan_id)
            if not results:
                logger.warning(f"Results not found in database for scan_id: {scan_id}")
                return jsonify({'error': 'Results not found'}), 404
        # Ensure results is serializable
        if hasattr(results, 'dict') and not isinstance(results, dict):
            results = results.dict()
        # Ensure all nested objects are serializable
        if isinstance(results, dict):
            # Convert ScanType enum to string
            if 'scan_type' in results and hasattr(results['scan_type'], 'value'):
                results['scan_type'] = results['scan_type'].value
            if 'services' in results and results['services']:
                for i, service in enumerate(results['services']):
                    if hasattr(service, 'dict') and not isinstance(service, dict):
                        results['services'][i] = service.dict()
            if 'host_info' in results and results['host_info']:
                if hasattr(results['host_info'], 'dict') and not isinstance(results['host_info'], dict):
                    results['host_info'] = results['host_info'].dict()
            # --- FIX: Ensure subdomains is always a list of dicts ---
            if 'subdomains' in results and results['subdomains']:
                filtered_subdomains = []
                for s in results['subdomains']:
                    if isinstance(s, dict):
                        # Keep the original structure but ensure subdomain field exists
                        subdomain_entry = {
                            'subdomain': s.get('subdomain') or s.get('domain'),
                            'valid': s.get('valid', True),
                            'ip': s.get('ip'),
                            'http': s.get('http'),
                            'https': s.get('https'),
                            'cert': s.get('cert'),
                        }
                        filtered_subdomains.append(subdomain_entry)
                    elif isinstance(s, str):
                        # Handle string subdomains
                        filtered_subdomains.append({
                            'subdomain': s,
                            'valid': True
                        })
                results['subdomains'] = filtered_subdomains
        logger.info(f"Successfully prepared results for scan {scan_id}")
        
        # Get scan info from database
        try:
            from core.db_sqlite import get_scan_by_id
            scan_info = get_scan_by_id(scan_id)
            if scan_info:
                return jsonify({
                    'scan_info': {
                        'scan_id': scan_info.scan_id,
                        'target': scan_info.target,
                        'scan_type': scan_info.scan_type,
                        'status': scan_info.status,
                        'start_time': scan_info.start_time.isoformat() if scan_info.start_time else None,
                        'end_time': scan_info.end_time.isoformat() if scan_info.end_time else None,
                        'duration': scan_info.duration
                    },
                    'results': results
                })
        except Exception as e:
            logger.warning(f"Could not get scan info for {scan_id}: {e}")
        
        # Fallback to just results if scan_info not available
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error getting scan results for {scan_id}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/scans')
def list_scans():
    """List all scans"""
    try:
        scans = []
        for scan_id, status in scan_status.items():
            scans.append({
                'scan_id': scan_id,
                'target': status.get('target'),
                'status': status.get('status'),
                'start_time': status.get('start_time'),
                'end_time': status.get('end_time'),
                'scan_type': status.get('scan_type')
            })
        
        return jsonify({'scans': scans})
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def cleanup_temp_file(file_path):
    """Clean up temporary file after download"""
    try:
        if os.path.exists(file_path):
            os.unlink(file_path)
    except Exception as e:
        logger.warning(f"Failed to cleanup temp file {file_path}: {e}")

@app.route('/api/scan/<scan_id>/download')
def download_scan_results(scan_id):
    """Download scan results as JSON file"""
    temp_file_path = None
    try:
        # Try to get results from memory first, then database
        if scan_id in scan_results:
            results = scan_results[scan_id]
            if scan_status.get(scan_id, {}).get('status') != 'completed':
                return jsonify({'error': 'Scan not completed'}), 400
        else:
            # Try database
            results = get_scan_results(scan_id)
            if not results:
                return jsonify({'error': 'Results not found'}), 404
        
        # Create filename
        target = results.get('target', scan_id)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"shadowprobe_scan_{target}_{timestamp}.json"
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as temp_file:
            # Prepare results for JSON serialization
            
            # Convert to dict if it's a Pydantic model
            if hasattr(results, 'dict') and not isinstance(results, dict):
                results = results.dict()
            
            # Ensure all nested objects are serializable
            if isinstance(results, dict):
                # Convert ScanType enum to string
                if 'scan_type' in results and hasattr(results['scan_type'], 'value'):
                    results['scan_type'] = results['scan_type'].value
                
                if 'services' in results and results['services']:
                    for i, service in enumerate(results['services']):
                        if hasattr(service, 'dict') and not isinstance(service, dict):
                            results['services'][i] = service.dict()
                
                if 'host_info' in results and results['host_info']:
                    if hasattr(results['host_info'], 'dict') and not isinstance(results['host_info'], dict):
                        results['host_info'] = results['host_info'].dict()
            
            # Write JSON to temporary file
            json.dump(results, temp_file, indent=2, ensure_ascii=False)
            temp_file_path = temp_file.name
        
        # Send file for download
        response = send_file(
            temp_file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
        # Add cleanup callback
        response.call_on_close(lambda: cleanup_temp_file(temp_file_path))
        return response
        
    except Exception as e:
        # Cleanup on error
        if temp_file_path:
            cleanup_temp_file(temp_file_path)
        logger.error(f"Error downloading scan results: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/info')
def get_system_info():
    """Get system information and scan capabilities"""
    try:
        scan_stats = port_scanner.get_scan_stats()
        resolver_stats = {}
        # Xóa các phần liên quan đến subdomain_scanner cũ
        subdomain_stats = {}
        
        return jsonify({
            'scan_capabilities': {
                'methods': scan_stats.get('methods', []),
                'max_concurrent': scan_stats.get('max_concurrent', 100),
                'timeout': scan_stats.get('timeout', 1.0),
                'banner_timeout': scan_stats.get('banner_timeout', 3.0)
            },
            'resolver_capabilities': resolver_stats,
            'subdomain_capabilities': subdomain_stats
        })
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/debug/scan/<scan_id>')
def debug_scan(scan_id):
    """Debug endpoint to check scan status and results"""
    try:
        debug_info = {
            'scan_id': scan_id,
            'status_exists': scan_id in scan_status,
            'results_exists': scan_id in scan_results,
            'status': scan_status.get(scan_id, 'NOT_FOUND'),
            'results_keys': list(scan_results.get(scan_id, {}).keys()) if scan_id in scan_results else [],
            'all_scan_ids': list(scan_status.keys()),
            'all_result_ids': list(scan_results.keys())
        }
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e), 'traceback': str(e.__traceback__)}), 500

@app.route('/api/debug/website/<int:website_id>/scans')
def debug_website_scans(website_id):
    """Debug endpoint to check all scans for a website"""
    try:
        debug_info = {
            'website_id': website_id,
            'memory_scans': [],
            'database_scans': [],
            'all_scans': []
        }
        
        # Check memory scans
        for scan_id, status in scan_status.items():
            if status.get('website_id') == website_id:
                debug_info['memory_scans'].append({
                    'scan_id': scan_id,
                    'status': status.get('status'),
                    'target': status.get('target'),
                    'start_time': status.get('start_time')
                })
        
        # Check database scans
        from core.db_sqlite import get_scans_by_website
        db_scans = get_scans_by_website(website_id)
        for scan in db_scans:
            debug_info['database_scans'].append({
                'scan_id': scan.scan_id,
                'status': scan.status,
                'target': scan.target,
                'start_time': scan.start_time.isoformat() if scan.start_time is not None else None,
                'end_time': scan.end_time.isoformat() if scan.end_time is not None else None
            })
        
        # Get combined results from the actual endpoint
        from core.db_sqlite import get_scans_by_website
        scans = get_scans_by_website(website_id)
        result = []
        
        for s in scans:
            result.append({
                'scan_id': s.scan_id,
                'target': s.target,
                'scan_type': s.scan_type,
                'status': s.status,
                'start_time': s.start_time.isoformat() if s.start_time is not None else None,
                'end_time': s.end_time.isoformat() if s.end_time is not None else None,
                'duration': s.duration,
                'website_id': s.website_id
            })
        
        for scan_id, status in scan_status.items():
            if status.get('website_id') == website_id and status.get('status') == 'running':
                existing_scan = next((s for s in result if s['scan_id'] == scan_id), None)
                if not existing_scan:
                    result.append({
                        'scan_id': scan_id,
                        'target': status.get('target'),
                        'scan_type': status.get('scan_type'),
                        'status': 'running',
                        'start_time': status.get('start_time'),
                        'end_time': None,
                        'duration': None,
                        'website_id': website_id
                    })
        
        debug_info['all_scans'] = result
        
        return jsonify(debug_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan_async', methods=['POST'])
def async_scan():
    """Start async scan for multiple targets"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        targets = data.get("targets", [])
        if not isinstance(targets, list) or not targets:
            return jsonify({'error': 'Invalid or empty targets list'}), 400

        # Validate each target
        invalid_targets = []
        for target in targets:
            if not validate_input(target.strip()):
                invalid_targets.append(target)
        
        if invalid_targets:
            return jsonify({
                'error': f'Invalid target format(s): {", ".join(invalid_targets)}',
                'invalid_targets': invalid_targets
            }), 400
        
        concurrency = 20
        # Generate scan ID for this batch
        scan_id = f"async_scan_{int(time.time())}_{len(targets)}_targets"
        
        # Initialize scan status
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Starting async scan...',
            'start_time': datetime.now().isoformat(),
            'targets': targets,
            'scan_type': 'async_batch',
            'concurrency': concurrency,
            'total_targets': len(targets)
        }
        
        # Start async scan in background thread
        thread = threading.Thread(
            target=run_async_scan,
            args=(scan_id, targets, concurrency)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'message': f'Async scan started for {len(targets)} targets',
            'targets': targets,
            'concurrency': concurrency
        })
        
    except Exception as e:
        logger.error(f"Error starting async scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def run_async_scan(scan_id, targets, concurrency):
    """Run async scan in background thread"""
    start_time = time.time()
    try:
        scan_status[scan_id]['message'] = 'Running async scan...'
        scan_status[scan_id]['progress'] = 10
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run the async scan
            # Xóa hoặc comment mọi chỗ sử dụng run_full_scan_async
            # Ví dụ:
            # results = loop.run_until_complete(run_full_scan_async(targets, concurrency))
            # Có thể thay thế bằng raise NotImplementedError hoặc bỏ qua tính năng này
            raise NotImplementedError("Async scan functionality is currently disabled.")
            
            scan_duration = time.time() - start_time
            
            # Store full batch result
            batch_result = {
                'scan_id': scan_id,
                'targets': targets,
                'results': results,
                'scan_duration': scan_duration,
                'concurrency': concurrency,
                'total_targets': len(targets),
                'completed_targets': len([r for r in results if r.get('status') == 'completed']),
                'failed_targets': len([r for r in results if r.get('status') == 'failed'])
            }
            scan_results[scan_id] = batch_result
            # Save to database
            save_scan_results(scan_id, batch_result)

            # Store individual target results in history for better tracking
            for res in results:
                target = res.get('target')
                if not target:
                    continue

                target_id = f"{scan_id}:{target.replace('.', '_').replace(':', '_')}"
                
                # Lấy start_time, end_time, duration thực tế từ res
                import datetime as dt
                def to_iso(ts):
                    try:
                        return dt.datetime.fromtimestamp(ts).isoformat()
                    except Exception:
                        return None
                scan_status[target_id] = {
                    'status': res.get('status'),
                    'target': target,
                    'scan_type': 'single_from_async',
                    'start_time': to_iso(res.get('start_time')) or scan_status[scan_id]['start_time'],
                    'end_time': to_iso(res.get('end_time')) or scan_status[scan_id].get('end_time'),
                    'duration': res.get('duration'),
                    'parent_scan_id': scan_id,
                    'progress': 100 if res.get('status') == 'completed' else 0,
                    'message': f"Completed as part of async batch scan" if res.get('status') == 'completed' else f"Failed: {res.get('error', 'Unknown error')}"
                }

                scan_results[target_id] = res
                # Save individual target result to database
                save_scan_results(target_id, res)
                session = SessionLocal()
                try:
                    session.add(
                        ScanHistory(
                            scan_id=target_id,
                            target=target,
                            scan_type='async',
                            start_time=datetime.fromisoformat(scan_status[target_id]['start_time']),
                            end_time=datetime.fromisoformat(scan_status[target_id]['end_time']) if scan_status[target_id].get('end_time') else None,
                            duration=res.get('duration') or 0.0,
                            status=res.get('status') or 'unknown'
                        )
                    )
                    session.commit()
                except Exception as e:
                    session.rollback()
                    logger.error(f"[DB] Failed to save scan history for {target_id}: {e}")
                finally:
                    session.close()

    
            scan_status[scan_id]['status'] = 'completed'
            scan_status[scan_id]['progress'] = 100
            scan_status[scan_id]['message'] = f'Async scan completed: {len(results)} targets processed'
            scan_status[scan_id]['end_time'] = datetime.now().isoformat()
            
            logger.info(f"Async scan {scan_id} completed successfully in {scan_duration:.2f} seconds")
            
        finally:
            loop.close()
            
            
    except Exception as e:
        logger.error(f"Async scan {scan_id} failed: {e}")
        scan_status[scan_id]['status'] = 'failed'
        scan_status[scan_id]['message'] = f'Async scan failed: {str(e)}'

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    """Fetch scan history from database"""
    try:
        scans = history_scan()
        result = []
        for s in scans:
            result.append({
                'scan_id': s.scan_id,
                'target': s.target,
                'scan_type': s.scan_type,
                'status': s.status,
                'start_time': s.start_time.isoformat() if s.start_time is not None else None,
                'end_time': s.end_time.isoformat() if s.end_time is not None else None,
                'duration': s.duration,
                'website_id': s.website_id
            })
        return jsonify({'scans': result})
    except Exception as e:
        logger.error(f"Error fetching scan history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/websites', methods=['GET'])
def api_get_websites():
    try:
        websites = get_all_websites()
        result = []
        for w in websites:
            # Get latest scan info for this website
            from core.db_sqlite import get_latest_scan_by_website, get_scan_results
            latest_scan = get_latest_scan_by_website(w.id)
            
            subdomain_count = 0
            last_scan_time = 'Never'
            
            if latest_scan:
                # Get scan results to count subdomains
                scan_results = get_scan_results(latest_scan.scan_id)
                if scan_results and 'subdomains' in scan_results:
                    subdomain_count = len(scan_results['subdomains']) if scan_results['subdomains'] else 0
                
                # Format last scan time
                if latest_scan.end_time is not None:
                    last_scan_time = latest_scan.end_time.strftime('%b %d, %Y')
                elif latest_scan.start_time is not None:
                    last_scan_time = latest_scan.start_time.strftime('%b %d, %Y')
            
            # Check if there's a running scan for this website
            has_running_scan = False
            for scan_id, status in scan_status.items():
                if status.get('website_id') == w.id and status.get('status') == 'running':
                    has_running_scan = True
                    break
            
            # Determine scan status
            if has_running_scan:
                scan_status_value = 'running'
            elif latest_scan:
                scan_status_value = latest_scan.status if latest_scan.status is not None else 'completed'
            else:
                scan_status_value = 'never'
            
            result.append({
                'id': w.id,
                'name': w.name,
                'address': w.address,
                'description': w.description,
                'type': w.type,
                'added_time': w.added_time.strftime('%b %d, %Y') if w.added_time is not None else '',
                'subdomain_count': subdomain_count,
                'last_scan_time': last_scan_time,
                'status': scan_status_value
            })
        return jsonify({'websites': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites', methods=['POST'])
def api_add_website():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        address = data.get('address', '').strip()
        description = data.get('description', '').strip() if data.get('description') else ''
        if not name or not address:
            return jsonify({'error': 'Name and Address are required'}), 400
        # Xác định loại (IP hay Domain)
        import re
        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', address)
        wtype = 'IP Address' if is_ip else 'Domain'
        website = add_website(name, address, description, wtype)
        return jsonify({
            'id': website.id,
            'name': website.name,
            'address': website.address,
            'description': website.description,
            'type': website.type,
            'added_time': website.added_time.strftime('%b %d, %Y') if website.added_time is not None else '',
            'subdomain_count': 0,
            'last_scan_time': 'Never'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites/<int:website_id>', methods=['DELETE'])
def api_delete_website(website_id):
    try:
        ok = delete_website_by_id(website_id)
        if ok:
            return jsonify({'success': True})
        return jsonify({'error': 'Not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites/<int:website_id>', methods=['PUT'])
def api_update_website(website_id):
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        address = data.get('address', '').strip()
        description = data.get('description', '').strip() if data.get('description') else ''
        if not name or not address:
            return jsonify({'error': 'Name and Address are required'}), 400
        import re
        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', address)
        wtype = 'IP Address' if is_ip else 'Domain'
        website = update_website_by_id(website_id, name, address, description, wtype)
        if not website:
            return jsonify({'error': 'Not found'}), 404
        # Get latest scan info for updated website
        from core.db_sqlite import get_latest_scan_by_website, get_scan_results
        latest_scan = get_latest_scan_by_website(website.id)
        
        subdomain_count = 0
        last_scan_time = 'Never'
        
        if latest_scan:
            # Get scan results to count subdomains
            scan_results = get_scan_results(latest_scan.scan_id)
            if scan_results and 'subdomains' in scan_results:
                subdomain_count = len(scan_results['subdomains']) if scan_results['subdomains'] else 0
            
            # Format last scan time
            if latest_scan.end_time is not None:
                last_scan_time = latest_scan.end_time.strftime('%b %d, %Y')
            elif latest_scan.start_time is not None:
                last_scan_time = latest_scan.start_time.strftime('%b %d, %Y')
        
        return jsonify({
            'id': website.id,
            'name': website.name,
            'address': website.address,
            'description': website.description,
            'type': website.type,
            'added_time': website.added_time.strftime('%b %d, %Y') if website.added_time is not None else '',
            'subdomain_count': subdomain_count,
            'last_scan_time': last_scan_time
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/website/<int:website_id>')
def website_detail(website_id):
    db = SessionLocal()
    website = db.query(Website).filter(Website.id == website_id).first()
    db.close()
    if not website:
        return render_template('404.html'), 404
    return render_template('website_detail.html', website=website)

@app.route('/api/websites/<int:website_id>/scans')
def get_website_scans(website_id):
    """Get scan history for a specific website"""
    try:
        logger.info(f"Getting scans for website {website_id}")
        from core.db_sqlite import get_scans_by_website
        scans = get_scans_by_website(website_id)
        result = []
        
        # Add scans from database
        for s in scans:
            result.append({
                'scan_id': s.scan_id,
                'target': s.target,
                'scan_type': s.scan_type,
                'status': s.status,
                'start_time': s.start_time.isoformat() if s.start_time is not None else None,
                'end_time': s.end_time.isoformat() if s.end_time is not None else None,
                'duration': s.duration,
                'website_id': s.website_id
            })
        
        logger.info(f"Database scans for website {website_id}: {len(result)} scans")
        
        # Add running scans from memory
        running_scans_added = 0
        for scan_id, status in scan_status.items():
            if status.get('website_id') == website_id and status.get('status') == 'running':
                logger.info(f"Found running scan in memory: {scan_id} for website {website_id}")
                # Check if this scan is already in the database results
                existing_scan = next((s for s in result if s['scan_id'] == scan_id), None)
                if not existing_scan:
                    result.append({
                        'scan_id': scan_id,
                        'target': status.get('target'),
                        'scan_type': status.get('scan_type'),
                        'status': 'running',
                        'start_time': status.get('start_time'),
                        'end_time': None,
                        'duration': None,
                        'website_id': website_id
                    })
                    running_scans_added += 1
                    logger.info(f"Added running scan {scan_id} to results")
        
        logger.info(f"Total scans returned for website {website_id}: {len(result)} (including {running_scans_added} running scans)")
        return jsonify({'scans': result})
    except Exception as e:
        logger.error(f"Error fetching website scans: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/websites/<int:website_id>/latest-scan')
def get_website_latest_scan(website_id):
    """Get the latest scan result for a website"""
    try:
        from core.db_sqlite import get_scan_results, get_scans_by_website
        scans = get_scans_by_website(website_id)
        if not scans:
            return jsonify({'results': None, 'error': 'No scan found'})
        latest_scan = scans[0] if scans else None
        if not latest_scan:
            return jsonify({'results': None, 'error': 'No scan found'})
        results = get_scan_results(latest_scan.scan_id)
        if not results:
            return jsonify({'results': None, 'error': 'No scan found'})
        # --- FIX: Ensure subdomains is always a list of dicts with proper validation ---
        if 'subdomains' in results and results['subdomains']:
            filtered_subdomains = []
            for s in results['subdomains']:
                if isinstance(s, dict):
                    # Determine validity based on IP address
                    subdomain_name = s.get('subdomain') or s.get('domain')
                    ip_address = s.get('ip')
                    
                    # A subdomain is valid if it has a valid IP address
                    is_valid = bool(ip_address and (
                        (isinstance(ip_address, list) and len(ip_address) > 0) or 
                        (isinstance(ip_address, str) and ip_address.strip())
                    ))
                    
                    subdomain_entry = {
                        'subdomain': subdomain_name,
                        'valid': is_valid,
                        'ip': ip_address,
                        'http': s.get('http'),
                        'https': s.get('https'),
                        'cert': s.get('cert'),
                    }
                    filtered_subdomains.append(subdomain_entry)
                elif isinstance(s, str):
                    # For string subdomains, we can't determine validity without IP
                    # So we'll mark as invalid by default (will be updated by DNS check)
                    filtered_subdomains.append({
                        'subdomain': s,
                        'valid': False  # Default to invalid for string subdomains
                    })
            results['subdomains'] = filtered_subdomains
        return jsonify({
            'scan_info': {
                'scan_id': latest_scan.scan_id,
                'target': latest_scan.target,
                'scan_type': latest_scan.scan_type,
                'status': latest_scan.status,
                'start_time': latest_scan.start_time.isoformat() if latest_scan.start_time is not None else None,
                'end_time': latest_scan.end_time.isoformat() if latest_scan.end_time is not None else None,
                'duration': latest_scan.duration
            },
            'results': results
        })
    except Exception as e:
        logger.error(f"Error fetching latest scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/websites/<int:website_id>/compare')
def compare_website_scans(website_id):
    """Compare latest scans to detect changes"""
    try:
        from core.db_sqlite import get_scan_comparison, get_scan_results
        scans = get_scan_comparison(website_id, 2)
        if len(scans) < 2:
            return jsonify({'error': 'Need at least 2 scans to compare'}), 400
        
        # Get results for both scans
        old_results = get_scan_results(scans[1].scan_id)  # Older scan
        new_results = get_scan_results(scans[0].scan_id)  # Newer scan
        
        if not old_results or not new_results:
            return jsonify({'error': 'Scan results not found'}), 404
        
        # Compare results
        comparison = {
            'old_scan': {
                'scan_id': scans[1].scan_id,
                'start_time': scans[1].start_time.isoformat() if scans[1].start_time is not None else None
            },
            'new_scan': {
                'scan_id': scans[0].scan_id,
                'start_time': scans[0].start_time.isoformat() if scans[0].start_time is not None else None
            },
            'changes': {
                'new_ports': [],
                'closed_ports': [],
                'new_subdomains': [],
                'removed_subdomains': []
            }
        }
        
        # Compare open ports
        old_ports = set(old_results.get('open_ports', []))
        new_ports = set(new_results.get('open_ports', []))
        comparison['changes']['new_ports'] = list(new_ports - old_ports)
        comparison['changes']['closed_ports'] = list(old_ports - new_ports)
        
        # Compare subdomains
        old_subdomains = set(old_results.get('subdomains', []))
        new_subdomains = set(new_results.get('subdomains', []))
        comparison['changes']['new_subdomains'] = list(new_subdomains - old_subdomains)
        comparison['changes']['removed_subdomains'] = list(old_subdomains - new_subdomains)
        
        return jsonify(comparison)
    except Exception as e:
        logger.error(f"Error comparing scans: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/scan_subdomains', methods=['POST'])
def scan_subdomains_api():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing domain'}), 400
    domain = data['domain']
    bruteforce = data.get('bruteforce', False)  # Tắt bruteforce mặc định
    wordlist = data.get('wordlist', None)
    try:
        logger.info(f"Starting async subdomain scan for {domain}")
        subs = knockpy.get_subdomains(domain, recon=True, bruteforce=bruteforce, wordlist=wordlist)
        enriched = asyncio.run(knockpy.enrich_subdomains_async(subs))
        live = knockpy.filter_live_domains(enriched)
        logger.info(f"Found {len(live)} live subdomains for {domain}")
        return jsonify({
            "domain": domain,
            "subdomains": live
        })
    except Exception as e:
        logger.error(f"Subdomain scan failed: {e}")
        return jsonify({'error': str(e)}), 500

from flask import Blueprint
bp_subdomain = Blueprint("subdomain", __name__)

@app.route("/api/scan/subdomain", methods=["POST"])
def scan_subdomain():
    data = request.get_json()
    domain = data.get("domain")
    bruteforce = data.get('bruteforce', False)  # Tắt bruteforce mặc định
    wordlist = data.get('wordlist', None)
    if not domain:
        return jsonify({"error": "Missing domain"}), 400
    try:
        logger.info(f"Starting async subdomain scan for {domain}")
        subs = knockpy.get_subdomains(domain, recon=True, bruteforce=bruteforce, wordlist=wordlist)
        enriched = asyncio.run(knockpy.enrich_subdomains_async(subs))
        live = knockpy.filter_live_domains(enriched)
        logger.info(f"Found {len(live)} live subdomains for {domain}")
        return jsonify({
            "domain": domain,
            "subdomains": live
        })
    except Exception as e:
        logger.error(f"Subdomain scan failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan_subdomains_advanced', methods=['POST'])
def scan_subdomains_advanced_api():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing domain'}), 400
    domain = data['domain']
    wordlist = data.get('wordlist', None)
    extra_words = data.get('extra_words', None)
    try:
        logger.info(f"Starting advanced subdomain scan for {domain}")
        from scanner.knock.knockpy import get_subdomains_advanced
        results = asyncio.run(get_subdomains_advanced(domain, wordlist=wordlist, extra_words=extra_words))
        logger.info(f"Advanced scan for {domain} found {len(results.get('live_subdomains', []))} live subdomains")
        return jsonify(results)
    except Exception as e:
        logger.error(f"Advanced subdomain scan failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/recon_subdomain', methods=['POST'])
def recon_subdomain_api():
    data = request.get_json()
    subdomain = data.get('subdomain')
    if not subdomain:
        return jsonify({'error': 'Missing subdomain'}), 400
    try:
        import asyncio
        from scanner.knock.knockpy import enrich_one_subdomain
        result = asyncio.run(enrich_one_subdomain(subdomain))
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/brave_search_subdomains', methods=['POST'])
def brave_search_subdomains_api():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400
    
    api_key = os.getenv("API_KEY_BRAVE")
    if not api_key:
        return jsonify({'error': 'Brave Search API key not configured'}), 400
    
    try:
        from scanner.knock.knockpy import brave_search_subdomains
        subdomains = brave_search_subdomains(domain, api_key)
        logger.info(f"Brave Search found {len(subdomains)} subdomains for {domain}")
        return jsonify({
            "domain": domain,
            "subdomains": subdomains,
            "count": len(subdomains)
        })
    except Exception as e:
        logger.error(f"Brave Search failed: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 