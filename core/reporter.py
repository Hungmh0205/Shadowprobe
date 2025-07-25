from core.models import ScanResult
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
console = Console()

class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'value'):
            return obj.value
        return super().default(obj)

class ReportGenerator:
    """Report generator for port scan results"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def save_report(self, scan_result: ScanResult, output_path: Optional[str] = None) -> bool:
        """
        Save scan result to JSON file
        """
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"scan_{scan_result.target}_{timestamp}.json"
                output_path = self.output_dir / filename
            
            # Convert to dict with enum serialization
            data = scan_result.model_dump()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, cls=EnumEncoder)
            
            logger.info(f"Report saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False
    
    def load_report(self, file_path: str) -> Optional[ScanResult]:
        """
        Load scan result from JSON file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Convert back to ScanResult
            return ScanResult(**data)
            
        except Exception as e:
            logger.error(f"Failed to load report: {e}")
            return None
    
    def print_summary(self, scan_result: ScanResult):
        """Print scan summary to console"""
        print("\n" + "="*60)
        print("SHADOWPROBE SCAN REPORT")
        print("="*60)
        
        print(f"Target: {scan_result.target}")
        print(f"Scan Type: {scan_result.scan_type}")
        print(f"Scan Duration: {scan_result.scan_duration:.2f} seconds")
        print()
        
        # Host Information
        if scan_result.host_info:
            print("HOST INFORMATION:")
            print("-" * 20)
            if scan_result.host_info.ips:
                print(f"IP Addresses: {', '.join(scan_result.host_info.ips)}")
            if scan_result.host_info.hostnames:
                print(f"Hostnames: {', '.join(scan_result.host_info.hostnames)}")
            if scan_result.host_info.reverse_dns:
                print(f"Reverse DNS: {', '.join(scan_result.host_info.reverse_dns)}")
            print()
        
        # Port Information
        if scan_result.open_ports:
            print(f"OPEN PORTS ({len(scan_result.open_ports)}):")
            print("-" * 20)
            for port in sorted(scan_result.open_ports):
                print(f"  Port {port}/tcp")
            print()
        
        # Service Information
        if scan_result.services:
            print("SERVICES:")
            print("-" * 20)
            for service in scan_result.services:
                service_info = f"  Port {service.port}/{service.protocol}: {service.service_name}"
                if service.ip_address:
                    service_info += f" on {service.ip_address}"
                if service.server_name:
                    service_info += f" ({service.server_name})"
                if service.version:
                    service_info += f" - {service.version}"
                print(service_info)
            print()
        
        # Subdomain Information
        if scan_result.subdomains:
            print(f"SUBDOMAINS ({len(scan_result.subdomains)}):")
            print("-" * 20)
            for subdomain in sorted(scan_result.subdomains):
                print(f"  {subdomain}")
            print()
        
        # Summary
        total_findings = len(scan_result.open_ports) + len(scan_result.subdomains or [])
        if scan_result.host_info and scan_result.host_info.ips:
            total_findings += len(scan_result.host_info.ips)
        
        print("SUMMARY:")
        print("-" * 20)
        print(f"Total Findings: {total_findings}")
        print(f"Open Ports: {len(scan_result.open_ports)}")
        print(f"Services Identified: {len(scan_result.services)}")
        print(f"Subdomains Found: {len(scan_result.subdomains)}")
        print("="*60)
    
    def print_scan_progress(self, message: str):
        """Print scan progress message"""
        print(f"[INFO] {message}")
    
    def print_error(self, message: str):
        """Print error message"""
        print(f"[ERROR] {message}")
    
    def print_success(self, message: str):
        """Print success message"""
        print(f"[SUCCESS] {message}")
    
    def create_progress_bar(self):
        """
        Create progress bar
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        )
    
    def print_scan_start(self, target: str):
        """
        Print scan start message
        """
        print(f"Starting port scan for: {target}")
    
    def print_scan_complete(self):
        """
        Print scan completion message
        """
        print("Port scan completed!")
