from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel

class ScanType(Enum):
    """Enumeration of available scan types."""
    QUICK_SCAN = "quick_scan"
    FULL_SCAN = "full_scan"
    PORT_SCAN = "port_scan"

class Service(BaseModel):
    """Model representing a network service."""
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    server_name: Optional[str] = None
    ip_address: Optional[str] = None
    state: str = "open"

class HostInfo(BaseModel):
    """Model representing host information."""
    ips: List[str]
    hostnames: List[str]
    primary_ip: Optional[str] = None
    primary_hostname: Optional[str] = None
    reverse_dns: Optional[List[str]] = None

class SubdomainEntry(BaseModel):
    subdomain: str
    valid: bool

class ScanResult(BaseModel):
    """Model representing scan results."""
    target: str
    scan_type: ScanType
    open_ports: List[int]
    services: List[Service]
    subdomains: Optional[List[SubdomainEntry]] = None  # Lưu list dict (subdomain, valid)
    host_info: Optional[HostInfo] = None
    scan_duration: Optional[float] = None
