"""
Scanner modules for ShadowProbe port scanner and vulnerability adapters.
"""

from typing import Callable, Dict, List

from .port_scanner import PortScanner
from .host_resolver import HostResolver

# Simple registry for vulnerability scanners (OWASP A01-A10)
_VULN_REGISTRY: Dict[str, Dict] = {}

def register_vuln_scanner(module_id: str, name: str, owasp: str, runner: Callable, supports_async: bool = True, targets: List[str] | None = None):
    _VULN_REGISTRY[module_id] = {
        'id': module_id,
        'name': name,
        'owasp': owasp,
        'runner': runner,
        'supports_async': supports_async,
        'targets': targets or ['web']
    }

def get_vuln_registry() -> Dict[str, Dict]:
    return _VULN_REGISTRY

__all__ = [
    'PortScanner',
    'HostResolver',
    'register_vuln_scanner',
    'get_vuln_registry',
] 
