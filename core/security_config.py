#!/usr/bin/env python3
"""
Security configuration for ShadowProbe Web
Centralized security settings and validation
"""

import os
import re
from typing import Dict, List, Optional, Any
from pathlib import Path

class SecurityConfig:
    """Security configuration and validation"""
    
    def __init__(self):
        self.load_config()
    
    def load_config(self):
        """Load security configuration from environment"""
        
        # API Security
        self.api_key_required = os.getenv('API_KEY', '').strip()
        self.api_key_header = 'X-API-Key'
        self.api_key_param = 'api_key'
        
        # CORS Security
        self.allowed_origins = self._parse_allowed_origins()
        self.cors_max_age = int(os.getenv('CORS_MAX_AGE', '86400'))  # 24 hours
        
        # Rate Limiting
        self.rate_limit_default = os.getenv('RATE_LIMIT_DEFAULT', '100 per minute')
        self.rate_limit_strict = os.getenv('RATE_LIMIT_STRICT', '10 per minute')
        self.max_requests_per_minute = int(os.getenv('MAX_REQUESTS_PER_MINUTE', '100'))
        
        # Input Validation
        self.max_input_length = int(os.getenv('MAX_INPUT_LENGTH', '1000'))
        self.max_url_length = int(os.getenv('MAX_URL_LENGTH', '2048'))
        self.blocked_patterns = self._get_blocked_patterns()
        
        # File Security
        self.allowed_file_extensions = [
            '.txt', '.log', '.json', '.xml', '.html', '.css', '.js',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'
        ]
        self.max_file_size = int(os.getenv('MAX_FILE_SIZE', '10*1024*1024'))  # 10MB
        
        # Session Security
        self.session_timeout = int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour
        self.session_secure = os.getenv('SESSION_SECURE', 'true').lower() == 'true'
        self.session_httponly = os.getenv('SESSION_HTTPONLY', 'true').lower() == 'true'
        
        # Scan Security
        self.max_concurrent_scans = int(os.getenv('MAX_CONCURRENT_SCANS', '3'))
        self.scan_timeout = int(os.getenv('SCAN_TIMEOUT', '600'))  # 10 minutes
        self.max_subdomains_per_scan = int(os.getenv('MAX_SUBDOMAINS_PER_SCAN', '50'))
        
        # Network Security
        self.blocked_ips = self._parse_blocked_ips()
        self.allowed_networks = self._parse_allowed_networks()
        self.max_connections_per_ip = int(os.getenv('MAX_CONNECTIONS_PER_IP', '10'))
        
        # Logging Security
        self.log_security_events = os.getenv('LOG_SECURITY_EVENTS', 'true').lower() == 'true'
        self.log_audit_events = os.getenv('LOG_AUDIT_EVENTS', 'true').lower() == 'true'
        self.log_retention_days = int(os.getenv('LOG_RETENTION_DAYS', '30'))
        
        # Security Headers
        self.enable_hsts = os.getenv('ENABLE_HSTS', 'true').lower() == 'true'
        self.enable_csp = os.getenv('ENABLE_CSP', 'true').lower() == 'true'
        self.enable_xss_protection = os.getenv('ENABLE_XSS_PROTECTION', 'true').lower() == 'true'
        
        # Database Security
        self.db_connection_limit = int(os.getenv('DB_CONNECTION_LIMIT', '10'))
        self.db_query_timeout = int(os.getenv('DB_QUERY_TIMEOUT', '30'))
        
        # External API Security
        self.external_api_timeout = int(os.getenv('EXTERNAL_API_TIMEOUT', '30'))
        self.max_external_api_calls = int(os.getenv('MAX_EXTERNAL_API_CALLS', '100'))
        
        # Validation patterns
        self.validation_patterns = self._get_validation_patterns()
    
    def _parse_allowed_origins(self) -> List[str]:
        """Parse and validate allowed origins"""
        origins = os.getenv('ALLOWED_ORIGINS', '').strip()
        if not origins:
            return []
        
        allowed = []
        for origin in origins.split(','):
            origin = origin.strip()
            if origin and self._is_valid_origin(origin):
                allowed.append(origin)
        
        return allowed
    
    def _is_valid_origin(self, origin: str) -> bool:
        """Validate origin format"""
        if not origin:
            return False
        
        # Must start with http:// or https://
        if not (origin.startswith('http://') or origin.startswith('https://')):
            return False
        
        # No wildcard subdomains
        if '*.' in origin:
            return False
        
        # No IP addresses (only domains)
        if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', origin):
            return False
        
        return True
    
    def _get_blocked_patterns(self) -> List[str]:
        """Get patterns that should be blocked"""
        return [
            # SQL Injection
            r'(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)',
            r'(\b(xp_|sp_|msys)\w*\b)',
            r'(\b(waitfor|benchmark|sleep)\s*\()',
            r'(\b(0x[0-9a-f]+)\b)',
            
            # XSS
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            
            # Path Traversal
            r'\.\./',
            r'\.\.\\',
            r'\.\.%2f',
            r'\.\.%5c',
            
            # Command Injection
            r'[;&|`$()<>]',
            r'\b(cat|rm|del|erase|format|fdisk)\b',
            
            # LDAP Injection
            r'[()&|!]',
            
            # NoSQL Injection
            r'\$where\s*:',
            r'\$ne\s*:',
            r'\$gt\s*:',
            r'\$lt\s*:'
        ]
    
    def _parse_blocked_ips(self) -> List[str]:
        """Parse blocked IP addresses"""
        blocked = os.getenv('BLOCKED_IPS', '').strip()
        if not blocked:
            return []
        
        ips = []
        for ip in blocked.split(','):
            ip = ip.strip()
            if ip and self._is_valid_ip(ip):
                ips.append(ip)
        
        return ips
    
    def _parse_allowed_networks(self) -> List[str]:
        """Parse allowed network ranges"""
        networks = os.getenv('ALLOWED_NETWORKS', '').strip()
        if not networks:
            return []
        
        allowed = []
        for network in networks.split(','):
            network = network.strip()
            if network and self._is_valid_network(network):
                allowed.append(network)
        
        return allowed
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_valid_network(self, network: str) -> bool:
        """Validate network range format"""
        try:
            import ipaddress
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    def _get_validation_patterns(self) -> Dict[str, str]:
        """Get validation patterns for different input types"""
        return {
            'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'domain': r'^(?!-)(?!.*--)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$',
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'url': r'^https?://[^\s/$.?#].[^\s]*$',
            'filename': r'^[a-zA-Z0-9._-]+$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        }
    
    def validate_input(self, input_data: str, input_type: str = 'general') -> bool:
        """Validate input based on type and security rules"""
        if not input_data or not isinstance(input_data, str):
            return False
        
        # Check length limits
        if len(input_data) > self.max_input_length:
            return False
        
        # Check for blocked patterns
        for pattern in self.blocked_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return False
        
        # Type-specific validation
        if input_type in self.validation_patterns:
            if not re.match(self.validation_patterns[input_type], input_data):
                return False
        
        return True
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def is_network_allowed(self, ip: str) -> bool:
        """Check if IP is in allowed networks"""
        if not self.allowed_networks:
            return True
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            for network in self.allowed_networks:
                if ip_obj in ipaddress.ip_network(network, strict=False):
                    return True
            
            return False
        except ValueError:
            return False
    
    def get_cors_config(self) -> Dict[str, Any]:
        """Get CORS configuration"""
        return {
            'origins': self.allowed_origins,
            'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            'allow_headers': ['Content-Type', 'Authorization', 'X-API-Key'],
            'supports_credentials': True,
            'max_age': self.cors_max_age
        }
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers configuration"""
        headers = {}
        
        if self.enable_hsts:
            headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        if self.enable_csp:
            headers['Content-Security-Policy'] = self._get_csp_policy()
        
        if self.enable_xss_protection:
            headers['X-XSS-Protection'] = '1; mode=block'
        
        headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        })
        
        return headers
    
    def _get_csp_policy(self) -> str:
        """Get Content Security Policy"""
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
    
    def validate_file_upload(self, filename: str, file_size: int) -> bool:
        """Validate file upload"""
        if not filename:
            return False
        
        # Check file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in self.allowed_file_extensions:
            return False
        
        # Check file size
        if file_size > self.max_file_size:
            return False
        
        # Check filename pattern
        if not re.match(self.validation_patterns['filename'], Path(filename).stem):
            return False
        
        return True

# Global security config instance
security_config = SecurityConfig()
