#!/usr/bin/env python3
"""
Scan Configuration
Cấu hình tập trung cho tất cả các module scan
"""

import os
from typing import Dict, Any, List
from pathlib import Path

class ScanConfig:
    """Cấu hình tập trung cho scan operations"""
    
    def __init__(self):
        self.load_config()
    
    def load_config(self):
        """Load configuration from environment and defaults"""
        # Base directories
        self.base_dir = Path.cwd()
        self.reports_dir = Path(os.getenv('SHADOWPROBE_OUTPUT_DIR', 'reports'))
        self.logs_dir = Path(os.getenv('SHADOWPROBE_LOGS_DIR', 'logs'))
        self.cache_dir = Path(os.getenv('SHADOWPROBE_CACHE_DIR', 'cache'))
        
        # Create directories if they don't exist
        for dir_path in [self.reports_dir, self.logs_dir, self.cache_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Scan settings
        self.default_timeout = int(os.getenv('SHADOWPROBE_TIMEOUT', '300'))
        self.max_concurrent_scans = int(os.getenv('SHADOWPROBE_MAX_CONCURRENT', '5'))
        self.scan_depth = int(os.getenv('SHADOWPROBE_SCAN_DEPTH', '3'))
        
        # Tool settings
        self.use_docker = os.getenv('SHADOWPROBE_USE_DOCKER', 'true').lower() == 'true'
        self.docker_timeout = int(os.getenv('SHADOWPROBE_DOCKER_TIMEOUT', '600'))
        
        # Security settings
        self.max_command_length = int(os.getenv('SHADOWPROBE_MAX_CMD_LENGTH', '1000'))
        self.blocked_patterns = os.getenv('SHADOWPROBE_BLOCKED_PATTERNS', 
                                        'rm -rf,dd if=,mkfs,format').split(',')
        
        # Output settings
        self.output_format = os.getenv('SHADOWPROBE_OUTPUT_FORMAT', 'txt')
        self.include_timestamps = os.getenv('SHADOWPROBE_INCLUDE_TIMESTAMPS', 'true').lower() == 'true'
        self.include_cvss = os.getenv('SHADOWPROBE_INCLUDE_CVSS', 'true').lower() == 'true'
        
        # Module specific settings
        self.module_configs = {
            'A01': {
                'enabled': True,
                'timeout': 600,
                'depth': 3,
                'tools': ['katana', 'nuclei', 'zap']
            },
            'A02': {
                'enabled': True,
                'timeout': 300,
                'depth': 2,
                'tools': ['sslyze', 'testssl', 'nmap']
            },
            'A03': {
                'enabled': True,
                'timeout': 900,
                'depth': 4,
                'tools': ['sqlmap', 'nuclei', 'zap']
            },
            'A04': {
                'enabled': True,
                'timeout': 600,
                'depth': 3,
                'tools': ['katana', 'nuclei', 'zap']
            },
            'A05': {
                'enabled': True,
                'timeout': 300,
                'depth': 2,
                'tools': ['nuclei', 'nikto', 'nmap']
            },
            'A06': {
                'enabled': True,
                'timeout': 600,
                'depth': 3,
                'tools': ['nuclei', 'nmap', 'whatweb']
            },
            'A07': {
                'enabled': True,
                'timeout': 450,
                'depth': 3,
                'tools': ['nuclei', 'zap', 'nikto']
            },
            'A08': {
                'enabled': True,
                'timeout': 300,
                'depth': 2,
                'tools': ['nuclei', 'nmap', 'zap']
            },
            'A09': {
                'enabled': True,
                'timeout': 300,
                'depth': 2,
                'tools': ['nuclei', 'zap', 'nmap']
            },
            'A10': {
                'enabled': True,
                'timeout': 600,
                'depth': 3,
                'tools': ['nuclei', 'ssrfmap', 'katana']
            }
        }
    
    def get_module_config(self, module_code: str) -> Dict[str, Any]:
        """Lấy cấu hình cho module cụ thể"""
        return self.module_configs.get(module_code, {})
    
    def get_output_dir(self, module_code: str) -> Path:
        """Lấy output directory cho module"""
        module_dir = self.reports_dir / f"{module_code.lower()}_scan_results"
        module_dir.mkdir(exist_ok=True)
        return module_dir
    
    def get_master_output_dir(self) -> Path:
        """Lấy master output directory"""
        master_dir = self.reports_dir / "owasp_master_results"
        master_dir.mkdir(exist_ok=True)
        return master_dir
    
    def get_log_file(self, module_code: str = None) -> Path:
        """Lấy log file path"""
        if module_code:
            log_file = self.logs_dir / f"{module_code.lower()}_scan.log"
        else:
            log_file = self.logs_dir / "scan.log"
        return log_file
    
    def is_module_enabled(self, module_code: str) -> bool:
        """Kiểm tra module có được enable không"""
        config = self.get_module_config(module_code)
        return config.get('enabled', True)
    
    def get_module_timeout(self, module_code: str) -> int:
        """Lấy timeout cho module"""
        config = self.get_module_config(module_code)
        return config.get('timeout', self.default_timeout)
    
    def get_module_tools(self, module_code: str) -> List[str]:
        """Lấy danh sách tools cho module"""
        config = self.get_module_config(module_code)
        return config.get('tools', [])
    
    def validate_target(self, target: str) -> bool:
        """Validate target input"""
        if not target or not isinstance(target, str):
            return False
        
        # Check length
        if len(target) > 500:
            return False
        
        # Check for blocked patterns
        target_lower = target.lower()
        for pattern in self.blocked_patterns:
            if pattern.strip() in target_lower:
                return False
        
        return True
    
    def get_scan_profile(self, profile: str = 'full') -> Dict[str, Any]:
        """Lấy scan profile"""
        profiles = {
            'quick': {
                'modules': ['A01', 'A03', 'A05'],
                'timeout_multiplier': 0.5,
                'depth': 1
            },
            'standard': {
                'modules': ['A01', 'A02', 'A03', 'A05', 'A07'],
                'timeout_multiplier': 0.8,
                'depth': 2
            },
            'full': {
                'modules': ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
                'timeout_multiplier': 1.0,
                'depth': 3
            },
            'comprehensive': {
                'modules': ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
                'timeout_multiplier': 1.5,
                'depth': 4
            }
        }
        
        return profiles.get(profile, profiles['full'])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'base_dir': str(self.base_dir),
            'reports_dir': str(self.reports_dir),
            'logs_dir': str(self.logs_dir),
            'cache_dir': str(self.cache_dir),
            'default_timeout': self.default_timeout,
            'max_concurrent_scans': self.max_concurrent_scans,
            'scan_depth': self.scan_depth,
            'use_docker': self.use_docker,
            'docker_timeout': self.docker_timeout,
            'max_command_length': self.max_command_length,
            'blocked_patterns': self.blocked_patterns,
            'output_format': self.output_format,
            'include_timestamps': self.include_timestamps,
            'include_cvss': self.include_cvss,
            'module_configs': self.module_configs
        }

# Global instance
scan_config = ScanConfig()

def get_scan_config() -> ScanConfig:
    """Lấy global scan config instance"""
    return scan_config

def get_module_config(module_code: str) -> Dict[str, Any]:
    """Lấy cấu hình cho module (convenience function)"""
    return scan_config.get_module_config(module_code)

def is_module_enabled(module_code: str) -> bool:
    """Kiểm tra module có được enable không (convenience function)"""
    return scan_config.is_module_enabled(module_code)
