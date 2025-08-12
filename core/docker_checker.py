#!/usr/bin/env python3
"""
Docker Availability Checker
Kiểm tra Docker có sẵn và cung cấp fallback tools
"""

import subprocess
import shutil
import os
import logging
from typing import Dict, List, Optional, Tuple
from .security_utils import SecurityUtils

logger = logging.getLogger(__name__)

class DockerChecker:
    """Kiểm tra và quản lý Docker dependencies"""
    
    def __init__(self):
        self.docker_available = self._check_docker()
        self.available_images = self._get_available_images() if self.docker_available else {}
        self.fallback_tools = self._get_fallback_tools()
    
    def _check_docker(self) -> bool:
        """Kiểm tra Docker có sẵn không"""
        try:
            result = SecurityUtils.safe_subprocess_run('docker --version', 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("✅ Docker is available")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        logger.warning("⚠️ Docker is not available")
        return False
    
    def _get_available_images(self) -> Dict[str, bool]:
        """Lấy danh sách Docker images có sẵn"""
        if not self.docker_available:
            return {}
        
        try:
            result = SecurityUtils.safe_subprocess_run('docker images --format "{{.Repository}}"', 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                available_images = result.stdout.strip().split('\n')
                return {img: True for img in available_images if img}
        except Exception as e:
            logger.error(f"Error getting Docker images: {e}")
        
        return {}
    
    def _get_fallback_tools(self) -> Dict[str, bool]:
        """Kiểm tra fallback tools có sẵn không"""
        tools = {
            'nuclei': shutil.which('nuclei'),
            'nmap': shutil.which('nmap'),
            'nikto': shutil.which('nikto'),
            'sslyze': shutil.which('sslyze'),
            'testssl': shutil.which('testssl.sh'),
            'whatweb': shutil.which('whatweb'),
            'katana': shutil.which('katana'),
            'zap': shutil.which('zap-cli')
        }
        
        available_tools = {tool: bool(path) for tool, path in tools.items()}
        
        # Log available tools
        for tool, available in available_tools.items():
            if available:
                logger.info(f"✅ {tool} is available as fallback")
            else:
                logger.warning(f"⚠️ {tool} is not available as fallback")
        
        return available_tools
    
    def is_docker_available(self) -> bool:
        """Kiểm tra Docker có sẵn không"""
        return self.docker_available
    
    def is_image_available(self, image_name: str) -> bool:
        """Kiểm tra Docker image có sẵn không"""
        return image_name in self.available_images
    
    def is_fallback_tool_available(self, tool_name: str) -> bool:
        """Kiểm tra fallback tool có sẵn không"""
        return self.fallback_tools.get(tool_name, False)
    
    def get_available_fallback_tools(self) -> List[str]:
        """Lấy danh sách fallback tools có sẵn"""
        return [tool for tool, available in self.fallback_tools.items() if available]
    
    def run_docker_command(self, image: str, args: List[str], 
                          timeout: int = 300) -> Optional[subprocess.CompletedProcess]:
        """Chạy Docker command an toàn"""
        if not self.docker_available:
            logger.error("Docker is not available")
            return None
        
        if not self.is_image_available(image):
            logger.error(f"Docker image {image} is not available")
            return None
        
        try:
            cmd = ['docker', 'run', '--rm', image] + args
            result = SecurityUtils.safe_subprocess_run(' '.join(cmd), timeout=timeout)
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Docker command timed out after {timeout}s")
            return None
        except Exception as e:
            logger.error(f"Error running Docker command: {e}")
            return None
    
    def get_fallback_command(self, tool_name: str, target: str, 
                           scan_type: str = 'basic') -> Optional[List[str]]:
        """Lấy fallback command cho tool cụ thể"""
        if not self.is_fallback_tool_available(tool_name):
            return None
        
        fallback_commands = {
            'nuclei': {
                'basic': ['nuclei', '-u', target, '-severity', 'critical,high,medium', '-silent'],
                'full': ['nuclei', '-u', target, '-severity', 'critical,high,medium,low', '-silent']
            },
            'nmap': {
                'basic': ['nmap', '-sS', '-sV', '-O', '--top-ports', '100', target],
                'full': ['nmap', '-sS', '-sV', '-O', '-p-', target]
            },
            'nikto': {
                'basic': ['nikto', '-host', target],
                'full': ['nikto', '-host', target, '-C', 'all']
            },
            'sslyze': {
                'basic': ['sslyze', '--regular', target],
                'full': ['sslyze', '--regular', '--http_headers', target]
            },
            'testssl': {
                'basic': ['testssl.sh', '--quiet', target],
                'full': ['testssl.sh', '--quiet', '--color', '0', target]
            }
        }
        
        if tool_name in fallback_commands and scan_type in fallback_commands[tool_name]:
            return fallback_commands[tool_name][scan_type]
        
        return None
    
    def get_scan_recommendations(self) -> Dict[str, List[str]]:
        """Lấy khuyến nghị scan dựa trên tools có sẵn"""
        recommendations = {
            'port_scanning': [],
            'vulnerability_scanning': [],
            'ssl_testing': [],
            'web_scanning': []
        }
        
        if self.is_fallback_tool_available('nmap'):
            recommendations['port_scanning'].append('nmap')
        
        if self.is_fallback_tool_available('nuclei'):
            recommendations['vulnerability_scanning'].append('nuclei')
        
        if self.is_fallback_tool_available('sslyze') or self.is_fallback_tool_available('testssl'):
            recommendations['ssl_testing'].extend(['sslyze', 'testssl'])
        
        if self.is_fallback_tool_available('nikto') or self.is_fallback_tool_available('whatweb'):
            recommendations['web_scanning'].extend(['nikto', 'whatweb'])
        
        return recommendations

# Global instance
docker_checker = DockerChecker()

def get_docker_checker() -> DockerChecker:
    """Lấy global Docker checker instance"""
    return docker_checker

def is_docker_available() -> bool:
    """Kiểm tra Docker có sẵn không (convenience function)"""
    return docker_checker.is_docker_available()

def get_fallback_tools() -> List[str]:
    """Lấy danh sách fallback tools có sẵn (convenience function)"""
    return docker_checker.get_available_fallback_tools()
