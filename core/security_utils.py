#!/usr/bin/env python3
"""
Security utilities for ShadowProbe Web
Provides secure alternatives to dangerous operations
"""

import subprocess
import shlex
import logging
import re
from typing import List, Optional, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityUtils:
    """Security utility class for safe operations"""
    
    # Allowed commands whitelist
    ALLOWED_COMMANDS = {
        'nmap': ['nmap', 'nmap.exe'],
        'whois': ['whois', 'whois.exe'],
        'dig': ['dig', 'dig.exe'],
        'nslookup': ['nslookup', 'nslookup.exe'],
        'ping': ['ping', 'ping.exe'],
        'traceroute': ['traceroute', 'tracert', 'tracert.exe'],
        'curl': ['curl', 'curl.exe'],
        'wget': ['wget', 'wget.exe']
    }
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        r'[;&|`$()<>]',  # Shell operators
        r'\.\./',         # Path traversal
        r'\/etc\/',       # System directories
        r'\/var\/',       # System directories
        r'\/tmp\/',       # Temporary directories
        r'\/proc\/',      # Process information
        r'\/sys\/',       # System information
        r'rm\s+-rf',      # Dangerous rm command
        r'dd\s+if=',      # Dangerous dd command
        r'>\/dev\/',      # Device redirection
        r'cat\s+>',       # File creation
        r'echo\s+.*\s*>', # File redirection
    ]
    
    @classmethod
    def is_command_allowed(cls, command: str) -> bool:
        """Check if command is in whitelist"""
        if not command:
            return False
        
        # Extract base command
        base_cmd = command.split()[0].lower()
        
        # Check against whitelist
        for allowed_cmds in cls.ALLOWED_COMMANDS.values():
            if base_cmd in allowed_cmds:
                return True
        
        return False
    
    @classmethod
    def contains_dangerous_patterns(cls, command: str) -> bool:
        """Check if command contains dangerous patterns"""
        if not command:
            return False
        
        command_lower = command.lower()
        
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, command_lower):
                logger.warning(f"Dangerous pattern detected: {pattern} in command: {command}")
                return True
        
        return False
    
    @classmethod
    def sanitize_command(cls, command: str) -> Optional[str]:
        """Sanitize command for safe execution"""
        if not command or not isinstance(command, str):
            return None
        
        # Remove dangerous characters
        sanitized = re.sub(r'[;&|`$()<>]', '', command)
        
        # Remove multiple spaces
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        # Check if still dangerous
        if cls.contains_dangerous_patterns(sanitized):
            logger.error(f"Command still dangerous after sanitization: {sanitized}")
            return None
        
        return sanitized
    
    @classmethod
    def safe_subprocess_run(cls, 
                          command: str, 
                          timeout: int = 30,
                          capture_output: bool = True,
                          text: bool = True,
                          **kwargs) -> Optional[subprocess.CompletedProcess]:
        """Safely execute subprocess command"""
        
        # Validate command
        if not cls.is_command_allowed(command):
            logger.error(f"Command not allowed: {command}")
            return None
        
        # Check for dangerous patterns
        if cls.contains_dangerous_patterns(command):
            logger.error(f"Command contains dangerous patterns: {command}")
            return None
        
        # Sanitize command
        sanitized_cmd = cls.sanitize_command(command)
        if not sanitized_cmd:
            logger.error(f"Failed to sanitize command: {command}")
            return None
        
        try:
            # Split command safely
            cmd_parts = shlex.split(sanitized_cmd)
            
            # Additional validation
            if len(cmd_parts) > 20:  # Prevent command injection with too many arguments
                logger.error(f"Command has too many arguments: {len(cmd_parts)}")
                return None
            
            # Execute with timeout
            result = SecurityUtils.safe_subprocess_run(
                cmd_parts,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                **kwargs
            )
            
            logger.info(f"Command executed successfully: {sanitized_cmd}")
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {sanitized_cmd}")
            return None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error: {e} for command: {sanitized_cmd}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error executing command: {e}")
            return None
    
    @classmethod
    def validate_file_path(cls, file_path: str) -> bool:
        """Validate file path for security"""
        if not file_path:
            return False
        
        try:
            path = Path(file_path).resolve()
            
            # Check for path traversal
            if '..' in str(path):
                logger.warning(f"Path traversal detected: {file_path}")
                return False
            
            # Check if path is within allowed directories
            allowed_dirs = [
                Path.cwd() / 'reports',
                Path.cwd() / 'logs',
                Path.cwd() / 'static',
                Path.cwd() / 'cache'
            ]
            
            for allowed_dir in allowed_dirs:
                if path.is_relative_to(allowed_dir):
                    return True
            
            logger.warning(f"File path not in allowed directories: {file_path}")
            return False
            
        except Exception as e:
            logger.error(f"Error validating file path: {e}")
            return False
    
    @classmethod
    def safe_file_operation(cls, operation: str, file_path: str, **kwargs) -> bool:
        """Safely perform file operations"""
        if not cls.validate_file_path(file_path):
            return False
        
        try:
            if operation == 'read':
                with open(file_path, 'r', **kwargs) as f:
                    return f.read()
            elif operation == 'write':
                with open(file_path, 'w', **kwargs) as f:
                    return True
            elif operation == 'delete':
                Path(file_path).unlink(missing_ok=True)
                return True
            else:
                logger.error(f"Unknown file operation: {operation}")
                return False
                
        except Exception as e:
            logger.error(f"File operation failed: {operation} on {file_path}: {e}")
            return False
