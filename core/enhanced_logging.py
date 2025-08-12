#!/usr/bin/env python3
"""
Enhanced logging configuration for ShadowProbe Web
Provides structured logging with security event tracking
"""

import os
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
import json

class EnhancedLogger:
    """Enhanced logger with security event tracking"""
    
    def __init__(self, app_name="ShadowProbe"):
        self.app_name = app_name
        self.setup_logging()
    
    def setup_logging(self):
        """Setup comprehensive logging configuration"""
        
        # Create logs directory
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Console handler with colored output
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler for general logs
        general_log_file = logs_dir / "app.log"
        file_handler = logging.handlers.RotatingFileHandler(
            general_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
        # Security log handler
        security_log_file = logs_dir / "security.log"
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.WARNING)
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        root_logger.addHandler(security_handler)
        
        # Error log handler
        error_log_file = logs_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter(
            '%(asctime)s - ERROR - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        error_handler.setFormatter(error_formatter)
        root_logger.addHandler(error_handler)
        
        # Audit log handler
        audit_log_file = logs_dir / "audit.log"
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=20,
            encoding='utf-8'
        )
        audit_handler.setLevel(logging.INFO)
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        root_logger.addHandler(audit_handler)
        
        # Set specific logger levels
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        
        # Create application logger
        self.logger = logging.getLogger(self.app_name)
        self.logger.setLevel(logging.INFO)
        
        # Log startup
        self.logger.info(f"Enhanced logging initialized for {self.app_name}")
        self.logger.info(f"Log files: {logs_dir.absolute()}")
    
    def log_security_event(self, event_type, details, severity='WARNING', user_ip=None, user_agent=None):
        """Log security events with structured data"""
        try:
            security_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'details': details,
                'user_ip': user_ip,
                'user_agent': user_agent,
                'source': 'security_middleware'
            }
            
            # Log to security log
            security_logger = logging.getLogger(f"{self.app_name}.security")
            if severity == 'CRITICAL':
                security_logger.critical(json.dumps(security_data))
            elif severity == 'ERROR':
                security_logger.error(json.dumps(security_data))
            elif severity == 'WARNING':
                security_logger.warning(json.dumps(security_data))
            else:
                security_logger.info(json.dumps(security_data))
            
            # Also log to audit log
            audit_logger = logging.getLogger(f"{self.app_name}.audit")
            audit_logger.info(f"SECURITY: {event_type} - {details}")
            
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
    
    def log_audit_event(self, event_type, details, user_ip=None, user_agent=None, additional_data=None):
        """Log audit events for compliance"""
        try:
            audit_data = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'details': details,
                'user_ip': user_ip,
                'user_agent': user_agent,
                'additional_data': additional_data or {}
            }
            
            audit_logger = logging.getLogger(f"{self.app_name}.audit")
            audit_logger.info(json.dumps(audit_data))
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
    
    def log_error(self, error, context=None, user_ip=None):
        """Log errors with context"""
        try:
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'error_type': type(error).__name__,
                'error_message': str(error),
                'context': context,
                'user_ip': user_ip,
                'traceback': self._get_traceback(error)
            }
            
            error_logger = logging.getLogger(f"{self.app_name}.errors")
            error_logger.error(json.dumps(error_data))
            
        except Exception as e:
            self.logger.error(f"Failed to log error: {e}")
    
    def _get_traceback(self, error):
        """Get traceback information safely"""
        try:
            import traceback
            return traceback.format_exc()
        except:
            return "Traceback not available"
    
    def cleanup_old_logs(self, days_to_keep=30):
        """Clean up old log files"""
        try:
            logs_dir = Path("logs")
            if not logs_dir.exists():
                return
            
            cutoff_date = datetime.now().timestamp() - (days_to_keep * 24 * 60 * 60)
            
            for log_file in logs_dir.glob("*.log.*"):
                if log_file.stat().st_mtime < cutoff_date:
                    log_file.unlink()
                    self.logger.info(f"Cleaned up old log file: {log_file}")
                    
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")

# Global logger instance
enhanced_logger = None

def init_enhanced_logging(app_name="ShadowProbe"):
    """Initialize enhanced logging globally"""
    global enhanced_logger
    enhanced_logger = EnhancedLogger(app_name)
    return enhanced_logger

def get_enhanced_logger():
    """Get the global enhanced logger instance"""
    return enhanced_logger
