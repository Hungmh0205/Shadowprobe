#!/usr/bin/env python3
"""
Security middleware for ShadowProbe Web
Adds security headers and implements security best practices
"""

import os
import logging
from functools import wraps
from flask import request, jsonify, g, current_app
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityMiddleware:
    """Security middleware for Flask application"""
    
    def __init__(self, app):
        self.app = app
        self.setup_security_headers()
        self.setup_request_filtering()
    
    def setup_security_headers(self):
        """Setup security headers for all responses"""
        
        @self.app.after_request
        def add_security_headers(response):
            """Add security headers to all responses"""
            
            # HTTP Strict Transport Security (HSTS)
            if os.getenv('ENABLE_HSTS', 'true').lower() == 'true':
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            
            # Content Security Policy (CSP)
            if os.getenv('ENABLE_CSP', 'true').lower() == 'true':
                csp_policy = (
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
                response.headers['Content-Security-Policy'] = csp_policy
            
            # XSS Protection
            if os.getenv('ENABLE_XSS_PROTECTION', 'true').lower() == 'true':
                response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Prevent MIME type sniffing
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'DENY'
            
            # Referrer Policy
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            # Permissions Policy
            response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
            
            # Remove server information
            response.headers['Server'] = 'ShadowProbe'
            
            return response
    
    def setup_request_filtering(self):
        """Setup request filtering and validation"""
        
        @self.app.before_request
        def filter_requests():
            """Filter and validate incoming requests"""
            
            # Log all requests for security monitoring
            self.log_request(request)
            
            # Check for suspicious patterns
            if self.is_suspicious_request(request):
                logger.warning(f"Suspicious request detected: {request.remote_addr} - {request.method} {request.path}")
                return jsonify({'error': 'Request blocked for security reasons'}), 403
            
            # Rate limiting check (basic implementation)
            if not self.check_rate_limit(request):
                logger.warning(f"Rate limit exceeded: {request.remote_addr}")
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            # Add request timestamp
            g.request_start_time = datetime.now()
            
            return None
    
    def log_request(self, request):
        """Log request details for security monitoring"""
        try:
            log_data = {
                'timestamp': datetime.now().isoformat(),
                'remote_addr': request.remote_addr,
                'method': request.method,
                'path': request.path,
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'referrer': request.headers.get('Referer', 'None'),
                'content_length': request.content_length or 0,
                'content_type': request.content_type or 'None'
            }
            
            # Log to security log file
            security_log_file = os.path.join('logs', 'security.log')
            os.makedirs('logs', exist_ok=True)
            
            with open(security_log_file, 'a', encoding='utf-8') as f:
                f.write(f"{log_data['timestamp']} - {log_data['remote_addr']} - {log_data['method']} {log_data['path']} - {log_data['user_agent']}\n")
                
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
    
    def is_suspicious_request(self, request):
        """Check if request contains suspicious patterns"""
        
        # Check for SQL injection patterns
        sql_patterns = [
            'union select', 'drop table', 'insert into', 'delete from',
            'update set', 'alter table', 'exec xp_', 'sp_', 'xp_',
            '--', '/*', '*/', 'waitfor delay', 'benchmark('
        ]
        
        # Check for XSS patterns
        xss_patterns = [
            '<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=',
            'onclick=', 'onmouseover=', 'eval(', 'document.cookie'
        ]
        
        # Check for path traversal
        path_patterns = ['..', '../', '..\\', '..%2f', '..%5c']
        
        # Check request path and query string
        request_data = f"{request.path} {request.query_string.decode('utf-8', errors='ignore')}"
        request_data_lower = request_data.lower()
        
        # Check for suspicious patterns
        for pattern in sql_patterns + xss_patterns + path_patterns:
            if pattern in request_data_lower:
                logger.warning(f"Suspicious pattern detected: {pattern} in request")
                return True
        
        # Check for unusually long requests
        if len(request_data) > 1000:
            logger.warning(f"Unusually long request: {len(request_data)} characters")
            return True
        
        # Check for suspicious User-Agent
        user_agent = request.headers.get('User-Agent', '').lower()
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'scanner', 'bot', 'crawler']
        
        if any(agent in user_agent for agent in suspicious_agents):
            logger.warning(f"Suspicious User-Agent: {user_agent}")
            return True
        
        return False
    
    def check_rate_limit(self, request):
        """Basic rate limiting check"""
        # This is a simple implementation - consider using Flask-Limiter for production
        
        # Get client IP
        client_ip = request.remote_addr
        
        # Simple in-memory rate limiting (not suitable for production)
        if not hasattr(g, 'rate_limit_data'):
            g.rate_limit_data = {}
        
        current_time = datetime.now()
        
        # Clean old entries
        g.rate_limit_data = {
            ip: data for ip, data in g.rate_limit_data.items()
            if current_time - data['last_request'] < timedelta(minutes=1)
        }
        
        # Check rate limit
        if client_ip in g.rate_limit_data:
            if g.rate_limit_data[client_ip]['count'] > 100:  # 100 requests per minute
                return False
            g.rate_limit_data[client_ip]['count'] += 1
            g.rate_limit_data[client_ip]['last_request'] = current_time
        else:
            g.rate_limit_data[client_ip] = {
                'count': 1,
                'last_request': current_time
            }
        
        return True

def require_https(f):
    """Decorator to require HTTPS"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure and not request.headers.get('X-Forwarded-Proto') == 'https':
            return jsonify({'error': 'HTTPS required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type, details, severity='INFO'):
    """Log security events"""
    try:
        security_log_file = os.path.join('logs', 'security.log')
        os.makedirs('logs', exist_ok=True)
        
        timestamp = datetime.now().isoformat()
        log_entry = f"{timestamp} - {severity} - {event_type}: {details}\n"
        
        with open(security_log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
            
        logger.info(f"Security event logged: {event_type} - {details}")
        
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")
