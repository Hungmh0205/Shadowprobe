#!/usr/bin/env python3
"""
ShadowProbe Web - Production Startup Script
Secure production deployment with all security features enabled
"""

import os
import sys
import logging
from pathlib import Path

def setup_production_environment():
    """Setup secure production environment"""
    print("🔒 Setting up PRODUCTION environment...")
    
    # Set production environment variables
    os.environ['SHADOWPROBE_ENVIRONMENT'] = 'production'
    os.environ['SHADOWPROBE_DEBUG_MODE'] = 'false'
    os.environ['SHADOWPROBE_LOG_LEVEL'] = 'WARNING'
    os.environ['SHADOWPROBE_API_KEY_REQUIRED'] = 'true'
    
    # Security settings
    os.environ['FLASK_ENV'] = 'production'
    os.environ['FLASK_DEBUG'] = 'false'
    
    print("✅ Production environment configured")

def setup_production_logging():
    """Setup production logging with security focus"""
    print("📝 Setting up production logging...")
    
    # Create logs directory
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # Configure production logging
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/production.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific logger levels
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    print("✅ Production logging configured")

def validate_security_configuration():
    """Validate security configuration"""
    print("🔍 Validating security configuration...")
    
    # Check critical security files
    required_files = [
        'core/security_utils.py',
        'core/security_middleware.py',
        'core/enhanced_logging.py',
        'core/security_config.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing critical security files: {missing_files}")
        return False
    
    # Check OWASP modules
    owasp_modules = list(Path('scanner/vulnerabilities/module_vuln_scan').glob('A*.py'))
    if len(owasp_modules) < 10:
        print(f"❌ Missing OWASP modules: found {len(owasp_modules)}/10")
        return False
    
    print("✅ Security configuration validated")
    return True

def start_production_server():
    """Start production server with security features"""
    print("🚀 Starting PRODUCTION server...")
    
    try:
        # Add ShadowProbe_Web to Python path
        sys.path.insert(0, 'ShadowProbe_Web')
        
        # Import and configure app
        from app import app
        
        # Configure production settings
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        
        # Start production server
        print("🌐 Production server starting...")
        print("   URL: http://localhost:5000")
        print("   Security: ENABLED")
        print("   Debug: DISABLED")
        print("   Press Ctrl+C to stop")
        print("-" * 50)
        
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            threaded=True
        )
        
    except KeyboardInterrupt:
        print("\n👋 Production server stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting production server: {e}")
        return False
    
    return True

def main():
    """Main production startup function"""
    print("🔒 ShadowProbe Web - PRODUCTION STARTUP")
    print("=" * 50)
    
    # Setup production environment
    setup_production_environment()
    
    # Setup production logging
    setup_production_logging()
    
    # Validate security configuration
    if not validate_security_configuration():
        print("\n❌ Security validation failed. Cannot start production server.")
        sys.exit(1)
    
    # Start production server
    print("\n" + "=" * 50)
    start_production_server()

if __name__ == "__main__":
    main()
