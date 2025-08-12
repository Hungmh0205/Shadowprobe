#!/usr/bin/env python3
"""
Startup script for ShadowProbe Web
Handles environment setup and server startup
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        ('flask', 'flask'),
        ('flask-cors', 'flask_cors'),
        ('requests', 'requests'),
        ('python-nmap', 'nmap'),
        ('aiodns', 'aiodns'),
        ('pydantic', 'pydantic')
    ]
    
    missing_packages = []
    
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
            print(f"✅ {package_name}")
        except ImportError:
            missing_packages.append(package_name)
            print(f"❌ {package_name} - Missing")
    
    if missing_packages:
        print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_packages)
            print("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            return False
    
    return True

def check_nmap():
    """Check if nmap is available"""
    try:
        result = SecurityUtils.safe_subprocess_run(['nmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Nmap is available")
            return True
        else:
            print("⚠️  Nmap not found or not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("⚠️  Nmap not found. Some scan features may be limited.")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ['logs', 'reports', 'static']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Directory {directory}/ created/verified")

def check_modules():
    """Check if ShadowProbe modules are available"""
    required_modules = [
        'core.models',
        'core.reporter',
        'scanner.port_scanner',
        'scanner.host_resolver'
    ]
    
    for module in required_modules:
        try:
            imported_module = __import__(module, fromlist=['*'])
            
            # Check for specific classes in each module
            if module == 'scanner.port_scanner':
                if not hasattr(imported_module, 'PortScanner'):
                    print(f"❌ {module} - PortScanner class not found")
                    all_ok = False
                else:
                    print(f"✅ {module}")
            elif module == 'scanner.host_resolver':
                if not hasattr(imported_module, 'HostResolver'):
                    print(f"❌ {module} - HostResolver class not found")
                    all_ok = False
                else:
                    print(f"✅ {module}")
            else:
                print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module} - {e}")
            return False
    
    return True

def start_server():
    """Start the Flask server"""
    print("\n🚀 Starting ShadowProbe Web Server...")
    print("   URL: http://localhost:5000")
    print("   Press Ctrl+C to stop")
    print("-" * 50)
    
    try:
        # Import and run the app
        from app import app
        # PRODUCTION MODE - Debug disabled for security
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        return False
    
    return True

def main():
    """Main startup function"""
    print("🔍 ShadowProbe Web - Startup Check")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check dependencies
    print("\n📦 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    
    # Check nmap
    print("\n🔧 Checking system tools...")
    check_nmap()
    
    # Create directories
    print("\n📁 Creating directories...")
    create_directories()
    
    # Check modules
    print("\n🔍 Checking ShadowProbe modules...")
    if not check_modules():
        print("\n❌ Some modules are missing. Please run setup.py first:")
        print("   python setup.py")
        sys.exit(1)
    
    # Start server
    print("\n" + "=" * 50)
    start_server()

if __name__ == "__main__":
    main() 