#!/usr/bin/env python3
"""
Setup script for ShadowProbe Web
Copies necessary modules from ShadowProbe_py and sets up the web application
"""

import os
import shutil
import sys
from pathlib import Path

def copy_modules():
    """Copy necessary modules from ShadowProbe_py to ShadowProbe_Web"""
    
    # Define source and destination paths
    source_dir = Path("../ShadowProbe_py")
    dest_dir = Path(".")
    
    # Only copy core modules, not scanner (we have new async scanners)
    modules_to_copy = [
        "core"
    ]
    
    print("🔄 Copying ShadowProbe modules...")
    
    for module in modules_to_copy:
        source_path = source_dir / module
        dest_path = dest_dir / module
        
        if source_path.exists():
            # Remove existing destination if it exists
            if dest_path.exists():
                shutil.rmtree(dest_path)
            
            # Copy the module
            shutil.copytree(source_path, dest_path)
            print(f"✅ Copied {module}/")
        else:
            print(f"❌ Source module {module} not found at {source_path}")
            return False
    
    # Check if async scanner modules exist
    print("🔍 Checking async scanner modules...")
    scanner_modules = ["scanner/port_scanner.py", "scanner/host_resolver.py"]
    
    for scanner_file in scanner_modules:
        if Path(scanner_file).exists():
            print(f"✅ {scanner_file} exists")
        else:
            print(f"❌ {scanner_file} not found")
            return False
    
    return True

def create_directories():
    """Create necessary directories"""
    
    directories = [
        "reports",
        "logs",
        "static",
        "templates"
    ]
    
    print("📁 Creating directories...")
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")

def check_dependencies():
    """Check if required dependencies are available"""
    
    print("🔍 Checking dependencies...")
    
    # Check Python version
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher is required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check if nmap is available
    try:
        import nmap
        print("✅ python-nmap is available")
    except ImportError:
        print("⚠️  python-nmap not found - will use fallback methods")
    
    # Check if aiodns is available
    try:
        import aiodns
        print("✅ aiodns is available")
    except ImportError:
        print("⚠️  aiodns not found - will install during requirements installation")
    
    # Check if pydantic is available
    try:
        import pydantic
        print(f"✅ pydantic {pydantic.VERSION} is available")
    except ImportError:
        print("⚠️  pydantic not found - will install during requirements installation")
    
    # Check if nmap executable is available
    nmap_path = shutil.which("nmap")
    if nmap_path:
        print(f"✅ nmap executable found at: {nmap_path}")
    else:
        print("⚠️  nmap executable not found - will use socket fallback")
    
    return True

def install_requirements():
    """Install Python requirements"""
    
    print("📦 Installing requirements...")
    
    try:
        import subprocess
        result = SecurityUtils.safe_subprocess_run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Requirements installed successfully")
            return True
        else:
            print(f"❌ Failed to install requirements: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error installing requirements: {e}")
        return False

def main():
    """Main setup function"""
    
    print("🚀 Setting up ShadowProbe Web...")
    print("=" * 50)
    
    # Check dependencies first
    if not check_dependencies():
        print("❌ Dependency check failed")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Copy modules
    if not copy_modules():
        print("❌ Failed to copy modules")
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print("❌ Failed to install requirements")
        sys.exit(1)
    
    print("=" * 50)
    print("✅ ShadowProbe Web setup completed successfully!")
    print()
    print("🎯 Next steps:")
    print("1. Run the application: python app.py")
    print("2. Open your browser to: http://localhost:5000")
    print("3. Start scanning!")
    print()
    print("📚 For more information, see README.md")

if __name__ == "__main__":
    main() 