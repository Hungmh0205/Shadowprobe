#!/usr/bin/env python3
"""
Quick restart script for ShadowProbe Web
"""

import os
import sys
import subprocess
import time

def restart_server():
    """Restart the ShadowProbe Web server"""
    print("🔄 Restarting ShadowProbe Web Server...")
    
    try:
        # Kill existing process if running
        try:
            subprocess.run(['taskkill', '/f', '/im', 'python.exe'], 
                         capture_output=True, timeout=5)
            print("✅ Stopped existing processes")
        except:
            pass
        
        # Wait a moment
        time.sleep(2)
        
        # Start server
        print("🚀 Starting server...")
        subprocess.run([sys.executable, 'start.py'])
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Error restarting: {e}")

if __name__ == "__main__":
    restart_server() 