#!/usr/bin/env python3
"""
Screenshot generator using Selenium as fallback
"""

import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class ScreenshotGenerator:
    def __init__(self):
        self.screenshot_dir = Path("static/screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
    
    async def generate_screenshot(self, url, subdomain):
        """Generate screenshot using Selenium"""
        try:
            # Check if Selenium is available
            try:
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options
                from selenium.webdriver.common.by import By
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
            except ImportError:
                logger.warning("Selenium not available, using external services only")
                return None
            
            # Configure Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1200,800")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            driver = None
            try:
                driver = webdriver.Chrome(options=chrome_options)
                driver.set_page_load_timeout(30)
                
                # Navigate to URL
                driver.get(url)
                
                # Wait for page to load
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Generate filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{subdomain}_{timestamp}.png"
                filepath = self.screenshot_dir / filename
                
                # Take screenshot
                driver.save_screenshot(str(filepath))
                
                # Return relative URL
                relative_url = f"/static/screenshots/{filename}"
                logger.info(f"✅ Screenshot generated: {relative_url}")
                
                return relative_url
                
            except Exception as e:
                logger.warning(f"❌ Selenium screenshot failed for {url}: {e}")
                return None
                
            finally:
                if driver:
                    driver.quit()
                    
        except Exception as e:
            logger.error(f"❌ Screenshot generation failed: {e}")
            return None
    
    def get_free_screenshot_urls(self, subdomain):
        """Get list of free screenshot service URLs"""
        urls = [
            f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
        ]
        return urls
    
    def get_screenshot_info(self, subdomain):
        """Get comprehensive screenshot information"""
        return {
            "screenshot_url": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}",
            "screenshot_alt1": f"https://image.thum.io/get/width/1200/crop/800/noanimate/https://{subdomain}",
            "screenshot_alt2": f"https://image.thum.io/get/width/1200/crop/800/http://{subdomain}",
            "screenshot_alt3": f"https://image.thum.io/get/width/1200/crop/800/https://{subdomain}",
            "screenshot_alt4": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}",
            "services": [
                "Thumb.io (Free)"
            ]
        }

# Global instance
screenshot_generator = ScreenshotGenerator() 