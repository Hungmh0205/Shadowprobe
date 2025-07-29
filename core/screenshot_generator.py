#!/usr/bin/env python3
"""
Screenshot generator using Selenium as fallback
"""

import asyncio
import logging
import os
import aiohttp
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class ScreenshotGenerator:
    def __init__(self):
        self.screenshot_dir = Path("static/screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.last_request_time = 0
        self.min_delay = 2  # Minimum delay between requests (seconds)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        self.current_ua_index = 0
    
    async def check_thumio_availability(self, subdomain):
        """Check if thum.io is available for this subdomain"""
        try:
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.min_delay:
                await asyncio.sleep(self.min_delay - time_since_last)
            
            # Rotate User-Agent
            user_agent = self.user_agents[self.current_ua_index]
            self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
            
            test_url = f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
            
            async with aiohttp.ClientSession() as session:
                async with session.head(test_url, timeout=5, headers={'User-Agent': user_agent}) as response:
                    self.last_request_time = time.time()
                    
                    if response.status == 200:
                        # Check if response is actually an image
                        content_type = response.headers.get('content-type', '')
                        if 'image' in content_type:
                            logger.info(f"✅ Thum.io available for {subdomain}")
                            return True
                        else:
                            logger.warning(f"❌ Thum.io returned non-image for {subdomain}: {content_type}")
                            return False
                    else:
                        logger.warning(f"❌ Thum.io failed for {subdomain}: {response.status}")
                        return False
        except Exception as e:
            logger.warning(f"❌ Thum.io check failed for {subdomain}: {e}")
            return False
    
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
    
    async def get_screenshot_info_async(self, subdomain):
        """Get comprehensive screenshot information with automatic fallback"""
        # Always try Selenium first for better reliability
        logger.info(f"📸 Using Selenium for {subdomain} (more reliable)")
        try:
            selenium_url = await self.generate_screenshot(f"http://{subdomain}", subdomain)
            if selenium_url:
                return {
                    "screenshot_url": selenium_url,
                    "screenshot_alt1": selenium_url,
                    "screenshot_alt2": selenium_url,
                    "screenshot_alt3": selenium_url,
                    "screenshot_alt4": selenium_url,
                    "services": ["Selenium Local"],
                    "method": "selenium"
                }
            else:
                # Try HTTPS if HTTP fails
                selenium_url_https = await self.generate_screenshot(f"https://{subdomain}", subdomain)
                if selenium_url_https:
                    return {
                        "screenshot_url": selenium_url_https,
                        "screenshot_alt1": selenium_url_https,
                        "screenshot_alt2": selenium_url_https,
                        "screenshot_alt3": selenium_url_https,
                        "screenshot_alt4": selenium_url_https,
                        "services": ["Selenium Local (HTTPS)"],
                        "method": "selenium_https"
                    }
        except Exception as e:
            logger.warning(f"❌ Selenium failed for {subdomain}: {e}")
        
        # Fallback to thum.io only if Selenium fails
        logger.info(f"📸 Selenium failed, trying Thum.io for {subdomain}")
        thumio_available = await self.check_thumio_availability(subdomain)
        
        if thumio_available:
            return {
                "screenshot_url": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}",
                "screenshot_alt1": f"https://image.thum.io/get/width/1200/crop/800/noanimate/https://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
                "screenshot_alt2": f"https://image.thum.io/get/width/1200/crop/800/http://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
                "screenshot_alt3": f"https://image.thum.io/get/width/1200/crop/800/https://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
                "screenshot_alt4": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
                "services": ["Thumb.io (Free)"],
                "method": "thumio"
            }
        else:
            # Both failed
            logger.warning(f"❌ Both Selenium and Thum.io failed for {subdomain}")
            return {
                "screenshot_url": "",
                "screenshot_alt1": "",
                "screenshot_alt2": "",
                "screenshot_alt3": "",
                "screenshot_alt4": "",
                "services": ["None Available"],
                "method": "none"
            }
    
    def get_free_screenshot_urls(self, subdomain):
        """Get list of free screenshot service URLs"""
        urls = [
            f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
        ]
        return urls
    
    def get_screenshot_info(self, subdomain):
        """Get comprehensive screenshot information (sync version for backward compatibility)"""
        return {
            "screenshot_url": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}",
            "screenshot_alt1": f"https://image.thum.io/get/width/1200/crop/800/noanimate/https://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
            "screenshot_alt2": f"https://image.thum.io/get/width/1200/crop/800/http://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
            "screenshot_alt3": f"https://image.thum.io/get/width/1200/crop/800/https://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
            "screenshot_alt4": f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}?user_agent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36",
            "services": [
                "Thumb.io (Free)"
            ]
        }

# Global instance
screenshot_generator = ScreenshotGenerator() 