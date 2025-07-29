import hashlib
import socket
import asyncio
import aiohttp
import concurrent.futures
from bs4 import BeautifulSoup
import re
import whois
import logging
import sys
from scanner.port_scanner import PortScanner

# Windows-specific asyncio configuration
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)

# Cache for geo information to avoid repeated API calls
geo_cache = {}

SECURITY_HEADER_KEYS = [
    "Content-Security-Policy",
    "Strict-Transport-Security", 
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Expect-CT"
]

def extract_security_headers(headers):
    return {k: v for k, v in headers.items() if k in SECURITY_HEADER_KEYS}

def detect_technologies(http_info, https_info):
    techs = set()
    infos = [https_info, http_info]
    
    for info in infos:
        if not info or 'error' in info:
            continue
            
        headers = info.get('headers', {})
        
        # Server detection (case-insensitive)
        server = headers.get('Server') or headers.get('server')
        if server:
            techs.add(server)
            
        # X-Powered-By detection
        xpb = headers.get('X-Powered-By') or headers.get('x-powered-by')
        if xpb:
            techs.add(xpb)
            
        # ASP.NET version
        asp = headers.get('X-AspNet-Version') or headers.get('x-aspnet-version')
        if asp:
            techs.add('ASP.NET ' + asp)
            
        # Cookie-based detection
        cookies = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
        if 'PHPSESSID' in cookies:
            techs.add('PHP')
        if 'JSESSIONID' in cookies:
            techs.add('Java')
        if 'wordpress' in cookies.lower():
            techs.add('WordPress')
            
        # HTML content analysis
        html = info.get('body', '')
        if html:
            # Meta generator tags
            gens = re.findall(r'<meta[^>]+name=["\"]generator["\"][^>]+content=["\"]([^"\"]+)["\"]', html, re.I)
            for g in gens:
                techs.add(g)
                
            # CMS detection
            if 'wp-content' in html or 'wp-includes' in html:
                techs.add('WordPress')
            if 'drupal-settings-json' in html:
                techs.add('Drupal')
            if 'Joomla!' in html:
                techs.add('Joomla')
            if 'content="Wix.com' in html:
                techs.add('Wix')
            if 'Shopify.theme' in html:
                techs.add('Shopify')
            if 'cdn.shopify.com' in html:
                techs.add('Shopify CDN')
                
        # CDN detection
        server_lower = (headers.get('Server') or headers.get('server') or '').lower()
        if 'cloudflare' in server_lower:
            techs.add('Cloudflare')
        if 'nginx' in server_lower:
            techs.add('Nginx')
        if 'apache' in server_lower:
            techs.add('Apache')
        if 'gws' in server_lower:
            techs.add('Google Web Server')
            
    logger.info(f"🔍 Technology detection found: {list(techs)}")
    return list(techs)

async def enrich_subdomain_fast(subdomain, timeout=30):
    """
    Fast async enrichment with parallel processing
    """
    logger.info(f"🚀 Starting fast enrichment for {subdomain}")
    
    # Resolve IP
    try:
        ip = socket.gethostbyname(subdomain)
        logger.info(f"✅ Resolved IP for {subdomain}: {ip}")
    except Exception as e:
        ip = None
        logger.warning(f"❌ Failed to resolve IP for {subdomain}: {e}")
    
    # Create tasks for parallel processing
    tasks = {}
    
    # HTTP/HTTPS tasks (always run)
    tasks['http'] = asyncio.create_task(get_http_async(f"http://{subdomain}"))
    tasks['https'] = asyncio.create_task(get_http_async(f"https://{subdomain}"))
    
    # Geo task (only if IP exists)
    if ip:
        tasks['geo'] = asyncio.create_task(get_geo_async(ip))
    
    # WHOIS task (in thread pool)
    tasks['whois'] = asyncio.create_task(get_whois_async(subdomain))
    
    # Wait for all tasks with timeout
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks.values(), return_exceptions=True), timeout=timeout)
        
        # Process results
        geo = {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}
        http = {"error": "Failed"}
        https = {"error": "Failed"}
        whois_info = {"registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A"}
        
        task_names = list(tasks.keys())
        for i, result in enumerate(results):
            task_name = task_names[i]
            if isinstance(result, Exception):
                logger.warning(f"❌ {task_name} failed: {result}")
                continue
                
            if task_name == "geo":
                geo = result
                if ip:
                    geo_cache[ip] = geo
            elif task_name == "http":
                http = result
            elif task_name == "https":
                https = result
            elif task_name == "whois":
                whois_info = result
                
    except asyncio.TimeoutError:
        logger.warning(f"⏰ Enrichment timeout for {subdomain}")
        geo = {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}
        http = {"error": "Timeout"}
        https = {"error": "Timeout"}
        whois_info = {"registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A"}
    
    # Quick port scan (only common ports)
    ports = []
    if ip:
        try:
            logger.info(f"🔌 Quick port scan for {subdomain}")
            # Only scan most common ports for speed
            quick_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
            scanner = PortScanner()
            open_ports, services = await scanner.scan_specific_ports(ip, quick_ports)
            for svc in services:
                ports.append({
                    "port": svc.port,
                    "service": svc.service_name,
                    "status": "open"
                })
            logger.info(f"✅ Quick port scan for {subdomain}: {len(ports)} open ports")
        except Exception as e:
            logger.warning(f"❌ Port scan failed for {subdomain}: {e}")
    
    # Process results with debug logging
    logger.info(f"🔍 Processing HTTP/HTTPS results for {subdomain}")
    logger.info(f"   HTTP status: {http.get('status', 'error')}")
    logger.info(f"   HTTPS status: {https.get('status', 'error')}")
    logger.info(f"   HTTP error: {http.get('error', 'none')}")
    logger.info(f"   HTTPS error: {https.get('error', 'none')}")
    
    hash_info = {
        "md5": http.get("md5") or https.get("md5") or "",
        "sha256": http.get("sha256") or https.get("sha256") or ""
    }
    security_headers = https.get("security_headers") or http.get("security_headers") or {}
    technologies = detect_technologies(http, https)
    
    logger.info(f"🔧 Technologies detected: {technologies}")
    
    # Screenshot URLs with free services
    try:
        from core.screenshot_generator import screenshot_generator
        screenshot_info = screenshot_generator.get_screenshot_info(subdomain)
        screenshot_url = screenshot_info["screenshot_url"]
        screenshot_alt1 = screenshot_info["screenshot_alt1"]
        screenshot_alt2 = screenshot_info["screenshot_alt2"]
        screenshot_alt3 = screenshot_info["screenshot_alt3"]
        screenshot_alt4 = screenshot_info["screenshot_alt4"]
        logger.info(f"📸 Screenshot URLs generated for {subdomain}")
    except ImportError:
        # Fallback if screenshot generator not available
        screenshot_url = f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
        screenshot_alt1 = f"https://image.thum.io/get/width/1200/crop/800/noanimate/https://{subdomain}"
        screenshot_alt2 = f"https://image.thum.io/get/width/1200/crop/800/http://{subdomain}"
        screenshot_alt3 = f"https://image.thum.io/get/width/1200/crop/800/https://{subdomain}"
        screenshot_alt4 = f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
        logger.info(f"📸 Fallback screenshot URLs for {subdomain}")
    
    # Mock SSL
    ssl = {"subject": subdomain, "issuer": "Cloudflare, Inc.", "not_after": "2025-01-01"}
    
    # Try to get reverse IP domains if IP exists
    reverse_ip_domains = []
    if ip:
        try:
            logger.info(f"🔄 Getting reverse IP domains for {ip}")
            reverse_ip_domains = await get_reverse_ip_async(ip)
            logger.info(f"✅ Reverse IP found {len(reverse_ip_domains)} domains for {ip}")
        except Exception as e:
            logger.warning(f"❌ Reverse IP failed for {ip}: {e}")
    
    result = {
        "subdomain": subdomain,
        "status": "active" if ip else "inactive",
        "ip": ip,
        "geo": geo,
        "ports": ports,
        "technologies": technologies,
        "screenshot_url": screenshot_url,
        "screenshot_alt1": screenshot_alt1,
        "screenshot_alt2": screenshot_alt2,
        "hash": hash_info,
        "security_headers": security_headers,
        "whois": whois_info,
        "reverse_ip_domains": reverse_ip_domains,
        "http": http,
        "https": https,
        "ssl": ssl
    }
    
    logger.info(f"🎉 Fast enrichment completed for {subdomain}: {len(ports)} ports, {len(technologies)} technologies")
    return result

async def get_geo_async(ip):
    """Async geo information with caching and better error handling"""
    if ip in geo_cache:
        logger.info(f"📋 Using cached geo info for {ip}")
        return geo_cache[ip]
    
    try:
        # Configure session with better Windows compatibility
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            force_close=True
        )
        
        timeout = aiohttp.ClientTimeout(total=3, connect=2)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        ) as session:
            async with session.get(f'http://ip-api.com/json/{ip}') as resp:
                if resp.status == 200:
                    data = await resp.json()
                    geo = {
                        "country": data.get("country", "N/A"),
                        "city": data.get("city", "N/A"),
                        "asn": data.get("as"),
                        "isp": data.get("isp", "N/A")
                    }
                    geo_cache[ip] = geo
                    return geo
    except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionResetError, OSError) as e:
        logger.debug(f"Geo API failed for {ip}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected geo error for {ip}: {e}")
    return {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}

async def get_http_async(url):
    """Async HTTP information retrieval with better error handling"""
    try:
        # Configure session with better Windows compatibility
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            force_close=True  # Force close connections to avoid Windows issues
        )
        
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        
        # Rotate User-Agents to avoid blocking
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        import random
        user_agent = random.choice(user_agents)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        ) as session:
            async with session.get(url, ssl=False) as resp:
                content = await resp.text()
                headers = dict(resp.headers)
                
                # Quick title extraction
                title = None
                if headers.get('content-type', '').startswith('text/html'):
                    try:
                        # Fast title extraction without full parsing
                        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.I)
                        if title_match:
                            title = title_match.group(1).strip()
                    except Exception:
                        pass
                
                # Hash calculation
                md5 = hashlib.md5(content.encode(errors='ignore')).hexdigest()
                sha256 = hashlib.sha256(content.encode(errors='ignore')).hexdigest()
                
                # Security headers
                security_headers = extract_security_headers(headers)
                
                return {
                    "status": resp.status,
                    "headers": headers,
                    "title": title,
                    "body": content,
                    "md5": md5,
                    "sha256": sha256,
                    "security_headers": security_headers
                }
    except (aiohttp.ClientError, asyncio.TimeoutError, ConnectionResetError, OSError) as e:
        logger.debug(f"HTTP request failed for {url}: {e}")
        return {"error": str(e)}
    except aiohttp.ClientResponseError as e:
        if e.status == 403:
            logger.warning(f"Access forbidden (403) for {url} - likely blocked by server")
            return {"error": "Access forbidden (403)", "status": 403}
        elif e.status == 429:
            logger.warning(f"Rate limited (429) for {url} - too many requests")
            return {"error": "Rate limited (429)", "status": 429}
        else:
            logger.warning(f"HTTP error {e.status} for {url}: {e}")
            return {"error": f"HTTP {e.status}", "status": e.status}
    except Exception as e:
        logger.warning(f"Unexpected error for {url}: {e}")
        return {"error": str(e)}

async def get_whois_async(subdomain):
    """Async WHOIS information retrieval with better error handling and multiple sources"""
    try:
        loop = asyncio.get_event_loop()
        
        # Try multiple WHOIS servers
        whois_servers = [
            None,  # Default
            "whois.verisign-grs.com",
            "whois.internic.net",
            "whois.iana.org"
        ]
        
        for server in whois_servers:
            try:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    if server:
                        w = await loop.run_in_executor(executor, whois.whois, subdomain, server)
                    else:
                        w = await loop.run_in_executor(executor, whois.whois, subdomain)
                    
                    # Better date handling
                    def format_date(date):
                        if not date:
                            return "N/A"
                        if isinstance(date, list):
                            date = date[0] if date else None
                        if date:
                            try:
                                return str(date)
                            except:
                                return "N/A"
                        return "N/A"
                    
                    # Check if we got valid data
                    if w and (w.registrar or w.creation_date or w.expiration_date):
                        whois_info = {
                            "registrar": w.registrar or "N/A",
                            "creation_date": format_date(w.creation_date),
                            "expiration_date": format_date(w.expiration_date),
                            "updated_date": format_date(w.updated_date),
                            "status": w.status or "N/A",
                            "name_servers": w.name_servers or "N/A"
                        }
                        
                        logger.info(f"✅ WHOIS info for {subdomain} (server: {server}): {whois_info.get('registrar')}")
                        return whois_info
                        
            except Exception as server_error:
                logger.debug(f"WHOIS server {server} failed for {subdomain}: {server_error}")
                continue
        
        # If all servers failed, try alternative method
        logger.info(f"🔄 Trying alternative WHOIS lookup for {subdomain}")
        try:
            import socket
            import subprocess
            
            # Try using system whois command
            result = await loop.run_in_executor(executor, subprocess.run, 
                ['whois', subdomain], 
                subprocess.PIPE, subprocess.PIPE, subprocess.PIPE)
            
            if result.returncode == 0:
                whois_output = result.stdout.decode('utf-8', errors='ignore')
                
                # Parse basic info from output
                registrar = "N/A"
                creation_date = "N/A"
                expiration_date = "N/A"
                
                for line in whois_output.split('\n'):
                    line = line.strip().lower()
                    if 'registrar:' in line:
                        registrar = line.split(':', 1)[1].strip()
                    elif 'creation date:' in line or 'created:' in line:
                        creation_date = line.split(':', 1)[1].strip()
                    elif 'expiration date:' in line or 'expires:' in line:
                        expiration_date = line.split(':', 1)[1].strip()
                
                whois_info = {
                    "registrar": registrar,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "updated_date": "N/A",
                    "status": "N/A",
                    "name_servers": "N/A"
                }
                
                logger.info(f"✅ Alternative WHOIS for {subdomain}: {registrar}")
                return whois_info
                
        except Exception as alt_error:
            logger.debug(f"Alternative WHOIS failed for {subdomain}: {alt_error}")
        
        # Return default values if all methods failed
        logger.warning(f"❌ All WHOIS methods failed for {subdomain}")
        return {
            "registrar": "N/A", 
            "creation_date": "N/A", 
            "expiration_date": "N/A",
            "updated_date": "N/A",
            "status": "N/A",
            "name_servers": "N/A"
        }
            
    except Exception as e:
        logger.warning(f"❌ WHOIS failed for {subdomain}: {e}")
        return {
            "registrar": "N/A", 
            "creation_date": "N/A", 
            "expiration_date": "N/A",
            "updated_date": "N/A",
            "status": "N/A",
            "name_servers": "N/A"
        }

async def get_reverse_ip_async(ip):
    """Async reverse IP lookup with multiple sources"""
    domains = []
    
    try:
        # Source 1: ViewDNS.info
        logger.info(f"🔄 Getting reverse IP from ViewDNS for {ip}")
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            force_close=True
        )
        
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        ) as session:
            url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
            async with session.get(url) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    soup = BeautifulSoup(content, "html.parser")
                    table = soup.find_all("table")[3] if len(soup.find_all("table")) > 3 else None
                    if table:
                        rows = table.find_all("tr")[1:]
                        for row in rows:
                            cols = row.find_all("td")
                            if cols and len(cols) >= 1:
                                domain = cols[0].get_text(strip=True)
                                if domain and domain != ip:
                                    domains.append(domain)
                    logger.info(f"✅ ViewDNS found {len(domains)} domains for {ip}")
                    
    except Exception as e:
        logger.warning(f"❌ ViewDNS reverse IP failed for {ip}: {e}")
    
    # If no domains found, try alternative method
    if not domains:
        try:
            # Source 2: DNS lookup for common reverse domains
            logger.info(f"🔄 Trying DNS reverse lookup for {ip}")
            common_domains = [
                f"reverse.{ip}.in-addr.arpa",
                f"dns.{ip}.in-addr.arpa",
                f"ptr.{ip}.in-addr.arpa"
            ]
            
            for domain in common_domains:
                try:
                    import socket
                    result = socket.gethostbyaddr(ip)
                    if result and result[0]:
                        domains.append(result[0])
                except:
                    continue
                    
            logger.info(f"✅ DNS reverse lookup found {len(domains)} domains for {ip}")
            
        except Exception as e:
            logger.warning(f"❌ DNS reverse lookup failed for {ip}: {e}")
    
    return domains

# Batch enrichment for multiple subdomains
async def enrich_subdomains_batch(subdomains, max_concurrent=20, timeout=30):
    """
    Enrich multiple subdomains in parallel with high concurrency
    """
    logger.info(f"🚀 Starting batch enrichment for {len(subdomains)} subdomains")
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def enrich_with_semaphore(subdomain):
        async with semaphore:
            return await enrich_subdomain_fast(subdomain, timeout)
    
    tasks = [enrich_with_semaphore(subdomain) for subdomain in subdomains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions
    valid_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning(f"❌ Enrichment failed for {subdomains[i]}: {result}")
        else:
            valid_results.append(result)
    
    logger.info(f"✅ Batch enrichment completed: {len(valid_results)}/{len(subdomains)} successful")
    return valid_results 