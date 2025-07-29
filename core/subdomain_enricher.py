import hashlib
import socket
import requests
import asyncio
from scanner.port_scanner import PortScanner
import httpx
from bs4 import BeautifulSoup
import re
import whois
import time

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
    # Ưu tiên HTTPS
    infos = [https_info, http_info]
    for info in infos:
        if not info or 'error' in info:
            continue
        headers = info.get('headers', {})
        # Server
        server = headers.get('server')
        if server:
            techs.add(server)
        # X-Powered-By
        xpb = headers.get('x-powered-by')
        if xpb:
            techs.add(xpb)
        # X-AspNet-Version
        asp = headers.get('x-aspnet-version')
        if asp:
            techs.add('ASP.NET ' + asp)
        # Set-Cookie (PHPSESSID, JSESSIONID, ...)
        cookies = headers.get('set-cookie', '')
        if 'PHPSESSID' in cookies:
            techs.add('PHP')
        if 'JSESSIONID' in cookies:
            techs.add('Java')
        if 'wordpress' in cookies.lower():
            techs.add('WordPress')
        # HTML meta generator
        html = info.get('body', '')
        if html:
            gens = re.findall(r'<meta[^>]+name=["\"]generator["\"][^>]+content=["\"]([^"\"]+)["\"]', html, re.I)
            for g in gens:
                techs.add(g)
            # CMS phổ biến
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
            if 'cloudflare' in headers.get('server', '').lower():
                techs.add('Cloudflare')
    return list(techs)

def get_http_info(url, timeout=8):
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }) as client:
            resp = client.get(url)
            status = resp.status_code
            headers = dict(resp.headers)
            server = headers.get('server', '')
            content = resp.text
            # Title
            title = None
            if headers.get('content-type', '').startswith('text/html'):
                try:
                    soup = BeautifulSoup(content, "html.parser")
                    t = soup.find("title")
                    if t:
                        title = t.get_text().strip()
                except Exception:
                    pass
            # Hash
            md5 = hashlib.md5(content.encode(errors='ignore')).hexdigest()
            sha256 = hashlib.sha256(content.encode(errors='ignore')).hexdigest()
            # Security headers
            sec_headers = extract_security_headers(headers)
            return {
                "status": status,
                "title": title,
                "headers": headers,
                "server": server,
                "md5": md5,
                "sha256": sha256,
                "security_headers": sec_headers,
                "body": content
            }
    except Exception as e:
        return {"error": str(e)}

import logging
logger = logging.getLogger(__name__)

def enrich_subdomain_full(subdomain):
    """
    Enrich subdomain: trả về dict với các trường enrich thật (Geo, Open Ports, HTTP/HTTPS, Security Headers, Hash)
    """
    logger.info(f"🔍 Starting enrichment for subdomain: {subdomain}")
    
    # Resolve IP
    try:
        ip = socket.gethostbyname(subdomain)
        logger.info(f"✅ Resolved IP for {subdomain}: {ip}")
    except Exception as e:
        ip = None
        logger.warning(f"❌ Failed to resolve IP for {subdomain}: {e}")
    # Enrich Geo
    geo = None
    if ip:
        try:
            logger.info(f"🌍 Getting geo info for IP: {ip}")
            resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                geo = {
                    "country": data.get("country", "N/A"),
                    "city": data.get("city", "N/A"),
                    "asn": data.get("as"),
                    "isp": data.get("isp", "N/A")
                }
                logger.info(f"✅ Geo info for {ip}: {geo.get('country')}, {geo.get('city')}")
            else:
                geo = {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}
                logger.warning(f"❌ Geo API failed for {ip}: status {resp.status_code}")
        except Exception as e:
            geo = {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}
            logger.warning(f"❌ Geo enrichment failed for {ip}: {e}")
    else:
        geo = {"country": "N/A", "city": "N/A", "asn": None, "isp": "N/A"}
        logger.info(f"ℹ️ Skipping geo enrichment - no IP available")
    # Enrich open ports (scan thực tế)
    ports = []
    if ip:
        try:
            logger.info(f"🔌 Scanning ports for {subdomain} ({ip})")
            common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
            scanner = PortScanner()
            open_ports, services = asyncio.run(scanner.scan_specific_ports(ip, common_ports))
            for svc in services:
                ports.append({
                    "port": svc.port,
                    "service": svc.service_name,
                    "status": "open"
                })
            logger.info(f"✅ Port scan for {subdomain}: {len(ports)} open ports")
        except Exception as e:
            ports = []
            logger.warning(f"❌ Port scan failed for {subdomain}: {e}")
    else:
        logger.info(f"ℹ️ Skipping port scan - no IP available")
    # Enrich HTTP/HTTPS
    logger.info(f"🌐 Getting HTTP/HTTPS info for {subdomain}")
    http = get_http_info(f"http://{subdomain}")
    https = get_http_info(f"https://{subdomain}")
    logger.info(f"✅ HTTP/HTTPS info collected for {subdomain}")
    # Hash (ưu tiên hash của HTTP, nếu có)
    hash_info = {
        "md5": http.get("md5") or https.get("md5") or "",
        "sha256": http.get("sha256") or https.get("sha256") or ""
    }
    # Security headers (ưu tiên HTTPS, nếu có)
    security_headers = https.get("security_headers") or http.get("security_headers") or {}
    # Technologies
    logger.info(f"🔧 Detecting technologies for {subdomain}")
    technologies = detect_technologies(http, https)
    logger.info(f"✅ Technologies detected for {subdomain}: {len(technologies)} found")
    
    # Screenshot (dùng thum.io, không cần API key)
    screenshot_url = f"https://image.thum.io/get/width/1200/crop/800/noanimate/http://{subdomain}"
    logger.info(f"📸 Screenshot URL generated for {subdomain}")
    # WHOIS
    logger.info(f"📋 Getting WHOIS info for {subdomain}")
    whois_info = {"registrar": "N/A", "creation_date": "N/A", "expiration_date": "N/A"}
    try:
        w = whois.whois(subdomain)
        whois_info = {
            "registrar": w.registrar or "N/A",
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else "N/A"
        }
        logger.info(f"✅ WHOIS info for {subdomain}: {whois_info.get('registrar')}")
    except Exception as e:
        logger.warning(f"❌ WHOIS failed for {subdomain}: {e}")
    # Reverse IP (dùng viewdns.info, miễn phí, không cần key)
    reverse_ip_domains = []
    if ip:
        try:
            logger.info(f"🔄 Getting reverse IP domains for {ip}")
            url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
            resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                # Parse HTML table
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                table = soup.find_all("table")[3] if len(soup.find_all("table")) > 3 else None
                if table:
                    rows = table.find_all("tr")[1:]
                    for row in rows:
                        cols = row.find_all("td")
                        if cols and len(cols) >= 1:
                            domain = cols[0].get_text(strip=True)
                            if domain and domain != subdomain:
                                reverse_ip_domains.append(domain)
                logger.info(f"✅ Reverse IP for {ip}: {len(reverse_ip_domains)} domains found")
            time.sleep(1)  # tránh bị block
        except Exception as e:
            logger.warning(f"❌ Reverse IP failed for {ip}: {e}")
    else:
        logger.info(f"ℹ️ Skipping reverse IP - no IP available")
    # Mock SSL
    ssl = {"subject": subdomain, "issuer": "Cloudflare, Inc.", "not_after": "2025-01-01"}
    
    result = {
        "subdomain": subdomain,
        "status": "active" if ip else "inactive",
        "ip": ip,
        "geo": geo,
        "ports": ports,
        "technologies": technologies,
        "screenshot_url": screenshot_url,
        "hash": hash_info,
        "security_headers": security_headers,
        "whois": whois_info,
        "reverse_ip_domains": reverse_ip_domains,
        "http": http,
        "https": https,
        "ssl": ssl
    }
    
    logger.info(f"🎉 Enrichment completed for {subdomain}: {len(ports)} ports, {len(technologies)} technologies")
    return result 