#!/usr/bin/env python3

from datetime import datetime, date
from collections import OrderedDict
import concurrent.futures
import dns.resolver
import OpenSSL
import ssl
import requests
from typing import Optional, Union
import argparse
import random
import string
import json
import bs4
import sys
import os
import re
import time
from tqdm.auto import tqdm
import warnings
from urllib3.exceptions import InsecureRequestWarning
import asyncio
import httpx
import aiodns
import subprocess
import dns.asyncresolver
import dns.exception
import dns.query
import dns.zone
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import logging
logger = logging.getLogger(__name__)

# Suppress the warnings from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

__version__ = '7.0.2'

ROOT = os.path.abspath(os.path.dirname(__file__))

def brave_search_subdomains(domain: str, api_key: str, max_results: int = 100) -> list:
    """
    Tìm subdomain bằng Brave Search API
    """
    subdomains = set()
    
    try:
        # Brave Search API endpoint
        url = "https://api.search.brave.com/res/v1/web/search"
        
        # Các query patterns để tìm subdomain
        search_queries = [
            f'site:*.{domain}',
            f'"{domain}" subdomain',
            f'"{domain}" -site:{domain}',
            f'*.{domain}',
            f'"{domain}" inurl:',
            f'"{domain}" hostname'
        ]
        
        headers = {
            'Accept': 'application/json',
            'X-Subscription-Token': api_key
        }
        
        for query in search_queries:
            try:
                params = {
                    'q': query,
                    'count': min(max_results, 50),  # Brave API limit
                    'safesearch': 'off'
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                
                data = response.json()
                
                if 'web' in data and 'results' in data['web']:
                    for result in data['web']['results']:
                        # Extract URLs from search results
                        if 'url' in result:
                            url = result['url']
                            # Parse URL to extract subdomain
                            parsed = urlparse(url)
                            hostname = parsed.netloc
                            
                            # Check if it's a subdomain of our target domain
                            if hostname.endswith(f'.{domain}') and hostname != domain:
                                subdomain = hostname.replace(f'.{domain}', '')
                                if subdomain and '.' not in subdomain:  # Avoid nested subdomains
                                    subdomains.add(f"{subdomain}.{domain}")
                        
                        # Also check title and description for subdomain mentions
                        for field in ['title', 'description']:
                            if field in result:
                                text = result[field]
                                # Find subdomain patterns in text
                                pattern = rf'\b([a-zA-Z0-9_-]+\.{re.escape(domain)})\b'
                                matches = re.findall(pattern, text)
                                for match in matches:
                                    if match.endswith(f'.{domain}') and match != domain:
                                        subdomain = match.replace(f'.{domain}', '')
                                        if subdomain and '.' not in subdomain:
                                            subdomains.add(match)
                
                # Rate limiting - wait a bit between requests
                time.sleep(0.5)
                
            except Exception as e:
                logger.warning(f"Brave search query '{query}' failed: {e}")
                continue
                
    except Exception as e:
        logger.error(f"Brave search failed: {e}")
    
    return list(subdomains)

# bruteforce via wordlist
class Bruteforce:
    def __init__(self, domain, wordlist=None):
            self.domain = domain
            self.wordlist = wordlist or os.path.join(ROOT, 'wordlist', 'wordlist.txt')

    def load_wordlist(self):
        try:
            with open(self.wordlist, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: wordlist '{self.wordlist}' not found.")
            return []

    def wildcard(self):
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 15))) + '.' + self.domain

    def start(self):
        wordlist = [str(word)+'.'+str(self.domain) for word in Bruteforce.load_wordlist(self) if word]
        wordlist = list(OrderedDict.fromkeys(wordlist))
        return wordlist

# reconnaissance via web services
class Recon:
    def __init__(self, domain: str, timeout: Optional[int] = 3, silent: Optional[bool] = None):
        """
        Initializes the Recon class.

        :param domain: The domain to analyze.
        :param timeout: Timeout for requests in seconds (default: 3).
        :param silent: If True, suppresses error messages (default: None).
        """
        self.domain = domain
        self.timeout = timeout
        self.silent = silent

    def req(self, url: str) -> Union[str, None]:
        """
        Makes a GET request to the specified URL.

        :param url: The URL to request.
        :return: The content of the response if the request is successful, otherwise [].
        """
        try:
            resp = requests.get(url, timeout=(self.timeout, self.timeout))
            resp.raise_for_status()  # Raise an exception for HTTP status codes 4xx/5xx
            return resp.text
        except requests.exceptions.Timeout:
            if not self.silent:
                print(f"Request to {url} timed out.")
            return []
        except requests.exceptions.RequestException as e:
            if not self.silent:
                print(f"An error occurred: {e}")
            return []

    def reconnaissance(self, service):
        name, url = service
        resp = Recon.req(self, url)
        return name, resp

    def services(self):
        services_list = [
            ("alienvault", f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"),
            ("certspotter", f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"),
            ("crtsh", f"https://crt.sh/?q={self.domain}&output=json"),
            ("hackertarget", f"https://api.hackertarget.com/hostsearch/?q={self.domain}"),
            ("rapiddns", f"https://rapiddns.io/subdomain/{self.domain}"),
            ("webarchive", f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt")
            ]

        API_KEY_VIRUSTOTAL = os.getenv("API_KEY_VIRUSTOTAL")
        if API_KEY_VIRUSTOTAL:
            services_list.append(("virustotal", f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={API_KEY_VIRUSTOTAL}&domain={self.domain}"))

        API_KEY_SHODAN = os.getenv("API_KEY_SHODAN")
        if API_KEY_SHODAN:
            services_list.append(("shodan", f"https://api.shodan.io/dns/domain/{self.domain}?key={API_KEY_SHODAN}"))

        # Add Brave Search if API key is available
        API_KEY_BRAVE = os.getenv("API_KEY_BRAVE")
        if API_KEY_BRAVE:
            services_list.append(("brave_search", "BRAVE_SEARCH_API"))  # Special marker for Brave Search

        return services_list

    def start(self):
        services_list = Recon.services(self)

        subdomains = []

        if not self.silent:
            pbar = tqdm(range(len(services_list)), desc="Recon.....", leave=True, ncols=80)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = {executor.submit(Recon.reconnaissance, self, service): service for service in services_list}

            for future in concurrent.futures.as_completed(results):
                if not self.silent:
                    pbar.update(1)
                try:
                    name, resp = future.result()
                    # Process the response as before...
                except Exception as e:
                    if not self.silent:
                        print(f"Error processing service {results[future]}: {e}")

                if name == "alienvault":
                    try:
                        resp = json.loads(resp)
                        subdomains += [item['hostname'] for item in resp['passive_dns'] if item['hostname'].endswith(self.domain)]
                    except:
                        pass
                elif name == "virustotal":
                    try:
                        resp = json.loads(resp)
                        if "subdomains" in resp.keys():
                            for subdomain in resp["subdomains"]:
                                if subdomain.endswith(self.domain):
                                    subdomains.append(subdomain)
                    except:
                        pass
                elif name == "shodan":
                    try:
                        resp = json.loads(resp)
                        if "subdomains" in resp.keys():
                            for subdomain in resp["subdomains"]:
                                subdomain = subdomain+"."+self.domain
                                subdomains.append(subdomain)
                    except:
                        pass
                elif name == "certspotter":
                    try:
                        resp = json.loads(resp)
                        for item in resp:
                            for subdomain in item['dns_names']:
                                if subdomain.endswith(self.domain):
                                    subdomains.append(subdomain)
                    except:
                        pass
                elif name == "crtsh":
                    try:
                        resp = json.loads(resp)
                        subdomains += [item['common_name'] for item in resp if item['common_name'].endswith(self.domain)]
                    except:
                        pass
                elif name == "hackertarget":
                    try:
                        subdomains += [item.split(',')[0] for item in resp.split('\n') if item.split(',')[0]]
                    except:
                        pass
                elif name == "rapiddns":
                    try:
                        soup = bs4.BeautifulSoup(resp, "html.parser")
                        subdomains += [item.text for item in soup.find_all("td") if item.text.endswith(self.domain)]
                    except:
                        pass            
                elif name == "webarchive":
                    try:
                        pattern = r"http(s)?:\/\/(.*\.%s)" % self.domain
                        for item in resp.split('\n'):
                            match = re.match(pattern, item)
                            if match and re.match(r"^[a-zA-Z0-9-\.]*$", match.groups()[1]):
                                subdomains += [item for item in match.groups()[1] if item.endswith(self.domain)]
                    except:
                        pass
                elif name == "brave_search":
                    try:
                        # Handle Brave Search API separately since it's not a simple HTTP request
                        API_KEY_BRAVE = os.getenv("API_KEY_BRAVE")
                        if API_KEY_BRAVE:
                            brave_results = brave_search_subdomains(self.domain, API_KEY_BRAVE)
                            subdomains.extend(brave_results)
                    except Exception as e:
                        if not self.silent:
                            print(f"Brave search failed: {e}")
                        pass
                        
            subdomains = [s for s in list(OrderedDict.fromkeys(subdomains)) if '*' not in s]

        return sorted(subdomains)

# List of user agents for HTTP requests
user_agent = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:33.0) Gecko/20120101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A',
    'Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)',
]

# test domains via DNS, HTTP, HTTPS and Certificate
class HttpStatus:
    def __init__(self, domain, dns=None, useragent=None, timeout=None):
        self.domain = domain
        self.dns = dns if dns else '8.8.8.8'
        self.headers = {'User-Agent': random.choice(user_agent)} if not useragent else {'User-Agent': useragent}
        self.timeout = timeout if timeout else 0.5

    def http_response(self, url):
        try:
            response = requests.get(url, headers=self.headers, allow_redirects=False, timeout=self.timeout, verify=False)
        except requests.RequestException as e:
            #print (str(e))
            """
            # verify=False disable security certificate checks
            # so, this exception is not used
            #
            # certificate error or expired
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                # {"https": [200, null, null]}
                return 200, None, None
            """
            return None, None, None
        
        #headers_response = response.headers
        #http_version = response.raw.version
        status_code = response.status_code
        redirect_location = response.headers.get('Location')
        server_name = response.headers.get('Server')

        return status_code, redirect_location, server_name

    def cert_status(self, domain):
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        except Exception as e:
            #print(f"Error connecting to {self.domain}: {e}")
            return None, None, None
        
        # 0=v1, 1=v2, 2=v3
        #version = x509.get_version()
        #print (version)
        bytes = x509.get_notAfter()
        timestamp = bytes.decode('utf-8')
        
        # convert dateobj and datenow to isoformat and compare the values
        dateobj = datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()
        datenow = datetime.now().date().isoformat()
        is_good = False if dateobj < datenow else True
        common_name = None

        if is_good:
            # looking for valid (CN) Common Name
            common_name = x509.get_subject().commonName
            #print (common_name)
            for i in range(x509.get_extension_count()):
                ext = x509.get_extension(i)
                if "subjectAltName" in str(ext.get_short_name()):
                    # ['DNS:domain.it', 'DNS:www.domain.it', 'DNS:sub.domain.domain.it']
                    cn = str(ext).replace("DNS:", "").split(", ")
                    if domain not in cn:
                        for name in cn:
                            # the domain use wildcard
                            # ['DNS:domain.it', 'DNS:www.domain.it', 'DNS:*.domain.domain.it']
                            if '*.' in name:
                                name = name.replace("*.", "")
                                if name in domain:
                                    break
                                is_good = False

        return is_good, dateobj, common_name

    def domain_resolver(self):
        res = dns.resolver.Resolver()
        res.timeout = self.timeout
        res.lifetime = self.timeout
        res.nameservers = [self.dns]

        try:
            ipv4 = res.resolve(self.domain, 'A')
        except:
            return None

        return [str(ip) for ip in ipv4]

    def scan(self):
        results = {"domain": self.domain}
        ip_list = self.domain_resolver()
        if not ip_list:
            return None
        
        # resolver
        results.update({"ip": ip_list})
        
        # http
        http_status_code, http_redirect_location, server_name = self.http_response(f"http://{self.domain}")
        results.update({"http": [http_status_code, http_redirect_location, server_name]})
        
        # https
        https_status_code, https_redirect_location, server_name = self.http_response(f"https://{self.domain}")
        results.update({"https": [https_status_code, https_redirect_location, server_name]})

        # https exception error
        if http_status_code and http_redirect_location and not https_status_code:
            if not http_redirect_location.startswith(('http://', 'https://')):
                http_redirect_location = 'http://' + http_redirect_location
            
            domain = http_redirect_location.split('://')[1]
            domain = domain.split('/')[0]
            https_status_code, https_redirect_location, server_name = self.http_response(f"https://{domain}")
            results.update({"https": [https_status_code, https_redirect_location, server_name]})

        is_good, dateobj, common_name = None, None, None
        if https_status_code:
            is_good, dateobj, common_name = self.cert_status(results["domain"])
        
        results.update({"cert": [is_good, dateobj, common_name]})

        return results

def KNOCKPY(domain, dns=None, useragent=None, timeout=None, threads=None, recon=None, bruteforce=None, wordlist=None, silent=None):
    def knockpy(domain, dns=None, useragent=None, timeout=None):
        return HttpStatus(domain, dns, useragent, timeout).scan()
    
    if recon and bruteforce:
        domain = Recon(domain, timeout, silent).start()
        domain += Bruteforce(domain, wordlist).start()
        domain = list(OrderedDict.fromkeys(domain))
    elif recon:
        domain = Recon(domain, timeout, silent).start()
    elif bruteforce:
        domain = Bruteforce(domain, wordlist).start()

    if isinstance(domain, list):
        if not threads:
            threads = min(30, len(domain))
        
        if not silent:
            pbar = tqdm(range(len(domain)), desc="Processing", leave=True, ncols=80)
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(knockpy, d, dns, useragent, timeout) for d in domain]

            results = []
            for future in concurrent.futures.as_completed(futures):
                if not silent:
                    pbar.update(1)
                if future.result():
                    results.append(future.result())

        return results

    return knockpy(domain, dns=None, useragent=None, timeout=None)

async def fetch_dns_records(domain, nameserver=None, timeout=3):
    """
    Lấy các bản ghi NS, MX, TXT, AXFR cho domain. Trả về dict các record và list subdomain tìm được.
    """
    import aiodns
    resolver = aiodns.DNSResolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    records = {"NS": [], "MX": [], "TXT": [], "AXFR": []}
    subdomains = set()
    # NS
    try:
        ns_result = await resolver.query(domain, 'NS')
        records["NS"] = [r.host for r in ns_result]
        subdomains.update(records["NS"])
    except Exception:
        pass
    # MX
    try:
        mx_result = await resolver.query(domain, 'MX')
        records["MX"] = [r.host for r in mx_result]
        subdomains.update(records["MX"])
    except Exception:
        pass
    # TXT
    try:
        txt_result = await resolver.query(domain, 'TXT')
        records["TXT"] = [r.text for r in txt_result]
    except Exception:
        pass
    # AXFR (zone transfer)
    try:
        ns_to_try = records["NS"] if records["NS"] else [domain]
        for ns in ns_to_try:
            try:
                zone = await dns.zone.async_from_xfr(dns.query.xfr(ns, domain, timeout=timeout))
                for name, node in zone.nodes.items():
                    fqdn = f"{name}.{domain}" if str(name) != '@' else domain
                    records["AXFR"].append(fqdn)
                    subdomains.add(fqdn)
            except Exception:
                continue
    except Exception:
        pass
    return records, list(subdomains)

async def enrich_one_async(sub, timeout=2):
    info = {"domain": sub, "ip": None, "http": None, "https": None, "cert": None, "error": ""}
    resolver = aiodns.DNSResolver()
    # DNS
    try:
        result = await resolver.gethostbyname(sub, family=2)
        info["ip"] = result.addresses[0]
    except Exception as e:
        info["error"] += f"DNS error: {e} | "
    # HTTP
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"http://{sub}")
            info["http"] = [resp.status_code, None, None]
    except Exception as e:
        info["http"] = [None, None, None]
        info["error"] += f"HTTP error: {e} | "
    # HTTPS
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(f"https://{sub}")
            info["https"] = [resp.status_code, None, None]
    except Exception as e:
        info["https"] = [None, None, None]
        info["error"] += f"HTTPS error: {e}"
    return info

async def crawl_html_for_subdomains(domain, urls=None, timeout=5, max_pages=5):
    """
    Crawl trang chủ và các trang con, extract subdomain từ HTML links (href, src, form action, ...).
    Trả về list subdomain tìm được.
    """
    import re
    import httpx
    from collections import deque
    visited = set()
    found_subdomains = set()
    if not urls:
        urls = [f"http://{domain}", f"https://{domain}"]
    queue = deque(urls)
    pattern = re.compile(rf"([a-zA-Z0-9_-]+\\.{re.escape(domain)})")
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        pages_crawled = 0
        while queue and pages_crawled < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = await client.get(url)
                html = resp.text
                soup = BeautifulSoup(html, "html.parser")
                # Extract all links, src, form actions
                tags = soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'form'])
                for tag in tags:
                    for attr in ['href', 'src', 'action']:
                        link = tag.get(attr)
                        if link:
                            # Normalize relative URLs
                            full_url = urljoin(url, link)
                            # Extract subdomain
                            for match in pattern.findall(full_url):
                                if match.endswith(domain):
                                    found_subdomains.add(match)
                            # Thêm vào queue nếu cùng domain và chưa crawl
                            parsed = urlparse(full_url)
                            if parsed.netloc.endswith(domain) and full_url not in visited:
                                queue.append(full_url)
                pages_crawled += 1
            except Exception:
                continue
    return list(found_subdomains)

async def reverse_dns_on_ips(ips, domain=None, timeout=3, max_concurrent=20):
    """
    Thực hiện reverse DNS (PTR) trên list IP, lọc ra subdomain thuộc domain mục tiêu (nếu có).
    Trả về list subdomain tìm được.
    """
    import aiodns
    import asyncio
    found = set()
    sem = asyncio.Semaphore(max_concurrent)
    async def ptr_lookup(ip):
        async with sem:
            try:
                resolver = aiodns.DNSResolver(timeout=timeout)
                result = await resolver.gethostbyaddr(ip)
                if result and result.name:
                    if domain:
                        if result.name.endswith(domain):
                            found.add(result.name.rstrip('.'))
                    else:
                        found.add(result.name.rstrip('.'))
            except Exception:
                pass
    await asyncio.gather(*(ptr_lookup(ip) for ip in ips))
    return list(found)

async def resolve_cname_chain(subdomain, timeout=3, max_depth=5):
    """
    Resolve CNAME chain cho subdomain, trả về list các CNAME trung gian và A record cuối cùng (nếu có).
    """
    import aiodns
    chain = []
    current = subdomain
    depth = 0
    resolver = aiodns.DNSResolver(timeout=timeout)
    try:
        while depth < max_depth:
            try:
                result = await resolver.query(current, 'CNAME')
                cname = result[0].host.rstrip('.')
                chain.append(cname)
                current = cname
                depth += 1
            except Exception:
                break
        # Resolve A record cuối cùng nếu có
        try:
            a_result = await resolver.query(current, 'A')
            a_ips = [r.host for r in a_result]
            return chain, a_ips
        except Exception:
            return chain, []
    except Exception:
        return chain, []

async def enrich_one_subdomain(sub, domain=None, timeout=5):
    """
    Enrich 1 subdomain: DNS (A, AAAA, MX, TXT, NS), CNAME chain, reverse DNS, HTTP/HTTPS, SSL cert.
    Trả về dict chi tiết, tối ưu cho popup recon từng subdomain.
    """
    import aiodns
    import httpx
    import ssl
    import OpenSSL
    import socket
    from datetime import datetime
    
    result = {
        "subdomain": sub,
        "ip": None,
        "dns": {},
        "cname_chain": [],
        "reverse_dns": None,
        "http": None,
        "https": None,
        "cert": None,
        "error": "",
        "enriched_at": datetime.now().isoformat()
    }
    
    resolver = aiodns.DNSResolver(timeout=timeout)
    
    # DNS records
    try:
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]:
            try:
                ans = await resolver.query(sub, rtype)
                if rtype in ["A", "AAAA"]:
                    result["dns"][rtype] = [r.host for r in ans]
                    if rtype == "A" and ans:
                        result["ip"] = ans[0].host
                elif rtype == "MX":
                    result["dns"][rtype] = [r.host for r in ans]
                elif rtype == "TXT":
                    result["dns"][rtype] = [r.text for r in ans]
                elif rtype == "NS":
                    result["dns"][rtype] = [r.host for r in ans]
                elif rtype == "CNAME":
                    result["dns"][rtype] = [r.host.rstrip('.') for r in ans]
            except Exception:
                result["dns"][rtype] = []
    except Exception as e:
        result["error"] += f"DNS error: {e} | "
    
    # CNAME chain
    try:
        cname_chain = []
        current = sub
        for _ in range(5):
            try:
                ans = await resolver.query(current, "CNAME")
                cname = ans[0].host.rstrip('.')
                cname_chain.append(cname)
                current = cname
            except Exception:
                break
        result["cname_chain"] = cname_chain
    except Exception as e:
        result["error"] += f"CNAME error: {e} | "
    
    # Reverse DNS
    try:
        if result["ip"]:
            ptr = await resolver.gethostbyaddr(result["ip"])
            result["reverse_dns"] = ptr.name.rstrip('.')
    except Exception:
        result["reverse_dns"] = None
    
    # HTTP/HTTPS with better error handling
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    }
    
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=timeout/2),
            follow_redirects=True, 
            verify=False,
            headers=headers,
            http2=False  # Disable HTTP/2 to avoid issues
        ) as client:
            # HTTP
            try:
                resp = await client.get(f"http://{sub}")
                result["http"] = {
                    "status": resp.status_code,
                    "url": str(resp.url),
                    "headers": dict(resp.headers),
                    "redirect": resp.headers.get("location"),
                    "server": resp.headers.get("server"),
                    "content_type": resp.headers.get("content-type"),
                    "content_length": resp.headers.get("content-length"),
                    "title": None
                }
                # Try to extract title
                try:
                    if resp.headers.get("content-type", "").startswith("text/html"):
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(resp.text, "html.parser")
                        title_tag = soup.find("title")
                        if title_tag:
                            result["http"]["title"] = title_tag.get_text().strip()
                except:
                    pass
            except Exception as e:
                result["http"] = {"error": str(e)}
            
            # HTTPS
            try:
                resp = await client.get(f"https://{sub}")
                result["https"] = {
                    "status": resp.status_code,
                    "url": str(resp.url),
                    "headers": dict(resp.headers),
                    "redirect": resp.headers.get("location"),
                    "server": resp.headers.get("server"),
                    "content_type": resp.headers.get("content-type"),
                    "content_length": resp.headers.get("content-length"),
                    "title": None
                }
                # Try to extract title
                try:
                    if resp.headers.get("content-type", "").startswith("text/html"):
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(resp.text, "html.parser")
                        title_tag = soup.find("title")
                        if title_tag:
                            result["https"]["title"] = title_tag.get_text().strip()
                except:
                    pass
            except Exception as e:
                result["https"] = {"error": str(e)}
    except Exception as e:
        result["error"] += f"HTTP error: {e} | "
    
    # SSL cert with better error handling
    try:
        context = ssl.create_default_context()
        with socket.create_connection((sub, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sub) as ssock:
                cert_bin = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                
                # Get subject alternative names
                san_list = []
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_str = str(ext)
                        san_list = [name.strip() for name in san_str.split(',') if 'DNS:' in name]
                        break
                
                result["cert"] = {
                    "subject": x509.get_subject().CN,
                    "issuer": x509.get_issuer().CN,
                    "not_before": x509.get_notBefore().decode(),
                    "not_after": x509.get_notAfter().decode(),
                    "serial_number": str(x509.get_serial_number()),
                    "subject_alt_names": san_list,
                    "version": x509.get_version()
                }
    except Exception as e:
        result["cert"] = {"error": str(e)}
    
    return result
    return result

# === EXPORTABLE API ===

def get_subdomains(domain, recon=True, bruteforce=False, wordlist=None, timeout=3, silent=False):  # Tắt bruteforce mặc định
    """
    Thu thập subdomain từ recon và bruteforce.
    Trả về list subdomain (chuỗi).
    """
    logger.info(f"🔍 Starting subdomain discovery for {domain}")
    subdomains = set()
    
    if recon:
        logger.info(f"📡 Running passive reconnaissance for {domain}")
        recon_results = Recon(domain, timeout, silent).start()
        subdomains.update(recon_results)
        logger.info(f"✅ Passive recon found {len(recon_results)} subdomains")
    
    if bruteforce:
        logger.info(f"🔨 Running bruteforce for {domain}")
        bruteforce_results = Bruteforce(domain, wordlist).start()
        subdomains.update(bruteforce_results)
        logger.info(f"✅ Bruteforce found {len(bruteforce_results)} subdomains")
    
    total_subdomains = list(subdomains)
    logger.info(f"🎯 Total subdomains found for {domain}: {len(total_subdomains)}")
    return total_subdomains

async def enrich_subdomains_async(subdomains, timeout=8, max_concurrent=5):
    """
    Nhận list subdomain, trả về list dict đã enrich (DNS, HTTP, HTTPS).
    Cải thiện: timeout dài hơn, concurrent thấp hơn, sử dụng enrich_one_subdomain.
    """
    logger.info(f"🔧 Starting enrichment for {len(subdomains)} subdomains")
    sem = asyncio.Semaphore(max_concurrent)
    
    async def sem_enrich(sub):
        async with sem:
            try:
                logger.debug(f"🔍 Enriching subdomain: {sub}")
                return await enrich_one_subdomain(sub, timeout=timeout)
            except Exception as e:
                logger.warning(f"❌ Enrichment failed for {sub}: {e}")
                return {
                    "subdomain": sub,
                    "error": f"Enrich failed: {str(e)}",
                    "ip": None,
                    "dns": {},
                    "http": None,
                    "https": None,
                    "cert": None
                }
    
    # Enrich tất cả subdomain với function mới
    results = await asyncio.gather(*(sem_enrich(sub) for sub in subdomains))
    
    # Lọc subdomain có IP
    valid_results = [r for r in results if r.get("ip")]
    
    logger.info(f"✅ Enrichment completed: {len(valid_results)} valid subdomains out of {len(subdomains)}")
    
    return valid_results

async def detect_wildcard_ips(domain, timeout=3):
    """
    Sinh 2 subdomain ngẫu nhiên, resolve IP, trả về set IP wildcard (nếu có).
    """
    resolver = aiodns.DNSResolver()
    ips = set()
    for _ in range(2):
        fake_sub = Bruteforce(domain).wildcard()
        try:
            result = await resolver.gethostbyname(fake_sub, family=2)
            ips.update(result.addresses)
        except Exception:
            pass
    return ips

def deduplicate_by_ip(enriched):
    """
    Lọc trùng IP: chỉ giữ lại 1 subdomain cho mỗi IP duy nhất.
    """
    seen = set()
    deduped = []
    for sd in enriched:
        ip = sd.get('ip')
        if ip and ip not in seen:
            seen.add(ip)
            deduped.append(sd)
    return deduped

def filter_live_domains(enriched):
    """
    Lọc domain sống: chỉ giữ lại subdomain có http hoặc https trả về mã 200, 301, 302.
    """
    valid_codes = {200, 301, 302}
    filtered = []
    for sd in enriched:
        http_code = sd.get('http', [None])[0]
        https_code = sd.get('https', [None])[0]
        if (http_code in valid_codes) or (https_code in valid_codes):
            filtered.append(sd)
    return filtered

def output(results, json_output=None):
    if not results:
        return None

    if json_output:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        sys.exit()

    if isinstance(results, dict):
        results = [results]

    # colors
    RED = '\033[1;31m'
    MAGENTA = '\033[1;35m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[1;36m'
    END = '\033[0m' # reset

    for item in results:
        status_ok = True
        if item['http'][0] != 200:
            http = 'http '
        else:
            http = YELLOW + 'http ' + END
            status_ok = False
        if item['cert'][0] != False:
            cert = 'cert '
        else:
            cert = YELLOW + 'cert ' + END
            status_ok = False

        if status_ok:
            if all(i is None for i in item['http']) and all(i is None for i in item['https']):
                print (MAGENTA + item['domain'] + END, item['ip'])
            else:
                print (CYAN + item['domain'] + END, item['ip'])
        else:
            print (RED + item['domain'] + END, item['ip'])
        
        print (http, item['http'])
        print ('https', item['https'])
        print (cert, item['cert'])
        print ()

    print (len(results), 'domains')

def save(domain, results, folder):
    dt = str(datetime.now()).replace("-", "_").replace(" ", "_").replace(":", "_").split('.')[0]
    if not folder:
        path = domain + '_' + dt + '.json'
    else:
        if not os.path.exists(folder):
            os.makedirs(folder)
        path = folder + os.sep + domain + '_' + dt + '.json'
    
    f = open(path, "w")
    f.write(json.dumps(results, indent=4))
    f.close()

def show_report(json_output, report_name):
    with open(report_name) as f:
        report = json.loads(f.read())
    output(report, json_output)

def scan_subdomains(domain, wordlist=None):
    # Nếu không truyền wordlist, dùng wordlist.txt mặc định trong thư mục knock
    if not wordlist:
        wordlist = os.path.join(os.path.dirname(__file__), 'wordlist', 'wordlist.txt')
    print(f"[knockpy] Using wordlist: {wordlist}")
    return KNOCKPY(domain, recon=True, bruteforce=False, wordlist=wordlist)  # Tắt bruteforce mặc định

def scan_subdomains_cli(domain):
    knockpy_path = os.path.join(os.path.dirname(__file__), 'knockpy.py')
    cmd = [
        'python', knockpy_path,
        '-d', domain,
        '--recon',
        '--json'
    ]
    print(f"[knockpy] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        output = result.stdout
        lines = output.strip().splitlines()
        json_line = lines[-1] if lines else '{}'
        data = json.loads(json_line)
        return data
    except Exception as e:
        print(f"[knockpy] Error parsing output: {e}")
        return []

def generate_alterations(subdomains, extra_words=None):
    """
    Sinh biến thể subdomain (alteration search): thêm số, tiền tố/hậu tố, thay thế ký tự, ...
    Trả về list subdomain biến thể.
    """
    import itertools
    alterations = set()
    # Các hậu tố, tiền tố phổ biến
    prefixes = ['dev', 'test', 'staging', 'beta', 'old', 'new', '1', '2']
    suffixes = ['dev', 'test', 'staging', 'beta', 'old', 'new', '1', '2']
    replaces = {'-': '', '_': '', '0': 'o', '1': 'l', 'l': '1', 'o': '0'}
    
    # Convert subdomains to strings if they are dictionaries
    subdomain_strings = set()
    for sub in subdomains:
        if isinstance(sub, dict):
            subdomain_strings.add(sub.get('subdomain', ''))
        else:
            subdomain_strings.add(str(sub))
    
    for sub in subdomain_strings:
        if not sub:  # Skip empty strings
            continue
        # Thêm tiền tố
        for pre in prefixes:
            alterations.add(f"{pre}-{sub}")
            alterations.add(f"{pre}{sub}")
        # Thêm hậu tố
        for suf in suffixes:
            alterations.add(f"{sub}-{suf}")
            alterations.add(f"{sub}{suf}")
        # Thay thế ký tự
        for i, c in enumerate(sub):
            if c in replaces:
                altered = sub[:i] + replaces[c] + sub[i+1:]
                alterations.add(altered)
        # Thêm số cuối
        for n in range(0, 3):
            alterations.add(f"{sub}{n}")
        # Thêm từ ngoài nếu có
        if extra_words:
            for w in extra_words:
                alterations.add(f"{w}-{sub}")
                alterations.add(f"{sub}-{w}")
    # Loại bỏ subdomain gốc
    alterations.difference_update(subdomain_strings)
    return list(alterations)

async def get_subdomains_advanced(domain, wordlist=None, extra_words=None, max_html_pages=5, timeout=5):
    """
    Pipeline tối ưu: chỉ scan và trả về danh sách subdomain thô (không enrich toàn bộ).
    Trả về dict kết quả chi tiết các nguồn, tổng hợp unique subdomain.
    """
    results = {"domain": domain}
    try:
        # 1. Recon + bruteforce (TẮT bruteforce)
        base_subs = set(get_subdomains(domain, recon=True, bruteforce=False, wordlist=wordlist, timeout=timeout))
        logger.info(f"[knockpy] Base subdomains ({len(base_subs)}): {list(base_subs)}")
        results["base_subdomains"] = list(base_subs)
        # 2. DNS records nâng cao
        dns_records, dns_subs = await fetch_dns_records(domain, timeout=timeout)
        logger.info(f"[knockpy] DNS subdomains ({len(dns_subs)}): {dns_subs}")
        results["dns_records"] = dns_records
        results["dns_subdomains"] = dns_subs
        # 3. Crawl HTML
        html_subs = await crawl_html_for_subdomains(domain, max_pages=max_html_pages, timeout=timeout)
        logger.info(f"[knockpy] HTML subdomains ({len(html_subs)}): {html_subs}")
        results["html_subdomains"] = html_subs
        # 4. Brave Search (if API key available)
        brave_subs = []
        API_KEY_BRAVE = os.getenv("API_KEY_BRAVE")
        if API_KEY_BRAVE:
            try:
                brave_subs = brave_search_subdomains(domain, API_KEY_BRAVE)
                logger.info(f"[knockpy] Brave Search subdomains ({len(brave_subs)}): {brave_subs}")
                results["brave_search_subdomains"] = brave_subs
            except Exception as e:
                logger.warning(f"[knockpy] Brave Search failed: {e}")
        # 5. Alteration search
        all_for_alter = base_subs | set(dns_subs) | set(html_subs) | set(brave_subs)
        alter_subs = generate_alterations(all_for_alter, extra_words=extra_words)
        logger.info(f"[knockpy] Alteration subdomains ({len(alter_subs)}): {alter_subs}")
        results["alteration_subdomains"] = alter_subs
        # 6. Tổng hợp tất cả subdomain unique với thông tin nguồn
        all_subs_with_source = []
        
        # Base subdomains (recon tools)
        for sub in base_subs:
            all_subs_with_source.append({"subdomain": sub, "source": "recon"})
        
        # DNS subdomains
        for sub in dns_subs:
            if sub not in base_subs:
                all_subs_with_source.append({"subdomain": sub, "source": "dns"})
        
        # HTML subdomains
        for sub in html_subs:
            if sub not in base_subs and sub not in dns_subs:
                all_subs_with_source.append({"subdomain": sub, "source": "html"})
        
        # Brave Search subdomains (SURFACE)
        for sub in brave_subs:
            if sub not in base_subs and sub not in dns_subs and sub not in html_subs:
                all_subs_with_source.append({"subdomain": sub, "source": "search"})
        
        # Alteration subdomains
        for sub in alter_subs:
            if sub not in base_subs and sub not in dns_subs and sub not in html_subs and sub not in brave_subs:
                all_subs_with_source.append({"subdomain": sub, "source": "alteration"})
        
        results["all_subdomains"] = all_subs_with_source
    except Exception as e:
        logger.error(f"[knockpy] Pipeline error: {e}")
    return results