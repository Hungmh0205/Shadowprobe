import asyncio
import aiodns
import socket
import random
from typing import List, Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class HostResolver:
    def __init__(self, max_concurrency: int = 20):
        # Thêm deterministic seed
        random.seed(42)
        
        # Fix for Windows compatibility - set event loop policy before creating resolver
        import sys
        if sys.platform.startswith("win"):
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # Fix aiodns deprecation warning by explicitly setting event loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        self.resolver = aiodns.DNSResolver(loop=loop)
        self.max_concurrency = max_concurrency
        self.max_retries = 3  # Thêm retry mechanism
        self.timeout = 10.0  # Tăng timeout

    async def resolve_hostname_with_retry(self, hostname: str, sem: asyncio.Semaphore) -> Optional[str]:
        """Resolve hostname to IP with retry mechanism"""
        if not hostname or not hostname.strip():
            return None
            
        for attempt in range(self.max_retries):
            async with sem:
                try:
                    # Try A record first
                    result = await asyncio.wait_for(
                        self.resolver.query(hostname, 'A'),
                        timeout=self.timeout
                    )
                    if result:
                        return result[0].host
                except asyncio.TimeoutError:
                    logger.debug(f"DNS resolution timeout for {hostname} on attempt {attempt + 1}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                except Exception as e:
                    logger.debug(f"DNS resolution failed for {hostname} on attempt {attempt + 1}: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
        
        return None

    async def reverse_dns_with_retry(self, ip: str, sem: asyncio.Semaphore) -> Optional[str]:
        """Reverse DNS lookup with retry mechanism"""
        if not ip or not ip.strip():
            return None
            
        for attempt in range(self.max_retries):
            async with sem:
                try:
                    # Try PTR record
                    result = await asyncio.wait_for(
                        self.resolver.query(ip, 'PTR'),
                        timeout=self.timeout
                    )
                    if result:
                        return result[0].hostname
                except asyncio.TimeoutError:
                    logger.debug(f"Reverse DNS timeout for {ip} on attempt {attempt + 1}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                except Exception as e:
                    logger.debug(f"Reverse DNS failed for {ip} on attempt {attempt + 1}: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(1)
                        continue
        
        return None

    def is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def is_valid_hostname(self, hostname: str) -> bool:
        """Check if string is a valid hostname"""
        if not hostname or len(hostname) > 253:
            return False
        
        # Check for valid characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        if not all(c in allowed_chars for c in hostname):
            return False
        
        # Check for valid structure
        parts = hostname.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63 or part.startswith('-') or part.endswith('-'):
                return False
        
        return True

    async def resolve_hosts(self, hosts: List[str]) -> Dict[str, str]:
        """Resolve multiple hostnames to IPs with improved consistency"""
        logger.info(f"Starting host resolution for {len(hosts)} hosts")
        
        sem = asyncio.Semaphore(self.max_concurrency)
        results = {}
        
        # Filter valid hostnames
        valid_hosts = [h.strip() for h in hosts if h and self.is_valid_hostname(h.strip())]
        logger.info(f"Valid hostnames to resolve: {len(valid_hosts)}")
        
        if not valid_hosts:
            return results
        
        # Process in batches để tránh quá tải
        batch_size = 50
        for i in range(0, len(valid_hosts), batch_size):
            batch = valid_hosts[i:i + batch_size]
            tasks = [self.resolve_hostname_with_retry(host, sem) for host in batch]
            
            try:
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for host, result in zip(batch, batch_results):
                    if isinstance(result, str) and result:
                        results[host] = result
                        logger.debug(f"Resolved {host} -> {result}")
                    elif isinstance(result, Exception):
                        logger.debug(f"Failed to resolve {host}: {result}")
                
                # Thêm delay giữa các batch để tránh rate limiting
                if i + batch_size < len(valid_hosts):
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                logger.error(f"Batch resolution failed: {e}")
                continue
        
        logger.info(f"Successfully resolved {len(results)} out of {len(valid_hosts)} hosts")
        return results

    async def reverse_resolve_ips(self, ips: List[str]) -> Dict[str, str]:
        """Reverse resolve multiple IPs to hostnames with improved consistency"""
        logger.info(f"Starting reverse DNS resolution for {len(ips)} IPs")
        
        sem = asyncio.Semaphore(self.max_concurrency)
        results = {}
        
        # Filter valid IPs
        valid_ips = [ip.strip() for ip in ips if ip and self.is_valid_ip(ip.strip())]
        logger.info(f"Valid IPs to reverse resolve: {len(valid_ips)}")
        
        if not valid_ips:
            return results
        
        # Process in batches
        batch_size = 50
        for i in range(0, len(valid_ips), batch_size):
            batch = valid_ips[i:i + batch_size]
            tasks = [self.reverse_dns_with_retry(ip, sem) for ip in batch]
            
            try:
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for ip, result in zip(batch, batch_results):
                    if isinstance(result, str) and result:
                        results[ip] = result
                        logger.debug(f"Reverse resolved {ip} -> {result}")
                    elif isinstance(result, Exception):
                        logger.debug(f"Failed to reverse resolve {ip}: {result}")
                
                # Thêm delay giữa các batch
                if i + batch_size < len(valid_ips):
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                logger.error(f"Batch reverse resolution failed: {e}")
                continue
        
        logger.info(f"Successfully reverse resolved {len(results)} out of {len(valid_ips)} IPs")
        return results

    async def resolve_and_reverse(self, hosts: List[str]) -> Dict[str, Dict[str, str]]:
        """Resolve hostnames to IPs and reverse resolve IPs to hostnames"""
        logger.info(f"Starting comprehensive host resolution for {len(hosts)} hosts")
        
        # First, resolve hostnames to IPs
        host_to_ip = await self.resolve_hosts(hosts)
        
        # Get unique IPs for reverse resolution
        unique_ips = list(set(host_to_ip.values()))
        logger.info(f"Found {len(unique_ips)} unique IPs for reverse resolution")
        
        # Reverse resolve IPs to hostnames
        ip_to_host = await self.reverse_resolve_ips(unique_ips)
        
        # Build comprehensive results
        results = {}
        for host, ip in host_to_ip.items():
            results[host] = {
                'ip': ip,
                'hostname': ip_to_host.get(ip, None)
            }
        
        logger.info(f"Completed comprehensive resolution for {len(results)} hosts")
        return results

    async def get_host_info(self, host: str) -> Optional[Dict[str, Optional[str]]]:
        """Get comprehensive information for a single host"""
        if not host or not host.strip():
            return None
        
        host = host.strip()
        
        if self.is_valid_ip(host):
            # It's an IP, do reverse resolution
            hostname = await self.reverse_dns_with_retry(host, asyncio.Semaphore(1))
            return {
                'ip': host,
                'hostname': hostname
            }
        elif self.is_valid_hostname(host):
            # It's a hostname, do forward resolution
            ip = await self.resolve_hostname_with_retry(host, asyncio.Semaphore(1))
            if ip:
                hostname = await self.reverse_dns_with_retry(ip, asyncio.Semaphore(1))
                return {
                    'ip': ip,
                    'hostname': hostname
                }
        
        return None

    def get_resolver_stats(self) -> dict:
        """Get resolver statistics"""
        return {
            'max_concurrency': self.max_concurrency,
            'max_retries': self.max_retries,
            'timeout': self.timeout,
            'resolver_type': 'aiodns'
        }

# Convenience functions
async def resolve_hosts(hosts: List[str]) -> Dict[str, str]:
    """Resolve multiple hostnames to IPs"""
    resolver = HostResolver()
    return await resolver.resolve_hosts(hosts)

async def reverse_resolve_ips(ips: List[str]) -> Dict[str, str]:
    """Reverse resolve multiple IPs to hostnames"""
    resolver = HostResolver()
    return await resolver.reverse_resolve_ips(ips)

async def get_host_info(host: str) -> Optional[Dict[str, Optional[str]]]:
    """Get information for a single host"""
    resolver = HostResolver()
    return await resolver.get_host_info(host)

async def resolve_and_reverse(hosts: List[str]) -> Dict[str, Dict[str, str]]:
    """Comprehensive host resolution"""
    resolver = HostResolver()
    return await resolver.resolve_and_reverse(hosts) 