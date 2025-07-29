import socket
import asyncio
import time
import re
import subprocess
import shutil
import random
from typing import List, Tuple, Optional, Dict
from core.models import Service
import logging

logger = logging.getLogger(__name__)

# Constants - Cải thiện timeout và retry
DEFAULT_TIMEOUT = 300
DEFAULT_PORT_TIMEOUT = 3.0  # Tăng từ 1.0 lên 3.0
DEFAULT_BANNER_TIMEOUT = 5.0  # Tăng từ 3.0 lên 5.0
MAX_PORT = 65535
MIN_PORT = 1
DEFAULT_CONCURRENT_SCANS = 50  # Giảm từ 100 xuống 50 để ổn định hơn
MAX_RETRIES = 3  # Thêm retry mechanism

# Global flag để track nmap initialization
_nmap_initialized = False
_nmap_path = None
_nmap_available = False

class AsyncPortScanner:
    def __init__(self, max_concurrent: int = DEFAULT_CONCURRENT_SCANS):
        global _nmap_initialized, _nmap_path, _nmap_available
        
        self.nm = None
        self.use_nmap = False
        
        # Chỉ khởi tạo nmap một lần duy nhất
        if not _nmap_initialized:
            self.nmap_path = self._find_nmap()
            self._init_nmap()
            # Khởi tạo nmap_available sau khi _init_nmap() được gọi
            self.nmap_available = self.nmap_path is not None
            _nmap_path = self.nmap_path
            _nmap_available = self.nmap_available
            _nmap_initialized = True
            logger.info("Nmap initialization completed (first time)")
        else:
            # Sử dụng giá trị đã được khởi tạo trước đó
            self.nmap_path = _nmap_path
            self.nmap_available = _nmap_available
            if self.nmap_available:
                try:
                    import nmap
                    self.nm = nmap.PortScanner()
                    self.use_nmap = True
                    logger.debug("Reusing existing nmap configuration")
                except ImportError:
                    self.use_nmap = True
                    logger.debug("Reusing subprocess nmap configuration")
        
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Thêm deterministic seed
        random.seed(42)
        
        if not self.nmap_available:
            logger.warning("Nmap not found in system PATH")
            logger.warning("Nmap not available, will use async socket fallback")
    
    def _find_nmap(self) -> Optional[str]:
        try:
            possible_paths = [
                "nmap",
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe",
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/opt/local/bin/nmap"
            ]
            for path in possible_paths:
                if shutil.which(path):
                    logger.info(f"Found nmap at: {path}")
                    return path
            logger.warning("Nmap not found in system PATH")
            return None
        except Exception as e:
            logger.error(f"Error finding nmap: {e}")
            return None

    def _init_nmap(self):
        if not self.nmap_path:
            logger.warning("Nmap not available, will use async socket fallback")
            self.use_nmap = False
            return
        try:
            import nmap
            self.nm = nmap.PortScanner()
            self.use_nmap = True
            logger.info("Python-nmap initialized successfully")
        except ImportError:
            logger.warning("python-nmap library not available, using subprocess nmap")
            self.use_nmap = True
        except Exception as e:
            logger.warning(f"Failed to initialize python-nmap: {e}, using subprocess nmap")
            self.use_nmap = True

    async def _run_nmap_subprocess(self, target: str, args: str, timeout: int = DEFAULT_TIMEOUT) -> str:
        if not self.nmap_path:
            logger.error("Nmap path is None, cannot run subprocess")
            return ""
        
        # Thêm retry mechanism cho nmap
        for attempt in range(MAX_RETRIES):
            try:
                cmd = [self.nmap_path] + args.split()
                process = await asyncio.create_subprocess_exec(
                    *cmd, target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                    if process.returncode == 0:
                        return stdout.decode('utf-8', errors='ignore')
                    else:
                        logger.warning(f"Nmap attempt {attempt + 1} failed: {stderr.decode('utf-8', errors='ignore')}")
                        if attempt < MAX_RETRIES - 1:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                        return ""
                except asyncio.TimeoutError:
                    process.kill()
                    logger.warning(f"Nmap attempt {attempt + 1} timed out after {timeout} seconds")
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return ""
            except Exception as e:
                logger.error(f"Nmap attempt {attempt + 1} unexpected error: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return ""
        return ""

    def _parse_nmap_output(self, output: str) -> Tuple[List[int], List[Service]]:
        ports = []
        services = []
        try:
            lines = output.split('\n')
            for line in lines:
                match = re.search(r'(\d+)/tcp\s+(\w+)\s+(\w+)(?:\s+(.+))?', line)
                if match:
                    try:
                        port = int(match.group(1))
                        state = match.group(2)
                        nmap_service_name = match.group(3)
                        version = match.group(4) if match.group(4) else None
                        if state == 'open' and 1 <= port <= 65535:
                            ports.append(port)
                            service_name = self._get_service_name(port)
                            server_name = None
                            if version:
                                server_name = self._parse_banner(version, port)
                            service = Service(
                                port=port,
                                protocol="tcp",
                                service_name=service_name,
                                version=version,
                                server_name=server_name,
                                ip_address=None
                            )
                            services.append(service)
                    except ValueError:
                        logger.warning(f"Invalid port number in nmap output: {line}")
                        continue
        except Exception as e:
            logger.error(f"Error parsing nmap output: {e}")
        
        # Sắp xếp để có kết quả nhất quán
        ports.sort()
        services.sort(key=lambda x: x.port)
        return ports, services

    async def scan_ports_and_services(self, target: str) -> Tuple[List[int], List[Service]]:
        try:
            if self.use_nmap:
                if self.nm:
                    return await self._nmap_scan_ports_and_services(target)
                else:
                    return await self._subprocess_nmap_scan(target)
            else:
                return await self._async_socket_scan_ports_and_services(target)
        except Exception as e:
            logger.error(f"Port scanning failed: {e}, falling back to async socket scanning")
            return await self._async_socket_scan_ports_and_services(target)

    async def _nmap_scan_ports_and_services(self, target: str) -> Tuple[List[int], List[Service]]:
        try:
            logger.info(f"Running python-nmap scan for target: {target}")
            # Use nmap arguments with version detection for better service info
            loop = asyncio.get_event_loop()
            scan_args = '-sT -sV --version-intensity 2 -p 80,443,22,21,25,53,110,143,993,995,3306,3389,5432,8080,8443'
            
            def run_nmap_scan():
                if not self.nm:
                    return [], []
                logger.info(f"Running nmap scan with args: {scan_args}")
                self.nm.scan(target, arguments=scan_args)
                logger.info(f"Nmap scan completed. All hosts: {self.nm.all_hosts()}")
                
                # Nmap resolves domains to IPs, so we need to check both the original target and resolved IPs
                all_hosts = self.nm.all_hosts()
                if not all_hosts:
                    logger.warning(f"No hosts found in nmap results for {target}")
                    return [], []
                
                # Use the first host found (nmap should have resolved the domain to IP)
                scan_host = all_hosts[0]
                logger.info(f"Using scan host: {scan_host} (original target: {target})")
                
                if scan_host not in self.nm.all_hosts():
                    logger.warning(f"Scan host {scan_host} not found in nmap results")
                    return [], []
                ports = []
                services = []
                for proto in self.nm[scan_host].all_protocols():
                    lport = self.nm[scan_host][proto].keys()
                    for port in sorted(lport):
                        try:
                            port_info = self.nm[scan_host][proto][port]
                            if port_info['state'] == 'open':
                                ports.append(port)
                                service_name = port_info.get('name', 'unknown')
                                product = port_info.get('product', '')
                                version = port_info.get('version', '')
                                full_version = f"{product} {version}".strip() if product or version else None
                                server_name = None
                                if product:
                                    server_name = self._parse_banner(product, port)
                                ip_address = target if self._is_ip(target) else None
                                service = Service(
                                    port=port,
                                    protocol=proto,
                                    service_name=service_name,
                                    version=full_version if full_version else None,
                                    server_name=server_name,
                                    ip_address=target if self._is_ip(target) else None
                                )
                                services.append(service)
                        except KeyError:
                            logger.warning(f"Missing port info for port {port}")
                            continue
                return ports, services
            
            ports, services = await loop.run_in_executor(None, run_nmap_scan)
            logger.info(f"Python-nmap found {len(ports)} open ports and {len(services)} services")
            return ports, services
        except Exception as e:
            logger.error(f"Python-nmap scan error: {e}, trying subprocess nmap")
            return await self._subprocess_nmap_scan(target)

    async def _subprocess_nmap_scan(self, target: str) -> Tuple[List[int], List[Service]]:
        try:
            logger.info(f"Running subprocess nmap scan for target: {target}")
            # Use nmap arguments with version detection for better service info
            scan_args = '-sT -sV --version-intensity 2 -p 80,443,22,21,25,53,110,143,993,995,3306,3389,5432,8080,8443'
            output = await self._run_nmap_subprocess(target, scan_args, timeout=300)
            
            if output:
                logger.info(f"Subprocess nmap output length: {len(output)}")
                logger.debug(f"Subprocess nmap output: {output[:500]}...")  # Show first 500 chars
                ports, services = self._parse_nmap_output(output)
                logger.info(f"Subprocess nmap found {len(ports)} open ports and {len(services)} services")
                return ports, services
            else:
                logger.warning("Subprocess nmap returned empty output, falling back to socket scan")
                return await self._async_socket_scan_ports_and_services(target)
        except Exception as e:
            logger.error(f"Subprocess nmap scan error: {e}, falling back to socket scan")
            return await self._async_socket_scan_ports_and_services(target)

    async def _async_socket_scan_ports_and_services(self, target: str) -> Tuple[List[int], List[Service]]:
        """Improved async socket scanning with retry mechanism"""
        logger.info(f"Running async socket scan for target: {target}")
        
        # Cải thiện port list - thêm nhiều port phổ biến
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080,
            8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017, 5432, 6379,
            1521, 1433, 389, 636, 119, 123, 161, 162, 514, 873, 1080, 3128,
            5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910
        ]
        
        open_ports = []
        services = []
        
        # Scan với retry mechanism
        for port in common_ports:
            service = await self._scan_single_port_with_retry(target, port)
            if service:
                open_ports.append(port)
                services.append(service)
        
        # Sắp xếp để có kết quả nhất quán
        open_ports.sort()
        services.sort(key=lambda x: x.port)
        
        logger.info(f"Async socket scan found {len(open_ports)} open ports")
        return open_ports, services

    async def _scan_single_port_with_retry(self, target: str, port: int) -> Optional[Service]:
        """Scan single port with retry mechanism"""
        for attempt in range(MAX_RETRIES):
            try:
                async with self.semaphore:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=DEFAULT_PORT_TIMEOUT
                    )
                    
                    # Try to get banner
                    banner = await self._async_banner_grab(reader, writer, port)
                    
                    # Close connection safely
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                    except (asyncio.TimeoutError, ConnectionResetError, OSError):
                        # Ignore connection close errors on Windows
                        pass
                    
                    service_name = self._get_service_name(port)
                    server_name = None
                    if banner:
                        server_name = self._parse_banner(banner, port)
                    
                    return Service(
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        version=banner,
                        server_name=server_name,
                        ip_address=target if self._is_ip(target) else None
                    )
                    
            except asyncio.TimeoutError:
                logger.debug(f"Port {port} timeout on attempt {attempt + 1}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
            except (ConnectionResetError, OSError) as e:
                logger.debug(f"Port {port} connection reset on attempt {attempt + 1}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
            except Exception as e:
                logger.debug(f"Port {port} failed on attempt {attempt + 1}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(1)
                    continue
        
        return None

    async def _async_banner_grab(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
        """Improved banner grabbing with better timeout handling"""
        try:
            # Send appropriate probe based on port
            probe = self._get_probe_for_port(port)
            if probe:
                writer.write(probe.encode())
                await writer.drain()
            
            # Wait for response with timeout
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=DEFAULT_BANNER_TIMEOUT)
                if data:
                    return data.decode('utf-8', errors='ignore').strip()
            except asyncio.TimeoutError:
                logger.debug(f"Banner grab timeout for port {port}")
                return None
                
        except Exception as e:
            logger.debug(f"Banner grab failed for port {port}: {e}")
        
        return None

    def _get_probe_for_port(self, port: int) -> Optional[str]:
        """Get appropriate probe for different port types"""
        probes = {
            21: "QUIT\r\n",
            22: "SSH-2.0-OpenSSH_8.0\r\n",
            23: "\r\n",
            25: "QUIT\r\n",
            80: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            443: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            110: "QUIT\r\n",
            143: "a001 LOGOUT\r\n",
            993: "a001 LOGOUT\r\n",
            995: "QUIT\r\n",
            3306: "\x0a",
            5432: "\x00\x00\x00\x08\x04\xd2\x16\x2f",
            27017: "\x3a\x00\x00\x00\xa3\x01\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\x01\x00\x00\x00\x33\x00\x00\x00\x02\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",
        }
        return probes.get(port, "\r\n")

    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_names = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
            27017: "mongodb", 6379: "redis", 8080: "http-proxy", 8443: "https-alt"
        }
        return service_names.get(port, "unknown")

    def _parse_banner(self, banner: str, port: int) -> Optional[str]:
        """Parse banner to extract server information"""
        if not banner:
            return None
        
        banner_lower = banner.lower()
        
        # Extract server names from common patterns
        server_patterns = [
            r'(apache[/\s][\d.]+)',
            r'(nginx[/\s][\d.]+)',
            r'(iis[/\s][\d.]+)',
            r'(openssh[/\s][\d.]+)',
            r'(mysql[/\s][\d.]+)',
            r'(postgresql[/\s][\d.]+)',
            r'(redis[/\s][\d.]+)',
            r'(mongodb[/\s][\d.]+)',
            r'(tomcat[/\s][\d.]+)',
            r'(jetty[/\s][\d.]+)',
            r'(node\.js[/\s][\d.]+)',
            r'(python[/\s][\d.]+)',
            r'(php[/\s][\d.]+)',
            r'(ruby[/\s][\d.]+)',
            r'(java[/\s][\d.]+)',
        ]
        
        for pattern in server_patterns:
            match = re.search(pattern, banner_lower)
            if match:
                return match.group(1)
        
        return None

    def _extract_server_name(self, banner: str, port: int) -> str:
        """Extract server name from banner"""
        if not banner:
            return "unknown"
        
        # Common server name patterns
        patterns = [
            r'Server:\s*([^\r\n]+)',
            r'^([A-Za-z0-9_-]+)[/\s]',
            r'([A-Za-z0-9_-]+)\s+Server',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "unknown"

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def get_scan_stats(self) -> dict:
        """Get scan statistics"""
        return {
            'nmap_available': self.nmap_available,
            'use_nmap': self.use_nmap,
            'max_concurrent': self.semaphore._value,
            'timeout': DEFAULT_PORT_TIMEOUT,
            'max_retries': MAX_RETRIES
        }

    async def scan(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Legacy scan method for compatibility"""
        results = {}
        for port in ports:
            service = await self._scan_single_port_with_retry(host, port)
            if service:
                results[port] = service.service_name
        return results

# Legacy compatibility class
class PortScanner(AsyncPortScanner):
    def __init__(self):
        super().__init__(max_concurrent=DEFAULT_CONCURRENT_SCANS)

    def scan_ports_and_services(self, target: str) -> Tuple[List[int], List[Service]]:
        """Synchronous wrapper for async scan"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(super().scan_ports_and_services(target))
        finally:
            loop.close()

    async def scan_specific_ports(self, target: str, ports: List[int]) -> Tuple[List[int], List[Service]]:
        """Scan specific ports with retry mechanism"""
        open_ports = []
        services = []
        
        for port in ports:
            service = await self._scan_single_port_with_retry(target, port)
            if service:
                open_ports.append(port)
                services.append(service)
        
        # Sắp xếp để có kết quả nhất quán
        open_ports.sort()
        services.sort(key=lambda x: x.port)
        
        return open_ports, services

# Convenience functions
async def scan_ports_and_services(target: str) -> Tuple[List[int], List[Service]]:
    """Async convenience function"""
    scanner = AsyncPortScanner()
    return await scanner.scan_ports_and_services(target)

async def quick_port_scan(target: str) -> List[int]:
    """Quick port scan for common ports"""
    scanner = AsyncPortScanner()
    ports, _ = await scanner.scan_ports_and_services(target)
    return ports

async def scan_all_ports(target: str) -> List[int]:
    """Scan all ports (not recommended for production)"""
    scanner = AsyncPortScanner()
    ports, _ = await scanner.scan_ports_and_services(target)
    return ports

async def scan_specific_ports(target: str, ports: List[int]) -> Tuple[List[int], List[Service]]:
    """Scan specific ports"""
    scanner = AsyncPortScanner()
    open_ports = []
    services = []
    
    for port in ports:
        service = await scanner._scan_single_port_with_retry(target, port)
        if service:
            open_ports.append(port)
            services.append(service)
    
    # Sắp xếp để có kết quả nhất quán
    open_ports.sort()
    services.sort(key=lambda x: x.port)
    
    return open_ports, services 