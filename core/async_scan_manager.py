# core/async_scan_manager.py

import asyncio
import logging
import time
import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from scanner.port_scanner import AsyncPortScanner
from scanner.host_resolver import HostResolver
from core.models import Service, HostInfo, ScanResult, ScanType
import core.db_sqlite as db
from scanner.knock.knockpy import KNOCKPY as subdomain_scan, enrich_subdomains_async

logger = logging.getLogger(__name__)

class AsyncScanManager:
    def __init__(self):
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_lock = asyncio.Lock()
        
        # Thêm deterministic seed
        random.seed(42)
        
        # Cải thiện scan configuration
        self.scan_config = {
            'max_concurrent_scans': 3,  # Giảm từ 5 xuống 3
            'scan_timeout': 600,  # 10 phút
            'retry_attempts': 3,
            'delay_between_scans': 2.0,  # Thêm delay giữa các scan
            'progress_update_interval': 5.0  # Cập nhật progress mỗi 5 giây
        }
        
        # Initialize scanners với configuration tốt hơn
        self.port_scanner = AsyncPortScanner(max_concurrent=30)  # Giảm concurrency
        self.host_resolver = HostResolver(max_concurrency=15)  # Giảm concurrency

    async def start_scan(self, target: str, scan_type: str = "full") -> str:
        """Start a new scan with improved error handling"""
        async with self.scan_lock:
            # Generate unique scan ID với timestamp chính xác hơn
            scan_id = f"scan_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
            
            # Check if target is already being scanned
            for existing_scan in self.active_scans.values():
                if existing_scan['target'] == target and existing_scan['status'] == 'running':
                    logger.warning(f"Target {target} is already being scanned")
                    return existing_scan['scan_id']
            
            # Check concurrent scan limit
            running_scans = sum(1 for scan in self.active_scans.values() if scan['status'] == 'running')
            if running_scans >= self.scan_config['max_concurrent_scans']:
                logger.warning(f"Maximum concurrent scans reached ({running_scans})")
                raise Exception("Maximum concurrent scans reached")
            
            # Initialize scan
            scan_data = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'status': 'running',
                'start_time': datetime.now(),
                'progress': 0,
                'current_step': 'Initializing...',
                'results': {
                    'ports': [],
                    'services': [],
                    'subdomains': [],
                    'host_info': {}
                },
                'errors': []
            }
            
            self.active_scans[scan_id] = scan_data
            
            # Start scan task
            asyncio.create_task(self._run_scan(scan_id))
            
            logger.info(f"Started scan {scan_id} for target {target}")
            return scan_id

    async def _run_scan(self, scan_id: str):
        """Run the actual scan with improved error handling and consistency"""
        scan_data = self.active_scans.get(scan_id)
        if not scan_data:
            logger.error(f"Scan {scan_id} not found")
            return
        
        target = scan_data['target']
        scan_type = scan_data['scan_type']
        
        try:
            logger.info(f"Running scan {scan_id} for {target}")
            
            # Step 1: Host Resolution (10%)
            await self._update_progress(scan_id, 10, "Resolving host information...")
            host_info = await self._resolve_host_with_retry(target)
            scan_data['results']['host_info'] = host_info
            
            # Step 2: Port Scanning (40%)
            await self._update_progress(scan_id, 30, "Scanning ports...")
            ports, services = await self._scan_ports_with_retry(target)
            scan_data['results']['ports'] = ports
            scan_data['results']['services'] = services
            
            # Step 3: Subdomain Scanning (50%)
            if scan_type in ["full", "subdomain"]:
                await self._update_progress(scan_id, 60, "Scanning subdomains...")
                subdomains = await self._scan_subdomains_with_retry(target)
                scan_data['results']['subdomains'] = subdomains
            
            # Step 4: Finalize (100%)
            await self._update_progress(scan_id, 100, "Finalizing scan results...")
            
            # Save results to database
            await self._save_scan_results(scan_id, scan_data)
            
            # Mark scan as completed
            scan_data['status'] = 'completed'
            scan_data['end_time'] = datetime.now()
            scan_data['current_step'] = 'Scan completed successfully'
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan_data['status'] = 'failed'
            scan_data['end_time'] = datetime.now()
            scan_data['current_step'] = f'Scan failed: {str(e)}'
            scan_data['errors'].append(str(e))
            
            # Save failed scan to database
            await self._save_scan_results(scan_id, scan_data)
        
        finally:
            # Cleanup after delay
            asyncio.create_task(self._cleanup_scan(scan_id))

    async def _resolve_host_with_retry(self, target: str) -> Dict[str, Any]:
        """Resolve host information with retry mechanism"""
        for attempt in range(self.scan_config['retry_attempts']):
            try:
                host_info = await self.host_resolver.get_host_info(target)
                if host_info:
                    logger.info(f"Host resolution successful for {target}: {host_info}")
                    return host_info
                else:
                    logger.warning(f"Host resolution returned None for {target}")
                    return {'ip': target, 'hostname': None}
            except Exception as e:
                logger.warning(f"Host resolution attempt {attempt + 1} failed for {target}: {e}")
                if attempt < self.scan_config['retry_attempts'] - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    logger.error(f"Host resolution failed after {self.scan_config['retry_attempts']} attempts")
                    return {'ip': target, 'hostname': None}
        
        # Fallback return
        return {'ip': target, 'hostname': None}

    async def _scan_ports_with_retry(self, target: str) -> tuple[List[int], List[Service]]:
        """Scan ports with retry mechanism"""
        for attempt in range(self.scan_config['retry_attempts']):
            try:
                ports, services = await self.port_scanner.scan_ports_and_services(target)
                logger.info(f"Port scan successful for {target}: {len(ports)} ports, {len(services)} services")
                return ports, services
            except Exception as e:
                logger.warning(f"Port scan attempt {attempt + 1} failed for {target}: {e}")
                if attempt < self.scan_config['retry_attempts'] - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                else:
                    logger.error(f"Port scan failed after {self.scan_config['retry_attempts']} attempts")
                    return [], []
        
        # Fallback return
        return [], []

    async def _scan_subdomains_with_retry(self, target: str) -> list:
        """Scan subdomains with retry mechanism using subdomain_scanner and enrich async"""
        for attempt in range(self.scan_config['retry_attempts']):
            try:
                # Lấy danh sách subdomain (sync, có thể dùng run_in_executor nếu KNOCKPY lâu)
                loop = asyncio.get_event_loop()
                subdomain_list = await loop.run_in_executor(None, subdomain_scan, target)
                logger.info(f"Subdomain scan successful for {target}: {len(subdomain_list)} subdomains. Enriching async...")
                # Enrich song song async
                try:
                    enriched = await enrich_subdomains_async([s['subdomain'] if isinstance(s, dict) and 'subdomain' in s else s for s in subdomain_list], timeout=2, max_concurrent=20)
                    # Ghép enrich info vào object gốc nếu cần
                    return enriched
                except Exception as enrich_e:
                    logger.warning(f"Enrich subdomains async failed: {enrich_e}")
                    return subdomain_list
            except Exception as e:
                logger.warning(f"Subdomain scan attempt {attempt + 1} failed for {target}: {e}")
                if attempt < self.scan_config['retry_attempts'] - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                else:
                    logger.error(f"Subdomain scan failed after {self.scan_config['retry_attempts']} attempts")
                    return []
        # Fallback return
        return []

    async def _update_progress(self, scan_id: str, progress: int, step: str):
        """Update scan progress"""
        scan_data = self.active_scans.get(scan_id)
        if scan_data:
            scan_data['progress'] = progress
            scan_data['current_step'] = step
            logger.debug(f"Scan {scan_id} progress: {progress}% - {step}")

    async def _save_scan_results(self, scan_id: str, scan_data: Dict[str, Any]):
        """Save scan results to database with improved error handling"""
        try:
            # Calculate duration
            start_time = scan_data['start_time']
            end_time = scan_data.get('end_time', datetime.now())
            duration = (end_time - start_time).total_seconds()
            
            # Save scan to database
            db.add_scan(
                scan_id=scan_id,
                target=scan_data['target'],
                scan_type=scan_data['scan_type'],
                start_time=start_time,
                end_time=end_time,
                duration=duration,
                status=scan_data['status']
            )
            
            # Save scan results
            db.save_scan_results(scan_id, scan_data['results'])
            
            logger.info(f"Scan results saved to database for {scan_id}")
            
        except Exception as e:
            logger.error(f"Failed to save scan results for {scan_id}: {e}")
            scan_data['errors'].append(f"Database save failed: {str(e)}")

    async def _cleanup_scan(self, scan_id: str):
        """Cleanup scan data after delay"""
        await asyncio.sleep(30)  # Keep scan data for 30 seconds
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            logger.debug(f"Cleaned up scan {scan_id}")

    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan status"""
        return self.active_scans.get(scan_id)

    async def get_all_active_scans(self) -> List[Dict[str, Any]]:
        """Get all active scans"""
        return list(self.active_scans.values())

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan"""
        scan_data = self.active_scans.get(scan_id)
        if scan_data and scan_data['status'] == 'running':
            scan_data['status'] = 'cancelled'
            scan_data['end_time'] = datetime.now()
            scan_data['current_step'] = 'Scan cancelled by user'
            logger.info(f"Scan {scan_id} cancelled")
            return True
        return False

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan manager statistics"""
        running_scans = sum(1 for scan in self.active_scans.values() if scan['status'] == 'running')
        completed_scans = sum(1 for scan in self.active_scans.values() if scan['status'] == 'completed')
        failed_scans = sum(1 for scan in self.active_scans.values() if scan['status'] == 'failed')
        
        return {
            'active_scans': len(self.active_scans),
            'running_scans': running_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'max_concurrent_scans': self.scan_config['max_concurrent_scans'],
            'scan_timeout': self.scan_config['scan_timeout'],
            'retry_attempts': self.scan_config['retry_attempts']
        }

    async def clear_completed_scans(self):
        """Clear completed and failed scans from memory"""
        current_time = datetime.now()
        scans_to_remove = []
        
        for scan_id, scan_data in self.active_scans.items():
            if scan_data['status'] in ['completed', 'failed', 'cancelled']:
                # Remove scans older than 1 hour
                if 'end_time' in scan_data:
                    time_diff = current_time - scan_data['end_time']
                    if time_diff > timedelta(hours=1):
                        scans_to_remove.append(scan_id)
        
        for scan_id in scans_to_remove:
            del self.active_scans[scan_id]
            logger.debug(f"Cleared old scan {scan_id}")
        
        logger.info(f"Cleared {len(scans_to_remove)} old scans from memory")

# Global scan manager instance
_scan_manager: Optional[AsyncScanManager] = None

def get_scan_manager() -> AsyncScanManager:
    """Get or create global scan manager instance"""
    global _scan_manager
    if _scan_manager is None:
        _scan_manager = AsyncScanManager()
    return _scan_manager

async def start_scan(target: str, scan_type: str = "full") -> str:
    """Convenience function to start a scan"""
    scan_manager = get_scan_manager()
    return await scan_manager.start_scan(target, scan_type)

async def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """Convenience function to get scan status"""
    scan_manager = get_scan_manager()
    return await scan_manager.get_scan_status(scan_id)
