"""
Asynchronous network scanner module for discovering devices on a LAN.
"""

import asyncio
import logging
import shutil
import socket
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, List, Optional, Set, Tuple

from netaddr import EUI, NotRegisteredError
from scapy.all import ARP, Ether, srp

# Check if nmap is available
NMAP_AVAILABLE = shutil.which("nmap") is not None

# Import nmap conditionally
if NMAP_AVAILABLE:
    try:
        import nmap
    except ImportError:
        NMAP_AVAILABLE = False

# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """Represents a discovered network device."""
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None

    def as_dict(self) -> Dict[str, str]:
        """Convert the device information to a dictionary."""
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname or "",
            "vendor": self.vendor or ""
        }


class AsyncNetworkScanner:
    """Asynchronous network scanner for discovering devices on a LAN."""

    def __init__(self, subnet: str, timeout: float = 1.0, concurrent_scans: int = 100):
        """
        Initialize the network scanner.

        Args:
            subnet: Network subnet to scan in CIDR notation (e.g., '192.168.1.0/24')
            timeout: Timeout for each scan in seconds
            concurrent_scans: Maximum number of concurrent scans
        """
        self.subnet = subnet
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrent_scans)
        self.devices: List[NetworkDevice] = []
        self.nm = None
        
        # Initialize nmap if available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
                logger.info("nmap is available and will be used for scanning")
            except Exception as e:
                logger.warning(f"Failed to initialize nmap: {e}")
        else:
            logger.warning("nmap is not available. Using ARP-only scanning mode.")
            logger.info("Install nmap for more accurate device information.")
            logger.info("  - On Debian/Ubuntu: sudo apt install nmap")
            logger.info("  - On CentOS/RHEL: sudo yum install nmap")
            logger.info("  - On macOS: brew install nmap")
            logger.info("  - On Windows: download from https://nmap.org/download.html")
    
    async def scan_network(self) -> List[NetworkDevice]:
        """
        Scan the network for devices.
        
        Returns:
            List of discovered NetworkDevice objects
        """
        network = IPv4Network(self.subnet)
        logger.info(f"Starting scan of network {self.subnet}")
        
        # First, do a quick ARP scan to find active hosts
        active_ips = await self._arp_scan()
        logger.info(f"Found {len(active_ips)} active hosts via ARP")
        
        # Then perform detailed scans on each active host
        tasks = []
        for ip_str in active_ips:
            tasks.append(self._scan_host(ip_str))
        
        # Wait for all scan tasks to complete
        results = await asyncio.gather(*tasks)
        
        # Filter out None results and extend the devices list
        self.devices = [device for device in results if device is not None]
        
        logger.info(f"Completed scan, found {len(self.devices)} devices")
        return self.devices
    
    async def _arp_scan(self) -> Set[str]:
        """
        Perform a quick ARP scan to find active hosts.
        
        Returns:
            Set of active IP addresses
        """
        loop = asyncio.get_event_loop()
        
        def _do_arp_scan() -> Set[str]:
            active_ips = set()
            try:
                # Create ARP request packet
                arp = ARP(pdst=self.subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether/arp
                
                # Send packet and receive responses
                result = srp(packet, timeout=self.timeout, verbose=0)[0]
                
                # Extract IP addresses from responses
                for sent, received in result:
                    active_ips.add(received.psrc)
            except Exception as e:
                logger.error(f"Error during ARP scan: {e}")
            
            return active_ips
        
        # Run the ARP scan in a separate thread
        return await loop.run_in_executor(None, _do_arp_scan)
    
    async def _scan_host(self, ip_str: str) -> Optional[NetworkDevice]:
        """
        Perform a detailed scan of a single host.
        
        Args:
            ip_str: IP address to scan
            
        Returns:
            NetworkDevice object if the scan is successful, None otherwise
        """
        async with self.semaphore:
            try:
                # Get hostname
                hostname = await self._resolve_hostname(ip_str)
                
                # Get MAC address and vendor
                mac_address, vendor = await self._get_mac_and_vendor(ip_str)
                
                if mac_address:
                    return NetworkDevice(
                        ip_address=ip_str,
                        mac_address=mac_address,
                        hostname=hostname,
                        vendor=vendor
                    )
                return None
            except Exception as e:
                logger.error(f"Error scanning host {ip_str}: {e}")
                return None

    async def _resolve_hostname(self, ip_str: str) -> Optional[str]:
        """
        Resolve hostname from IP address.
        
        Args:
            ip_str: IP address to resolve
            
        Returns:
            Hostname if resolution is successful, None otherwise
        """
        loop = asyncio.get_event_loop()
        try:
            hostname = await loop.run_in_executor(
                None, socket.gethostbyaddr, ip_str
            )
            return hostname[0] if hostname else None
        except (socket.herror, socket.gaierror):
            return None
    
    async def _get_mac_and_vendor(self, ip_str: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get MAC address and vendor for a given IP.
        
        Args:
            ip_str: IP address to query
            
        Returns:
            Tuple of (MAC address, vendor) or (None, None) if not found
        """
        loop = asyncio.get_event_loop()
        
        def _do_scan():
            try:
                # Try nmap method if available
                if NMAP_AVAILABLE and self.nm:
                    try:
                        self.nm.scan(ip_str, arguments='-sn')
                        for host in self.nm.all_hosts():
                            if 'mac' in self.nm[host]['addresses']:
                                mac = self.nm[host]['addresses']['mac']
                                vendor = self.nm[host].get('vendor', {}).get(mac)
                                return mac, vendor
                    except Exception as e:
                        logger.debug(f"nmap scan failed for {ip_str}: {e}")
                
                # Use ARP scan method (works without nmap)
                arp = ARP(pdst=ip_str)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_str), 
                            timeout=self.timeout, verbose=0)[0]
                
                if result:
                    mac = result[0][1].hwsrc
                    try:
                        eui = EUI(mac)
                        vendor = eui.oui.registration().org
                    except NotRegisteredError:
                        vendor = None
                    except Exception as e:
                        logger.debug(f"Failed to get vendor for {mac}: {e}")
                        vendor = None
                    return mac, vendor
                    
                return None, None
            except Exception as e:
                logger.error(f"Error getting MAC address for {ip_str}: {e}")
                return None, None
        
        return await loop.run_in_executor(None, _do_scan)