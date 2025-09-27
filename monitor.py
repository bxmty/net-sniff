#!/usr/bin/env python3
"""
Continuous network monitoring script for Docker container.
This script monitors for new devices joining the network and logs them.
"""

import asyncio
import logging
import os
import signal
import sys
import time
from datetime import datetime
from typing import Dict, Set, Optional

from app.scanner import AsyncNetworkScanner, NetworkDevice

# Configure logging for container output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Monitors network for new devices joining."""
    
    def __init__(self, subnet: str, scan_interval: int = 300, timeout: float = 2.0):
        """
        Initialize the network monitor.
        
        Args:
            subnet: Network subnet to monitor in CIDR notation
            scan_interval: Time between scans in seconds (default: 5 minutes)
            timeout: Scan timeout in seconds
        """
        self.subnet = subnet
        self.scan_interval = scan_interval
        self.timeout = timeout
        self.known_devices: Dict[str, NetworkDevice] = {}
        self.running = True
        
        # Create scanner
        self.scanner = AsyncNetworkScanner(subnet, timeout=timeout, concurrent_scans=50)
        
        logger.info(f"Network Monitor initialized for subnet: {subnet}")
        logger.info(f"Scan interval: {scan_interval} seconds")
        logger.info(f"Scan timeout: {timeout} seconds")
    
    def stop_monitoring(self):
        """Stop the monitoring loop."""
        logger.info("Stopping network monitoring...")
        self.running = False
    
    async def scan_and_detect_new_devices(self) -> Set[NetworkDevice]:
        """
        Perform network scan and detect new devices.
        
        Returns:
            Set of newly discovered devices
        """
        try:
            logger.info("Starting network scan...")
            devices = await self.scanner.scan_network()
            
            new_devices = set()
            current_ips = set()
            
            for device in devices:
                current_ips.add(device.ip_address)
                
                if device.ip_address not in self.known_devices:
                    # New device detected
                    new_devices.add(device)
                    self.known_devices[device.ip_address] = device
                    logger.info(f"NEW DEVICE DETECTED: {device.ip_address} "
                              f"({device.mac_address}) "
                              f"{'[' + device.hostname + ']' if device.hostname else '[Unknown hostname]'} "
                              f"{device.vendor or '[Unknown vendor]'}")
                else:
                    # Update existing device info if it has changed
                    existing = self.known_devices[device.ip_address]
                    if (device.mac_address != existing.mac_address or
                        device.hostname != existing.hostname or
                        device.vendor != existing.vendor):
                        logger.info(f"DEVICE UPDATED: {device.ip_address} "
                                  f"MAC: {existing.mac_address} -> {device.mac_address}, "
                                  f"Hostname: {existing.hostname} -> {device.hostname}, "
                                  f"Vendor: {existing.vendor} -> {device.vendor}")
                        self.known_devices[device.ip_address] = device
            
            # Check for devices that may have left the network
            offline_ips = set(self.known_devices.keys()) - current_ips
            for ip in offline_ips:
                device = self.known_devices[ip]
                logger.info(f"DEVICE OFFLINE: {device.ip_address} "
                          f"({device.mac_address}) "
                          f"{'[' + device.hostname + ']' if device.hostname else '[Unknown hostname]'}")
                # Remove from known devices after logging
                del self.known_devices[ip]
            
            logger.info(f"Scan completed. Active devices: {len(devices)}, "
                       f"New devices: {len(new_devices)}, "
                       f"Offline devices: {len(offline_ips)}")
            
            return new_devices
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            return set()
    
    async def monitor_loop(self):
        """Main monitoring loop."""
        logger.info("Starting network monitoring loop...")
        
        try:
            while self.running:
                start_time = time.time()
                
                # Perform scan and detect new devices
                new_devices = await self.scan_and_detect_new_devices()
                
                scan_duration = time.time() - start_time
                logger.info(f"Scan completed in {scan_duration:.2f} seconds")
                
                # Wait for next scan interval
                if self.running:
                    logger.info(f"Waiting {self.scan_interval} seconds until next scan...")
                    await asyncio.sleep(self.scan_interval)
                    
        except asyncio.CancelledError:
            logger.info("Monitoring loop cancelled")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
        finally:
            logger.info("Network monitoring stopped")


async def main():
    """Main entry point for the monitoring application."""
    # Get configuration from environment variables
    subnet = os.getenv('SUBNET', '192.168.1.0/24')
    scan_interval = int(os.getenv('SCAN_INTERVAL', '300'))  # 5 minutes default
    timeout = float(os.getenv('SCAN_TIMEOUT', '2.0'))
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Set log level
    try:
        logging.getLogger().setLevel(getattr(logging, log_level))
    except AttributeError:
        logger.warning(f"Invalid log level '{log_level}', using INFO")
        logging.getLogger().setLevel(logging.INFO)
    
    logger.info(f"Net-Sniff Network Monitor starting...")
    logger.info(f"Configuration:")
    logger.info(f"  - Subnet: {subnet}")
    logger.info(f"  - Scan interval: {scan_interval} seconds")
    logger.info(f"  - Scan timeout: {timeout} seconds")
    logger.info(f"  - Log level: {logging.getLogger().level}")
    
    # Validate subnet format
    try:
        from ipaddress import IPv4Network
        IPv4Network(subnet)
    except Exception as e:
        logger.error(f"Invalid subnet format '{subnet}': {e}")
        logger.error("Please provide a valid subnet in CIDR notation (e.g., '192.168.1.0/24')")
        sys.exit(1)
    
    monitor = NetworkMonitor(subnet, scan_interval, timeout)
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        monitor.stop_monitoring()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await monitor.monitor_loop()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        logger.info("Network monitor shutting down...")


if __name__ == '__main__':
    asyncio.run(main())