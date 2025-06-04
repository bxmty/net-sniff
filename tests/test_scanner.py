"""Tests for the network scanner module."""

import pytest
from unittest.mock import patch, MagicMock
from app.scanner import NetworkDevice, AsyncNetworkScanner
import socket


def test_network_device_creation():
    """Test NetworkDevice creation and dictionary conversion."""
    device = NetworkDevice(
        ip_address="192.168.1.1",
        mac_address="00:11:22:33:44:55",
        hostname="test.local",
        vendor="Test Vendor"
    )
    
    assert device.ip_address == "192.168.1.1"
    assert device.mac_address == "00:11:22:33:44:55"
    assert device.hostname == "test.local"
    assert device.vendor == "Test Vendor"
    
    device_dict = device.as_dict()
    assert device_dict["ip_address"] == "192.168.1.1"
    assert device_dict["mac_address"] == "00:11:22:33:44:55"
    assert device_dict["hostname"] == "test.local"
    assert device_dict["vendor"] == "Test Vendor"


def test_network_device_optional_fields():
    """Test NetworkDevice with optional fields."""
    device = NetworkDevice(
        ip_address="192.168.1.1",
        mac_address="00:11:22:33:44:55"
    )
    
    assert device.hostname is None
    assert device.vendor is None
    
    device_dict = device.as_dict()
    assert device_dict["hostname"] == ""
    assert device_dict["vendor"] == ""


@pytest.mark.asyncio
async def test_scanner_initialization():
    """Test AsyncNetworkScanner initialization."""
    scanner = AsyncNetworkScanner("192.168.1.0/24", timeout=2.0, concurrent_scans=50)
    
    assert scanner.subnet == "192.168.1.0/24"
    assert scanner.timeout == 2.0
    assert scanner.concurrent_scans == 50
    assert isinstance(scanner.devices, list)
    assert len(scanner.devices) == 0


@pytest.mark.asyncio
async def test_arp_scan_mock():
    """Test ARP scan with mocked scapy."""
    with patch("app.scanner.srp") as mock_srp:
        # Mock successful ARP response
        mock_srp.return_value = [
            (
                MagicMock(),  # sent packet
                MagicMock(psrc="192.168.1.1")  # received packet
            ),
            (
                MagicMock(),
                MagicMock(psrc="192.168.1.2")
            )
        ]
        
        scanner = AsyncNetworkScanner("192.168.1.0/24")
        active_ips = await scanner._arp_scan()
        
        assert len(active_ips) == 2
        assert "192.168.1.1" in active_ips
        assert "192.168.1.2" in active_ips


@pytest.mark.asyncio
async def test_resolve_hostname():
    """Test hostname resolution."""
    with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
        mock_gethostbyaddr.return_value = ("test.local", [], ["192.168.1.1"])
        
        scanner = AsyncNetworkScanner("192.168.1.0/24")
        hostname = await scanner._resolve_hostname("192.168.1.1")
        
        assert hostname == "test.local"


@pytest.mark.asyncio
async def test_resolve_hostname_failure():
    """Test hostname resolution failure."""
    with patch("socket.gethostbyaddr") as mock_gethostbyaddr:
        mock_gethostbyaddr.side_effect = socket.herror
        
        scanner = AsyncNetworkScanner("192.168.1.0/24")
        hostname = await scanner._resolve_hostname("192.168.1.1")
        
        assert hostname is None 