"""Test configuration and fixtures for pytest."""

import pytest
from app.scanner import NetworkDevice, AsyncNetworkScanner
from app.exporter import ResultExporter


@pytest.fixture
def sample_devices():
    """Fixture providing sample network devices for testing."""
    return [
        NetworkDevice(
            ip_address="192.168.1.1",
            mac_address="00:11:22:33:44:55",
            hostname="router.local",
            vendor="Cisco"
        ),
        NetworkDevice(
            ip_address="192.168.1.2",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="printer.local",
            vendor="HP"
        ),
        NetworkDevice(
            ip_address="192.168.1.3",
            mac_address="11:22:33:44:55:66",
            hostname=None,
            vendor="Unknown"
        )
    ]


@pytest.fixture
def scanner():
    """Fixture providing an AsyncNetworkScanner instance."""
    return AsyncNetworkScanner("192.168.1.0/24")


@pytest.fixture
def exporter(tmp_path):
    """Fixture providing a ResultExporter instance with a temporary output directory."""
    return ResultExporter(str(tmp_path)) 