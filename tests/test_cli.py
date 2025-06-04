"""Tests for the command-line interface."""

import os
import pytest
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock
from app.cli import cli


@pytest.fixture
def runner():
    """Fixture providing a Click CLI test runner."""
    return CliRunner()


def test_cli_version(runner):
    """Test CLI version command."""
    result = runner.invoke(cli, ['--version'])
    assert result.exit_code == 0
    assert "net-sniff" in result.output


@pytest.mark.asyncio
async def test_scan_command_basic(runner):
    """Test basic scan command."""
    with patch('app.cli.AsyncNetworkScanner') as mock_scanner_class:
        # Mock scanner instance
        mock_scanner = AsyncMock()
        mock_scanner.scan_network.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        # Mock exporter
        with patch('app.cli.ResultExporter') as mock_exporter_class:
            mock_exporter = AsyncMock()
            mock_exporter.to_csv.return_value = "test_output.csv"
            mock_exporter_class.return_value = mock_exporter
            
            result = runner.invoke(cli, ['scan', '--subnet', '192.168.1.0/24'])
            
            assert result.exit_code == 0
            assert "Starting network scan" in result.output
            assert "No devices found" in result.output


@pytest.mark.asyncio
async def test_scan_command_with_devices(runner):
    """Test scan command with discovered devices."""
    with patch('app.cli.AsyncNetworkScanner') as mock_scanner_class:
        # Mock scanner instance with sample devices
        mock_scanner = AsyncMock()
        mock_scanner.scan_network.return_value = [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "router.local",
                "vendor": "Cisco"
            }
        ]
        mock_scanner_class.return_value = mock_scanner
        
        # Mock exporter
        with patch('app.cli.ResultExporter') as mock_exporter_class:
            mock_exporter = AsyncMock()
            mock_exporter.to_csv.return_value = "test_output.csv"
            mock_exporter_class.return_value = mock_exporter
            
            result = runner.invoke(cli, ['scan', '--subnet', '192.168.1.0/24'])
            
            assert result.exit_code == 0
            assert "Starting network scan" in result.output
            assert "Found 1 devices" in result.output


@pytest.mark.asyncio
async def test_scan_command_with_verbose(runner):
    """Test scan command with verbose output."""
    with patch('app.cli.AsyncNetworkScanner') as mock_scanner_class:
        # Mock scanner instance
        mock_scanner = AsyncMock()
        mock_scanner.scan_network.return_value = [
            {
                "ip_address": "192.168.1.1",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "router.local",
                "vendor": "Cisco"
            }
        ]
        mock_scanner_class.return_value = mock_scanner
        
        # Mock exporter
        with patch('app.cli.ResultExporter') as mock_exporter_class:
            mock_exporter = AsyncMock()
            mock_exporter.to_csv.return_value = "test_output.csv"
            mock_exporter_class.return_value = mock_exporter
            
            result = runner.invoke(cli, ['scan', '--subnet', '192.168.1.0/24', '--verbose'])
            
            assert result.exit_code == 0
            assert "Starting network scan" in result.output
            assert "Found 1 devices" in result.output
            assert "192.168.1.1" in result.output
            assert "00:11:22:33:44:55" in result.output
            assert "router.local" in result.output
            assert "Cisco" in result.output


@pytest.mark.asyncio
async def test_scan_command_with_custom_output(runner, tmp_path):
    """Test scan command with custom output directory."""
    output_dir = str(tmp_path / "custom_output")
    
    with patch('app.cli.AsyncNetworkScanner') as mock_scanner_class:
        # Mock scanner instance
        mock_scanner = AsyncMock()
        mock_scanner.scan_network.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        # Mock exporter
        with patch('app.cli.ResultExporter') as mock_exporter_class:
            mock_exporter = AsyncMock()
            mock_exporter.to_csv.return_value = os.path.join(output_dir, "test_output.csv")
            mock_exporter_class.return_value = mock_exporter
            
            result = runner.invoke(cli, [
                'scan',
                '--subnet', '192.168.1.0/24',
                '--output', output_dir
            ])
            
            assert result.exit_code == 0
            assert os.path.exists(output_dir) 