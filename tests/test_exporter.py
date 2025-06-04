"""Tests for the result exporter module."""

import os
import pytest
import csv
from pathlib import Path
from app.exporter import ResultExporter


@pytest.mark.asyncio
async def test_exporter_initialization(tmp_path):
    """Test ResultExporter initialization."""
    exporter = ResultExporter(str(tmp_path))
    assert exporter.output_dir == str(tmp_path)
    assert os.path.exists(tmp_path)


@pytest.mark.asyncio
async def test_csv_export_async(sample_devices, exporter):
    """Test async CSV export functionality."""
    # Export devices to CSV
    csv_path = await exporter.to_csv(sample_devices)
    
    # Verify file was created
    assert os.path.exists(csv_path)
    
    # Read and verify CSV contents
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        
        assert len(rows) == len(sample_devices)
        
        # Verify first device
        assert rows[0]["ip_address"] == "192.168.1.1"
        assert rows[0]["mac_address"] == "00:11:22:33:44:55"
        assert rows[0]["hostname"] == "router.local"
        assert rows[0]["vendor"] == "Cisco"
        
        # Verify second device
        assert rows[1]["ip_address"] == "192.168.1.2"
        assert rows[1]["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert rows[1]["hostname"] == "printer.local"
        assert rows[1]["vendor"] == "HP"
        
        # Verify third device (with None values)
        assert rows[2]["ip_address"] == "192.168.1.3"
        assert rows[2]["mac_address"] == "11:22:33:44:55:66"
        assert rows[2]["hostname"] == ""
        assert rows[2]["vendor"] == "Unknown"


@pytest.mark.asyncio
async def test_csv_export_sync(sample_devices, exporter):
    """Test synchronous CSV export functionality."""
    # Export devices to CSV
    csv_path = await exporter.to_csv_sync(sample_devices)
    
    # Verify file was created
    assert os.path.exists(csv_path)
    
    # Read and verify CSV contents
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        
        assert len(rows) == len(sample_devices)
        
        # Verify first device
        assert rows[0]["ip_address"] == "192.168.1.1"
        assert rows[0]["mac_address"] == "00:11:22:33:44:55"
        assert rows[0]["hostname"] == "router.local"
        assert rows[0]["vendor"] == "Cisco"


@pytest.mark.asyncio
async def test_csv_export_custom_filename(sample_devices, exporter):
    """Test CSV export with custom filename."""
    custom_filename = "custom_scan.csv"
    csv_path = await exporter.to_csv(sample_devices, custom_filename)
    
    assert os.path.exists(csv_path)
    assert os.path.basename(csv_path) == custom_filename


@pytest.mark.asyncio
async def test_csv_export_empty_devices(exporter):
    """Test CSV export with empty device list."""
    csv_path = await exporter.to_csv([])
    assert os.path.exists(csv_path)
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 0 