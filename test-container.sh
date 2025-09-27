#!/bin/bash

# Container test script - verifies the containerized application
# This should be run inside the container or in a test environment

echo "Testing Net-Sniff Container..."
echo "=============================="

# Test 1: Check Python dependencies
echo "1. Testing Python imports..."
python -c "
import asyncio
import aiofiles
import click
import scapy.all
import nmap
import netaddr
print('✓ All Python dependencies imported successfully')
" || echo "✗ Python import test failed"

# Test 2: Check system tools
echo -e "\n2. Testing system tools..."
which nmap > /dev/null && echo "✓ nmap available" || echo "✗ nmap not found"
which ping > /dev/null && echo "✓ ping available" || echo "✗ ping not found"

# Test 3: Check application imports
echo -e "\n3. Testing application imports..."
python -c "
from app.scanner import AsyncNetworkScanner, NetworkDevice
from app.exporter import ResultExporter
from app.cli import main
print('✓ Application modules imported successfully')
" || echo "✗ Application import test failed"

# Test 4: Test CLI help
echo -e "\n4. Testing CLI help..."
python -m app.cli --help > /dev/null 2>&1 && echo "✓ CLI help works" || echo "✗ CLI help failed"

# Test 5: Test monitor script (dry run)
echo -e "\n5. Testing monitor script import..."
python -c "
import monitor
print('✓ Monitor script imports successfully')
" || echo "✗ Monitor script import failed"

# Test 6: Check output directory
echo -e "\n6. Testing output directory..."
if [ -d "/app/output" ]; then
    echo "✓ Output directory exists"
    [ -w "/app/output" ] && echo "✓ Output directory is writable" || echo "✗ Output directory not writable"
else
    # Check local output directory for non-container testing
    if [ -d "output" ]; then
        echo "✓ Local output directory exists"
        [ -w "output" ] && echo "✓ Local output directory is writable" || echo "✗ Local output directory not writable"
    else
        echo "✗ Output directory missing"
    fi
fi

echo -e "\n✓ Container tests completed!"