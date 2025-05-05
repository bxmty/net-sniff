"""
Command-line interface for network scanning tool.
"""

import asyncio
import functools
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click

from app.exporter import ResultExporter
from app.scanner import AsyncNetworkScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)


@click.group()
@click.version_option()
def cli():
    """Network discovery tool for scanning LAN devices."""
    pass


def async_command(f):
    """Decorator to properly handle async Click commands."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper

@cli.command('scan')
@click.option(
    '--subnet',
    '-s',
    required=True,
    help='Subnet to scan in CIDR notation (e.g., 192.168.1.0/24)'
)
@click.option(
    '--timeout',
    '-t',
    default=1.0,
    type=float,
    help='Timeout in seconds for each scan (default: 1.0)'
)
@click.option(
    '--concurrent',
    '-c',
    default=100,
    type=int,
    help='Maximum number of concurrent scans (default: 100)'
)
@click.option(
    '--output',
    '-o',
    default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output'),
    type=click.Path(file_okay=False, dir_okay=True),
    help='Directory to save output CSV file (default: output directory in project root)'
)
@click.option(
    '--filename',
    '-f',
    default=None,
    help='Filename for the CSV output (default: auto-generated with timestamp)'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Enable verbose output'
)
@async_command
async def scan(
    subnet: str,
    timeout: float,
    concurrent: int,
    output: str,
    filename: Optional[str],
    verbose: bool
):
    """
    Scan a network subnet for active devices and export results to CSV.
    """
    # Set log level based on verbose flag
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Ensure output directory exists
    os.makedirs(output, exist_ok=True)
    
    click.echo(f"Starting network scan of {subnet}...")
    
    try:
        # Create scanner and exporter
        scanner = AsyncNetworkScanner(subnet, timeout, concurrent)
        exporter = ResultExporter(output)
        
        # Run the scan
        devices = await scanner.scan_network()
        
        if not devices:
            click.echo("No devices found on the network.")
            return
        
        # Display summary of found devices
        click.echo(f"Found {len(devices)} devices on the network:")
        
        # Format for display
        headers = ['IP Address', 'MAC Address', 'Hostname', 'Vendor']
        rows = []
        
        for device in devices:
            row = [
                device.ip_address,
                device.mac_address,
                device.hostname or 'N/A',
                device.vendor or 'Unknown'
            ]
            rows.append(row)
            
            if verbose:
                click.echo(f"  - {device.ip_address} ({device.mac_address}) "
                           f"{'[' + device.hostname + ']' if device.hostname else ''} "
                           f"{device.vendor or ''}")
        
        # Export results to CSV
        try:
            csv_path = await exporter.to_csv(devices, filename)
            click.echo(f"Results exported to: {csv_path}")
        except Exception as e:
            logger.warning(f"Error with async CSV export: {e}. Trying synchronous export...")
            csv_path = await exporter.to_csv_sync(devices, filename)
            click.echo(f"Results exported to: {csv_path}")
            
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def main():
    """Entry point for the command-line application."""
    # Using a wrapper function to handle async commands
    cli()


if __name__ == '__main__':
    # Allow execution as a script
    main()