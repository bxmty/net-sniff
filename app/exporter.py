"""
Export module for saving scan results to CSV format.
"""

import csv
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiofiles
from aiofiles import os as aio_os

from app.scanner import NetworkDevice

# Setup logging
logger = logging.getLogger(__name__)


class ResultExporter:
    """Export scan results to various formats."""

    def __init__(self, output_dir: str = '.'):
        """
        Initialize the result exporter.

        Args:
            output_dir: Directory where output files will be saved
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    async def to_csv(self, devices: List[NetworkDevice], filename: Optional[str] = None) -> str:
        """
        Export the scan results to a CSV file.

        Args:
            devices: List of NetworkDevice objects
            filename: Optional filename, if not provided a timestamped name will be used

        Returns:
            Path to the created CSV file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.csv"
        
        # Ensure the filename has .csv extension
        if not filename.lower().endswith('.csv'):
            filename += '.csv'
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Convert devices to dictionaries for CSV export
        rows = [device.as_dict() for device in devices]
        
        if not rows:
            logger.warning("No devices to export")
            return filepath
        
        fieldnames = list(rows[0].keys())
        
        try:
            # Check if directory exists, create if not
            dir_path = os.path.dirname(filepath)
            if dir_path and not os.path.exists(dir_path):
                await aio_os.makedirs(dir_path, exist_ok=True)
            
            # Write the CSV file asynchronously
            async with aiofiles.open(filepath, mode='w', newline='') as csvfile:
                # We need to write the CSV data manually since csv module doesn't support async
                csv_content = []
                # Add header
                csv_content.append(','.join(fieldnames))
                # Add device rows
                for row in rows:
                    csv_content.append(','.join([str(row.get(field, '')) for field in fieldnames]))
                
                await csvfile.write('\n'.join(csv_content))
            
            logger.info(f"Successfully exported {len(rows)} devices to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            raise

    async def to_csv_sync(self, devices: List[NetworkDevice], filename: Optional[str] = None) -> str:
        """
        Export the scan results to a CSV file using synchronous operations.
        Use this if the async version encounters issues.

        Args:
            devices: List of NetworkDevice objects
            filename: Optional filename, if not provided a timestamped name will be used

        Returns:
            Path to the created CSV file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}.csv"
        
        # Ensure the filename has .csv extension
        if not filename.lower().endswith('.csv'):
            filename += '.csv'
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Convert devices to dictionaries for CSV export
        rows = [device.as_dict() for device in devices]
        
        if not rows:
            logger.warning("No devices to export")
            return filepath
        
        fieldnames = list(rows[0].keys())
        
        try:
            # Check if directory exists, create if not
            dir_path = os.path.dirname(filepath)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            
            # Write the CSV file synchronously
            with open(filepath, mode='w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            
            logger.info(f"Successfully exported {len(rows)} devices to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            raise