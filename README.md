# Net-Sniff

An asynchronous network discovery tool for scanning and identifying devices on a local area network (LAN).

## Features

- Fast asynchronous network scanning
- Device discovery with IP, MAC address, hostname, and vendor information
- CSV export of discovered devices
- Command-line interface with Click
- Configurable scan parameters

## Installation

```bash
# Install from the current directory
poetry install

# Or install in development mode
poetry install --develop
```

## Usage

### Basic Scan

Scan your local network and export results to a CSV file:

```bash
# Replace with your network CIDR
net-sniff scan --subnet 192.168.1.0/24
```

### Advanced Options

```bash
# Scan with custom timeout and concurrency settings
net-sniff scan --subnet 192.168.1.0/24 --timeout 2.0 --concurrent 50

# Specify custom output directory and filename
net-sniff scan --subnet 192.168.1.0/24 --output ./custom-results --filename network_inventory.csv

# Enable verbose output
net-sniff scan --subnet 192.168.1.0/24 --verbose
```

### Getting Help

```bash
# Show general help
net-sniff --help

# Show scan command help
net-sniff scan --help
```

## CSV Output Format

By default, scan results are saved to the `output` directory in the project root.

The generated CSV file includes the following columns:

- `ip_address`: Device IP address
- `mac_address`: Device MAC address
- `hostname`: Device hostname (if resolvable)
- `vendor`: Hardware vendor based on MAC address (if available)

## Requirements

- Python 3.11+
- Dependencies managed with Poetry:
  - asyncio
  - aiofiles
  - click
  - scapy
  - python-nmap
  - netaddr

## Development

```bash
# Install development dependencies
poetry install

# Run tests
poetry run pytest

# Format code
poetry run black .
poetry run isort .

# Lint code
poetry run flake8
poetry run mypy .
```

## License

[MIT](LICENSE)