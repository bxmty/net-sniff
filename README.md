# Net-Sniff

An asynchronous network discovery tool for scanning and identifying devices on a local area network (LAN).

## Features

- Fast asynchronous network scanning
- Device discovery with IP, MAC address, hostname, and vendor information
- CSV export of discovered devices
- Command-line interface with Click
- Configurable scan parameters
- **Docker containerization for easy deployment**
- **Continuous network monitoring with device change detection**

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

### System Requirements

For optimal performance, the following system packages are recommended:

- **nmap**: Used for more accurate MAC address and vendor detection
  - On Debian/Ubuntu: `sudo apt install nmap`
  - On CentOS/RHEL: `sudo yum install nmap`
  - On macOS: `brew install nmap`
  - On Windows: download from [nmap.org](https://nmap.org/download.html)

**Note**: The tool will still work without nmap, but with reduced functionality (using ARP-only scanning).

## Docker Usage

### Quick Start with Docker

The easiest way to run Net-Sniff is using Docker, which includes all required dependencies.

#### Build and Run with Docker Compose

```bash
# Clone the repository
git clone <repository-url>
cd net-sniff

# Update docker-compose.yml with your network subnet
# Edit the SUBNET environment variable (default: 192.168.1.0/24)

# Start the continuous monitoring service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

#### Build and Run with Docker

```bash
# Build the Docker image
docker build -t net-sniff .

# Run continuous monitoring (recommended)
docker run -d \
  --name net-sniff-monitor \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e SUBNET=192.168.1.0/24 \
  -e SCAN_INTERVAL=300 \
  -v ./output:/app/output \
  net-sniff

# Run a single scan
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v ./output:/app/output \
  net-sniff python -m app.cli scan -s 192.168.1.0/24 -v
```

### Docker Configuration

The containerized application supports the following environment variables:

- `SUBNET`: Network subnet to scan in CIDR notation (default: `192.168.1.0/24`)
- `SCAN_INTERVAL`: Time between scans in seconds (default: `300` = 5 minutes)
- `SCAN_TIMEOUT`: Scan timeout in seconds (default: `2.0`)

### Container Features

- **Continuous Monitoring**: Automatically detects new devices joining the network
- **Device Change Detection**: Logs when devices come online/offline or change properties
- **Persistent Storage**: CSV outputs are saved to mounted volume
- **Security**: Runs with minimal required privileges
- **Health Checks**: Built-in container health monitoring
- **Graceful Shutdown**: Handles SIGTERM/SIGINT signals properly

### Networking Requirements

The container requires `host` networking mode to perform network scanning effectively. This allows the container to:

- Send ARP requests to discover devices
- Access the local network interfaces
- Perform accurate network topology discovery

**Security Note**: The container needs `NET_RAW` and `NET_ADMIN` capabilities for network scanning operations.

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