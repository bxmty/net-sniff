# Net-Sniff Docker Quick Start

This guide helps you get Net-Sniff running in Docker in under 5 minutes.

## Prerequisites

- Docker installed and running
- Basic knowledge of your network setup (subnet)

## Option 1: Quick Start with Docker Compose (Recommended)

```bash
# 1. Clone the repository
git clone <repository-url>
cd net-sniff

# 2. Copy and edit the environment file
cp .env.example .env
# Edit .env and set your SUBNET (e.g., SUBNET=192.168.1.0/24)

# 3. Start monitoring
docker-compose up -d

# 4. View logs
docker-compose logs -f

# 5. Stop when done
docker-compose down
```

## Option 2: Quick Start with Helper Script

```bash
# 1. Build the image
./net-sniff.sh build

# 2. Start monitoring (replace with your subnet)
./net-sniff.sh start 192.168.1.0/24

# 3. View logs
./net-sniff.sh logs

# 4. Check status
./net-sniff.sh status

# 5. Stop monitoring
./net-sniff.sh stop
```

## Option 3: Manual Docker Commands

```bash
# Build
docker build -t net-sniff .

# Run continuous monitoring
docker run -d \
  --name net-sniff-monitor \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e SUBNET=192.168.1.0/24 \
  -v ./output:/app/output \
  net-sniff

# Run single scan
docker run --rm \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v ./output:/app/output \
  net-sniff python -m app.cli scan -s 192.168.1.0/24 -v
```

## Important Notes

1. **Subnet Configuration**: Change `192.168.1.0/24` to match your actual network
2. **Privileges**: The container needs `NET_RAW` and `NET_ADMIN` for network scanning
3. **Host Networking**: Required for proper network access
4. **Output**: CSV files are saved to the `output/` directory

## What You'll See

The monitor will log:
- New devices joining the network
- Devices going offline
- Device information updates
- Scan summaries every few minutes

Example output:
```
2024-01-01 12:00:00 - INFO - NEW DEVICE DETECTED: 192.168.1.50 (aa:bb:cc:dd:ee:ff) [iPhone] [Apple]
2024-01-01 12:05:00 - INFO - Scan completed. Active devices: 12, New devices: 1, Offline devices: 0
```

## Troubleshooting

- **Permission errors**: Ensure you're using `--cap-add NET_RAW --cap-add NET_ADMIN`
- **No devices found**: Check your subnet configuration
- **Container won't start**: Check Docker logs with `docker logs net-sniff-monitor`