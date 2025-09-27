#!/bin/bash

# Net-Sniff Docker Helper Script
# Provides easy commands for managing the containerized network scanner

set -e

CONTAINER_NAME="net-sniff-monitor"
IMAGE_NAME="net-sniff"
DEFAULT_SUBNET="192.168.1.0/24"

show_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build                Build the Docker image"
    echo "  start [subnet]       Start continuous monitoring (default: $DEFAULT_SUBNET)"
    echo "  stop                 Stop the monitoring container"
    echo "  logs                 Show container logs"
    echo "  scan <subnet>        Run a single scan"
    echo "  shell                Open shell in container"
    echo "  status               Show container status"
    echo "  clean                Remove container and image"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 start 10.0.1.0/24"
    echo "  $0 scan 192.168.1.0/24"
    echo "  $0 logs"
    echo ""
}

build_image() {
    echo "Building Net-Sniff Docker image..."
    docker build -t $IMAGE_NAME .
    echo "✓ Image built successfully"
}

start_monitoring() {
    local subnet=${1:-$DEFAULT_SUBNET}
    echo "Starting Net-Sniff monitor for subnet: $subnet"
    
    # Stop existing container if running
    if docker ps -q -f name=$CONTAINER_NAME | grep -q .; then
        echo "Stopping existing container..."
        docker stop $CONTAINER_NAME > /dev/null
        docker rm $CONTAINER_NAME > /dev/null
    fi
    
    # Create output directory
    mkdir -p output
    
    # Start new container
    docker run -d \
        --name $CONTAINER_NAME \
        --network host \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        --restart unless-stopped \
        -e SUBNET=$subnet \
        -e SCAN_INTERVAL=${SCAN_INTERVAL:-300} \
        -e SCAN_TIMEOUT=${SCAN_TIMEOUT:-2.0} \
        -v "$(pwd)/output:/app/output" \
        $IMAGE_NAME
    
    echo "✓ Monitor started. Use '$0 logs' to view output."
}

stop_monitoring() {
    echo "Stopping Net-Sniff monitor..."
    if docker ps -q -f name=$CONTAINER_NAME | grep -q .; then
        docker stop $CONTAINER_NAME
        docker rm $CONTAINER_NAME
        echo "✓ Monitor stopped"
    else
        echo "Monitor is not running"
    fi
}

show_logs() {
    if docker ps -q -f name=$CONTAINER_NAME | grep -q .; then
        echo "Showing Net-Sniff logs (press Ctrl+C to exit):"
        docker logs -f $CONTAINER_NAME
    else
        echo "Monitor is not running"
        exit 1
    fi
}

run_scan() {
    local subnet=$1
    if [ -z "$subnet" ]; then
        echo "Error: Please specify a subnet"
        echo "Usage: $0 scan <subnet>"
        exit 1
    fi
    
    echo "Running single scan of $subnet..."
    mkdir -p output
    
    docker run --rm \
        --network host \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        -v "$(pwd)/output:/app/output" \
        $IMAGE_NAME python -m app.cli scan -s $subnet -v
}

open_shell() {
    echo "Opening shell in Net-Sniff container..."
    docker run --rm -it \
        --network host \
        --cap-add NET_RAW \
        --cap-add NET_ADMIN \
        -v "$(pwd)/output:/app/output" \
        $IMAGE_NAME bash
}

show_status() {
    echo "Net-Sniff Container Status:"
    echo "=========================="
    
    if docker images -q $IMAGE_NAME | grep -q .; then
        echo "✓ Image exists: $IMAGE_NAME"
    else
        echo "✗ Image not found: $IMAGE_NAME (run '$0 build' first)"
    fi
    
    if docker ps -q -f name=$CONTAINER_NAME | grep -q .; then
        echo "✓ Container running: $CONTAINER_NAME"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" -f name=$CONTAINER_NAME
    else
        echo "✗ Container not running: $CONTAINER_NAME"
    fi
    
    if [ -d "output" ]; then
        local csv_count=$(find output -name "*.csv" 2>/dev/null | wc -l)
        echo "📁 Output directory: $(pwd)/output ($csv_count CSV files)"
    else
        echo "📁 Output directory: Not created"
    fi
}

clean_all() {
    echo "Cleaning up Net-Sniff containers and images..."
    
    # Stop and remove container
    if docker ps -aq -f name=$CONTAINER_NAME | grep -q .; then
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
        echo "✓ Container removed"
    fi
    
    # Remove image
    if docker images -q $IMAGE_NAME | grep -q .; then
        docker rmi $IMAGE_NAME
        echo "✓ Image removed"
    fi
    
    echo "✓ Cleanup completed"
}

# Main command processing
case "$1" in
    build)
        build_image
        ;;
    start)
        start_monitoring "$2"
        ;;
    stop)
        stop_monitoring
        ;;
    logs)
        show_logs
        ;;
    scan)
        run_scan "$2"
        ;;
    shell)
        open_shell
        ;;
    status)
        show_status
        ;;
    clean)
        clean_all
        ;;
    *)
        show_usage
        exit 1
        ;;
esac