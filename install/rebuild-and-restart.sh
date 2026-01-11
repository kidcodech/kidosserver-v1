#!/bin/bash

# Stops, Rebuilds, and Starts all Kidos components
# Must be run as root

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: This script must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

echo "=========================================="
echo "   RESTARTING KIDOS SERVER (FULL REBUILD)"
echo "=========================================="

echo ">>> PHASE 1: STOPPING SERVICES"
"$SCRIPT_DIR/stop-all.sh"
echo ""

echo ">>> PHASE 2: BUILDING COMPONENTS"
"$SCRIPT_DIR/build-all.sh"
echo ""

echo ">>> PHASE 3: STARTING SERVICES"
"$SCRIPT_DIR/start-all.sh"
echo ""

echo "=========================================="
echo "   ALL SYSTEMS RESTARTED SUCCESSFULLY"
echo "=========================================="
