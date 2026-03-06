#!/bin/sh
# ML Defense System - Skip sklearn install (use threshold detection)

echo "Starting Ryu controller (threshold-based detection)..."
exec /ENTRYPOINT.sh "$@"
