#!/bin/bash
# Install ML dependencies and start Ryu controller

echo "Installing ML dependencies..."
pip install scikit-learn joblib pandas numpy --quiet

echo "Starting Ryu controller..."
exec ryu-manager scripts/dc_switch_1.py scripts/ml_defender.py \
    scripts/monitor_influxdb.py scripts/monitor_graphite.py \
    scripts/monitor_prometheus.py --observe-links
