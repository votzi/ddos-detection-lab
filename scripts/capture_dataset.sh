#!/bin/bash

OUTPUT_DIR="/home/ryu/Desktop/Labo/SdnShare/datasets"
INTERVAL=5

ATTACK_THRESHOLD_PPS=50
ATTACK_THRESHOLD_BPS=50000

AUTO_DETECT=true

mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="$OUTPUT_DIR/dataset_$(date +%Y%m%d_%H%M%S).csv"

echo "Dataset Generator for ML - DDoS Detection"
echo "==========================================="
echo "Full Topology Capture"
echo "Output: $OUTPUT_FILE"
echo "Interval: ${INTERVAL}s"
echo "Auto-detect attacks: $AUTO_DETECT"
echo "Threshold PPS: $ATTACK_THRESHOLD_PPS"
echo "Threshold BPS: $ATTACK_THRESHOLD_BPS"
echo ""

cat > "$OUTPUT_FILE" << EOF
timestamp,switch,port,connection_type,connected_to,rx_pkts,tx_pkts,rx_bytes,tx_bytes,drops,errors,collisions,rx_pps,tx_pps,rx_bps,tx_bps,avg_packet_size_rx,avg_packet_size_tx,rx_tx_ratio,label
EOF

declare -A prev_rx_pkts
declare -A prev_tx_pkts
declare -A prev_rx_bytes
declare -A prev_tx_bytes

declare -A port_connection
port_connection["s11-1"]="spine-link:s21"
port_connection["s11-2"]="spine-link:s22"
port_connection["s11-3"]="spine-link:s23"
port_connection["s12-1"]="spine-link:s21"
port_connection["s12-2"]="spine-link:s22"
port_connection["s12-3"]="spine-link:s23"
port_connection["s21-1"]="spine-link:s11"
port_connection["s21-2"]="spine-link:s12"
port_connection["s21-3"]="host:h1"
port_connection["s21-4"]="host:h2"
port_connection["s22-1"]="spine-link:s11"
port_connection["s22-2"]="spine-link:s12"
port_connection["s22-3"]="host:h3"
port_connection["s22-4"]="host:h4"
port_connection["s23-1"]="spine-link:s11"
port_connection["s23-2"]="spine-link:s12"
port_connection["s23-3"]="host:h5"
port_connection["s23-4"]="host:h6"

ALL_SWITCHES="s11 s12 s21 s22 s23"
ALL_PORTS="1 2 3 4"

detect_attack() {
    local rx_pps=$1
    local tx_pps=$2
    local rx_bps=$3
    local tx_bps=$4
    
    if [ $rx_pps -gt $ATTACK_THRESHOLD_PPS ] || [ $tx_pps -gt $ATTACK_THRESHOLD_PPS ]; then
        echo "1"
        return
    fi
    
    if [ $rx_bps -gt $ATTACK_THRESHOLD_BPS ] || [ $tx_bps -gt $ATTACK_THRESHOLD_BPS ]; then
        echo "1"
        return
    fi
    
    echo "0"
}

init_values() {
    echo "Initializing full topology..."
    for switch in $ALL_SWITCHES; do
        for port in $ALL_PORTS; do
            key="${switch}-${port}"
            
            port_data=$(docker compose exec -T mininet ovs-ofctl dump-ports $switch 2>/dev/null | grep -E "port[[:space:]]+$port:" -A 1)
            
            rx_pkts=$(echo "$port_data" | grep -oP 'rx pkts=\K[0-9]+' | head -1)
            tx_pkts=$(echo "$port_data" | grep -oP 'tx pkts=\K[0-9]+' | head -1)
            rx_bytes=$(echo "$port_data" | grep -oP 'bytes=\K[0-9]+' | head -1)
            tx_bytes=$(echo "$port_data" | grep -oP 'bytes=\K[0-9]+' | tail -1)
            
            prev_rx_pkts[$key]=${rx_pkts:-0}
            prev_tx_pkts[$key]=${tx_pkts:-0}
            prev_rx_bytes[$key]=${rx_bytes:-0}
            prev_tx_bytes[$key]=${tx_bytes:-0}
        done
    done
    echo "Done"
}

capture() {
    timestamp=$(date +%Y-%m-%d\ %H:%M:%S)
    current_label=0
    
    for switch in $ALL_SWITCHES; do
        for port in $ALL_PORTS; do
            key="${switch}-${port}"
            connection="${port_connection[$key]:-unknown}"
            connection_type=$(echo "$connection" | cut -d':' -f1)
            connected_to=$(echo "$connection" | cut -d':' -f2)
            
            port_data=$(docker compose exec -T mininet ovs-ofctl dump-ports $switch 2>/dev/null | grep -E "port[[:space:]]+$port:" -A 1)
            
            rx_pkts=$(echo "$port_data" | grep -oP 'rx pkts=\K[0-9]+' | head -1)
            tx_pkts=$(echo "$port_data" | grep -oP 'tx pkts=\K[0-9]+' | head -1)
            rx_bytes=$(echo "$port_data" | grep -oP 'bytes=\K[0-9]+' | head -1)
            tx_bytes=$(echo "$port_data" | grep -oP 'bytes=\K[0-9]+' | tail -1)
            drops=$(echo "$port_data" | grep -oP 'drop=\K[0-9]+' | head -1)
            errors=$(echo "$port_data" | grep -oP 'errs=\K[0-9]+' | head -1)
            collisions=$(echo "$port_data" | grep -oP 'coll=\K[0-9]+' | head -1)
            
            rx_pkts=${rx_pkts:-0}
            tx_pkts=${tx_pkts:-0}
            rx_bytes=${rx_bytes:-0}
            tx_bytes=${tx_bytes:-0}
            drops=${drops:-0}
            errors=${errors:-0}
            collisions=${collisions:-0}
            
            prev_rx=${prev_rx_pkts[$key]:-0}
            prev_tx=${prev_tx_pkts[$key]:-0}
            prev_rx_b=${prev_rx_bytes[$key]:-0}
            prev_tx_b=${prev_tx_bytes[$key]:-0}
            
            delta_rx_pkts=$((rx_pkts - prev_rx))
            delta_tx_pkts=$((tx_pkts - prev_tx))
            delta_rx_bytes=$((rx_bytes - prev_rx_b))
            delta_tx_bytes=$((tx_bytes - prev_tx_b))
            
            [ $delta_rx_pkts -lt 0 ] && delta_rx_pkts=0
            [ $delta_tx_pkts -lt 0 ] && delta_tx_pkts=0
            [ $delta_rx_bytes -lt 0 ] && delta_rx_bytes=0
            [ $delta_tx_bytes -lt 0 ] && delta_tx_bytes=0
            
            rx_pps=$((delta_rx_pkts / INTERVAL))
            tx_pps=$((delta_tx_pkts / INTERVAL))
            rx_bps=$((delta_rx_bytes / INTERVAL))
            tx_bps=$((delta_tx_bytes / INTERVAL))
            
            if [ $delta_rx_pkts -gt 0 ]; then
                avg_pkt_size_rx=$((delta_rx_bytes / delta_rx_pkts))
            else
                avg_pkt_size_rx=0
            fi
            
            if [ $delta_tx_pkts -gt 0 ]; then
                avg_pkt_size_tx=$((delta_tx_bytes / delta_tx_pkts))
            else
                avg_pkt_size_tx=0
            fi
            
            if [ $tx_pps -gt 0 ]; then
                rx_tx_ratio=$(echo "scale=2; $rx_pps / $tx_pps" | bc)
            else
                rx_tx_ratio=0
            fi
            
            if [ "$AUTO_DETECT" = true ]; then
                detected_label=$(detect_attack $rx_pps $tx_pps $rx_bps $tx_bps)
                if [ "$detected_label" = "1" ]; then
                    current_label=1
                fi
            fi
            
            echo "$timestamp,$switch,$port,$connection_type,$connected_to,$rx_pkts,$tx_pkts,$rx_bytes,$tx_bytes,$drops,$errors,$collisions,$rx_pps,$tx_pps,$rx_bps,$tx_bps,$avg_pkt_size_rx,$avg_pkt_size_tx,$rx_tx_ratio,$current_label" >> "$OUTPUT_FILE"
            
            prev_rx_pkts[$key]=$rx_pkts
            prev_tx_pkts[$key]=$tx_pkts
            prev_rx_bytes[$key]=$rx_bytes
            prev_tx_bytes[$key]=$tx_bytes
        done
    done
}

init_values

echo ""
echo "Starting full topology capture... Press Ctrl+C to stop"
echo ""

while true; do
    capture
    label_status=$(tail -1 "$OUTPUT_FILE" | cut -d',' -f20)
    if [ "$label_status" = "1" ]; then
        echo "[$(date +%H:%M:%S)] Captured - ⚠️  ATTACK DETECTED (label=1)"
    else
        echo "[$(date +%H:%M:%S)] Captured - ✓ Normal (label=0)"
    fi
    sleep $INTERVAL
done
