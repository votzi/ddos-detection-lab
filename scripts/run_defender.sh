#!/bin/bash
# ML Defender Launcher
# Inicia el controlador Ryu con el sistema de defensa ML

echo "=========================================="
echo "🛡️  ML DEFENSE SYSTEM LAUNCHER"
echo "=========================================="
echo ""

# Verificar que el modelo existe
MODEL_PATH="/home/ryu/Desktop/Labo/SdnShare/models/ddos_dt_model.pkl"
if [ ! -f "$MODEL_PATH" ]; then
    echo "❌ Error: Modelo no encontrado en $MODEL_PATH"
    echo "   Primero entrena el modelo ejecutando el notebook:"
    echo "   jupyter notebook /home/ryu/Desktop/Labo/SdnShare/notebooks/ddos_detection_dt.ipynb"
    exit 1
fi

echo "✅ Modelo encontrado: $MODEL_PATH"
echo ""

# Verificar que los scripts existen
SCRIPT_DIR="/home/ryu/Desktop/Labo/SdnShare/scripts"
if [ ! -f "$SCRIPT_DIR/dc_switch_1.py" ] || [ ! -f "$SCRIPT_DIR/ml_defender.py" ]; then
    echo "❌ Error: Scripts no encontrados en $SCRIPT_DIR"
    exit 1
fi

echo "✅ Scripts encontrados"
echo ""

# Verificar si hay contenedores de Docker ejecutándose
echo "📋 Contenedores en ejecución:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "   Docker no disponible"
echo ""

# Mostrar cómo ejecutar
echo "=========================================="
echo "🚀 INSTRUCCIONES PARA EJECUTAR"
echo "=========================================="
echo ""
echo "Opción 1 - Usando docker-compose:"
echo "  cd /home/ryu/Desktop/Labo/SdnShare"
echo "  docker-compose up"
echo ""
echo "Opción 2 - Ejecutar manualmente:"
echo "  docker run -it --rm \\"
echo "    --privileged \\"
echo "    -v \$(pwd)/scripts:/home/ryu/scripts \\"
echo "    -v \$(pwd)/models:/home/ryu/Desktop/Labo/SdnShare/models \\"
echo "    -p 6653:6653 \\"
echo "    -p 8080:8080 \\"
echo "    SDNLab/ryu:latest \\"
echo "    ryu-manager scripts/dc_switch_1.py scripts/ml_defender.py --observe-links"
echo ""
echo "=========================================="
echo "📊 MONITOREO"
echo "=========================================="
echo "  - Panel Ryu:     http://localhost:8080"
echo "  - Puerto OpenFlow: localhost:6653"
echo "  - Logs:          docker-compose logs -f ryu"
echo ""
