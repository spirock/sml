
#!/bin/bash
# Inicia el servicio Avahi
service avahi-daemon start


# Esperar a que MongoDB esté listo
echo "Esperando a que MongoDB esté disponible..."
/app/wait-for-it.sh database:27017 --timeout=30 --strict -- echo "MongoDB está listo."

# Crear el archivo de logs si no existe
LOG_FILE="/var/log/fastapi.log"
touch $LOG_FILE
chmod 666 $LOG_FILE  # Permitir escritura


# Ejecutar init_db() desde db_connection.py para crear la base de datos y colección
echo "📂 Verificando la base de datos en MongoDB..."
python -c 'import asyncio; from db_connection import init_db; asyncio.run(init_db())'
echo "✅ Base de datos y colección verificadas."

# === Asegurar artefactos mínimos para primer arranque (placeholders) ===
MODEL_DIR="/app/models"
mkdir -p "$MODEL_DIR"

# CSVs con solo cabeceras si no existen o están vacíos
[ ! -s "$MODEL_DIR/suricata_preprocessed.csv" ] && \
  printf "src_ip,dest_ip,proto,src_port,dest_port,alert_severity,packet_length,hour,is_night,ports_used,conn_per_ip,anomaly\n" > "$MODEL_DIR/suricata_preprocessed.csv"

[ ! -s "$MODEL_DIR/ground_truth.csv" ] && \
  printf "timestamp,src_ip,dest_ip,label\n" > "$MODEL_DIR/ground_truth.csv"

[ ! -s "$MODEL_DIR/suricata_anomaly_analysis.csv" ] && \
  printf "timestamp,src_ip,dest_ip,prediction,anomaly_score\n" > "$MODEL_DIR/suricata_anomaly_analysis.csv"


# Iniciar monitoreo de Suricata en segundo plano
python suricata_to_mongo.py &

# Ejecutar ml_processing.py (best-effort, no bloquear primer arranque)
echo "[ENTRY] Ejecutando ml_processing.py (best-effort)..."
python ml_processing.py || echo "[ENTRY] ml_processing.py no generó filas (puede ser normal en primer arranque)."


# Entrenar modelo sólo si hay datos reales (más de cabecera) o si no existe el PKL
CSV="/app/models/suricata_preprocessed.csv"
PKL="/app/models/isolation_forest_model.pkl"

[ -f "$CSV" ] && LINES=$(wc -l < "$CSV" | tr -d ' ')

if [ ! -f "$PKL" ]; then
  if [ "$LINES" -gt 1 ]; then
    echo "[ENTRY] Modelo no encontrado y hay datos. Entrenando Isolation Forest..."
    python train_model.py || echo "[ENTRY] Entrenamiento falló."
  else
    echo "[ENTRY] Modelo no encontrado pero el CSV no tiene datos (solo cabecera). Omitiendo entrenamiento por ahora."
  fi
else
  # PKL existe; reentrenar sólo si hay datos y se desea lógica futura
  if [ "$LINES" -gt 1 ]; then
    echo "[ENTRY] Modelo encontrado. Continuando sin reentrenar."
  else
    echo "[ENTRY] Modelo encontrado, pero el CSV está vacío (solo cabecera)."
  fi
fi

# Ejecutar el script de monitoreo de logs en segundo plano
python log_watcher.py &


# ===========================
# 🚀 **Iniciar FastAPI**
# ===========================
echo "Iniciando FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload
