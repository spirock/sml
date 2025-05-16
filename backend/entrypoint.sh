
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


# Iniciar monitoreo de Suricata en segundo plano
python suricata_to_mongo.py &

# Verificar si los datos preprocesados existen, si no, generarlos
if [ ! -f "/app/models/suricata_preprocessed.csv" ]; then
    echo "[ENTRY] Datos preprocesados no encontrados. Ejecutando ml_processing.py..."
    python ml_processing.py 

    # Esperar hasta que el archivo sea generado
    while [ ! -f "/app/models/suricata_preprocessed.csv" ]; do
        echo "[ENTRY] Esperando a que suricata_preprocessed.csv sea generado..."
        sleep 10
    done
fi


# Verificar si el modelo existe, si no, entrenarlo
if [ ! -f "/app/models/isolation_forest_model.pkl" ]; then
    echo "Modelo no encontrado. Entrenando Isolation Forest..."
    python train_model.py
else
    echo "Modelo encontrado. Continuando..."
fi

# Ejecutar el script de monitoreo de logs en segundo plano
python log_watcher.py &


# ===========================
# 🚀 **Iniciar FastAPI**
# ===========================
echo "Iniciando FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload
