
#!/bin/bash

# Esperar a que MongoDB esté listo
echo "Esperando a que MongoDB esté disponible..."
/app/wait-for-it.sh database:27017 --timeout=30 --strict -- echo "MongoDB está listo."

# Iniciar monitoreo de Suricata en segundo plano
python suricata_to_mongo.py &

# Verificar si los datos preprocesados existen, si no, generarlos
if [ ! -f "suricata_preprocessed.csv" ]; then
    echo "Datos preprocesados no encontrados. Ejecutando ml_processing.py..."
    python ml_processing.py 

    # Esperar hasta que el archivo sea generado
    while [ ! -f "suricata_preprocessed.csv" ]; do
        echo "Esperando a que suricata_preprocessed.csv sea generado..."
        sleep 5
    done
fi


# Verificar si el modelo existe, si no, entrenarlo
if [ ! -f "isolation_forest_model.pkl" ]; then
    echo "Modelo no encontrado. Entrenando Isolation Forest..."
    python train_model.py
else
    echo "Modelo encontrado. Continuando..."
fi

# Ejecutar el script de monitoreo de logs en segundo plano
python log_watcher.py &
# Iniciar la aplicación FastAPI
echo "Iniciando FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload
