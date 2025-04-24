from fastapi import APIRouter
import os
import json
import pandas as pd
import joblib
import numpy as np
from db_connection import db
import socket
router = APIRouter()

LOG_FILE = "/var/log/suricata/eve.json"
# 📌 Rutas importantes
RULES_FILE = "/var/lib/suricata/rules/sml.rules"



@router.get("/host-ip")
async def get_host_ip():
    """Devuelve la IP local del host donde corre FastAPI (útil para descubrir servicios en red local)."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return {"ip": local_ip}


@router.get("/disvovery")
async def get_discovery():
    ip_address = socket.gethostbyname(socket.gethostname())
    return {"message": "Soc SML",
            "ip": ip_address,
            "port": 8000,
            "service":"flowSML"}

@router.get("/logs")
async def get_logs():
    """Lee los logs de Suricata directamente desde el archivo eve.json"""
    if not os.path.exists(LOG_FILE):
        return {"error": "El archivo de logs no existe"}
    
    try:
        with open(LOG_FILE, "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
        return logs
    except Exception as e:
        return {"error": str(e)}
    
MODEL_PATH = "/app/models/isolation_forest_model.pkl"

# Cargar el modelo entrenado
model = joblib.load(MODEL_PATH)


@router.post("/predict")
async def predict_anomaly(data: dict):
    try:
        # Convertir datos de entrada en DataFrame
        df = pd.DataFrame([data])

        # Preprocesamiento (debe coincidir con el del entrenamiento)
        df["src_ip"] = sum([int(num) << (8 * i) for i, num in enumerate(reversed(df["src_ip"][0].split('.')))])
        df["dest_ip"] = sum([int(num) << (8 * i) for i, num in enumerate(reversed(df["dest_ip"][0].split('.')))])
        df["proto"] = df["proto"].astype("category").cat.codes
        df = (df - df.min()) / (df.max() - df.min())

        # Realizar predicción
        prediction = model.predict(df)

        return {"anomaly": bool(prediction[0] == -1)}

    except Exception as e:
        return {"error": str(e)}

@router.get("/stats")
async def get_model_stats():
    """Devuelve estadísticas de las detecciones del modelo."""
    collection = db["events"]
    
    total_events = await collection.count_documents({})
    anomalies = await collection.count_documents({"prediction": -1})  # Eventos anómalos

    if total_events == 0:
        return {"message": "No hay datos disponibles."}

    anomaly_percentage = (anomalies / total_events) * 100

    # Obtener las IPs con más anomalías
    pipeline = [
        {"$match": {"prediction": -1}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_ips = await collection.aggregate(pipeline).to_list(length=5)

    return {
        "total_events": total_events,
        "anomalies_detected": anomalies,
        "anomaly_percentage": anomaly_percentage,
        "top_anomalous_ips": top_ips
    }



@router.get("/rules")
async def list_rules():
    """Devuelve la lista de reglas de Suricata."""
    try:
        with open(RULES_FILE, "r") as file:
            rules = file.readlines()
        return {"rules": rules}
    except Exception as e:
        return {"error": str(e)}
    

@router.put("/rules/{sid}/{status}")
async def toggle_rule(sid: int, status: str):
    """Activa o desactiva una regla según su `sid`."""
    if status not in ["enable", "disable"]:
        return {"error": "Estado inválido. Usa 'enable' o 'disable'."}

    try:
        with open(RULES_FILE, "r") as file:
            lines = file.readlines()

        updated_lines = []
        for line in lines:
            if f"sid:{sid};" in line:
                if status == "disable" and not line.startswith("#"):
                    line = "#" + line  # Desactivar
                elif status == "enable":
                    line = line.lstrip("#")  # Activar
            updated_lines.append(line)

        with open(RULES_FILE, "w") as file:
            file.writelines(updated_lines)

        return {"message": f"Regla {sid} {status} correctamente."}
    except Exception as e:
        return {"error": str(e)}
