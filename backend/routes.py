from fastapi import APIRouter, Query
from typing import Optional
import os
import json
import pandas as pd
import joblib
import numpy as np
from db_connection import db
from datetime import datetime
import socket
router = APIRouter()

LOG_FILE = "/var/log/suricata/eve.json"
# 📌 Rutas importantes
#RULES_FILE = "/var/lib/suricata/rules/sml.rules"
RULES_DIR = "/var/lib/suricata/rules"
  

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
async def get_logs(page: int = 1, limit: int = 100, dia: int = None, mes: int = None, ano: int = None):
    """
    Lee los últimos logs de Suricata desde eve.json.
    Soporta paginación y filtrado opcional por fecha (día, mes, año).
    Ejemplo: /logs?page=1&limit=100&dia=12&mes=5&ano=2025
    """
    MAX_TOTAL = 1000
    if not os.path.exists(LOG_FILE):
        return {"error": "El archivo de logs no existe"}

    try:
        hoy = datetime.today()
        dia = dia if dia is not None else hoy.day
        mes = mes if mes is not None else hoy.month
        ano = ano if ano is not None else hoy.year

        fecha_objetivo = datetime(ano, mes, dia)

        with open(LOG_FILE, "r") as f:
            lines = f.readlines()[-MAX_TOTAL:]

        logs_filtrados = []
        for line in reversed(lines):  # del más reciente al más antiguo
            if not line.strip():
                continue
            try:
                log = json.loads(line)
                timestamp = log.get("timestamp")
                if timestamp:
                    fecha_log = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    if fecha_log.date() == fecha_objetivo.date():
                        logs_filtrados.append(log)
            except Exception:
                continue

        # paginar los logs ya filtrados
        start = (page - 1) * limit
        end = start + limit
        selected_logs = logs_filtrados[start:end]

        return {
            "page": page,
            "limit": limit,
            "total": len(logs_filtrados),
            "logs": selected_logs
        }
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
async def list_rules(file: Optional[str] = Query(None, description="Nombre del archivo de reglas")):
    """
    Devuelve las reglas de un archivo específico o lista los nombres disponibles.
    Ejemplo: /rules?file=sml.rules
    """
    try:
        if file:
            file_path = os.path.join(RULES_DIR, file)
            if not os.path.exists(file_path):
                return {"error": f"El archivo {file} no existe en {RULES_DIR}"}
            with open(file_path, "r") as f:
                rules = f.readlines()
            return {
                "file": file,
                "rules": rules
            }
        else:
            # Si no se pasa archivo, devolver listado de archivos .rules disponibles
            files = [f for f in os.listdir(RULES_DIR) if f.endswith(".rules")]
            return {
                "available_rule_files": files,
                "message": "Usa /rules?file=nombre.rules para ver el contenido."
            }
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

@router.get("/csv-preview")
async def preview_csv():
    """Devuelve las primeras filas del archivo Suricata_preprocessed.csv."""
    csv_path = "Suricata_preprocessed.csv"
    if not os.path.exists(csv_path):
        return {"error": "El archivo CSV no existe"}
    
    try:
        df = pd.read_csv(csv_path)
        return df.head(50).to_dict(orient="records")  # Solo las primeras 50 filas
    except Exception as e:
        return {"error": str(e)}


@router.get("/log-watcher-status")
async def log_status():
    """Muestra las últimas líneas del log_watcher.log si existe."""
    log_path = "log_watcher.log"
    if not os.path.exists(log_path):
        return {"error": "No se encontró log_watcher.log"}
    
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()[-20:]  # Últimas 20 líneas
        return {"log": lines}
    except Exception as e:
        return {"error": str(e)}
