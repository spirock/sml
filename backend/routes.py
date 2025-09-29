from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from typing import Optional
import os
import json
import pandas as pd
import joblib
import numpy as np
from db_connection import db
from datetime import datetime
import socket
from hashlib import sha256
import time

from generate_rules import generate_suricata_rules  # 👈 Asegúrate que el nombre y la ruta sean correctos
from constants import IFOREST_MODEL, RULES_FILE, RULES_DIR



router = APIRouter()

LOG_FILE = "/var/log/suricata/eve.json"

@router.post("/generate-rules")
async def generate_rules_endpoint(background_tasks: BackgroundTasks):
    background_tasks.add_task(generate_suricata_rules)
    return {"message": "🚀 Generación de reglas iniciada en segundo plano"}  

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
    

# Cargar el modelo entrenado de forma segura (no fallar si no existe)
MODEL_PATH = IFOREST_MODEL
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("[ROUTER] ✅ Modelo cargado correctamente desde", MODEL_PATH)
    except Exception as e:
        # No queremos que un error al deserializar el modelo haga caer toda la API
        print(f"[ROUTER] ⚠ Error cargando el modelo {MODEL_PATH}: {e}")
else:
    print(f"[ROUTER] ⚠ Modelo no encontrado en {MODEL_PATH}; la API de predicción quedará en modo degradado.")


@router.post("/predict")
async def predict_anomaly(data: dict):
    try:
        # Si el modelo no está cargado, devolver un error 503 claro
        if model is None:
            raise HTTPException(status_code=503, detail="Modelo no cargado. Ejecuta el entrenamiento o carga el modelo antes de usar /predict.")
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


# ===== MODO (unificado) =====
async def _read_mode():
    cfg = await db["config"].find_one({"_id": "mode"}) or {}
    # Nuevo esquema
    mode = str(cfg.get("mode", "")).strip().lower()
    if mode in {"normal", "anomaly", "off"}:
        return {"mode": mode, "session_hash": cfg.get("session_hash")}
    # Compatibilidad con esquema anterior
    if bool(cfg.get("value", False)):
        if str(cfg.get("label", "")).lower() in {"normal", "anomaly"}:
            return {"mode": str(cfg.get("label")).lower(), "session_hash": cfg.get("session_hash")}
    return {"mode": "off", "session_hash": cfg.get("session_hash")}

async def _write_mode(mode: str, new_hash: bool = False):
    mode = str(mode).strip().lower()
    if mode not in {"normal", "anomaly", "off"}:
        raise HTTPException(status_code=400, detail="Modo inválido. Usa normal|anomaly|off")
    cfg = await db["config"].find_one({"_id": "mode"}) or {}
    session_hash = cfg.get("session_hash")
    if mode in {"normal", "anomaly"} and (new_hash or not session_hash):
        session_hash = sha256(f"{mode}-{time.time()}".encode()).hexdigest()[:16]
    update = {"mode": mode}
    if session_hash:
        update["session_hash"] = session_hash
    # Compatibilidad con esquema anterior
    if mode == "off":
        update.update({"value": False, "label": "undefined"})
    else:
        update.update({"value": True, "label": mode})
    await db["config"].update_one({"_id": "mode"}, {"$set": update}, upsert=True)
    return {"mode": mode, "session_hash": session_hash}

@router.get("/mode")
async def get_mode():
    return await _read_mode()

@router.post("/mode")
async def set_mode(payload: dict):
    mode = payload.get("mode")
    new_hash = bool(payload.get("new_hash", False))
    res = await _write_mode(mode, new_hash=new_hash)
    return {"ok": True, **res}

@router.get("/training-mode")
async def get_training_mode():
    m = await _read_mode()
    return {"value": m["mode"] in {"normal", "anomaly"}, "label": m["mode"] if m["mode"] != "off" else "undefined", "session_hash": m.get("session_hash") or "undefined"}


@router.post("/training-mode/on")
async def activate_training_mode(
    label: str = Query(..., description="Tipo de entrenamiento: 'normal' o 'anomaly'"),
    new_hash: bool = Query(False, description="¿Desea generar un nuevo hash de entrenamiento?")
):
    if label not in ["normal", "anomaly"]:
        raise HTTPException(status_code=400, detail="Etiqueta inválida. Usa 'normal' o 'anomaly'")
    res = await _write_mode(label, new_hash=new_hash)
    return {"message": f"Modo entrenamiento activado como '{label}'.", **res}


@router.post("/training-mode/off")
async def deactivate_training_mode():
    res = await _write_mode("off")
    return {"message": "Modo entrenamiento desactivado.", **res}