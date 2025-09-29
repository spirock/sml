"""
suricata_to_mongo.py

📌 Objetivo:
Este módulo se encarga de leer en tiempo real el archivo de logs `eve.json` generado por Suricata y almacenar en MongoDB únicamente los eventos relevantes.

🧠 Comportamiento:
- En modo entrenamiento (training_mode=True), guarda todos los eventos sin filtrar (se clasifican como 'normal' o 'anomaly' según configuración).
- Fuera de modo entrenamiento, solo almacena eventos tipo 'alert' para análisis y generación de reglas.
- Cada evento se identifica mediante un hash único para evitar duplicados.
- Añade campos `training_mode` y `training_label` para poder distinguir los datos en fases posteriores del sistema.

🔗 Dependencias:
- MongoDB vía `db_connection.py`
- Archivo `eve.json` como fuente de eventos generados por Suricata.

🧪 Uso:
Este script se ejecuta como parte del backend y puede iniciarse automáticamente desde un entrypoint para mantener la base de datos actualizada en tiempo real.

"""
import json
import asyncio
import hashlib
import aiofiles
import datetime as dt
from typing import Tuple
from db_connection import db
from constants import LABEL_NORMAL, LABEL_ANOMALY

LOG_FILE = "/var/log/suricata/eve.json"


def hash_event(event):
    """Genera un hash único para el evento usando campos robustos"""
    parts = [
        str(event.get('event_type')),
        str(event.get('timestamp')),
        str(event.get('src_ip')),
        str(event.get('dest_ip')),
        str(event.get('proto')),
        str(event.get('src_port')),
        str(event.get('dest_port')),
        str(event.get('flow_id')),
        str(event.get('alert', {}).get('signature')),
        # señales de capa app si existen
        str(event.get('dns', {}).get('rrname')),
        str(event.get('tls', {}).get('sni')),
        str(event.get('http', {}).get('hostname')),
        str(event.get('http', {}).get('url')),
    ]
    key = "|".join(parts)
    return hashlib.sha256(key.encode()).hexdigest()


async def insert_event_if_new(collection, event_data):
    """Inserta el evento solo si no existe (por hash)"""
    event_hash = hash_event(event_data)
    existing = await collection.find_one({"event_hash": event_hash})
    if not existing:
        event_data["event_hash"] = event_hash
        event_data["processed"] = False
        await collection.insert_one(event_data)
        print(f"[SM] ✅ Evento insertado: {event_data.get('alert_signature','(sin firma)')}")
    else:
        print("[SM] 🔁 Evento duplicado ignorado")


async def monitor_log_file():
    """Monitorea nuevas líneas en eve.json de forma continua."""
    try:
        async with aiofiles.open(LOG_FILE, 'r') as f:
            await f.seek(0, 2)  # Ir al final del archivo
            while True:
                line = await f.readline()
                if not line:
                    await asyncio.sleep(1)
                    continue
                try:
                    event = json.loads(line)
                    yield event
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[SM] ❌ Error leyendo eve.json: {e}")


async def read_mode(config_collection) -> Tuple[bool, str, str]:
    """Lee el modo desde db.config(_id="mode").
    Compatibilidad:
      - {"mode": "normal"|"anomaly"|"off"}
      - {"value": bool, "label": "normal"|"anomaly"}
    Devuelve: (is_training, training_label, session_hash)
    Si está en entrenamiento y no hay session_hash, crea uno y lo persiste.
    """
    doc = await config_collection.find_one({"_id": "mode"})
    is_training = False
    label = "unknown"
    session_hash = None

    if doc:
        mode = str(doc.get("mode", "")).lower().strip()
        if mode in {"normal", "anomaly"}:
            is_training = True
            label = mode
        elif mode == "off":
            is_training = False
        else:
            # compatibilidad con esquema antiguo
            is_training = bool(doc.get("value", False))
            label = str(doc.get("label", label)).lower().strip() if is_training else label

        session_hash = doc.get("session_hash") if is_training else None
        if is_training and not session_hash:
            session_hash = f"{label}-{dt.datetime.utcnow().strftime('%Y%m%d-%H%M')}"
            await config_collection.update_one({"_id": "mode"}, {"$set": {"session_hash": session_hash}}, upsert=True)

    return is_training, label, session_hash


async def main():
    print("[SM] 🚀 Iniciando monitoreo continuo de Suricata...")
    await db.list_collection_names()  # Confirma la conexión
    collection = db["events"]
    config_collection = db["config"]

    async for event in monitor_log_file():
        is_training, training_label, session_hash = await read_mode(config_collection)

        # Definir comportamiento según modo entrenamiento
        if is_training:
            if event.get("event_type") not in ["flow", "http", "dns", "tls", "alert"]:
                print(f"[SM] ℹ️ Evento ignorado (no es relevante para entrenamiento): {event.get('event_type')}")
                continue
            event["anomaly"] = 0  # marcar explícitamente como tráfico normal
        else:
            # Si no está en modo entrenamiento, solo aceptar eventos tipo "alert"
            if event.get("event_type") != "alert":
                print("[SM] ℹ️ Evento ignorado (no es 'alert' y no estamos en entrenamiento)")
                continue

        # Preparar datos del evento
        event_data = {
            # red y transporte
            "event_type": event.get("event_type"),
            "timestamp": event.get("timestamp", "Desconocido"),
            "flow_id": event.get("flow_id"),
            "proto": str(event.get("proto", "UNKNOWN")).upper(),
            "src_ip": event.get("src_ip", "0.0.0.0"),
            "src_port": event.get("src_port", 0),
            "dest_ip": event.get("dest_ip", "0.0.0.0"),
            "dest_port": event.get("dest_port", 0),
            "packet_length": event.get("packet", {}).get("length", 0),

            # alertas y severidad
            "alert_severity": event.get("alert", {}).get("severity", 0),
            "alert_signature": event.get("alert", {}).get("signature", "Sin firma"),

            # capa aplicación (para reglas/ML posteriores)
            "dns_query": event.get("dns", {}).get("rrname"),
            "tls_sni": event.get("tls", {}).get("sni"),
            "http_hostname": event.get("http", {}).get("hostname"),
            "http_url": event.get("http", {}).get("url"),
            "file_magic": event.get("fileinfo", {}).get("magic"),
            "file_mime": event.get("fileinfo", {}).get("mime_type"),

            # modo/entrenamiento
            "training_mode": is_training,
            "training_label": training_label if is_training else "unknown",
            "training_session": session_hash if is_training else None,
            "anomaly": 1 if training_label == "anomaly" else 0,
        }



        await insert_event_if_new(collection, event_data)


if __name__ == "__main__":
    asyncio.run(main())
