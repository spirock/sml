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
from db_connection import db

LOG_FILE = "/var/log/suricata/eve.json"


def hash_event(event):
    """Genera un hash único para el evento"""
    key = f"{event.get('timestamp')}|{event.get('src_ip')}|{event.get('dest_ip')}|{event.get('alert', {}).get('signature')}"
    return hashlib.sha256(key.encode()).hexdigest()


async def insert_event_if_new(collection, event_data):
    """Inserta el evento solo si no existe (por hash)"""
    event_hash = hash_event(event_data)
    existing = await collection.find_one({"event_hash": event_hash})
    if not existing:
        event_data["event_hash"] = event_hash
        event_data["processed"] = False
        await collection.insert_one(event_data)
        print(f"[SM] ✅ Evento insertado: {event_data['alert_signature']}")
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


async def main():
    print("[SM] 🚀 Iniciando monitoreo continuo de Suricata...")
    await db.list_collection_names()  # Confirma la conexión
    collection = db["events"]
    config_collection = db["config"]

    async for event in monitor_log_file():
        config = await config_collection.find_one({"_id": "mode"})
        is_training = config and config.get("value", False)
        training_label = config.get("label") if is_training else "unknown"

        # Definir comportamiento según modo entrenamiento
        if is_training:
            # En modo entrenamiento aceptamos todos los tipos de eventos
            pass
        else:
            # Si no está en modo entrenamiento, solo aceptar eventos tipo "alert"
            if event.get("event_type") != "alert":
                print("[SM] ℹ️ Evento ignorado (no es 'alert' y no estamos en entrenamiento)")
                continue

        # Preparar datos del evento
        event_data = {
            "src_ip": event.get("src_ip", "0.0.0.0"),
            "dest_ip": event.get("dest_ip", "0.0.0.0"),
            "proto": event.get("proto", "UNKNOWN"),
            "src_port": event.get("src_port", 0),
            "dest_port": event.get("dest_port", 0),
            "alert_severity": event.get("alert", {}).get("severity", 0),
            "alert_signature": event.get("alert", {}).get("signature", "Sin firma"),
            "packet_length": event.get("packet", {}).get("length", 0),
            "timestamp": event.get("timestamp", "Desconocido"),
            "event_type": event.get("event_type"),
            "training_mode": is_training,
            "training_label": training_label
        }



        await insert_event_if_new(collection, event_data)


if __name__ == "__main__":
    asyncio.run(main())
