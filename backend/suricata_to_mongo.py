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
        print(f"[SM] ✅ Evento insertado: {event_data['alert.signature']}")
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

    async for event in monitor_log_file():
        if event.get("event_type") == "alert":
            event_data = {
                "src_ip": event.get("src_ip", "0.0.0.0"),
                "dest_ip": event.get("dest_ip", "0.0.0.0"),
                "proto": event.get("proto", "UNKNOWN"),
                "src_port": event.get("src_port", 0),
                "dest_port": event.get("dest_port", 0),
                "alert.severity": event.get("alert", {}).get("severity", 0),
                "alert.signature": event.get("alert", {}).get("signature", "Sin firma"),
                "packet_length": event.get("packet", {}).get("length", 0),  # ⬅️ este es vital
                "timestamp": event.get("timestamp", "Desconocido")
            }
            await insert_event_if_new(collection, event_data)
        else:
            print("[SM] ℹ️ Evento ignorado (no es alerta)")


if __name__ == "__main__":
    asyncio.run(main())
