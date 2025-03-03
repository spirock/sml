import json
import asyncio
import time
from db_connection import db  # Importar la conexión a MongoDB

# Ruta del log de Suricata
LOG_FILE = "/var/log/suricata/eve.json"


async def read_last_event():
    """Lee el último evento de eve.json, si existe."""
    try:
        with open(LOG_FILE, "r") as file:
            lines = file.readlines()
            if lines:
                return json.loads(lines[-1])  # Devuelve el último evento
    except FileNotFoundError:
        print("⚠ Archivo eve.json no encontrado.")
    except json.JSONDecodeError as e:
        print(f"⚠ Error al decodificar JSON: {e}")
    return None

async def insert_event(collection, event_data):
    """Inserta un evento en MongoDB."""
    try:
        collection = db["events"]
        await collection.insert_one(event_data)
        print(f"✅ Evento insertado en MongoDB: {event_data}")
    except Exception as e:
        print(f"⚠ Error al insertar en MongoDB: {e}")

async def main():
    """Bucle principal para monitorear eve.json e insertar eventos en MongoDB."""
    print("🚀 Iniciando monitoreo de Suricata...")
    await db.list_collection_names()  # Asegurar conexión inicial
    collection = db["events"]  # 🔹 Definir la colección aquí
    last_timestamp = None
    while True:
        print("🔁 Revisando el archivo eve.json...", flush=True)
        event = await read_last_event()
        if event and event.get("event_type") == "alert":
            # Verificar si el evento es nuevo
            if event.get("timestamp") != last_timestamp:
                last_timestamp = event.get("timestamp")

                # Extraer campos relevantes
                event_data = {
                    "src_ip": event.get("src_ip", "0.0.0.0"),
                    "dest_ip": event.get("dest_ip", "0.0.0.0"),
                    "proto": event.get("proto", "UNKNOWN"),
                    "src_port": event.get("src_port", 0),
                    "dest_port": event.get("dest_port", 0),
                    "alert.severity": event.get("alert", {}).get("severity", 0),
                    "alert.signature": event.get("alert", {}).get("signature", "Sin firma"),
                    "timestamp": event.get("timestamp", "Desconocido")
                }
                await insert_event(collection,event_data)
        else:
            print("⚠ Evento ignorado (no es una alerta).")

        await asyncio.sleep(5)  # Espera 5 segundos antes de volver a comprobar



if __name__ == "__main__":
    asyncio.run(main())
