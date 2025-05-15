from motor.motor_asyncio import AsyncIOMotorClient
import pandas as pd
import numpy as np
import asyncio
from db_connection import db  # Importar la conexión a MongoDB
COLLECTION_NAME = "events"



async def fetch_suricata_data():
    collection = db[COLLECTION_NAME]
    
    cursor = collection.find({}, {"_id": 0})  # Excluir _id para evitar problemas
    events = await cursor.to_list(length=1000)  # Tomar hasta 1000 eventos
    

    
    print(f"[ML]Se encontraron {len(events)} eventos en MongoDB.")
    return events

def ip_to_int(ip):
    """Convierte una dirección IP en formato string a un número entero."""
    try:
        if isinstance(ip, str) and ip.count('.') == 3:  # Verifica que sea una IP válida
            return sum([int(num) << (8 * i) for i, num in enumerate(reversed(ip.split('.')))])
        else:
            print(f"[ML] ⚠ Advertencia: IP inválida detectada -> {ip}")
            return 0  # Asignar 0 si la IP es inválida
    except ValueError:
        print(f"[ML] ⚠ Error: No se pudo convertir la IP -> {ip}")
        return 0
    
def preprocess_data(events):
    df = pd.DataFrame(events)

    if df.empty:
        print("[ML] ⚠ No se encontraron datos en la base de datos. No se generará suricata_preprocessed.csv.")
        return None

    print("[ML] Procesando los datos de Suricata...")

    # Seleccionar características clave (ajusta según los datos disponibles)
    selected_columns = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity","packet_length"]

    # Verificar si las columnas existen antes de seleccionarlas
    missing_columns = [col for col in selected_columns if col not in df.columns]
    if missing_columns:
        print(f"[ML] ⚠ Falta(n) las siguientes columnas en los datos de MongoDB: {missing_columns}")
        return None

    df = df[selected_columns].copy()

    # Convertir direcciones IP a valores numéricos usando ip_to_int()
    df["src_ip"] = df["src_ip"].apply(ip_to_int)
    df["dest_ip"] = df["dest_ip"].apply(ip_to_int)

    # Reemplazar valores categóricos del protocolo
    df["proto"] = df["proto"].astype("category").cat.codes

    # Normalizar datos numéricos (evita dividir por 0 si todos los valores son iguales)
    df = (df - df.min()) / (df.max() - df.min()).replace(0, 1)

    return df

async def main():
    events = await fetch_suricata_data()
    df = preprocess_data(events)

    if df is not None:
        df.to_csv("/app/models/suricata_preprocessed.csv", index=False)  # Guardar datos procesados
        print("[ML] ✅ Datos preprocesados guardados en suricata_preprocessed.csv")
    else:
        print("[ML] ⚠ No se generó ningún archivo CSV.")

if __name__ == "__main__":
    asyncio.run(main())
