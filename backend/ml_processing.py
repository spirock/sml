from motor.motor_asyncio import AsyncIOMotorClient
import pandas as pd
import numpy as np
import asyncio

# Conexión a MongoDB
MONGO_URI = "mongodb://user:password@database:27017"
DB_NAME = "suricata"
COLLECTION_NAME = "events"

async def fetch_suricata_data():
    print("Conectando a MongoDB...")
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    cursor = collection.find({}, {"_id": 0})  # Excluir _id para evitar problemas
    events = await cursor.to_list(length=1000)  # Tomar hasta 1000 eventos
    
    client.close()
    
    print(f"Se encontraron {len(events)} eventos en MongoDB.")
    return events

def preprocess_data(events):
    df = pd.DataFrame(events)

    if df.empty:
        print("⚠ No se encontraron datos en la base de datos. No se generará suricata_preprocessed.csv.")
        return None

    print("Procesando los datos de Suricata...")

    # Seleccionar características clave (ajusta según los datos disponibles)
    selected_columns = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity"]

    # Verificar si las columnas existen antes de seleccionarlas
    missing_columns = [col for col in selected_columns if col not in df.columns]
    if missing_columns:
        print(f"⚠ Falta(n) las siguientes columnas en los datos de MongoDB: {missing_columns}")
        return None

    df = df[selected_columns].copy()

    # Convertir direcciones IP a valores numéricos
    df["src_ip"] = df["src_ip"].apply(lambda x: sum([int(num) << (8 * i) for i, num in enumerate(reversed(x.split('.')))]))
    df["dest_ip"] = df["dest_ip"].apply(lambda x: sum([int(num) << (8 * i) for i, num in enumerate(reversed(x.split('.')))]))

    # Reemplazar valores categóricos del protocolo
    df["proto"] = df["proto"].astype("category").cat.codes

    # Normalizar datos numéricos
    df = (df - df.min()) / (df.max() - df.min())

    return df

async def main():
    events = await fetch_suricata_data()
    df = preprocess_data(events)

    if df is not None:
        df.to_csv("suricata_preprocessed.csv", index=False)  # Guardar datos procesados
        print("✅ Datos preprocesados guardados en suricata_preprocessed.csv")
    else:
        print("⚠ No se generó ningún archivo CSV.")

if __name__ == "__main__":
    asyncio.run(main())
