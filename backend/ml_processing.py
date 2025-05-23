"""
📁 ml_processing.py

Este script se encarga de preprocesar los eventos de red almacenados en MongoDB (colección 'events')
generados por Suricata. Extrae los datos, los transforma en un formato adecuado para el entrenamiento
de modelos de Machine Learning, y los guarda en un archivo CSV ('suricata_preprocessed.csv').

Funcionalidades principales:
- Convierte direcciones IP en enteros.
- Codifica protocolos.
- Calcula nuevas features como hora del evento, si es de noche, número de puertos únicos y conexiones por IP.
- Normaliza los datos.
- Prepara el dataset de entrada para el modelo de detección de anomalías.

Este preprocesamiento es fundamental para que el modelo de aprendizaje automático pueda aprender patrones
de tráfico normal y detectar anomalías de manera efectiva.
"""
from motor.motor_asyncio import AsyncIOMotorClient
import pandas as pd
import numpy as np
import asyncio
from db_connection import db  # Importar la conexión a MongoDB
import hashlib
COLLECTION_NAME = "events"



async def fetch_suricata_data():
    collection = db[COLLECTION_NAME]
    
    cursor = collection.find({}, {"_id": 0})  # Excluir _id para evitar problemas
    events = await cursor.to_list(length=1000)  # Tomar hasta 1000 eventos
    #print(events)
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

    # Enriquecer con nuevas features
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["timestamp"].dt.hour.fillna(0)
        df["is_night"] = df["hour"].apply(lambda h: 1 if h < 7 or h > 20 else 0)

        def generar_event_id(row):
            base = f"{row['src_ip']}_{row['dest_ip']}_{row['timestamp']}"
            return hashlib.md5(base.encode()).hexdigest()

        df["event_id"] = df.apply(generar_event_id, axis=1)
    else:
        df["hour"] = 0
        df["is_night"] = 0

    df["ports_used"] = df.groupby("src_ip")["dest_port"].transform("nunique")
    df["conn_per_ip"] = df.groupby("src_ip")["dest_ip"].transform("count")

    # Añadir columna 'anomaly' basado en training_mode y training_label
    def label_anomaly(row):
        if row.get("training_mode") == True:
            label = row.get("training_label")
            if label == "normal":
                return 0
            elif label == "anomaly":
                return 1
        return -1

    df["anomaly"] = df.apply(label_anomaly, axis=1)

    selected_columns = [
        "src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert_severity",
        "packet_length", "hour", "is_night", "ports_used", "conn_per_ip", "anomaly", "event_id"
    ]

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

    # Normalizar solo las columnas numéricas
    df = df.drop(columns=["timestamp"], errors="ignore")
    # Seleccionar columnas numéricas para normalizar
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df_numeric = df[numeric_cols]
    df_normalized = (df_numeric - df_numeric.min()) / (df_numeric.max() - df_numeric.min()).replace(0, 1)

    # Combinar con columnas no numéricas (por ejemplo event_id si existe)
    df = pd.concat([df_normalized, df.drop(columns=numeric_cols)], axis=1)

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
