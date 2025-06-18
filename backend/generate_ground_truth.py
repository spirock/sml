import pandas as pd
from db_connection import db
from datetime import datetime
import os
import asyncio

GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"

async def generate_ground_truth_from_mongo():
    """
    Extrae eventos de MongoDB marcados como normal o anomalía durante modo entrenamiento y los guarda en un CSV.
    Añade campos de predicción simulada y etiqueta tipo.
    """
    collection = db["events"]
    #config = await db["config"].find_one({"_id": "mode"})
    #if not config or not config.get("value", False):
    #    print("🚫 El modo entrenamiento no está activo. No se generará ground_truth.")
    #    return

    print("🔍 Extrayendo eventos del modo entrenamiento (normal o anomaly)...")

        # Obtener sesiones disponibles
    sessions = await collection.distinct("training_session", {"training_mode": True})
    if not sessions:
        print("⚠ No se encontraron sesiones de entrenamiento activas.")
        return

    print("🔢 Selecciona una sesión de entrenamiento para generar el ground_truth:")
    for idx, sess in enumerate(sessions):
        print(f"{idx + 1}. {sess}")
    
    try:
        choice = int(input("Selecciona una opción (número): "))
        selected_session = sessions[choice - 1]
    except (ValueError, IndexError):
        print("❌ Opción inválida.")
        return

    print(f"🔍 Extrayendo eventos de la sesión: {selected_session}")

    query = {
        "training_mode": True,
        "training_session": selected_session
    }
    projection = {
        "timestamp": 1,
        "src_ip": 1,
        "dest_ip": 1,
        "proto": 1,
        "src_port": 1,
        "dest_port": 1,
        "alert_severity": 1,
        "packet_length": 1,
        "hour": 1,
        "is_night": 1,
        "ports_used": 1,
        "conn_per_ip": 1,
        "training_label": 1
    }

    cursor = collection.find(query, projection)
    events = await cursor.to_list(length=None)
    if not events:
        print("⚠ No se encontraron eventos etiquetados como entrenamiento.")
        return

    df = pd.DataFrame(events)
    df["event_id"] = df["_id"].astype(str)
    df = df.drop(columns=["_id"])  # Elimina la columna _id
    
    def assign_anomaly_score(label):
        # Asigna un puntaje negativo para anomalías y 0 para normales
        return -1.0 if label == "anomaly" else 0

    def prediction(label):
        return 1 if label == "anomaly" else 0

    df["anomaly_score_g"] = df["training_label"].apply(assign_anomaly_score)
    df["prediction_g"] = df["training_label"].apply(prediction)

    os.makedirs(os.path.dirname(GROUND_TRUTH_PATH), exist_ok=True)
    try:
        df.to_csv(GROUND_TRUTH_PATH, index=False)
        print(f"✅ Ground truth guardado en {GROUND_TRUTH_PATH} con {len(df)} eventos.")
        print(df.head(5))
    except Exception as e:
        print(f"❌ Error al guardar el archivo: {e}")

if __name__ == "__main__":
    asyncio.run(generate_ground_truth_from_mongo())