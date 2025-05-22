import pandas as pd
from db_connection import db
from datetime import datetime
import os
import asyncio

GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"

async def generate_ground_truth_from_mongo():
    """
    Extrae eventos de MongoDB marcados como anomalía durante modo entrenamiento y los guarda en un CSV.
    """
    collection = db["events"]
    config = await db["config"].find_one({"_id": "mode"})
    if not config or not config.get("value", False):
        print("🚫 El modo entrenamiento no está activo. No se generará ground_truth.")
        return

    print("🔍 Extrayendo eventos del modo entrenamiento (normal o anomaly)...")

    training_label = config.get("label", None)
    if training_label not in ["normal", "anomaly"]:
        print("⚠ La configuración no contiene 'training_label' válido (normal o anomaly).")
        return

    query = {"training_mode": True}
    projection = {
        "_id": 0,
        "timestamp": 1,
        "src_ip": 1,
        "dest_ip": 1
    }

    events = list(collection.find(query, projection))
    if not events:
        print("⚠ No se encontraron eventos anómalos.")
        return

    df = pd.DataFrame(events)
    if training_label == "anomaly":
        df["prediction"] = -1
        df["anomaly_score"] = 1.0
    elif training_label == "normal":
        df["prediction"] = 0
        df["anomaly_score"] = -1.0
    df["label"] = training_label

    os.makedirs(os.path.dirname(GROUND_TRUTH_PATH), exist_ok=True)
    df.to_csv(GROUND_TRUTH_PATH, index=False)
    print(f"✅ Ground truth guardado en {GROUND_TRUTH_PATH} con {len(df)} eventos.")

if __name__ == "__main__":
    asyncio.run(generate_ground_truth_from_mongo())