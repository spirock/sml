

import pandas as pd
from db_connection import db
from datetime import datetime
import os

GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"

def generate_ground_truth_from_mongo():
    """
    Extrae eventos de MongoDB marcados como anomalía durante modo entrenamiento y los guarda en un CSV.
    """
    collection = db["events"]
    config = db["config"].find_one({"_id": "mode"})
    if not config or not config.get("training_mode", False):
        print("🚫 El modo entrenamiento no está activo. No se generará ground_truth.")
        return

    print("🔍 Extrayendo eventos anómalos durante modo entrenamiento...")

    query = {"prediction": -1}
    projection = {
        "_id": 0,
        "timestamp": 1,
        "src_ip": 1,
        "dest_ip": 1,
        "anomaly_score": 1
    }

    events = list(collection.find(query, projection))
    if not events:
        print("⚠ No se encontraron eventos anómalos.")
        return

    df = pd.DataFrame(events)
    df["description"] = "Anomalía detectada durante entrenamiento"
    df["label"] = "anomaly"

    os.makedirs(os.path.dirname(GROUND_TRUTH_PATH), exist_ok=True)
    df.to_csv(GROUND_TRUTH_PATH, index=False)
    print(f"✅ Ground truth guardado en {GROUND_TRUTH_PATH} con {len(df)} eventos.")

if __name__ == "__main__":
    generate_ground_truth_from_mongo()