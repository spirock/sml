import joblib
import pandas as pd
from db_connection import db

# Ruta donde se guardan las reglas de Suricata
RULES_FILE = "./suricata/rules/sml.rules"

# Cargar modelo de Machine Learning
MODEL_PATH = "isolation_forest_model.pkl"
model = joblib.load(MODEL_PATH)

async def fetch_latest_events():
    """Obtiene los eventos más recientes de MongoDB."""
    collection = db["events"]
    cursor = collection.find({}, {"_id": 0}).limit(100)
    return await cursor.to_list(length=100)

async def generate_suricata_rules():
    """Genera reglas Suricata basadas en eventos anómalos detectados."""
    events = await fetch_latest_events()
    df = pd.DataFrame(events)

    if df.empty:
        print("⚠ No hay eventos recientes para analizar.")
        return

    # Preprocesar datos para que coincidan con el entrenamiento
    df_processed = df[["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity"]].copy()
    df_processed["proto"] = df_processed["proto"].astype("category").cat.codes

    # Predecir anomalías
    df["prediction"] = model.predict(df_processed)
    anomalies = df[df["prediction"] == -1]  # -1 indica anomalía

    rules = []
    for _, event in anomalies.iterrows():
        rule = f"alert {event['proto']} {event['src_ip']} any -> {event['dest_ip']} any (msg:\"Anomalous traffic detected\"; sid:{hash(event['src_ip'] + event['dest_ip']) % 100000}; rev:1;)"
        rules.append(rule)
    
    if rules:
        with open(RULES_FILE, "a") as file:
            file.write("\n".join(rules) + "\n")
        print(f"✅ {len(rules)} reglas generadas y guardadas en {RULES_FILE}.")
    else:
        print("⚠ No se detectaron anomalías.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(generate_suricata_rules())
