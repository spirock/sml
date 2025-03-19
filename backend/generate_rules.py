import joblib
import pandas as pd
from db_connection import db
import os
import asyncio
import ipaddress
import numpy as np

# 📌 Rutas importantes
RULES_FILE = "/var/lib/suricata/rules/sml.rules"
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_PATH = "/app/models/isolation_forest_model.pkl"

# 📂 Verificar modelo entrenado
if not os.path.exists(MODEL_PATH):
    print(f"❌ No se encontró el modelo {MODEL_PATH}. Asegúrate de entrenarlo antes.")
    exit(1)

model = joblib.load(MODEL_PATH)

# 📂 Verificar que los datos preprocesados existen
if not os.path.exists(DATA_PATH):
    print(f"❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutarlo antes.")
    exit(1)

df_processed = pd.read_csv(DATA_PATH)

# 🧪 Validar datos
if df_processed.empty:
    print("❌ Error: No hay datos para predecir reglas de Suricata.")
    exit(1)

# 📌 Convertir IPs a enteros
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0

if "src_ip" in df_processed.columns:
    df_processed["src_ip"] = df_processed["src_ip"].astype(str).apply(ip_to_int)
if "dest_ip" in df_processed.columns:
    df_processed["dest_ip"] = df_processed["dest_ip"].astype(str).apply(ip_to_int)

# Convertir columnas a numérico y limpiar NaN
for col in df_processed.columns:
    df_processed[col] = pd.to_numeric(df_processed[col], errors="coerce")
df_processed.fillna(0, inplace=True)

# ✅ Solo columnas numéricas para el modelo
df_numeric = df_processed.select_dtypes(include=[np.number])

# Verificar dimensiones
expected_features = model.n_features_in_
if df_numeric.shape[1] != expected_features:
    print(f"❌ El modelo espera {expected_features} columnas, pero los datos tienen {df_numeric.shape[1]}.")
    print(f"📝 Columnas entregadas: {df_numeric.columns.tolist()}")
    exit(1)

# 🔍 Ejecutar predicción
print("🔍 Ejecutando predicciones con Isolation Forest...")
df_processed["prediction"] = model.predict(df_numeric)

# 📥 Obtener eventos desde MongoDB
async def fetch_latest_events():
    collection = db["events"]
    cursor = collection.find({}, {"_id": 0}).limit(100)
    return await cursor.to_list(length=100)

# 🧠 Generar reglas Suricata desde tráfico anómalo
async def generate_suricata_rules():
    events = await fetch_latest_events()
    df_events = pd.DataFrame(events)

    if df_events.empty:
        print("⚠ No hay eventos recientes para analizar.")
        return

    # 📊 Columnas necesarias
    required_columns = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity"]
    missing_columns = [col for col in required_columns if col not in df_events.columns]
    if missing_columns:
        print(f"❌ Error: Faltan columnas necesarias: {missing_columns}")
        return

    # Preprocesamiento para predicción
    df_processed_events = df_events[required_columns].copy()
    df_processed_events["proto"] = df_processed_events["proto"].astype("category").cat.codes
    for col in df_processed_events.columns:
        df_processed_events[col] = pd.to_numeric(df_processed_events[col], errors="coerce")
    df_processed_events.fillna(0, inplace=True)

    # Validar dimensiones para predicción
    df_numeric_events = df_processed_events.select_dtypes(include=[np.number])
    if df_numeric_events.shape[1] != model.n_features_in_:
        print(f"❌ El modelo espera {model.n_features_in_} columnas, pero recibió {df_numeric_events.shape[1]}.")
        print(f"📝 Columnas entregadas: {df_numeric_events.columns.tolist()}")
        return

    # Predecir anomalías
    print("🔍 Analizando eventos recientes para anomalías...")
    df_events["prediction"] = model.predict(df_numeric_events)
    anomalies = df_events[df_events["prediction"] == -1]

    # Generar reglas Suricata
    rules = []
    for _, event in anomalies.iterrows():
        if pd.notna(event["src_ip"]) and pd.notna(event["dest_ip"]):
            sid = abs(hash(event["src_ip"] + event["dest_ip"])) % 100000
            rule = f'alert ip {event["src_ip"]} any -> {event["dest_ip"]} any (msg:"Anomalous traffic detected"; sid:{sid}; rev:1;)'
            rules.append(rule)

    # Guardar reglas
    if rules:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, "a") as file:
            file.write("\n".join(rules) + "\n")
        print(f"✅ {len(rules)} reglas generadas y guardadas en {RULES_FILE}.")
    else:
        print("⚠ No se detectaron anomalías.")

# 🚀 Ejecutar
if __name__ == "__main__":
    try:
        asyncio.run(generate_suricata_rules())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(generate_suricata_rules())