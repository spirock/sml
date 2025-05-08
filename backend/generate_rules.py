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
    print(f"[GR] ❌ No se encontró el modelo {MODEL_PATH}. Asegúrate de entrenarlo antes.")
    exit(1)

model = joblib.load(MODEL_PATH)

# 📂 Verificar que los datos preprocesados existen
if not os.path.exists(DATA_PATH):
    print(f"[GR] ❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutarlo antes.")
    exit(1)

df_processed = pd.read_csv(DATA_PATH)

# 🧪 Validar datos
if df_processed.empty:
    print("[GR] ❌ Error: No hay datos para predecir reglas de Suricata.")
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
    print(f"[GR] ❌ El modelo espera {expected_features} columnas, pero los datos tienen {df_numeric.shape[1]}.")
    print(f"[GR] 📝 Columnas entregadas: {df_numeric.columns.tolist()}")
    exit(1)

# 🔍 Ejecutar predicción
print("[GR] 🔍 Ejecutando predicciones con Isolation Forest...")
df_processed["prediction"] = model.predict(df_numeric)

# 📥 Obtener eventos desde MongoDB
async def fetch_latest_events():
    collection = db["events"]
    cursor = collection.find({}, {"_id": 0}).limit(100)
    return await cursor.to_list(length=100)

def rule_exists_in_file(rule_content, filename):
    """Verifica si una regla ya existe en el archivo"""
    if not os.path.exists(filename):
        return False
    with open(filename, 'r') as f:
        existing_rules = f.read().splitlines()
    return rule_content in existing_rules

async def generate_suricata_rules():
    events = await fetch_latest_events()
    df_events = pd.DataFrame(events)

    if df_events.empty:
        print("[GR] ⚠ No hay eventos recientes para analizar.")
        return

    # 📊 Columnas necesarias
    required_columns = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity"]
    missing_columns = [col for col in required_columns if col not in df_events.columns]
    if missing_columns:
        print(f"[GR] ❌ Error: Faltan columnas necesarias: {missing_columns}")
        return

    # Preprocesamiento para predicción
    df_processed_events = df_events[required_columns].copy()
    df_processed_events["proto"] = df_processed_events["proto"].astype("category").cat.codes
    for col in df_processed_events.columns:
        df_processed_events[col] = pd.to_numeric(df_processed_events[col], errors="coerce")
    df_processed_events.fillna(0, inplace=True)

    df_numeric_events = df_processed_events.select_dtypes(include=[np.number])

    # Alinear índices
    df_numeric_events = df_numeric_events.reset_index(drop=True)
    df_events = df_events.reset_index(drop=True)

    # Validar dimensiones
    if df_numeric_events.shape[1] != model.n_features_in_:
        print(f"[GR] ❌ El modelo espera {model.n_features_in_} columnas, pero recibió {df_numeric_events.shape[1]}.")
        print(f"[GR] 📝 Columnas entregadas: {df_numeric_events.columns.tolist()}")
        return

    # Predecir anomalías + scores
    print("[GR] 🔍 Analizando eventos recientes para anomalías...")
    scores = model.decision_function(df_numeric_events)
    predictions = model.predict(df_numeric_events)

    df_events["anomaly_score"] = scores
    df_events["prediction"] = predictions

    anomalies = df_events[df_events["prediction"] == -1]

    # Cargar reglas existentes para evitar duplicados
    existing_rules = set()
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            existing_rules = set(line.strip() for line in f if line.strip())

    # Generar nuevas reglas
    rules_set = set()
    new_rules = []

    for _, event in anomalies.iterrows():
        if pd.notna(event["src_ip"]) and pd.notna(event["dest_ip"]):
            # Determinar acción basada en el score
            score = event.get("anomaly_score", 0)
            if score <= -0.2:
                action = "drop"
                msg = "BLOCKED traffic (high risk)"
            else:
                action = "alert"
                msg = "Suspicious traffic (alert only)"
            
            # Generar identificador único para la regla
            rule_id = f"{event['src_ip']}-{event['dest_ip']}-{action}-{msg}"
            sid = 1000000 + (abs(hash(rule_id)) % 900000 ) # SIDs entre 1,000,000 y 1,999,999
            
            # Construir contenido de la regla
            rule_content = f'{action} ip {event["src_ip"]} any -> {event["dest_ip"]} any (msg:"{msg}"; sid:{sid}; rev:1;)'
            
            # Verificar si la regla es nueva
            if rule_content not in rules_set and rule_content not in existing_rules:
                new_rules.append(rule_content)
                rules_set.add(rule_content)

    # Guardar reglas (modo append para no perder las existentes)
    if new_rules:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
        with open(RULES_FILE, 'a') as file:
            for rule in new_rules:
                file.write(rule.strip() + "\n")
        print(f"[GR] ✅ {len(new_rules)} nuevas reglas añadidas a {RULES_FILE}.")
    else:
        print("[GR] No se detectaron anomalías nuevas o todas ya estaban registradas.")


# 🚀 Ejecutar
if __name__ == "__main__":
    try:
        asyncio.run(generate_suricata_rules())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(generate_suricata_rules())
