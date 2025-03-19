import joblib
import pandas as pd
from db_connection import db
import os
import asyncio
import ipaddress  # 📌 Nuevo: Para convertir IPs en valores numéricos

# Ruta donde se guardan las reglas de Suricata
RULES_FILE = "/var/lib/suricata/rules/sml.rules"
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_PATH = "/app/models/isolation_forest_model.pkl"

# Cargar el modelo
if not os.path.exists(MODEL_PATH):
    print(f"❌ No se encontró el modelo {MODEL_PATH}. Asegúrate de entrenarlo antes.")
    exit(1)

model = joblib.load(MODEL_PATH)


# Cargar los datos preprocesados
if not os.path.exists(DATA_PATH):
    print(f"❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutarlo antes.")
    exit(1)

df_processed = pd.read_csv(DATA_PATH)

# 🔍 Validar los datos antes de hacer predicciones
if df_processed.empty:
    print("❌ Error: No hay datos para predecir reglas de Suricata.")
    exit(1)
df_processed.fillna(0, inplace=True)  # Reemplazar NaN con 0
# 📌 Convertir direcciones IP a valores numéricos
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0  # Si la IP no es válida, se reemplaza con 0


df_processed["src_ip"] = df_processed["src_ip"].astype(str).apply(ip_to_int)
df_processed["dest_ip"] = df_processed["dest_ip"].astype(str).apply(ip_to_int)


# Verificar valores NaN
if df_processed.isnull().values.any():
    print("⚠ Advertencia: Se encontraron valores NaN en los datos. Rellenando con ceros.")
    df_processed.fillna(0, inplace=True)




# Asegurar que todas las columnas sean numéricas
for col in df_processed.columns:
    df_processed[col] = pd.to_numeric(df_processed[col], errors="coerce")

# Verificar que las dimensiones sean correctas
expected_features = model.n_features_in_
if df_processed.shape[1] != expected_features:
    print(f"❌ Error: El modelo espera {expected_features} columnas, pero los datos tienen {df_processed.shape[1]}.")
    exit(1)

# Predecir tráfico anómalo
print("🔍 Ejecutando predicciones con Isolation Forest...")
df_processed["prediction"] = model.predict(df_processed)

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
     # Asegurar que las columnas necesarias están presentes
    required_columns = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert.severity"]
    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        print(f"❌ Error: Faltan columnas necesarias en los datos: {missing_columns}")
        return
     # Preprocesamiento de datos
    df_processed = df[required_columns].copy()

    # Convertir `proto` a categoría numérica si es necesario
    if "proto" in df_processed.columns:
        df_processed["proto"] = df_processed["proto"].astype("category").cat.codes

    # Verificar si hay datos suficientes para predecir
    if df_processed.shape[1] != model.n_features_in_:
        print(f"❌ Error: El modelo espera {model.n_features_in_} características, pero se encontraron {df_processed.shape[1]}.")
        return

    # Predecir anomalías
    df["prediction"] = model.predict(df_processed)
    anomalies = df[df["prediction"] == -1]  # -1 indica anomalía

    # Generar reglas de Suricata
    rules = []
    for _, event in anomalies.iterrows():
        if pd.notna(event["src_ip"]) and pd.notna(event["dest_ip"]):
            sid = abs(hash(event["src_ip"] + event["dest_ip"])) % 100000  # Evitar números negativos
            rule = f'alert ip {event["src_ip"]} any -> {event["dest_ip"]} any (msg:"Anomalous traffic detected"; sid:{sid}; rev:1;)'
            rules.append(rule)

    # Guardar reglas en el archivo de Suricata
    if rules:
        os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)  # Crear directorios si no existen
        with open(RULES_FILE, "a") as file:
            file.write("\n".join(rules) + "\n")
        print(f"✅ {len(rules)} reglas generadas y guardadas en {RULES_FILE}.")
    else:
        print("⚠ No se detectaron anomalías.")

if __name__ == "__main__":
    try:
        asyncio.run(generate_suricata_rules())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(generate_suricata_rules())