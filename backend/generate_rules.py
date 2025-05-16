import joblib
import pandas as pd
from db_connection import db
import os
import asyncio
import ipaddress
import numpy as np
import subprocess
from pathlib import Path
import hashlib
from bson import ObjectId

# 📌 Configuración de rutas
RULES_FILE = "/var/lib/suricata/rules/sml.rules"
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_PATH = "/app/models/isolation_forest_model.pkl"
SOCKET_PATH = "/var/run/suricata/suricata-command.socket"

# 📦 Cargar modelo y datos
def load_resources():
    """Carga el modelo y los datos necesarios"""
    if not all(os.path.exists(path) for path in [MODEL_PATH, DATA_PATH]):
        raise FileNotFoundError("No se encontraron los archivos del modelo o datos preprocesados")
    
    model = joblib.load(MODEL_PATH)
    print("[GR] 📋 Modelo espera:", list(model.feature_names_in_))
    df_processed = pd.read_csv(DATA_PATH)

    # 🔄 Renombrar columnas si vienen con puntos del CSV
    df_processed = df_processed.rename(columns={
        "alert.severity": "alert_severity",
        "packet.length": "packet_length"
    })
    
    #print("[GR] 📋 Modelo espera:", list(model.feature_names_in_))
    print("[GR] Columnas disponibles:", df_processed.columns.tolist())
    if df_processed.empty:
        raise ValueError("No hay datos para predecir reglas de Suricata")
    
    return model, df_processed


def safe_ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except (ValueError, ipaddress.AddressValueError):
        return 0
    

# def preprocess_data(df):
#     """Preprocesa los datos para el modelo"""
#     expected_numeric = [
#         "src_ip", "dest_ip", "proto",
#         "src_port", "dest_port",
#         "alert_severity", "packet_length"
#     ]

#     # Convertir IPs a enteros
#     for ip_col in ["src_ip", "dest_ip"]:
#         if ip_col in df.columns:
#             df[ip_col] = df[ip_col].astype(str).apply(safe_ip_to_int)

#     # Convertir a numérico explícitamente
#     for col in expected_numeric:
#         if col in df.columns:
#             df[col] = pd.to_numeric(df[col], errors="coerce")
#         else:
#             print(f"[GR] ⚠️ Columna faltante durante preprocesamiento: {col}")
#             df[col] = 0  # Rellenar con 0 si falta, para evitar que explote

#     return df.fillna(0)[expected_numeric]
def preprocess_data(df, expected_columns):
    """Preprocesa los datos para el modelo"""

    # Renombrar campos a lo que espera el modelo
    df = df.rename(columns={
        "alert_severity": "alert.severity",
        "packet_length": "packet.length"
    })

    # Convertir IPs a enteros
    for ip_col in ["src_ip", "dest_ip"]:
        if ip_col in df.columns:
            df[ip_col] = df[ip_col].astype(str).apply(safe_ip_to_int)

    # Convertir columnas esperadas a numérico
    for col in expected_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            print(f"[GR] ⚠️ Columna faltante durante preprocesamiento: {col}")
            df[col] = 0

    return df.fillna(0)[expected_columns]

# 📥 Obtener eventos desde MongoDB
async def fetch_latest_events(limit=100):
    """Obtiene los últimos eventos de MongoDB"""
    collection = db["events"]
    #cursor = collection.find({}, {"_id": 0}).limit(limit)
    cursor = collection.find(
    {"processed": {"$ne": True}},
        {
            "_id": 1,
            "src_ip": 1,
            "dest_ip": 1,
            "proto": 1,
            "src_port": 1,
            "dest_port": 1,
            "alert_severity": 1,
            "packet_length": 1,
            "timestamp": 1
        }
    ).limit(limit)

    return await cursor.to_list(length=limit)

# 🛡️ Gestión de reglas existentes
def load_existing_rules():
    """Carga y clasifica las reglas existentes"""
    existing_rules = set()
    rule_patterns = set()
    
    if Path(RULES_FILE).exists():
        with open(RULES_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    existing_rules.add(line)
                    # Extraer patrón base (sin metadatos)
                    rule_base = line.split('(')[0].strip()
                    rule_patterns.add(rule_base)
    
    return existing_rules, rule_patterns

# ✨ Generación de reglas
def generate_rule(event):
    """Genera una regla Suricata individual"""
    try:
        src_ip = str(ipaddress.ip_address(event["src_ip"]))
        dest_ip = str(ipaddress.ip_address(event["dest_ip"]))
    except (ValueError, ipaddress.AddressValueError):
        return None
    
    score = event.get("anomaly_score", 0)
    action = "drop" if score <= -0.2 else "alert"
    severity = "HIGH risk" if action == "drop" else "suspicious"
    
    # Identificador único para SID consistente
    rule_id = f"{src_ip}-{dest_ip}-{action}-{severity}"
    sid = 1000000 + (int(hashlib.sha256(rule_id.encode()).hexdigest(), 16) % 900000)
    
    return (
        f"{action} ip {src_ip} any -> {dest_ip} any "
        f'(msg:"{severity} traffic (score: {score:.2f})"; '
        f"sid:{sid}; rev:1;)"
    )

# 🔄 Recarga de reglas en Suricata
async def reload_suricata_rules():
    """Recarga las reglas en Suricata mediante el socket compartido"""
    try:
        result = subprocess.run(
            ['suricatasc', SOCKET_PATH],
            input="reload-rules\n",
            capture_output=True,
            text=True,
            timeout=15
        )
        print(f"[GR] Resultado de recarga:\n{result.stdout.strip()}")

        if result.returncode == 0 and "OK" in result.stdout:
            return True
        else:
            error = result.stderr or result.stdout
            print(f"[GR] Error al recargar reglas: {error}")
            return False
    except Exception as e:
        print(f"[GR] Excepción al recargar reglas: {str(e)}")
        return False

async def mark_events_as_processed(event_ids):
    """Marca eventos como procesados en MongoDB"""
    if not event_ids:
        return
    
    try:
        result = await db["events"].update_many(
            {"_id": {"$in": event_ids}},
            {"$set": {"processed": True}}
        )
        print(f"[GR] Eventos marcados como procesados: {result.modified_count}")
    except Exception as e:
        print(f"[GR] Error al marcar eventos como procesados: {str(e)}")

# 🚀 Función principal actualizada y corregida
async def generate_suricata_rules():
    try:
        # 1. Cargar modelo (ya no se usa df_processed aquí)
        model, _ = load_resources()

        # 2. Obtener eventos recientes
        events = await fetch_latest_events()
        if not events:
            print("[GR] No hay eventos recientes para analizar")
            return

        df_events = pd.DataFrame(events)
        # Renombrar campos a lo que espera el modelo
        df_events = df_events.rename(columns={
            "alert_severity": "alert.severity",
            "packet_length": "packet.length"
        })
        event_ids = [event["_id"] for event in events if "_id" in event]

        # 3. Preprocesar eventos para el modelo
        #df_numeric = preprocess_data(df_events.copy())
        expected_columns = list(model.feature_names_in_)
        df_numeric = preprocess_data(df_events.copy(), expected_columns)


        # ✅ Seleccionar solo las columnas que el modelo espera
        expected_columns = model.feature_names_in_ if hasattr(model, "feature_names_in_") else list(df_numeric.columns[:model.n_features_in_])
        df_numeric = df_numeric[[col for col in expected_columns if col in df_numeric.columns]]

        # ✅ Seleccionar solo las columnas que espera el modelo
        #expected_cols = ["src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert_severity", "packet_length"]
        expected_cols = list(model.feature_names_in_)
        print("[GR] Columnas reales en df_numeric:", df_numeric.columns.tolist())
        missing = [col for col in expected_cols if col not in df_numeric.columns]
        if missing:
            print(f"[GR] ❌ Faltan columnas esperadas: {missing}")
            return

        df_numeric = df_numeric[expected_cols]


        # 4. Verificar dimensiones del modelo
        if df_numeric.shape[1] != model.n_features_in_:
            print("[GR] Columnas utilizadas por el modelo:", df_numeric.columns.tolist())
            print(f"[GR] Error: El modelo espera {model.n_features_in_} features, se obtuvieron {df_numeric.shape[1]}")
            return

        # 5. Predecir anomalías
        df_events["anomaly_score"] = model.decision_function(df_numeric)
        df_events["prediction"] = model.predict(df_numeric)
        print("[GR] Conteo de predicciones:", df_events["prediction"].value_counts().to_dict())
        anomalies = df_events[df_events["prediction"] == -1].copy()

        
        if anomalies.empty:
            print("[GR] No se detectaron anomalías")
            return

        # 6. Cargar reglas existentes
        existing_rules, rule_patterns = load_existing_rules()
        new_rules = []

        # 7. Generar nuevas reglas evitando duplicados
        for _, event in anomalies.iterrows():
            if pd.notna(event["src_ip"]) and pd.notna(event["dest_ip"]):
                rule = generate_rule(event)
                print(f"[GR] ➕ Posible nueva regla:\n{rule}")
                if rule and rule.split('(')[0].strip() not in rule_patterns:
                    if rule not in existing_rules:
                        print("[GR] ✅ Esta regla es nueva y se agregará")
                        new_rules.append(rule)
                        rule_patterns.add(rule.split('(')[0].strip())

        # 8. Guardar reglas (manteniendo manuales intactas)
        if new_rules:
            manual_rules = [r for r in existing_rules if not r.startswith(('drop ip', 'alert ip'))]
            with open(RULES_FILE, 'w') as f:
                if manual_rules:
                    f.write("\n".join(manual_rules) + "\n")
                f.write("\n".join(new_rules) + "\n")

            print(f"[GR] ✅✅✅ {len(new_rules)} nuevas reglas añadidas (Total: {len(manual_rules) + len(new_rules)})")

            
            # 9. Recargar reglas en Suricata
            if not await reload_suricata_rules():
                print("[GR] ⚠ Las reglas se guardaron pero no se recargaron en Suricata")
        #else:
        #    print("[GR] No se generaron reglas nuevas (todas existían previamente)")
        # 10. Marcar eventos como procesados (tanto anomalías como normales)
        await mark_events_as_processed(event_ids)
    except Exception as e:
        print(f"[GR] ❌ Error crítico: {str(e)}")


# Punto de entrada principal
if __name__ == "__main__":
    try:
        asyncio.run(generate_suricata_rules())
    except RuntimeError as e:
        if "Event loop is closed" in str(e):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(generate_suricata_rules())
            loop.close()
        else:
            raise  # Mostrar el error real si no es el esperado
