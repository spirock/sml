"""
generate_rules.py

📌 Función principal:
    Este módulo analiza eventos recientes desde MongoDB, ejecuta el modelo de detección de anomalías (Isolation Forest),
    y genera reglas de Suricata para eventos considerados anómalos.

📈 Objetivo:
    - Clasificar eventos de red como normales o anómalos.
    - Generar y guardar reglas de Suricata para los eventos detectados como anómalos.
    - Recargar dinámicamente las reglas en Suricata a través del socket.

🔁 Flujo general:
    1. Cargar modelo entrenado y datos de preprocesamiento.
    2. Obtener eventos recientes de MongoDB.
    3. Evaluar si está activo el modo entrenamiento.
        - Si está activo, no se generan reglas, solo se marcan eventos.
    4. Preprocesar los eventos para el modelo de ML.
    5. Predecir con Isolation Forest y extraer anomalías.
    6. Generar reglas y evitar duplicados.
    7. Guardar nuevas reglas en el archivo sml.rules.
    8. Recargar las reglas en Suricata mediante suricatasc.
    9. Marcar los eventos como procesados en la base de datos.

🧩 Dependencias:
    - MongoDB (colección 'events' y 'config')
    - Archivos:
        * /app/models/suricata_preprocessed.csv
        * /app/models/isolation_forest_model.pkl
        * /var/lib/suricata/rules/sml.rules
    - Suricata con acceso a suricatasc y su socket.

🛠 Requiere:
    - Un modelo entrenado previamente.
    - Datos preprocesados en formato compatible.
    - Docker con contenedores montados correctamente y permisos adecuados.
"""
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
import json
from constants import (
    ANOMALY_THRESHOLD,
    ANOMALY_PREDICTION,
    IFOREST_MODEL,
    THRESHOLDS_JSON,
    SELECTED_THRESHOLD_FILE,
    ALERT_ONLY_PORTS,
    LOCAL_SERVICES,
    MIN_SEVERITY_TO_DROP,
    MIN_FREQ_TO_DROP,
    RULES_FILE,
)


# --- Funciones auxiliares para reglas contextuales ---
def gen_sid(event):
    """Genera un SID único basado en IP y puertos"""
    unique_str = f"{event['src_ip']}-{event['dest_port']}-{event['proto']}"
    return 3000000 + int(hashlib.sha256(unique_str.encode()).hexdigest(), 16) % 900000

def generate_contextual_rule(event, historical_data):
    """Genera reglas basadas en comportamiento histórico"""
    ip_behavior = historical_data[historical_data['src_ip'] == event['src_ip']]
    
    if len(ip_behavior) > 10:
        port_range = f"{ip_behavior['dest_port'].min()}:{ip_behavior['dest_port'].max()}"
        return (
            f"alert {event['proto']} {event['src_ip']} any -> any {port_range} "
            f'(msg:"Suspicious port range access from {event["src_ip"]}"; sid:{gen_sid(event)};)'
        )
    return None


# Umbral seleccionado por evaluación (opcional)
SELECTED_THRESHOLD = None
try:
    # Prioridad 1: thresholds.json
    p = Path(THRESHOLDS_JSON)
    if p.exists():
        data = json.loads(p.read_text())
        SELECTED_THRESHOLD = float(data.get("thr_if"))
        print(f"[GR] thr_if desde thresholds.json: {SELECTED_THRESHOLD:.6f}")
    else:
        # Prioridad 2: selected_threshold.txt
        thr_path = Path(SELECTED_THRESHOLD_FILE)
        if thr_path.exists():
            SELECTED_THRESHOLD = float(thr_path.read_text().strip())
            print(f"[GR] Umbral seleccionado cargado: {SELECTED_THRESHOLD:.6f}")
        else:
            print("[GR] No hay thresholds.json ni selected_threshold.txt; se usará ANOMALY_THRESHOLD.")
except Exception as e:
    print(f"[GR] No se pudo leer thresholds: {e}")


# 📌 Configuración de rutas
# Ruta de reglas según tu despliegue real

HISTORICAL_CSV = "/app/models/suricata_preprocessed.csv"  # opcional
MODEL_PATH = IFOREST_MODEL
SOCKET_PATH = "/var/run/suricata/suricata-command.socket"

# 📦 Cargar modelo y datos
def load_resources():
    """Carga el modelo y (opcional) datos históricos"""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"No existe el modelo en {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    print("✔ Modelo cargado correctamente")

    hist_df = pd.read_csv(HISTORICAL_CSV) if os.path.exists(HISTORICAL_CSV) else pd.DataFrame()
    if hist_df.empty:
        print("[GR] Sin histórico CSV; las reglas contextuales usarán sólo conteos en memoria.")
    else:
        print("[GR] Columnas histórico:", hist_df.columns.tolist())
    return model, hist_df


def safe_ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except (ValueError, ipaddress.AddressValueError):
        return 0
    
async def is_training_mode():
    try:
        config = await db["config"].find_one({"_id": "mode"})
        if not config:
            return False
        # Compatibilidad: nuevo esquema {mode: normal|anomaly|off}
        mode = str(config.get("mode", "")).strip().lower()
        if mode in {"normal", "anomaly"}:
            return True
        if mode == "off":
            return False
        # Esquema anterior: {training_mode: bool}
        return bool(config.get("training_mode", False) or config.get("value", False))
    except Exception as e:
        print(f"[GR] ⚠ Error al verificar modo entrenamiento: {e}")
        return False

def preprocess_data(df, expected_columns):
    """Preprocesa los datos para el modelo"""
    # Convertir IPs a enteros si existen como texto
    for ip_col in ["src_ip", "dest_ip"]:
        if ip_col in df.columns:
            df[ip_col] = df[ip_col].astype(str).apply(safe_ip_to_int)

    # Asegurar todas las columnas esperadas como numéricas
    out = {}
    for col in expected_columns:
        if col in df.columns:
            out[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            out[col] = pd.Series(0, index=df.index, dtype="float64")
    X = pd.DataFrame(out)
    return X.fillna(0)[expected_columns]

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
    """Genera una regla Suricata individual con políticas anti-FP."""
    try:
        proto = str(event.get("proto", "")).lower()
        if proto not in {"tcp", "udp"}:
            return None
        src_ip = str(ipaddress.ip_address(event.get("src_ip")))
        dst_ip = str(ipaddress.ip_address(event.get("dest_ip")))
        src_port = int(event.get("src_port", 0)) if event.get("src_port") else "any"
        dst_port = int(event.get("dest_port", 0))
        if dst_port <= 0:
            return None
    except Exception:
        return None

    # No reglas DROP hacia servicios locales conocidos
    if str(event.get("dest_ip")) in LOCAL_SERVICES:
        return None

    sev = int(pd.to_numeric(event.get("alert_severity", 0)))
    pkt_len = int(pd.to_numeric(event.get("packet_length", 0)))
    score = float(pd.to_numeric(event.get("anomaly_score", 0.0)))
    thr = SELECTED_THRESHOLD if SELECTED_THRESHOLD is not None else ANOMALY_THRESHOLD

    # Política de acción
    alert_only = dst_port in ALERT_ONLY_PORTS
    should_drop = bool(event.get("should_drop", False)) and not alert_only
    action = "drop" if should_drop and (score < thr) else "alert"

    severity_str = "HIGH risk" if action == "drop" else "suspicious"
    unique_id = f"{src_ip}-{dst_ip}-{proto}-{dst_port}-{sev}-{pkt_len}-{round(score, 3)}"
    sid = 3000000 + (int(hashlib.sha256(unique_id.encode()).hexdigest(), 16) % 500000)

    msg = f'"ML anomaly (score: {score:.2f}, len: {pkt_len}, severity: {sev}, thr: {thr:.2f})"'
    return f"{action} {proto} {src_ip} {src_port} -> {dst_ip} {dst_port} (msg:{msg}; sid:{sid}; rev:1;)"


# 🔄 Recarga de reglas en Suricata
async def reload_suricata_rules():
    """Recarga las reglas en Suricata mediante el socket compartido"""
    try:

        result = subprocess.run(
            ["suricatasc", "-c", "reload-rules"],
            capture_output=True,
            text=True,
            timeout=35
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
        # 1. Obtener eventos recientes
        events = await fetch_latest_events()
        if await is_training_mode():
            print("[GR] 🧠 Modo entrenamiento activo: no se generarán reglas para estos eventos.")
            await mark_events_as_processed([event["_id"] for event in events if "_id" in event])
            return
        # 2. Cargar modelo
        model, historical_data = load_resources()
        if not events:
            print("[GR] No hay eventos recientes para analizar")
            return

        df_events = pd.DataFrame(events)
        event_ids = [event["_id"] for event in events if "_id" in event]

        # 3. Preprocesar eventos para el modelo
        expected_columns = list(model.feature_names_in_)
        df_numeric = preprocess_data(df_events.copy(), expected_columns)

        # ✅ Seleccionar solo las columnas que el modelo espera
        expected_columns = model.feature_names_in_ if hasattr(model, "feature_names_in_") else list(df_numeric.columns[:model.n_features_in_])
        df_numeric = df_numeric[[col for col in expected_columns if col in df_numeric.columns]]

        # Cambiado para verificar columnas contra df_numeric en lugar de df_events
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
        anomalies = df_events[df_events["prediction"] == ANOMALY_PREDICTION].copy()

        # 📏 Filtro por umbral y políticas anti-FP
        thr = SELECTED_THRESHOLD if SELECTED_THRESHOLD is not None else ANOMALY_THRESHOLD
        anomalies = anomalies.copy()

        # Tipados y exclusiones
        anomalies["dest_port"] = pd.to_numeric(anomalies.get("dest_port", 0), errors="coerce").fillna(0).astype(int)
        anomalies = anomalies[~anomalies["dest_ip"].astype(str).isin(LOCAL_SERVICES)]

        # Umbral externo del IF
        anomalies = anomalies[anomalies["anomaly_score"] < thr]

        # Frecuencia por {src_ip, dest_port}
        if {"src_ip", "dest_port", "_id"}.issubset(anomalies.columns):
            anomalies["freq_sp"] = anomalies.groupby(["src_ip", "dest_port"])['_id'].transform("count").fillna(0).astype(int)
        else:
            anomalies["freq_sp"] = 0

        # Señales mínimas para permitir DROP
        sev = pd.to_numeric(anomalies.get("alert_severity", 0), errors="coerce").fillna(0).astype(int)
        anomalies["should_drop"] = (sev >= MIN_SEVERITY_TO_DROP) & (anomalies["freq_sp"] >= MIN_FREQ_TO_DROP) & (~anomalies["dest_port"].isin(ALERT_ONLY_PORTS))

        # Clustering simple para no duplicar reglas: prioriza menor score
        keys = ["proto", "src_ip", "dest_ip", "dest_port"]
        existing_cols = [c for c in keys if c in anomalies.columns]
        if existing_cols:
            anomalies = anomalies.sort_values("anomaly_score").drop_duplicates(existing_cols, keep="first")

        if anomalies.empty:
            print("[GR] No hay anomalías tras aplicar umbral y filtros")
            return

        # 6. Cargar reglas existentes
        existing_rules, rule_patterns = load_existing_rules()
        new_rules = []

        # 🔍 Paso adicional: detectar escaneo de puertos y generar regla por IP
        from collections import defaultdict
        port_scan_ips = defaultdict(set)

        for _, row in anomalies.iterrows():
            port_scan_ips[row["src_ip"]].add(row["src_port"])

        for ip, ports in port_scan_ips.items():
            if len(ports) > 10:  # Umbral de escaneo de puertos
                try:
                    ip_str = str(ipaddress.ip_address(ip))
                    rule_base = f"alert ip {ip_str} any -> any any"
                    if rule_base not in rule_patterns:
                        sid = 2000000 + int(hashlib.sha256(ip_str.encode()).hexdigest(), 16) % 900000
                        rule = f'{rule_base} (msg:"Detected port scanning activity from {ip_str}"; sid:{sid}; rev:1;)'
                        new_rules.append(rule)
                        rule_patterns.add(rule_base)
                        print(f"[GR] 🚨 Regla de escaneo añadida para {ip_str}")
                except Exception as e:
                    print(f"[GR] ⚠ Error generando regla para IP {ip}: {e}")

        # 6b. Generar reglas contextuales por comportamiento histórico
        if not historical_data.empty:
            for _, event in anomalies.iterrows():
                contextual_rule = generate_contextual_rule(event, historical_data)
                if contextual_rule and contextual_rule not in existing_rules:
                    print(f"[GR] ➕ Regla contextual generada:\n{contextual_rule}")
                    new_rules.append(contextual_rule)

        # 7. Generar nuevas reglas evitando duplicados y reglas redundantes (mismo src_ip, dest_ip, dest_port)
        seen_combinations = set()
        for _, event in anomalies.iterrows():
            key = (event["src_ip"], event["dest_ip"], event["dest_port"])
            if key in seen_combinations:
                continue
            seen_combinations.add(key)
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
