"""
📁 ml_processing.py

Este script se encarga de preprocesar los eventos de red almacenados en MongoDB (colección 'events')
generados por Suricata. Extrae los datos, los transforma en un formato adecuado para el entrenamiento
de modelos de Machine Learning, y los guarda en un archivo CSV ('suricata_preprocessed.csv').

Funcionalidades principales:
- Convierte direcciones IP en enteros.
- Codifica protocolos.
- Calcula nuevas features como hora del evento, si es de noche, número de puertos únicos y conexiones por IP.
- Calcula rareza de puerto/IP destino (1/frecuencia).
- Calcula conexiones en ventana de 5 minutos por IP origen.
- Normaliza los datos.
- Prepara el dataset de entrada para el modelo de detección de anomalías.

Este preprocesamiento es fundamental para que el modelo de aprendizaje automático pueda aprender patrones
de tráfico normal y detectar anomalías de manera efectiva.
"""
import pandas as pd
import numpy as np
import ipaddress  # Asegúrate de importar este módulo al inicio del archivo
import asyncio
from db_connection import db  # Importar la conexión a MongoDB
import hashlib
from sklearn.preprocessing import RobustScaler
COLLECTION_NAME = "events"



async def fetch_suricata_data(train_only=False):
    collection = db[COLLECTION_NAME]

    if train_only:
        # Este comportamiento se conserva de forma manual para que el usuario pueda elegir interactivamente qué sesión de entrenamiento usar.
        # No se cambió a automático intencionalmente.
        # Buscar sesiones únicas
        sessions = await collection.distinct("training_session", {"training_mode": True})
        if not sessions:
            print("[ML] ⚠ No se encontraron sesiones de entrenamiento.")
            return []

        # Selección no interactiva: tomar la última sesión disponible (más reciente)
        selected = sessions[-1]
        print(f"[ML] ✅ Usando la sesión más reciente: {selected}")

        query = {
            "training_mode": True,
            "training_session": selected
        }
    else:
        query = {}

    cursor = collection.find(query)
    events = await cursor.to_list(length=1000)
    print(f"[ML] Se encontraron {len(events)} eventos en MongoDB.")
    return events

def ip_to_int(ip):
    """Convierte una dirección IP (IPv4 o IPv6) a un número entero único."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        print(f"[ML] ⚠ Advertencia: IP inválida detectada -> {ip}")
        return 0

def preprocess_data(events):
    df = pd.DataFrame(events)

    def ensure_column(df, col, default=0):
        if col not in df.columns:
            df[col] = default
        return df

    if df.empty:
        print("[ML] ⚠ No se encontraron datos en la base de datos. No se generará suricata_preprocessed.csv.")
        return None

    print("[ML] Procesando los datos de Suricata...")

    def add_port_entropy_feature(df):
        """Calcula la entropía de puertos destino por IP origen (detecta scans)"""
        port_distribution = df.groupby('src_ip')['dest_port'].value_counts(normalize=True).unstack(fill_value=0)
        entropy = port_distribution.apply(lambda x: -np.sum(x * np.log(x + 1e-10)), axis=1)
        df['port_entropy'] = df['src_ip'].map(entropy)
        return df

    def add_failed_connections_feature(df):
        """Calcula el ratio de conexiones con SYN fallidos por src_ip si existen flags TCP; si no, usa severidad"""
        if {"tcp_flags", "tcp_flags_tc"}.issubset(df.columns) and "src_ip" in df.columns:
            try:
                syn_series = (df["tcp_flags_tc"] == "S").astype(int)
                df["failed_ratio"] = (
                    syn_series.groupby(df["src_ip"]).rolling(20, min_periods=1).mean().reset_index(level=0, drop=True)
                )
            except Exception:
                df["failed_ratio"] = (df["tcp_flags_tc"] == "S").astype(int).rolling(20, min_periods=1).mean()
        elif "alert_severity" in df.columns and "src_ip" in df.columns:
            df["failed_ratio"] = df.groupby("src_ip")["alert_severity"].transform(lambda x: (x > 0).mean())
        else:
            df["failed_ratio"] = 0
        return df

    def add_temporal_anomaly_feature(df):
        """Identifica actividad en horarios inusuales para la IP"""
        if 'hour' in df.columns:
            ip_hour_mode = df.groupby('src_ip')['hour'].agg(lambda x: x.mode()[0])
            df['hour_anomaly'] = df.apply(
                lambda row: 1 if abs(row['hour'] - ip_hour_mode.get(row['src_ip'], 0)) > 3 else 0,
                axis=1
            )
        return df

    def add_connection_velocity(df):
        """Calcula la velocidad de conexiones por IP origen"""
        if 'timestamp' in df.columns:
            df['conn_velocity'] = df.groupby('src_ip')['timestamp'].transform(
                lambda x: x.diff().dt.total_seconds().rolling(5, min_periods=1).mean().fillna(0)
            )
        else:
            df['conn_velocity'] = 0
        return df

    def add_protocol_behavior(df):
        """Analiza comportamiento anómalo por protocolo"""
        if 'packet_length' in df.columns and 'proto' in df.columns:
            protocol_stats = df.groupby('proto').agg({
                'packet_length': ['mean', 'std'],
                'dest_port': 'nunique'
            }).reset_index()
            protocol_stats.columns = ['proto', 'proto_pkt_mean', 'proto_pkt_std', 'proto_ports']
            
            df = df.merge(protocol_stats, on='proto', how='left')
            df['pkt_anomaly'] = (
                (df['packet_length'] - df['proto_pkt_mean']).abs() > 2 * df['proto_pkt_std']
            ).astype(int)
        else:
            df['pkt_anomaly'] = 0
        return df

    def add_port_ip_rarity_feature(df):
        """Rareza de puerto y destino: 1/frecuencia normalizada"""
        # Rareza de puerto destino
        if "dest_port" in df.columns:
            port_freq = df["dest_port"].value_counts(normalize=True)
            df["port_rarity"] = 1.0 / (1e-6 + df["dest_port"].map(port_freq).fillna(0))
        else:
            df["port_rarity"] = 0.0
        # Rareza de IP destino
        if "dest_ip" in df.columns:
            ip_freq = df["dest_ip"].value_counts(normalize=True)
            df["ip_rarity"] = 1.0 / (1e-6 + df["dest_ip"].map(ip_freq).fillna(0))
        else:
            df["ip_rarity"] = 0.0
        return df

    def add_conn_5m_feature(df):
        """Conteo de conexiones por src_ip en ventana móvil de 5 minutos"""
        df["conn_5m"] = 0.0
        if "timestamp" in df.columns and "src_ip" in df.columns:
            try:
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
                df.sort_values("timestamp", inplace=True)
                for src, g in df.groupby("src_ip"):
                    idx = g.index
                    ts = g["timestamp"]
                    ones = pd.Series(1, index=ts)
                    counts = ones.rolling("5min").sum()
                    df.loc[idx, "conn_5m"] = counts.values
            except Exception as e:
                print(f"[ML] Aviso calculando conn_5m: {e}")
                df["conn_5m"] = 0.0
        return df

    # Enriquecer con nuevas features (robusto a columnas faltantes)
    if "_id" in df.columns:
        df["_id"] = df["_id"].astype(str)
        df["event_id"] = df["_id"]
    else:
        # Si no hay _id, intentamos construir un hash estable
        if "timestamp" in df.columns:
            tmp_ts = df["timestamp"].astype(str)
        else:
            tmp_ts = df.index.astype(str)
        s_concat = df.get("src_ip", pd.Series("", index=df.index)).astype(str) + "-" + \
                   df.get("dest_ip", pd.Series("", index=df.index)).astype(str) + "-" + tmp_ts
        df["event_id"] = s_concat.apply(lambda s: hashlib.md5(s.encode()).hexdigest())

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = df["timestamp"].dt.hour.fillna(0).astype(int)
    else:
        df["hour"] = 0
    df["is_night"] = df["hour"].apply(lambda h: 1 if h < 7 or h > 20 else 0)

    # Asegurar columnas base antes de cálculos dependientes
    for base_col in ["src_ip", "dest_ip", "dest_port", "proto", "packet_length", "alert_severity"]:
        df = ensure_column(df, base_col, 0)

    # Cálculos que requieren columnas específicas
    if "src_ip" in df.columns and "dest_port" in df.columns:
        try:
            df["ports_used"] = df.groupby("src_ip")["dest_port"].transform("nunique")
        except Exception:
            df["ports_used"] = 0
    else:
        df["ports_used"] = 0

    if "src_ip" in df.columns and "dest_ip" in df.columns:
        try:
            df["conn_per_ip"] = df.groupby("src_ip")["dest_ip"].transform("count")
        except Exception:
            df["conn_per_ip"] = 0
    else:
        df["conn_per_ip"] = 0

    df = add_port_entropy_feature(df)
    df = add_failed_connections_feature(df)
    df = add_temporal_anomaly_feature(df)
    df = add_connection_velocity(df)
    df = add_protocol_behavior(df)
    df = add_port_ip_rarity_feature(df)
    df = add_conn_5m_feature(df)

    # Añadir columna 'anomaly' basado en training_mode y training_label
    def label_anomaly(row):
        if row.get("training_mode") == True:
            label = row.get("training_label")
            if label == "anomaly":
                return 1
            elif label == "normal":
                return 0
        return -1

    df["anomaly"] = df.apply(label_anomaly, axis=1)

    selected_columns = [
        "src_ip", "dest_ip", "proto", "src_port", "dest_port", "alert_severity",
        "packet_length", "hour", "is_night", "ports_used", "conn_per_ip",
        "port_rarity", "ip_rarity", "conn_5m",
        "port_entropy", "failed_ratio", "hour_anomaly",
        "conn_velocity", "proto_pkt_mean", "proto_pkt_std", "proto_ports", "pkt_anomaly",
        "anomaly", "event_id"
    ]

    # Asegurar columnas faltantes con valores por defecto antes de seleccionar
    defaults = {
        "alert_severity": 0, "packet_length": 0, "hour": 0, "is_night": 0,
        "ports_used": 0, "conn_per_ip": 0, "port_rarity": 0.0, "ip_rarity": 0.0,
        "conn_5m": 0.0, "port_entropy": 0.0, "failed_ratio": 0.0, "hour_anomaly": 0,
        "conn_velocity": 0.0, "proto_pkt_mean": 0.0, "proto_pkt_std": 0.0,
        "proto_ports": 0.0, "pkt_anomaly": 0, "anomaly": -1
    }
    for col, default in defaults.items():
        df = ensure_column(df, col, default)
    df = ensure_column(df, "event_id", "")
    df = ensure_column(df, "proto", 0)
    df = ensure_column(df, "src_port", 0)
    df = ensure_column(df, "dest_port", 0)
    df = ensure_column(df, "src_ip", "0.0.0.0")
    df = ensure_column(df, "dest_ip", "0.0.0.0")

    df = df[[c for c in selected_columns if c in df.columns]].copy()

    # Convertir direcciones IP a valores numéricos usando ip_to_int()
    df["src_ip"] = df["src_ip"].apply(ip_to_int)
    df["dest_ip"] = df["dest_ip"].apply(ip_to_int)

    # Reemplazar valores categóricos del protocolo
    try:
        df["proto"] = df["proto"].astype("category").cat.codes
    except Exception:
        # si ya es numérico o la conversión falla, forzar a numérico
        df["proto"] = pd.to_numeric(df["proto"], errors="coerce").fillna(0).astype(int)

    # Normalizar solo las columnas numéricas
    df = df.drop(columns=["timestamp"], errors="ignore")
    # Seleccionar columnas numéricas para normalizar
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df_numeric = df[numeric_cols]
    scaler = RobustScaler()
    df_normalized = pd.DataFrame(scaler.fit_transform(df_numeric), columns=df_numeric.columns)

    # Combinar con columnas no numéricas (por ejemplo event_id si existe)
    df = pd.concat([df_normalized, df.drop(columns=numeric_cols)], axis=1)

    return df

async def main(train_only=False):
    events = await fetch_suricata_data(train_only)
    df = preprocess_data(events)

    if df is not None:
        df.to_csv("/app/models/suricata_preprocessed.csv", index=False)  # Guardar datos procesados
        print("[ML] ✅ Datos preprocesados guardados en suricata_preprocessed.csv")
    else:
        print("[ML] ⚠ No se generó ningún archivo CSV.")

if __name__ == "__main__":
    import sys
    train_only = "--train_only" in sys.argv
    asyncio.run(main(train_only=train_only))
