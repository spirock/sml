"""
🔍 train_model.py

📌 Función principal:
    Entrenar un modelo de Machine Learning (Isolation Forest) utilizando datos preprocesados por `ml_processing.py`.
    El objetivo es identificar patrones anómalos en el tráfico de red observado por Suricata.

🎯 Objetivo:
    Cargar los datos procesados desde `suricata_preprocessed.csv`, entrenar un modelo de detección de anomalías,
    guardar el modelo entrenado (`isolation_forest_model.pkl`) y generar un archivo con los resultados y predicciones
    (`suricata_anomaly_analysis.csv`).

🔗 Dependencias y vínculos:
    - Entrada: `/app/models/suricata_preprocessed.csv` (generado por ml_processing.py)
    - Salida:
        - `/app/models/isolation_forest_model.pkl` → Modelo entrenado
        - `/app/models/suricata_anomaly_analysis.csv` → Resultados de score y predicción por evento
    - Librerías: scikit-learn (IsolationForest), pandas, numpy, joblib

📝 Requisitos previos:
    Asegurarse de haber ejecutado `ml_processing.py` para que los datos estén preparados antes de entrenar.

"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score
import joblib
import os
from constants import ANOMALY_PREDICTION
try:
    from constants import LABEL_ANOMALY, LABEL_NORMAL, DEFAULT_PERCENTILE
except Exception:
    LABEL_ANOMALY = "anomaly"
    LABEL_NORMAL = "normal"
    DEFAULT_PERCENTILE = 0.98
import ipaddress

# Rutas de los archivos
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_DIR = "/app/models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")

# Verificar si el archivo de datos existe
if not os.path.exists(DATA_PATH):
    print(f"[TM]❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutar el preprocesamiento antes.")
    exit(1)

df = pd.read_csv(DATA_PATH, dtype={"event_id": str})

def ip_to_numeric(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except:
        return 0

df["src_ip"] = df["src_ip"].apply(ip_to_numeric)
df["dest_ip"] = df["dest_ip"].apply(ip_to_numeric)

# Verificar si hay valores NaN o datos faltantes
if df.isnull().values.any():
    print("[TM] ⚠ Advertencia: Se encontraron valores NaN en los datos. Rellenando con ceros.")
    df.fillna(0, inplace=True)

# Asegurar que todas las columnas sean numéricas excepto event_id
for col in df.columns:
    if col != "event_id":
        df[col] = pd.to_numeric(df[col], errors="coerce")

# Si todavía hay NaN, reemplazarlos con ceros
df.fillna(0, inplace=True)

df_original = df.copy()

# [TM-DBG] Mostrar los primeros event_id antes de cualquier modificación
if "event_id" in df.columns:
    print("[TM-DBG] Primeros event_id antes del entrenamiento:")
    print(df[["event_id"]].head(10))
else:
    print("[TM-DBG] ⚠ event_id no encontrado en df")

label_column = "label_num"
# Conjunto de características completo para predicción
X_full_df = df.drop(columns=["timestamp", "src_ip", "dest_ip", "label_text", label_column], errors="ignore")
feature_cols = X_full_df.columns.tolist()
# Nota: event_id no se incluye en el entrenamiento ya que representa un identificador único de MongoDB (ObjectId),
# no aporta valor predictivo y podría sesgar el modelo. Se conserva solo en los resultados para trazabilidad.
y = df[label_column] if label_column in df.columns else None

# Crear la carpeta models/ si no existe
os.makedirs(MODEL_DIR, exist_ok=True)

# Verificar que no haya columnas vacías antes de entrenar
if X_full_df.shape[1] == 0:
    print("[TM] ❌ Error: No hay columnas en los datos después del preprocesamiento.")
    exit(1)

# Entrenar el modelo Isolation Forest
print("[TM] 🔍 Entrenando modelo Isolation Forest...")
model = IsolationForest(contamination=0.05, random_state=42)  # 5% de tráfico anómalo

try:
    # Entrenar solo con tráfico normal si existe etiqueta
    df_train = df.copy()
    if "training_label" in df_train.columns:
        df_train = df_train[df_train["training_label"].astype(str).str.lower() == "normal"]
    elif "label_text" in df_train.columns:
        df_train = df_train[df_train["label_text"].astype(str).str.lower() == "normal"]

    X_train = df_train[feature_cols].values
    X_full = X_full_df.values

    print(f"[TM] 🧪 Columnas usadas para entrenamiento: {feature_cols}")
    print(f"[TM] 🧪 Muestras de entrenamiento: {len(X_train)} / {len(X_full)} totales")
    model.fit(X_train)
    # Guardar el modelo en la carpeta persistente
    joblib.dump(model, MODEL_PATH)
    print(f"[TM] ✅ Modelo entrenado y guardado en {MODEL_PATH}")

    # **Evaluación del Modelo**
    print("\n [TM] 📊 Evaluando el modelo...")

    # Puntajes de normalidad: mayor = más normal
    scores = model.decision_function(X_full)

    # Selección de umbral para maximizar F1 si hay ground truth
    best_thr = None
    best_f1 = None
    # Construir y_true de forma robusta según columnas disponibles
    y_true = None
    if "label" in df_original.columns:
        y_true = (df_original["label"].astype(str).str.lower() == LABEL_ANOMALY).astype(int).values
    elif "label_text" in df_original.columns:
        y_true = (df_original["label_text"].astype(str).str.lower() == LABEL_ANOMALY).astype(int).values
    elif "training_label" in df_original.columns:
        y_true = (df_original["training_label"].astype(str).str.lower() == LABEL_ANOMALY).astype(int).values
    elif "label_num" in df_original.columns:
        # Si -1 está presente, asúmelo como anomalía; si no, usa 1 como anomalía
        uniques = set(pd.Series(df_original["label_num"]).dropna().unique().tolist())
        if -1 in uniques:
            y_true = (df_original["label_num"] == -1).astype(int).values
        else:
            y_true = (df_original["label_num"] == 1).astype(int).values

    if y_true is not None:
        # Barrido de cuantiles altos (región de anomalías)
        quantiles = np.linspace(0.80, 0.995, 60)
        grid = np.quantile(scores, quantiles)
        # Evitar duplicados en la rejilla
        grid = np.unique(grid)
        evals = []
        for t in grid:
            y_pred_bin = (scores < t).astype(int)
            f1 = f1_score(y_true, y_pred_bin, zero_division=0)
            evals.append((t, f1))
        best_thr, best_f1 = max(evals, key=lambda x: x[1]) if evals else (np.quantile(scores, DEFAULT_PERCENTILE), None)
        if best_f1 is not None:
            print(f"[TM] 🎯 Umbral seleccionado por F1: {best_thr:.6f} (F1={best_f1:.3f})")
    else:
        best_thr = np.quantile(scores, DEFAULT_PERCENTILE)
        print(f"[TM] 📈 Umbral por percentil (sin etiquetas): {best_thr:.6f} (p={DEFAULT_PERCENTILE})")

    # Predicción binaria basada en umbral
    predictions = np.where(scores < best_thr, ANOMALY_PREDICTION, 1)

    result_df = pd.DataFrame()
    # Mantener campos clave
    for col in ["proto", "src_port", "dest_port", "alert_severity", "packet_length",
                "hour", "is_night", "ports_used", "conn_per_ip", "port_entropy", "failed_ratio", "hour_anomaly",
                "event_id", "src_ip", "dest_ip", "timestamp"]:
        if col in df_original.columns:
            result_df[col] = df_original[col]
    # Añadir resultados del modelo
    result_df["anomaly_score"] = scores
    result_df["prediction"] = predictions
    # Convertimos la predicción a binaria para consistencia (1 = anomalía, 0 = normal)
    result_df["is_anomaly"] = (predictions == ANOMALY_PREDICTION).astype(int)
    # Añadir columna label en formato texto ("anomaly"/"normal"), como en otros scripts
    result_df["label"] = result_df["prediction"].apply(lambda x: "anomaly" if x == ANOMALY_PREDICTION else "normal")
    # Contar anomalías detectadas
    total_anomalies = (predictions == ANOMALY_PREDICTION).sum()
    print(f"[TM] ⚠ Total de anomalías detectadas: {total_anomalies} de {len(X_full)} eventos.")
    # Guardar en CSV
    result_file = "/app/models/suricata_anomaly_analysis.csv"
    result_df.to_csv(result_file, index=False)
    print(f"[TM] ✅ Resultados guardados en {result_file}")
    # Mostrar conteo de instancias por etiqueta
    print(result_df["label"].value_counts())
except Exception as e:
    print(f"[TM] ❌ Error al entrenar el modelo: {e}")
