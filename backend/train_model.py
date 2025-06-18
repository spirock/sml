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
import joblib
import os
from constants import ANOMALY_PREDICTION

# Rutas de los archivos
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_DIR = "/app/models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")

# Verificar si el archivo de datos existe
if not os.path.exists(DATA_PATH):
    print(f"[TM]❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutar el preprocesamiento antes.")
    exit(1)

df = pd.read_csv(DATA_PATH)
df_original = df.copy()

# Verificar si hay valores NaN o datos faltantes
if df.isnull().values.any():
    print("[TM] ⚠ Advertencia: Se encontraron valores NaN en los datos. Rellenando con ceros.")
    df.fillna(0, inplace=True)

# Asegurar que todas las columnas sean numéricas
for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Si todavía hay NaN, reemplazarlos con ceros
df.fillna(0, inplace=True)

label_column = "label_num"
X = df.drop(columns=["timestamp", "src_ip", "dest_ip", "label_text", label_column], errors="ignore")
# Nota: event_id no se incluye en el entrenamiento ya que representa un identificador único de MongoDB (ObjectId),
# no aporta valor predictivo y podría sesgar el modelo. Se conserva solo en los resultados para trazabilidad.
y = df[label_column] if label_column in df.columns else None

# Crear la carpeta models/ si no existe
os.makedirs(MODEL_DIR, exist_ok=True)

# Verificar que no haya columnas vacías antes de entrenar
if X.shape[1] == 0:
    print("[TM] ❌ Error: No hay columnas en los datos después del preprocesamiento.")
    exit(1)

# Entrenar el modelo Isolation Forest
print("[TM] 🔍 Entrenando modelo Isolation Forest...")
model = IsolationForest(contamination=0.05, random_state=42)  # 5% de tráfico anómalo

try:
    model.fit(X)
    # Guardar el modelo en la carpeta persistente
    joblib.dump(model, MODEL_PATH)
    print(f"[TM] ✅ Modelo entrenado y guardado en {MODEL_PATH}")

    # **Evaluación del Modelo**
    print("\n [TM] 📊 Evaluando el modelo...")

    # Obtener los puntajes de anomalía
    anomaly_scores = model.decision_function(X)
    predictions = model.predict(X)
    # Convertimos la predicción a binaria para consistencia (1 = anomalía, 0 = normal)
    result_df = pd.DataFrame()
    # Mantener campos clave
    for col in ["proto", "src_port", "dest_port", "alert_severity", "packet_length",
                "hour", "is_night", "ports_used", "conn_per_ip", "event_id",
                "src_ip", "dest_ip", "timestamp"]:
        if col in df_original.columns:
            result_df[col] = df_original[col]
    # Añadir resultados del modelo
    result_df["anomaly_score"] = anomaly_scores
    result_df["prediction"] = predictions
    # Convertimos la predicción a binaria para consistencia (1 = anomalía, 0 = normal)
    result_df["is_anomaly"] = (predictions == ANOMALY_PREDICTION).astype(int)
    # Añadir columna label en formato texto ("anomaly"/"normal"), como en otros scripts
    result_df["label"] = result_df["prediction"].apply(lambda x: "anomaly" if x == ANOMALY_PREDICTION else "normal")
    # Contar anomalías detectadas
    total_anomalies = (predictions == ANOMALY_PREDICTION).sum()
    print(f"[TM] ⚠ Total de anomalías detectadas: {total_anomalies} de {len(X)} eventos.")
    # Guardar en CSV
    result_file = "/app/models/suricata_anomaly_analysis.csv"
    result_df.to_csv(result_file, index=False)
    print(f"[TM] ✅ Resultados guardados en {result_file}")
    # Mostrar conteo de instancias por etiqueta
    print(result_df["label"].value_counts())
except Exception as e:
    print(f"[TM] ❌ Error al entrenar el modelo: {e}")
