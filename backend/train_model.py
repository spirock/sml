import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Rutas de los archivos
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_DIR = "/app/models"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")

# Verificar si el archivo de datos existe
if not os.path.exists(DATA_PATH):
    print(f"❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutar el preprocesamiento antes.")
    exit(1)

df = pd.read_csv(DATA_PATH)

# Verificar si hay valores NaN o datos faltantes
if df.isnull().values.any():
    print("⚠ Advertencia: Se encontraron valores NaN en los datos. Rellenando con ceros.")
    df.fillna(0, inplace=True)

# Asegurar que todas las columnas sean numéricas
for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# Si todavía hay NaN, reemplazarlos con ceros
df.fillna(0, inplace=True)

# Crear la carpeta models/ si no existe
os.makedirs(MODEL_DIR, exist_ok=True)

# Verificar que no haya columnas vacías antes de entrenar
if df.shape[1] == 0:
    print("❌ Error: No hay columnas en los datos después del preprocesamiento.")
    exit(1)

# Entrenar el modelo Isolation Forest
print("🔍 Entrenando modelo Isolation Forest...")
model = IsolationForest(contamination=0.05, random_state=42)  # 5% de tráfico anómalo

try:
    model.fit(df)
    # Guardar el modelo en la carpeta persistente
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Modelo entrenado y guardado en {MODEL_PATH}")

    # **Evaluación del Modelo**
    print("\n📊 Evaluando el modelo...")

    # Obtener los puntajes de anomalía
    anomaly_scores = model.decision_function(df)
    predictions = model.predict(df)

    # Contar anomalías detectadas
    total_anomalies = (predictions == -1).sum()
    print(f"⚠ Total de anomalías detectadas: {total_anomalies} de {len(df)} eventos.")

    # Agregar los resultados al DataFrame
    df["anomaly_score"] = anomaly_scores
    df["prediction"] = predictionfs

    # Guardar resultados en un CSV para análisis
    result_file = "/app/models/suricata_anomaly_analysis.csv"
    df.to_csv(result_file, index=False)
    print(f"✅ Resultados guardados en {result_file}")
except Exception as e:
    print(f"❌ Error al entrenar el modelo: {e}")
