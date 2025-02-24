import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# Cargar datos preprocesados
df = pd.read_csv("suricata_preprocessed.csv")

# Entrenar el modelo
model = IsolationForest(contamination=0.05, random_state=42)  # 5% de tráfico anómalo
model.fit(df)

# Guardar el modelo entrenado
joblib.dump(model, "isolation_forest_model.pkl")

print("Modelo entrenado y guardado como isolation_forest_model.pkl")
