from fastapi import APIRouter
import os
import json
import pandas as pd
import joblib
import numpy as np

router = APIRouter()

LOG_FILE = "/var/log/suricata/eve.json"

@router.get("/logs")
async def get_logs():
    """Lee los logs de Suricata directamente desde el archivo eve.json"""
    if not os.path.exists(LOG_FILE):
        return {"error": "El archivo de logs no existe"}
    
    try:
        with open(LOG_FILE, "r") as f:
            logs = [json.loads(line) for line in f.readlines()]
        return logs
    except Exception as e:
        return {"error": str(e)}
    
MODEL_PATH = "/app/models/isolation_forest_model.pkl"

# Cargar el modelo entrenado
model = joblib.load(MODEL_PATH)


@router.post("/predict")
async def predict_anomaly(data: dict):
    try:
        # Convertir datos de entrada en DataFrame
        df = pd.DataFrame([data])

        # Preprocesamiento (debe coincidir con el del entrenamiento)
        df["src_ip"] = sum([int(num) << (8 * i) for i, num in enumerate(reversed(df["src_ip"][0].split('.')))])
        df["dest_ip"] = sum([int(num) << (8 * i) for i, num in enumerate(reversed(df["dest_ip"][0].split('.')))])
        df["proto"] = df["proto"].astype("category").cat.codes
        df = (df - df.min()) / (df.max() - df.min())

        # Realizar predicción
        prediction = model.predict(df)

        return {"anomaly": bool(prediction[0] == -1)}

    except Exception as e:
        return {"error": str(e)}