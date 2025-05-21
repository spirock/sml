

import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

# Umbral para considerar un evento como anómalo
THRESHOLD = 0.6

# Rutas de los archivos
GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"
MODEL_OUTPUT_PATH = "/app/models/model_output.csv"

def evaluar_modelo():
    print("📊 Evaluando el rendimiento del modelo con base en el ground truth...")

    try:
        # Cargar archivos CSV
        ground_truth = pd.read_csv(GROUND_TRUTH_PATH)
        model_output = pd.read_csv(MODEL_OUTPUT_PATH)
    except Exception as e:
        print(f"❌ Error al cargar archivos: {e}")
        return

    # Verificación mínima
    if ground_truth.empty or model_output.empty:
        print("⚠ Archivos vacíos. Asegúrate de haber generado correctamente los datos.")
        return

    # Asegurar estructura con columnas clave
    ground_truth["true_label"] = ground_truth["label"].apply(lambda x: 1 if x == "anomaly" else 0)
    ground_truth["id"] = ground_truth["timestamp"] + "-" + ground_truth["src_ip"] + "-" + ground_truth["dest_ip"]

    model_output["pred_label"] = model_output["anomaly_score"].apply(lambda x: 1 if x > THRESHOLD else 0)
    model_output["id"] = model_output["timestamp"] + "-" + model_output["src_ip"] + "-" + model_output["dest_ip"]

    # Unir ambos datasets por el ID común
    df = model_output.merge(ground_truth[["id", "true_label"]], on="id", how="left")
    df["true_label"] = df["true_label"].fillna(0)  # Eventos no etiquetados se consideran normales

    # Evaluar métricas
    y_true = df["true_label"]
    y_pred = df["pred_label"]
    y_scores = df["anomaly_score"]

    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    auc_roc = roc_auc_score(y_true, y_scores)

    print("✅ Evaluación completada:")
    print(f"  🔹 Precisión:     {precision:.2f}")
    print(f"  🔹 Recall:        {recall:.2f}")
    print(f"  🔹 F1-Score:      {f1:.2f}")
    print(f"  🔹 AUC-ROC:       {auc_roc:.2f}")

if __name__ == "__main__":
    evaluar_modelo()