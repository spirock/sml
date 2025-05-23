import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

# Rutas de los archivos
GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"
MODEL_OUTPUT_PATH = "/app/models/suricata_anomaly_analysis.csv"

def evaluar_modelo():
    print("📊 Evaluando el rendimiento del modelo con base en el ground truth...")

    try:
        ground_truth = pd.read_csv(GROUND_TRUTH_PATH)
        model_output = pd.read_csv(MODEL_OUTPUT_PATH)
    except Exception as e:
        print(f"❌ Error al cargar archivos: {e}")
        return

    if ground_truth.empty or model_output.empty:
        print("⚠ Archivos vacíos. Asegúrate de haber generado correctamente los datos.")
        return

    # Crear IDs únicos
    ground_truth["id"] = ground_truth["timestamp"] + "-" + ground_truth["src_ip"] + "-" + ground_truth["dest_ip"]
    ground_truth["true_label"] = ground_truth["label"].map({"anomaly": 1, "normal": 0})

    model_output["id"] = model_output["timestamp"] + "-" + model_output["src_ip"] + "-" + model_output["dest_ip"]
    model_output["pred_label"] = model_output["prediction"].map({-1: 1, 1: 0})  # Anomalía = 1

    df = model_output.merge(ground_truth[["id", "true_label"]], on="id", how="left")
    df["true_label"] = df["true_label"].fillna(0).astype(int)  # default: normal

    y_true = df["true_label"]
    y_pred = df["pred_label"]
    y_score = df["anomaly_score"]

    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_score)

    print("✅ Evaluación completada:")
    print(f"  🔹 Precisión:     {precision:.2f}")
    print(f"  🔹 Recall:        {recall:.2f}")
    print(f"  🔹 F1-Score:      {f1:.2f}")
    print(f"  🔹 AUC-ROC:       {auc:.2f}")

if __name__ == "__main__":
    evaluar_modelo()