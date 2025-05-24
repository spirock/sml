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

    expected_columns = {"event_id", "prediction", "anomaly_score"}
    missing_columns = expected_columns - set(model_output.columns)
    if missing_columns:
        print(f"❌ El archivo de salida del modelo no contiene las columnas esperadas: {missing_columns}")
        return

    expected_gt_columns = {"event_id", "label"}
    missing_gt_columns = expected_gt_columns - set(ground_truth.columns)
    if missing_gt_columns:
        print(f"❌ El archivo ground_truth.csv no contiene las columnas esperadas: {missing_gt_columns}")
        return

    df = pd.merge(model_output, ground_truth, on="event_id", how="inner")
    print(f"🔍 Total eventos combinados: {len(df)}")
    print(df.head())

    y_true = df["label"]
    y_pred = df["prediction"]
    score_col = "anomaly_score_x" if "anomaly_score_x" in df.columns else "anomaly_score"
    if score_col not in df.columns:
        print(f"❌ '{score_col}' no encontrado en el DataFrame combinado.")
        print(f"Columnas disponibles: {df.columns.tolist()}")
        return
    y_score = df[score_col]

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