import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import io
from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
from rich.table import Table
import shutil
# Rutas de los archivos
GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"
MODEL_OUTPUT_PATH = "/app/models/suricata_anomaly_analysis.csv"

def evaluar_modelo():
    print("📊 Evaluando el rendimiento del modelo con base en el ground truth...")

    try:
        ground_truth = pd.read_csv(GROUND_TRUTH_PATH, dtype={"event_id": str})
        model_output = pd.read_csv(MODEL_OUTPUT_PATH, dtype={"event_id": str})
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

    expected_gt_columns = {"event_id", "prediction_g"}
    missing_gt_columns = expected_gt_columns - set(ground_truth.columns)
    if missing_gt_columns:
        print(f"❌ El archivo ground_truth.csv no contiene las columnas esperadas: {missing_gt_columns}")
        return

    df = pd.merge(model_output, ground_truth, on="event_id", how="inner")
    print(f"🔍 Total eventos combinados: {len(df)}")
    print(df.head())

    y_true = df["prediction_g"]
    y_pred = df["prediction"]
    score_col = "anomaly_score_x" if "anomaly_score_x" in df.columns else "anomaly_score"
    if score_col not in df.columns:
        print(f"❌ '{score_col}' no encontrado en el DataFrame combinado.")
        print(f"Columnas disponibles: {df.columns.tolist()}")
        return
    y_score = df[score_col]

    unique_labels = set(y_true)
    average_type = 'binary' if len(unique_labels) == 2 and unique_labels <= {0, 1} else 'weighted'
    print(f"🔍 Tipo de clasificación detectado: {'Binaria' if average_type == 'binary' else 'Multiclase'}")

    precision = precision_score(y_true, y_pred, average=average_type)
    recall = recall_score(y_true, y_pred, average=average_type)
    f1 = f1_score(y_true, y_pred, average=average_type)
    auc = roc_auc_score(y_true, y_score)

    print("✅ Evaluación completada:")
    print(f"  🔹 Precisión:     {precision:.2f}")
    print(f"  🔹 Recall:        {recall:.2f}")
    print(f"  🔹 F1-Score:      {f1:.2f}")
    print(f"  🔹 AUC-ROC:       {auc:.2f}")

    # Convertir etiquetas a formato binario para la matriz de confusión
    y_true_bin = [1 if label == 1 else 0 for label in y_true]
    y_pred_bin = [1 if pred == -1 else 0 for pred in y_pred]

    cm = confusion_matrix(y_true_bin, y_pred_bin)
    print("\n📊 Matriz de Confusión (formato [TN, FP]\n                          [FN, TP]):")
    print(cm)

    # Guardar imagen de la matriz de confusión
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Pred: Normal", "Pred: Anomaly"],
                yticklabels=["Real: Normal", "Real: Anomaly"])
    plt.title("Matriz de Confusión")
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    plt.savefig("/app/models/confusion_matrix.png")
    plt.close()

    # Mostrar la matriz de confusión en consola como tabla colorida (ASCII)
    print("\n📉 Matriz de Confusión (Visualización):\n")


    try:

        matplotlib.use('Agg')
        


        table = Table(title="Matriz de Confusión")
        table.add_column(" ", justify="right", style="cyan", no_wrap=True)
        table.add_column("Pred: Normal", justify="center", style="magenta")
        table.add_column("Pred: Anomaly", justify="center", style="magenta")

        table.add_row("Real: Normal", str(cm[0][0]), str(cm[0][1]))
        table.add_row("Real: Anomaly", str(cm[1][0]), str(cm[1][1]))

        console = Console()
        console.print(table)

    except Exception as e:
        print(f"⚠ No se pudo renderizar la tabla en consola: {e}")

if __name__ == "__main__":
    evaluar_modelo()