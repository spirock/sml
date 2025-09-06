import sys
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    precision_recall_curve,
    average_precision_score,
)
import seaborn as sns
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from rich.console import Console
from rich.table import Table
from constants import ANOMALY_PREDICTION

# Rutas de los archivos
GROUND_TRUTH_PATH = "/app/models/ground_truth.csv"
MODEL_OUTPUT_PATH = "/app/models/suricata_anomaly_analysis.csv"
THRESHOLD_REPORT = "/app/models/threshold_report.csv"
SELECTED_THRESHOLD_FILE = "/app/models/selected_threshold.txt"


def _pick_label_column(gt: pd.DataFrame) -> str:
    # Compatibilidad con tus variantes previas
    for c in ["prediction_g", "training_label", "label"]:
        if c in gt.columns:
            return c
    return None


def evaluar_modelo():
    print("📊 Evaluando el rendimiento del modelo con base en el ground truth…")

    try:
        ground_truth = pd.read_csv(GROUND_TRUTH_PATH, dtype={"event_id": str})
        model_output = pd.read_csv(MODEL_OUTPUT_PATH, dtype={"event_id": str})
    except Exception as e:
        print(f"❌ Error al cargar archivos: {e}")
        sys.exit(1)

    if ground_truth.empty or model_output.empty:
        print("⚠ Archivos vacíos. Asegúrate de haber generado correctamente los datos.")
        sys.exit(1)

    # Chequeos mínimos
    if "event_id" not in model_output.columns:
        print("❌ El archivo de modelo debe contener 'event_id'.")
        sys.exit(1)

    score_col_candidates = ["anomaly_score", "anomaly_score_x"]
    score_col = next((c for c in score_col_candidates if c in model_output.columns), None)
    if score_col is None:
        print("❌ El archivo de salida del modelo no contiene columna 'anomaly_score'.")
        sys.exit(1)

    label_col = _pick_label_column(ground_truth)
    if label_col is None:
        print("❌ ground_truth.csv no contiene 'prediction_g', 'training_label' ni 'label'.")
        sys.exit(1)

    df = pd.merge(model_output, ground_truth[["event_id", label_col]], on="event_id", how="inner")
    df = df.rename(columns={label_col: "gt_label"})

    if df.empty:
        print("⚠ No hay intersección entre eventos del modelo y ground truth.")
        sys.exit(1)

    # Normalizamos predicción del modelo a binaria: 1 = anomalía, 0 = normal
    if "prediction" in df.columns:
        df["prediction_bin"] = np.where(df["prediction"] == ANOMALY_PREDICTION, 1, 0)
    else:
        df["prediction_bin"] = 0  # fallback si no venía la columna

    # Ground truth binaria
    y_true = (df["gt_label"].astype(str).str.lower() == "anomaly").astype(int).values

    # Puntaje de normalidad del modelo (mayor = más normal)
    # Tras el merge puede duplicarse como *_x; priorizamos la del modelo
    if "anomaly_score_x" in df.columns:
        score_col = "anomaly_score_x"
    elif "anomaly_score" in df.columns:
        score_col = "anomaly_score"
    else:
        print("❌ No se encontró columna de 'anomaly_score' tras el merge.")
        sys.exit(1)
    y_score = df[score_col].astype(float).values

    print(f"🔍 Total eventos combinados: {len(df)}")

    # ========= 1) MÉTRICAS BASE usando la predicción original del modelo =========
    y_pred_base = df["prediction_bin"].values
    unique_labels = set(y_true)
    average_type = 'binary' if len(unique_labels) == 2 and unique_labels <= {0, 1} else 'weighted'

    # Curva Precision-Recall y AP con los scores continuos
    precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_score)
    ap_score = average_precision_score(y_true, y_score)

    print("\n📋 Reporte de Clasificación (predicción original del modelo):")
    print(classification_report(y_true, y_pred_base, target_names=["Normal", "Anomaly"]))

    precision_base = precision_score(y_true, y_pred_base, average=average_type, zero_division=0)
    recall_base = recall_score(y_true, y_pred_base, average=average_type, zero_division=0)
    f1_base = f1_score(y_true, y_pred_base, average=average_type, zero_division=0)
    auc_base = roc_auc_score(y_true, y_score)

    print("✅ Evaluación base:")
    print(f"  🔹 Precisión:     {precision_base:.2f}")
    print(f"  🔹 Recall:        {recall_base:.2f}")
    print(f"  🔹 F1-Score:      {f1_base:.2f}")
    print(f"  🔹 AUC-ROC:       {auc_base:.2f}")

    cm_base = confusion_matrix(y_true, y_pred_base)
    print("\n📊 Matriz de Confusión (BASE) [TN FP; FN TP]:")
    print(cm_base)

    # Guardar imagen de la matriz de confusión base
    sns.heatmap(cm_base, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Pred: Normal", "Pred: Anomaly"],
                yticklabels=["Real: Normal", "Real: Anomaly"])
    plt.title("Matriz de Confusión - Base")
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    plt.savefig("/app/models/confusion_matrix_base.png")
    plt.close()

    # ========= 2) SELECCIÓN DE UMBRAL por F1 con los scores =========
    grid = np.quantile(y_score, np.linspace(0.80, 0.995, 60))
    grid = np.unique(grid)
    if grid.size == 0:
        print("⚠ Rejilla vacía para scores. Revisa 'anomaly_score'.")
        sys.exit(1)

    evals = []
    for t in grid:
        y_pred_thr = (y_score < t).astype(int)
        evals.append((
            t,
            precision_score(y_true, y_pred_thr, zero_division=0),
            recall_score(y_true, y_pred_thr, zero_division=0),
            f1_score(y_true, y_pred_thr, zero_division=0),
        ))

    thr, p, r, f1v = max(evals, key=lambda x: x[3])

    # Persistir artefactos del umbral
    pd.DataFrame({"threshold": [thr], "precision": [p], "recall": [r], "f1": [f1v]}).to_csv(THRESHOLD_REPORT, index=False)
    with open(SELECTED_THRESHOLD_FILE, "w") as f:
        f.write(str(thr))

    cm_thr = confusion_matrix(y_true, (y_score < thr).astype(int))

    print("\n🎯 Selección de umbral por F1 (con scores):")
    print(f"Precision={p:.3f} Recall={r:.3f} F1={f1v:.3f} Thr={thr:.6f}")
    print("CM (umbral):")
    print(cm_thr)

    # Guardar imagen de la matriz de confusión con umbral
    sns.heatmap(cm_thr, annot=True, fmt="d", cmap="Greens",
                xticklabels=["Pred: Normal", "Pred: Anomaly"],
                yticklabels=["Real: Normal", "Real: Anomaly"])
    plt.title("Matriz de Confusión - Umbral F1")
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    plt.savefig("/app/models/confusion_matrix_threshold.png")
    plt.close()

    # Mostrar matrices en consola con Rich
    console = Console()
    for title, cm in [("BASE", cm_base), ("UMBRAL F1", cm_thr)]:
        table = Table(title=f"Matriz de Confusión - {title}")
        table.add_column(" ", justify="right", style="cyan", no_wrap=True)
        table.add_column("Pred: Normal", justify="center", style="magenta")
        table.add_column("Pred: Anomaly", justify="center", style="magenta")
        table.add_row("Real: Normal", str(cm[0][0]), str(cm[0][1]))
        table.add_row("Real: Anomaly", str(cm[1][0]), str(cm[1][1]))
        console.print(table)

    analizar_falsos_negativos(df, score_col)


def analizar_falsos_negativos(df: pd.DataFrame, score_col: str):
    # Falsos negativos respecto al UMBRAL F1: reales anomalías pero predichas como normal
    gt = (df["gt_label"].astype(str).str.lower() == "anomaly").astype(int)
    # Si guardaste el umbral, recupéralo; si no, usa percentil 98 como fallback
    try:
        thr = float(open(SELECTED_THRESHOLD_FILE).read().strip())
    except Exception:
        thr = float(np.quantile(df[score_col].astype(float).values, 0.98))

    y_pred_thr = (df[score_col].astype(float).values < thr).astype(int)
    fn_mask = (gt == 1) & (y_pred_thr == 0)
    fn = df.loc[fn_mask]

    print("\n🔍 Análisis Detallado de Falsos Negativos (umbral F1):")
    proto_col = next((c for c in ["proto_x", "proto"] if c in fn.columns), None)
    dport_col = next((c for c in ["dest_port_x", "dest_port"] if c in fn.columns), None)
    if proto_col:
        print("Top Protocolos:", fn[proto_col].value_counts().head(3).to_dict())
    if dport_col:
        print("Distribución de Puertos:")
        try:
            print(fn[dport_col].describe(percentiles=[0.5, 0.9, 0.99]))
        except Exception:
            pass

    # Guardar ejemplos críticos: los con score más alto (más "normales", peores FN)
    try:
        fn_sorted = fn.sort_values(score_col, ascending=False).head(20)
        fn_sorted.to_csv("/app/models/fn_analysis.csv", index=False)
    except Exception as e:
        print(f"⚠ No se pudo guardar fn_analysis.csv: {e}")


if __name__ == "__main__":
    evaluar_modelo()