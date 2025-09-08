# backend/artifacts_bootstrap.py
import os, csv
from pathlib import Path

MODELS_DIR = Path("/app/models")
PREPROC = MODELS_DIR / "suricata_preprocessed.csv"
GROUND  = MODELS_DIR / "ground_truth.csv"
ANALYSIS = MODELS_DIR / "suricata_anomaly_analysis.csv"
MODEL_PKL = MODELS_DIR / "isolation_forest_model.pkl"

PREPROC_HEADERS = [
    "src_ip","dest_ip","proto","src_port","dest_port",
    "alert_severity","packet_length","hour","is_night","ports_used","conn_per_ip",
    "anomaly"  # 0 normal, 1 anomaly, -1 unknown
]
GROUND_HEADERS = ["timestamp","src_ip","dest_ip","label"]  # normal|anomaly
ANALYSIS_HEADERS = ["timestamp","src_ip","dest_ip","prediction","anomaly_score"]

def _touch_csv_with_headers(path: Path, headers: list[str]):
    if not path.exists() or path.stat().st_size == 0:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as f:
            csv.writer(f).writerow(headers)

def ensure_artifacts_exist():
    _touch_csv_with_headers(PREPROC, PREPROC_HEADERS)
    _touch_csv_with_headers(GROUND, GROUND_HEADERS)
    _touch_csv_with_headers(ANALYSIS, ANALYSIS_HEADERS)
    MODEL_PKL.parent.mkdir(parents=True, exist_ok=True)