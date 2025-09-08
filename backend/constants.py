"""
Constantes globales para Suricata+ML.

- Umbrales y etiquetas
- Rutas de artefactos de modelo
- Modos de operación
- Políticas anti-falsos positivos para generación de reglas
"""

# Etiquetas y predicción del modelo
ANOMALY_PREDICTION = -1
LABEL_NORMAL = "normal"
LABEL_ANOMALY = "anomaly"
RULES_FILE = "/var/lib/suricata/rules/sml.rules"
RULES_DIR  = "/var/lib/suricata/rules"

# Umbrales
ANOMALY_THRESHOLD = -0.2  # Fallback si no hay umbral calibrado
DEFAULT_PERCENTILE = 0.98  # Percentil (0–1) por defecto para el umbral externo

# Directorios y rutas de artefactos
MODEL_DIR = "/app/models"
SURICATA_ANALYSIS_CSV = f"{MODEL_DIR}/suricata_anomaly_analysis.csv"
GROUND_TRUTH_CSV = f"{MODEL_DIR}/ground_truth.csv"
THRESHOLD_REPORT_CSV = f"{MODEL_DIR}/threshold_report.csv"
SELECTED_THRESHOLD_FILE = f"{MODEL_DIR}/selected_threshold.txt"
THRESHOLDS_JSON = f"{MODEL_DIR}/thresholds.json"
FEATURE_COLS_JSON = f"{MODEL_DIR}/feature_cols.json"
IFOREST_MODEL = f"{MODEL_DIR}/isolation_forest_model.pkl"
SUPERVISED_MODEL = f"{MODEL_DIR}/supervised.pkl"
PROTOTYPES_PKL = f"{MODEL_DIR}/prototypes.pkl"
APP_MODE_FILE = f"{MODEL_DIR}/app_mode.json"

# Modos de operación
MODE_NORMAL = "normal"   # etiqueta en vivo como normal
MODE_ANOMALY = "anomaly" # etiqueta en vivo como anomalía
MODE_OFF = "off"         # detección/producción, sin etiquetado

# Políticas anti-falsos positivos
ALERT_ONLY_PORTS = {53, 80, 123, 443}              # Nunca DROP por score aislado
LOCAL_SERVICES = {"10.0.2.3", "192.168.10.1"}      # DNS VBox y Smlu (excluir de DROP)

# Criterios de decisión
MIN_PRECISION_FOR_THRESHOLD = 0.95                 # Precisión mínima al calibrar umbral IF
MIN_SEVERITY_TO_DROP = 2                           # Severidad requerida para permitir DROP
MIN_FREQ_TO_DROP = 5                               # Frecuencia mínima por {src_ip,dest_port}