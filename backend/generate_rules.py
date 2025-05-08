import joblib
import pandas as pd
from db_connection import db
import os
import asyncio
import ipaddress
import numpy as np
import subprocess
from pathlib import Path
import hashlib

# 📌 Rutas importantes
RULES_FILE = "/var/lib/suricata/rules/sml.rules"
DATA_PATH = "/app/models/suricata_preprocessed.csv"
MODEL_PATH = "/app/models/isolation_forest_model.pkl"
SOCKET_PATH = "/var/run/suricata/suricata-command.socket"

# 📂 Verificar modelo entrenado
if not os.path.exists(MODEL_PATH):
    print(f"[GR] ❌ No se encontró el modelo {MODEL_PATH}. Asegúrate de entrenarlo antes.")
    exit(1)

model = joblib.load(MODEL_PATH)

# 📂 Verificar que los datos preprocesados existen
if not os.path.exists(DATA_PATH):
    print(f"[GR] ❌ No se encontró el archivo {DATA_PATH}. Asegúrate de ejecutarlo antes.")
    exit(1)

df_processed = pd.read_csv(DATA_PATH)

# 🧪 Validar datos
if df_processed.empty:
    print("[GR] ❌ Error: No hay datos para predecir reglas de Suricata.")
    exit(1)

# 📌 Convertir IPs a enteros
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0

if "src_ip" in df_processed.columns:
    df_processed["src_ip"] = df_processed["src_ip"].astype(str).apply(ip_to_int)
if "dest_ip" in df_processed.columns:
    df_processed["dest_ip"] = df_processed["dest_ip"].astype(str).apply(ip_to_int)

# Convertir columnas a numérico y limpiar NaN
for col in df_processed.columns:
    df_processed[col] = pd.to_numeric(df_processed[col], errors="coerce")
df_processed.fillna(0, inplace=True)

# ✅ Solo columnas numéricas para el modelo
df_numeric = df_processed.select_dtypes(include=[np.number])

# Verificar dimensiones
expected_features = model.n_features_in_
if df_numeric.shape[1] != expected_features:
    print(f"[GR] ❌ El modelo espera {expected_features} columnas, pero los datos tienen {df_numeric.shape[1]}.")
    print(f"[GR] 📝 Columnas entregadas: {df_numeric.columns.tolist()}")
    exit(1)

# 🔍 Ejecutar predicción
print("[GR] 🔍 Ejecutando predicciones con Isolation Forest...")
df_processed["prediction"] = model.predict(df_numeric)

# 📥 Obtener eventos desde MongoDB
async def fetch_latest_events():
    collection = db["events"]
    cursor = collection.find({}, {"_id": 0}).limit(100)
    return await cursor.to_list(length=100)

def rule_exists_in_file(rule_content, filename):
    """Verifica si una regla ya existe en el archivo"""
    if not os.path.exists(filename):
        return False
    with open(filename, 'r') as f:
        existing_rules = f.read().splitlines()
    return rule_content in existing_rules

async def generate_suricata_rules():
    # [Código anterior para obtener eventos y detectar anomalías...]
    
    # Cargar TODAS las reglas existentes (no solo las de esta ejecución)
    existing_rules = set()
    rule_patterns = set()  # Para detectar patrones duplicados
    
    if Path(RULES_FILE).exists():
        with open(RULES_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    existing_rules.add(line)
                    # Extraer el patrón básico (sin SID ni rev)
                    rule_parts = line.split('(')
                    if len(rule_parts) > 1:
                        rule_base = rule_parts[0].strip()
                        rule_patterns.add(rule_base)

    # Generar nuevas reglas
    new_rules = []
    rules_to_add = set()
    
    for _, event in anomalies.iterrows():
        if pd.notna(event["src_ip"]) and pd.notna(event["dest_ip"]):
            # Normalizar IPs para consistencia
            src_ip = str(ipaddress.ip_address(event["src_ip"]))
            dest_ip = str(ipaddress.ip_address(event["dest_ip"]))
            
            # Determinar acción y mensaje
            score = event.get("anomaly_score", 0)
            action = "drop" if score <= -0.2 else "alert"
            msg = "BLOCKED traffic (high risk)" if action == "drop" else "Suspicious traffic (alert only)"
            
            # Crear patrón de regla base (sin SID)
            rule_base = f'{action} ip {src_ip} any -> {dest_ip} any'
            
            # Verificar si este patrón ya existe
            if rule_base in rule_patterns:
                continue
                
            # Generar SID consistente usando hash SHA1
            rule_id = f"{src_ip}-{dest_ip}-{action}-{msg}"
            sid = 1000000 + (int(hashlib.sha1(rule_id.encode()).hexdigest(), 16) % 900000)
            
            # Construir regla completa
            rule_content = f'{rule_base} (msg:"{msg}"; sid:{sid}; rev:1;)'
            
            # Verificar duplicados exactos
            if rule_content not in existing_rules and rule_content not in rules_to_add:
                new_rules.append(rule_content)
                rules_to_add.add(rule_content)
                rule_patterns.add(rule_base)

    # Escribir todas las reglas (sobrescribiendo el archivo completo)
    if new_rules:
        # Mantener las reglas existentes válidas
        valid_existing_rules = [r for r in existing_rules if not r.startswith(('drop ip', 'alert ip'))]
        
        with open(RULES_FILE, 'w') as f:
            # 1. Escribir reglas existentes no generadas automáticamente
            f.write("\n".join(valid_existing_rules))
            f.write("\n")
            
            # 2. Escribir nuevas reglas
            f.write("\n".join(new_rules))
            f.write("\n")
            
        print(f"[GR] ✅ {len(new_rules)} nuevas reglas añadidas (total: {len(valid_existing_rules)+len(new_rules)})")
        
        # Recargar reglas en Suricata (usando tu método preferido)
        await reload_suricata_rules()
    else:
        print("[GR] No se detectaron nuevas anomalías o todas ya estaban registradas.")

async def reload_suricata_rules():
    """Función para recargar reglas en Suricata"""
    try:
        socket_path = "/var/run/suricata/suricata-command.socket"
        reload_result = subprocess.run(
            ['suricatasc', '-s', socket_path, '-c', 'reload-rules'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if reload_result.returncode == 0 and "OK" in reload_result.stdout:
            print("[GR] 🔄 Reglas recargadas exitosamente en Suricata")
            return True
        else:
            error_msg = reload_result.stderr or reload_result.stdout
            print(f"[GR] ❌ Error al recargar reglas: {error_msg}")
            return False
    except Exception as e:
        print(f"[GR] ❌ Error al recargar reglas: {str(e)}")
        return False

# 🚀 Ejecutar
if __name__ == "__main__":
    try:
        asyncio.run(generate_suricata_rules())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(generate_suricata_rules())
