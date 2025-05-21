# 📁 suricata_preprocessed.csv

Este archivo contiene los datos de eventos de red preprocesados por el sistema Suricata + Machine Learning, y es la **fuente de entrenamiento del modelo Isolation Forest**.

---

## 📌 Objetivo

`suricata_preprocessed.csv` sirve como entrada para el modelo de Machine Learning encargado de detectar tráfico anómalo en la red. El archivo incluye **eventos extraídos desde MongoDB**, transformados y normalizados, listos para entrenamiento.

---

## 📄 Formato esperado

El archivo debe tener las siguientes columnas, todas numéricas y normalizadas:

| Columna        | Descripción                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
| src_ip         | IP origen (convertida a entero)                                              |
| dest_ip        | IP destino (convertida a entero)                                             |
| proto          | Protocolo (TCP, UDP, ICMP, convertido a código numérico)                     |
| src_port       | Puerto de origen                                                             |
| dest_port      | Puerto de destino                                                            |
| alert_severity | Severidad de la alerta (si existe)                                           |
| packet_length  | Longitud del paquete                                                         |
| hour           | Hora del evento (0-23)                                                       |
| is_night       | 1 si el evento ocurre de noche (antes de las 7 o después de las 20), 0 si no |
| ports_used     | Cantidad de puertos únicos usados por IP origen                              |
| conn_per_ip    | Total de conexiones hechas por la IP origen                                  |

> 🔍 Todos los valores son **normalizados entre 0 y 1**, excepto `is_night` que es binario (0 o 1).

---

## 🧠 ¿Cómo se genera?

Este archivo es generado automáticamente por el script:

```bash
ml_processing.py
```

Este script es ejecutado automáticamente por `log_watcher.py` cuando se detectan nuevos eventos en `eve.json`.

---

## 🛠 Uso posterior

El archivo `suricata_preprocessed.csv` es usado por:

```bash
train_model.py
```

...para entrenar el modelo Isolation Forest y generar:

- `isolation_forest_model.pkl` (modelo entrenado)
- `suricata_anomaly_analysis.csv` (resultado con scores y predicciones)

---

## ⚠ Importante

- El archivo no debe contener valores vacíos (NaN).
- Si no hay eventos válidos, el archivo puede no generarse.
- Debe estar ubicado en la ruta:

```bash
/app/models/suricata_preprocessed.csv
```

---

## 🧪 Validación recomendada

Antes de entrenar, asegúrate de que:

- El archivo existe.
- Contiene columnas válidas y al menos una fila.
