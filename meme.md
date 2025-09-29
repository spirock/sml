# TÍTULO DEL PFM

## SUBTÍTULO DEL PFM

**Autor:** Elkin Leonel Rodríguez Castro
**Programa:** Master de Ciberseguridad
**Universidad:** Universidad Politecnica de catalunya
**Tutor/a:** Rene  
**Fecha:** Septiembre, 2025

> _(Esta página queda en blanco intencionalmente para respetar el formato de memoria.)_

---

## Contenido

1. Resumen
2. Presentación  
   2.1 Motivación  
   2.2 Objetivos y alcance  
   2.3 Aportaciones
3. Metodología  
   3.1 Tecnologías analizadas y decisiones de diseño  
   3.2 Fases y desarrollo del trabajo  
   3.3 Calendario
4. Descripción del sistema  
   4.1 Arquitectura y flujo de datos  
   4.2 Ingesta y almacenamiento (Suricata → MongoDB)  
   4.3 Preprocesamiento y _feature engineering_  
   4.4 Entrenamiento y evaluación del modelo  
   4.5 Generación y recarga de reglas en Suricata  
   4.6 API y despliegue con Docker  
   4.7 Seguridad, privacidad y consideraciones éticas
5. Resultados y evaluación  
   5.1 Dataset y _ground truth_  
   5.2 Procedimiento experimental  
   5.3 Métricas y análisis
6. Conclusiones y trabajo futuro
7. Bibliografía
8. Anexos

---

## 1. Resumen

Este proyecto implementa un prototipo de **detección y respuesta ante anomalías de red** que integra el IDS/IPS **Suricata** con un pipeline de **aprendizaje automático** (_Isolation Forest_) y una **API** (_FastAPI_) para control operativo. La solución:

- captura eventos en tiempo real (**eve.json**),
- persiste en **MongoDB**,
- preprocesa y enriquece datos,
- entrena/actualiza un modelo de anomalías,
- **genera reglas** para mitigar tráfico sospechoso y las recarga vía `suricatasc`,
- incorpora un **modo entrenamiento** con etiquetas (_normal/anomaly_) para construir _ground truth_ interno y evaluar el rendimiento (Precisión, _Recall_, F1, AUC-ROC).

Se presentan decisiones de diseño, procedimientos reproducibles con Docker, pruebas con tráfico real/sintético y una **estrategia de agregación de reglas por IP** que reduce la explosión de reglas por puerto.

---

## 2. Presentación

### 2.1 Motivación

El crecimiento del tráfico y la diversidad de amenazas limita a los IDS basados en firmas. Se requiere detectar **comportamientos inéditos** y **automatizar** respuestas de forma controlada. Este trabajo explora un enfoque práctico y reproducible para un entorno corporativo/educativo.

### 2.2 Objetivos y alcance

**Objetivo general.** Diseñar y validar un pipeline de detección basada en anomalías integrado con un IDS/IPS para respuesta automática.

**Objetivos específicos.**

- O1. Integrar Suricata, MongoDB y FastAPI en Docker.
- O2. Diseñar un **modo _training_** etiquetado (_normal/anomaly_).
- O3. Preprocesar y generar _features_ relevantes de tráfico.
- O4. Entrenar y evaluar **Isolation Forest** con métricas estándar.
- O5. Generar y recargar reglas Suricata automáticamente.
- O6. Documentar reproducibilidad, riesgos y mejoras futuras.

**Alcance.** Detección de anomalías en flujo de red; respuesta vía reglas Suricata.  
**No incluye.** Clasificación por familia de malware, forense profundo, despliegue multi-sede.

### 2.3 Aportaciones

- Modo _training_ con etiqueta persistida (MongoDB) para construir _ground truth_.
- Pipeline completo **Suricata → MongoDB → ML → Reglas**, reproducible con Docker.
- _Feature engineering_ extensible (hora, nocturnidad, puertos únicos, conexiones por IP, etc.).
- **Agregación por IP** para reducir miles de reglas por-puerto.
- Playbook de evaluación con _tcpreplay_ y script de métricas.

---

## 3. Metodología

### 3.1 Enfoque metodológico (ágil y modular)

La metodología combina **prácticas ágiles** (iteraciones cortas, feedback continuo) y un **diseño modular** que permite evolucionar cada componente por separado. Cada iteración incluye:

1. planificación y análisis de requisitos,
2. implementación o mejora de un módulo,
3. pruebas unitarias/integración,
4. revisión de métricas (Precisión/Recall/F1/AUC), y
5. decisiones de siguiente sprint.

**Principios rectores**: reproducibilidad (Docker Compose), _infra as code_, trazabilidad (Git), observabilidad (logs/métricas) y bajo acoplamiento entre módulos.

### 3.2 Tecnologías analizadas y decisiones de diseño

- **IDS/IPS:** Suricata (multi-hilo, salida JSON en `eve.json`, soporte TLS/QUIC/JA3) vs Snort.  
  **Decisión:** Suricata por rendimiento y formato JSON nativo.
- **Almacenamiento:** MongoDB por inserción rápida y **esquema flexible** (eventos heterogéneos).
- **ML:** Isolation Forest (no supervisado, robusto a _outliers_) para detección de anomalías.  
  Alternativas consideradas: One-Class SVM, LOF, Autoencoders (en trabajo futuro).
- **API/orquestación:** FastAPI (asincronía, tipado, documentación automática).
- **Contenedores:** Docker Compose (entorno reproducible).  
  **Red:** `network_mode: host` para Suricata y socket UNIX compartido para recarga de reglas con `suricatasc`.

### 3.3 Fases y desarrollo del trabajo

- **Recolección de datos.** Suricata captura eventos en `eve.json` que se ingieren en MongoDB. En modo _training_ se almacenan todos los tipos de evento; en modo normal se priorizan `alert`.
- **Preprocesamiento y análisis.** `ml_processing.py` limpia, transforma y construye _features_ (IP/puerto/protocolo, hora, nocturnidad, puertos únicos, conexiones por IP), normaliza y genera `suricata_preprocessed.csv`.
- **Entrenamiento del modelo.** `train_model.py` entrena **Isolation Forest** (no supervisado, robusto frente a valores atípicos) y produce `isolation_forest_model.pkl` y `suricata_anomaly_analysis.csv` con `prediction` y `anomaly_score`.
- **Generación de reglas.** `generate_rules.py` aplica umbrales sobre `anomaly_score` y crea reglas Suricata. Incluye **agregación por IP** para bloquear orígenes que atacan múltiples puertos y evita duplicados; recarga con `suricatasc`.
- **Implementación y monitoreo.** Despliegue en Docker (FastAPI + Suricata + MongoDB); `log_watcher.py` y endpoints `/training-mode` permiten actualizar reglas y repetir ciclos de aprendizaje con _ground truth_.

### 3.4 Plan de calidad y validación

- **Unitarias:** transformaciones de _features_, parsers de IP, mapeos de etiquetas.
- **Integración:** inserciones en MongoDB, generación de CSV, entrenamiento y evaluación.
- **E2E:** reproducción de tráfico (normal/anómalo) con `tcpreplay`, verificación de detecciones y reglas aplicadas.
- **Evaluación continua:** reporte de KPIs por iteración.
- **Mitigaciones:** listas blancas, límite de reglas agregadas por IP y _dry-run_ para nuevas políticas.

### 3.5 Calendario (estimado)

| Fase | Actividad                         | Semanas |
| ---: | --------------------------------- | :-----: |
|    1 | Planificación y análisis          |    1    |
|    2 | Ingesta y persistencia            |    1    |
|    3 | Preprocesamiento/_features_       |    1    |
|    4 | Entrenamiento y evaluación        |    1    |
|    5 | Generación/recarga de reglas      |    1    |
|    6 | Integración y pruebas E2E         |    1    |
|    7 | Despliegue, monitorización y docs |    1    |

---

## 4. Descripción del sistema

### 4.1 Arquitectura y flujo de datos

```mermaid
flowchart LR
  A[Tráfico de red] --> B[Suricata (eve.json)]
  B --> C[suricata_to_mongo.py]
  C --> D[MongoDB (events)]
  D --> E[ml_processing.py (features CSV)]
  E --> F[train_model.py (IF model + analysis CSV)]
  F --> G[generate_rules.py (sml.rules)]
  G --> H[suricatasc (reload)]
  D --> I[generate_ground_truth.py (ground_truth.csv)]
  F --> J[evaluate.py (métricas)]
  K[FastAPI /routes] --> D
  K --> H
```

### 4.2 Ingesta y almacenamiento (Suricata → MongoDB)

- Suricata escribe JSON en `/var/log/suricata/eve.json`.
- `suricata_to_mongo.py`:
  - lee línea a línea,
  - _modo normal_: prioriza `event_type="alert"`,
  - _modo training_: inserta **todos** los `event_type` (alert, dns, http, quic, stats, etc.),
  - añade `training_mode: bool` y `training_label: "normal"|"anomaly"|"undefined"` (siempre presentes).

### 4.3 Preprocesamiento y _feature engineering_

- `ml_processing.py` genera `/app/models/suricata_preprocessed.csv`.
- Conversión a numérico:
  - IP → entero (IPv4), IPv6 → valor neutro/0 si no se soporta.
  - Protocolo → códigos categóricos.
- _Features_ base:
  - `src_ip`, `dest_ip`, `proto`, `src_port`, `dest_port`,
  - `alert_severity` (si existe), `packet_length`.
- _Features_ derivadas:
  - `hour`, `is_night` (0/1),
  - `ports_used` por `src_ip`,
  - `conn_per_ip` (conteo de conexiones por `src_ip`),
  - `anomaly_flag` (del _training_label_: normal=0, anomaly=1, undefined=0.5).
- Normalización robusta y _fillna_ seguro. Manejo de columnas ausentes.

> **Nota:** aunque se almacena `anomaly_flag`, **Isolation Forest** se entrena como no supervisado; la etiqueta sirve para análisis y calibración.

### 4.4 Entrenamiento y evaluación del modelo

- `train_model.py`:
  - carga `suricata_preprocessed.csv`,
  - entrena **IsolationForest (n_estimators≈100–200, contamination≈0.03–0.05)**,
  - guarda `isolation_forest_model.pkl`,
  - exporta `suricata_anomaly_analysis.csv` con `prediction` (1 normal / -1 anomalía) y `anomaly_score`.
- `evaluate.py`:
  - compara `suricata_anomaly_analysis.csv` vs `ground_truth.csv`,
  - calcula **Precisión, Recall, F1, AUC-ROC**,
  - identifica FPs/FNs para análisis cualitativo.

### 4.5 Generación y recarga de reglas en Suricata

- `generate_rules.py`:
  - convierte eventos anómalos en reglas (por flujo),
  - **agregación por IP**: si una IP abre muchos puertos sospechosos, genera una **regla global por IP** (e.g., `drop ip &lt;src_ip&gt; any -&gt; any any`) cuando supera un umbral,
  - evita duplicados y _SIDs_ repetidos,
  - guarda en `sml.rules` y recarga con `suricatasc` sin bloquear el _pipeline_.
- Estrategia: primero bloquear _fine-grained_; cuando un origen persiste, subir a _drop IP_.

### 4.6 API y despliegue (Docker)

- **FastAPI** (`routes.py`):
  - `GET /training-mode` → `{ value, label }`
  - `POST /training-mode/on?label=normal|anomaly`
  - `POST /training-mode/off`
  - `POST /generate-rules`, `GET /rules`, `GET /stats`, etc.
- **Docker Compose**:
  - Volúmenes para `logs`, `models`, `rules`,
  - `network_mode: host` para Suricata,
  - socket compartido `/var/run/suricata` para recarga.

### 4.7 Seguridad, privacidad y ética

- Minimizar datos personales: no almacenar _payloads_ sensibles.
- Consentimiento en pruebas con usuarios/entornos reales.
- _Fail-safe_: listas blancas y modo _alert_ antes de _drop_ global.
- Retención de datos y cumplimiento normativo (GDPR/LOPDGDD si aplica).

---

## 5. Resultados y evaluación

### 5.1 Dataset y _ground truth_

- **Tráfico normal**: navegación web, correo, repositorios, herramientas corporativas (10–30 min).
- **Tráfico anómalo**: escaneo Nmap, floods HTTP/ICMP, conexiones a puertos no expuestos, etc.
- **Mezcla** con `mergecap` y reproducción con `tcpreplay`.
- **Etiquetado**:
  - _training normal_ → etiqueta `normal`,
  - _training anomaly_ → etiqueta `anomaly`,
  - consolidación con `generate_ground_truth.py`.

### 5.2 Procedimiento experimental

1. Activar _training normal_ y generar tráfico legítimo.
2. Activar _training anomaly_ y lanzar ataques controlados.
3. Ejecutar `ml_processing.py` → CSV de _features_.
4. Entrenar: `train_model.py`.
5. Evaluar: `evaluate.py` → métricas y matriz FP/FN.
6. Ajustar umbral/contamination y repetir.

### 5.3 Métricas y análisis

|   Métrica | Valor | Observación breve |
| --------: | :---: | ----------------- |
| Precisión |   …   | …                 |
|    Recall |   …   | …                 |
|  F1-Score |   …   | …                 |
|   AUC-ROC |   …   | …                 |

**Análisis cualitativo.**

- **FPs** más comunes: … (p. ej., picos nocturnos, backups, _scans_ internos autorizados).
- **FNs** más comunes: … (p. ej., tráfico cifrado poco distintivo, puertos comunes).
- **Efecto agregación por IP:** reducción de N reglas → 1 por IP en casos de _port-scan_ persistente.

---

## 6. Conclusiones y trabajo futuro

**Conclusiones.**

- El pipeline propuesto es **reproducible** y **útil** para detectar comportamientos inusuales, integrando respuesta automática.
- El modo _training_ permite construir _ground truth_ propio y **medir** el rendimiento del modelo de forma continua.

**Trabajo futuro.**

- Nuevas _features_ (ratio _in/out_, periodicidad, JA3/JA3S, _burstiness_).
- Modelos alternativos (LOF, OCSVM, autoencoders).
- **Active learning** / _human-in-the-loop_ para reducir _label noise_.
- Correlación multi-host, alertas enriquecidas y listas blancas dinámicas.
- Despliegue distribuido con _tenants_ y _multi-sensor_.

---

## 7. Bibliografía

> Añade URL y fecha de consulta según el estilo exigido por tu universidad (APA/IEEE/Chicago).

1. Pedregosa, F., et al. (2011). _Scikit-learn: Machine Learning in Python_. JMLR, 12, 2825–2830.
2. Liu, F. T., et al. (2008). _Isolation Forest_. IEEE ICDM.
3. Open Information Security Foundation (OISF). _Suricata User Guide_.
4. MongoDB Inc. _MongoDB Manual_.
5. Docker Inc. _Docker Documentation_.
6. Tiangolo, S. _FastAPI Documentation_.
7. IETF (2021). _RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport_.
8. Salesforce Engineering. _JA3/JA3S TLS Fingerprinting_.
9. Chandola, V., Banerjee, A., Kumar, V. (2009). _Anomaly Detection: A Survey_. ACM Computing Surveys.

---

## 8. Anexos

### Anexo A — Playbook de ejecución

```bash
# 1) Levantar entorno
docker-compose down && docker-compose up --build -d

# 2) Activar modo entrenamiento (normal), generar tráfico legítimo
curl -X POST "http://192.168.10.1:8000/training-mode/on?label=normal"
# ... navegar / usar apps ...
curl -X POST "http://192.168.10.1:8000/training-mode/off"

# 3) Activar modo entrenamiento (anomaly), lanzar ataques controlados
curl -X POST "http://192.168.10.1:8000/training-mode/on?label=anomaly"
# ... nmap, hping3, curl flood, etc. ...
curl -X POST "http://192.168.10.1:8000/training-mode/off"

# 4) Consolidar ground truth
docker exec -it cron python generate_ground_truth.py

# 5) Preprocesar features
docker exec -it cron python ml_processing.py

# 6) Entrenar modelo
docker exec -it cron python train_model.py

# 7) Evaluar métricas
docker exec -it cron python evaluate.py

# 8) Generar y recargar reglas
docker exec -it cron python generate_rules.py
```

### Anexo B — Mapa de scripts y artefactos

- `suricata_to_mongo.py` → Ingesta `eve.json` → `db.events` (respeta _training mode_).
- `ml_processing.py` → `/app/models/suricata_preprocessed.csv`.
- `train_model.py` → `isolation_forest_model.pkl` + `suricata_anomaly_analysis.csv`.
- `generate_ground_truth.py` → `ground_truth.csv` (desde MongoDB con etiquetas).
- `evaluate.py` → Precisión, Recall, F1, AUC-ROC.
- `generate_rules.py` → `sml.rules` + recarga `suricatasc` (agregación por IP).
- `routes.py` → Endpoints de control (modo training, reglas, stats, etc.).
- `entrypoint.sh` → Orquestación de arranque.

---

**Fin del documento**
