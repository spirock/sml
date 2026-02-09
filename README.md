# Generador Automático de Reglas para Suricata con Machine Learning

## Descripción
Este proyecto desarrolla un sistema inteligente capaz de analizar eventos de red detectados por **Suricata**, identificar patrones de tráfico sospechoso mediante **Machine Learning**, y generar automáticamente reglas optimizadas que mejoran la detección de amenazas y reducen falsos positivos.

El objetivo principal es automatizar el proceso de creación y optimización de reglas IDS/IPS, facilitando la gestión de seguridad en entornos empresariales y de investigación.

---

## Objetivos
- Analizar logs de Suricata en tiempo real.
- Detectar anomalías en tráfico de red mediante modelos de Machine Learning.
- Generar automáticamente reglas Suricata basadas en patrones detectados.
- Aplicar y validar reglas generadas de forma automática.
- Reducir falsos positivos y mejorar la precisión de detección.

---

## Arquitectura del Sistema
1. **Captura de tráfico**
   - Suricata genera eventos en `eve.json`.

2. **Procesamiento de eventos**
   - FastAPI procesa los eventos generados.
   - Los eventos se almacenan en la base de datos.

3. **Análisis con Machine Learning**
   - Modelos de detección de anomalías (Isolation Forest inicialmente).
   - Identificación de patrones sospechosos.

4. **Generación automática de reglas**
   - Conversión de patrones detectados en reglas Suricata.
   - Validación automática de reglas generadas.

5. **Aplicación de reglas**
   - Integración directa con Suricata para recarga dinámica de reglas.

---

## Tecnologías Utilizadas
- **IDS/IPS:** Suricata
- **Backend:** FastAPI (Python)
- **Machine Learning:** Scikit-Learn, TensorFlow (futuras versiones)
- **Base de datos:** MongoDB / PostgreSQL
- **Contenedores:** Docker
- **Procesamiento de tráfico:** Scapy / Tshark

---

## Funcionalidades Principales
- Captura de eventos de seguridad en tiempo real.
- Almacenamiento y consulta avanzada de logs.
- Detección automática de tráfico anómalo.
- Generación automática de reglas Suricata.
- Aplicación dinámica de reglas sin reiniciar el sistema.

---

## Flujo de Funcionamiento
