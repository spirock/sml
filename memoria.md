Memoria Suricata ML
Detección de Amenazas en Redes mediante Machine Learning y Suricata

1. Presentación del Proyecto
   1.1 Motivación
   En el actual entorno digital, la ciberseguridad es un elemento crítico para la continuidad y reputación de las organizaciones. La creciente sofisticación de los ataques y la enorme cantidad de datos que se generan en la red hacen imprescindible contar con soluciones que permitan identificar de forma proactiva actividades maliciosas.
   Este proyecto surge de la necesidad de automatizar la detección de anomalías en el tráfico de red, aprovechando los logs generados por Suricata y aplicando técnicas de machine learning – en concreto, el algoritmo Isolated Forest – para generar reglas de detección que se actualicen de manera dinámica.
   1.2 Objetivos y Alcance
   El objetivo principal es desarrollar un sistema integral que:

- Ingesta y almacenamiento: Recoja los logs de Suricata y los almacene en una base de datos (por ejemplo, MongoDB) para su posterior análisis.
- Procesamiento y análisis: Prepare y procese los datos utilizando técnicas de limpieza y transformación (módulo ml_processing.py), y entrene un modelo de machine learning basado en IsolationForest (módulo train_model.py) para detectar comportamientos anómalos.
- Generación de reglas automáticas: A partir de la detección de anomalías, genere reglas (módulo generate_rules.py) que se puedan implementar en Suricata para mejorar la capacidad de respuesta ante amenazas.
- Monitoreo y orquestación: Coordine la ingesta, el análisis en tiempo real y la actualización de reglas mediante scripts dedicados (como log_watcher.py, suricata_to_mongo.py, y main.py) y ofrezca una interfaz de consulta a través de una API (definida en routes.py).
  El alcance del proyecto incluye desde la recolección y procesamiento de datos hasta la generación de respuestas automatizadas para la protección de la red, permitiendo la integración de técnicas de machine learning en entornos de ciberseguridad.

2. Metodología
   La metodología empleada combina prácticas de desarrollo ágil con un enfoque modular, lo que permite iterar y mejorar continuamente cada componente del sistema. Las fases principales son:

- Planificación y análisis: Definición de requisitos y objetivos, identificando los datos necesarios y estableciendo los indicadores de rendimiento.
- Procesamiento y análisis:
- Desarrollo modular: Implementación de cada uno de los componentes del sistema (conexión a base de datos, ingesta de logs, procesamiento de datos, entrenamiento del modelo y generación de reglas).
- Integración y pruebas: Coordinación de los módulos a través del script principal (main.py) y realización de pruebas de integración para validar el flujo de datos y la efectividad del algoritmo.
- Despliegue y monitoreo: Uso de scripts de arranque (entrypoint.sh y wait-for-it.sh) para garantizar que todos los servicios estén disponibles y operativos, y monitorización continua mediante log_watcher.py.
  Esta metodología permite ajustar rápidamente el sistema ante cambios en el entorno de red y nuevos tipos de amenazas.

3. Descripción del Proyecto
   ￼
   3.1 Arquitectura y Componentes
   El proyecto se estructura en módulos independientes que interactúan para formar un sistema de detección de amenazas:

- db_connection.py: Gestiona la conexión con la base de datos, permitiendo almacenar los logs y resultados del análisis.
- suricata_to_mongo.py: Se encarga de extraer los logs de Suricata y volcarlos en la base de datos.
- ml_processing.py: Realiza el procesamiento de los datos, aplicando técnicas de transformación y normalización para que el modelo pueda interpretarlos correctamente.
- train_model.py: Entrena el algoritmo IsolationForest utilizando los datos procesados, estableciendo patrones normales y detectando anomalías.
- generate_rules.py: A partir de las anomalías detectadas, genera reglas de seguridad que pueden ser implementadas en Suricata para bloquear o alertar sobre posibles ataques.
- log_watcher.py: Monitorea en tiempo real la aparición de nuevos logs y, en consecuencia, activa el proceso de análisis.
- main.py: Funciona como punto de entrada del sistema, orquestando la interacción entre todos los módulos.
- routes.py: Define los endpoints de la API que permiten interactuar con el sistema, consultando resultados y gestionando el flujo de información.
  3.2 Fases de Desarrollo

  El proceso de desarrollo se ha dividido en varias fases bien estructuradas, orientadas a garantizar una detección efectiva y automatizada de amenazas:

  🔹 Recolección de Datos  
   Se diseñó una red de laboratorio virtual en VirtualBox con la siguiente infraestructura:

  - Sensor: Ubuntu Server con Suricata.
  - Clientes: Una máquina Debian y una Windows generando tráfico legítimo.
  - Atacante: Kali Linux desde una red externa lanzando escaneos y ataques simulados.

  Los logs (`eve.json`) generados por Suricata se insertan automáticamente en MongoDB usando el script `suricata_to_mongo.py`.

  🔹 Modo de Entrenamiento Manual  
   El sistema incluye un modo "training" que puede activarse mediante un endpoint de la API (`/toggle-training`). Cuando este modo está habilitado, los ataques generados manualmente (por ejemplo, desde Kali Linux) son detectados por Suricata, y los eventos generados se etiquetan explícitamente como anómalos (`label: 1`). Esta información etiquetada se almacena en MongoDB, sirviendo como fuente de datos valiosa para entrenar el modelo. Gracias a este enfoque supervisado, se logra mejorar progresivamente la capacidad del sistema para reconocer patrones maliciosos con mayor precisión. El etiquetado manual permite ajustar el sistema en función de distintos tipos de amenazas simuladas, consolidando una base sólida para el análisis.

  🔹 Preprocesamiento y Análisis  
   El módulo `ml_processing.py` transforma los eventos en vectores numéricos:

  - Convierte IPs, puertos, protocolos, severidad, longitud de paquetes y hora en características normalizadas.
  - Los datos procesados se exportan a `suricata_anomaly_analysis.csv` y se marcan en MongoDB como procesados.

  🔹 Entrenamiento del Modelo  
   El módulo `train_model.py` entrena el modelo `IsolationForest` con tráfico etiquetado como normal:

  - El modelo detecta outliers sin necesidad de etiquetas manuales.
  - Se calcula el `anomaly_score` y se etiqueta cada evento (`label: 0` normal, `1` anómalo).
  - El entrenamiento se puede activar o desactivar dinámicamente mediante la API REST con la ruta `/toggle-training`.

  🔹 Generación de Reglas  
   El módulo `generate_rules.py` crea reglas Suricata automáticamente:

  - Se generan reglas tipo `alert` o `drop` con IP, puerto, score y severidad.
  - Se evita la duplicación mediante hash SHA-256 y control por `sid`.
  - Cuando una IP escanea múltiples puertos o un único puerto repetidamente, se consolidan en una única regla:
    ```
    drop ip 192.168.10.30 any -> any any (msg:"Detected port scanning activity from 192.168.10.30"; sid:XXXXXX; rev:1;)
    ```

  🔹 Implementación y Monitoreo  
   El sistema completo se orquesta desde `main.py`:

  - Secuencia: Ingesta → Procesamiento → Entrenamiento → Generación de reglas → Recarga automática.
  - `log_watcher.py` vigila MongoDB en tiempo real para disparar la generación de nuevas reglas si se detectan anomalías.
  - Las reglas generadas se aplican sin reiniciar Suricata gracias a `suricatasc -c reload-rules`.

  🔹 Evaluación del Rendimiento  
   Se utiliza `evaluate.py` junto con el archivo `ground_truth.csv` para comparar resultados del modelo:

  - Se calculan métricas clave como precisión, recall, F1-score y ROC AUC.
  - El archivo `evaluate.py` combina los eventos detectados con el ground truth y permite validar objetivamente la efectividad del sistema.

  3.3.1 Características utilizadas para el entrenamiento del modelo

Para alimentar el modelo de aprendizaje automático (Isolation Forest), se realizó un proceso de extracción y transformación de datos con el objetivo de convertir los eventos de red en vectores numéricos significativos. Las características seleccionadas fueron:
• src_ip y dest_ip: Direcciones IP de origen y destino, convertidas a enteros para poder ser interpretadas por el modelo.
• proto: Protocolo de red (TCP, UDP, ICMP…), codificado de forma numérica.
• src_port y dest_port: Puertos involucrados en la conexión, tanto de origen como de destino.
• alert_severity: Nivel de severidad de la alerta detectada por Suricata.
• packet_length: Longitud del paquete capturado.
• hour: Hora del día en que se generó el evento, útil para identificar patrones por franja horaria.
• is_night: Indicador binario que marca si el evento ocurrió en horario nocturno (antes de las 07:00 o después de las 20:00).
• ports_used: Número de puertos únicos utilizados por cada IP de origen.
• conn_per_ip: Número de conexiones que realizó cada IP de origen.

---

### 4. Justificación de las Tecnologías Utilizadas

Se seleccionó **Suricata** como motor de detección de intrusos por su capacidad de análisis en tiempo real, soporte para reglas personalizadas y su amplio uso en entornos profesionales. Frente a alternativas como Snort o Zeek, Suricata ofrece un mayor rendimiento multi-hilo y una salida de logs en formato JSON, lo que facilita su integración con bases de datos como MongoDB.

El algoritmo de machine learning elegido fue **IsolationForest**, por su eficacia en tareas de detección de anomalías sin necesidad de un conjunto de datos completamente etiquetado. Comparado con otras alternativas como One-Class SVM o Autoencoders, IsolationForest ofrece un bajo coste computacional, alta capacidad para identificar outliers en grandes volúmenes de datos, y facilidad de implementación en entornos en tiempo real.

MongoDB fue seleccionada por su flexibilidad en el manejo de documentos JSON (como los generados por Suricata) y su escalabilidad horizontal, lo cual permite adaptarse fácilmente a diferentes volúmenes de tráfico de red.

---

### 5. Limitaciones del Sistema

Durante el desarrollo se identificaron algunas limitaciones:

- El sistema depende de un modo de entrenamiento manual inicial para etiquetar tráfico malicioso, lo cual requiere intervención del analista.
- Actualmente no se realiza análisis de tráfico cifrado (HTTPS), lo que podría ocultar ciertos tipos de amenazas.
- No se cuenta con un mecanismo de verificación de firmas externas ni integración directa con sistemas SIEM.
- La calidad del modelo depende de la representatividad de los datos normales capturados durante el entrenamiento.

Estas limitaciones no impiden su uso efectivo, pero son relevantes al considerar su aplicación en entornos productivos.

---

### 6. Trabajo Futuro

Este proyecto sienta las bases para futuras extensiones. Entre las mejoras propuestas se incluyen:

- Entrenamiento continuo del modelo para adaptarse a cambios en el comportamiento de red.
- Uso de modelos más avanzados, como Autoencoders o redes neuronales recurrentes (RNN) para detección de ataques complejos.
- Inclusión de análisis de comportamiento en capas superiores (L7), como protocolos HTTP o DNS.
- Integración con herramientas SIEM como ELK o Wazuh para ampliar las capacidades de correlación de eventos.
- Aplicación de técnicas de aprendizaje semi-supervisado o activo para mejorar el etiquetado.

---

### 7. Análisis del Rendimiento Computacional

El modelo IsolationForest mostró un buen desempeño en entornos con recursos limitados. Durante las pruebas:

- El entrenamiento inicial con aproximadamente 1000 eventos tarda menos de 10 segundos.
- La evaluación de eventos y la generación de reglas se completa en menos de 1 segundo por batch de eventos.
- La recarga de reglas en Suricata mediante `suricatasc` es inmediata, sin requerir reinicios del servicio.

Estas métricas hacen viable su uso tanto en entornos de laboratorio como en redes pequeñas o medianas.

---

### 8. Consideraciones Éticas y de Privacidad

Este sistema fue diseñado para operar en entornos controlados. Sin embargo, en escenarios reales se deben considerar aspectos como:

- La anonimización de direcciones IP y puertos al compartir logs para entrenamiento o evaluación.
- La obtención del consentimiento de los usuarios si el tráfico proviene de redes de producción.
- El almacenamiento cifrado de logs históricos para prevenir accesos no autorizados.

La implementación de estas prácticas garantizará el cumplimiento con normativas como el RGPD en entornos europeos.

---

### 9. Ejemplos de Reglas Generadas

A continuación, se muestran ejemplos reales de reglas generadas automáticamente:

```suricata
# Regla para tráfico anómalo identificado en múltiples puertos
drop ip 192.168.10.30 any -> any any (msg:"Detected port scanning activity from 192.168.10.30"; sid:2722469; rev:1;)

# Reglas específicas para conexiones sospechosas
alert tcp 192.168.10.30 26838 -> 192.168.10.1 22 (msg:"suspicious traffic (score: -0.08, len: 0, severity: 0)"; sid:1001498; rev:1;)
alert tcp 192.168.10.30 26842 -> 192.168.10.1 22 (msg:"suspicious traffic (score: -0.08, len: 0, severity: 0)"; sid:1001499; rev:1;)
```

Estas reglas son generadas con un control hash sobre las combinaciones origen/destino para evitar duplicaciones y asegurar la integridad del archivo `sml.rules`.

6. Resultados y Evaluación
   Durante la fase de pruebas se ha observado que el uso de IsolationForest permite detectar con eficacia anomalías en el tráfico de red, lo que se traduce en la identificación temprana de posibles ataques. La arquitectura modular facilita la integración y actualización del sistema, y la generación automática de reglas ha mostrado un alto grado de precisión en la detección de comportamientos anómalos.
   Se realizaron pruebas de rendimiento que demostraron que el modelo es escalable y rápido, siendo capaz de procesar grandes volúmenes de datos en tiempo real. Además, la interfaz de consulta implementada mediante la API permite a los operadores monitorear el estado de la red y reaccionar ante alertas de seguridad de forma inmediata.

7. Conclusiones
   El proyecto ha permitido integrar técnicas de machine learning en un entorno operativo de ciberseguridad, aportando una solución innovadora para la detección y mitigación de amenazas en tiempo real. Entre las principales conclusiones se destacan:

- Efectividad del Algoritmo: IsolationForest se muestra como una herramienta eficaz para detectar anomalías sin requerir datos etiquetados, lo cual es ideal para entornos dinámicos.
- Arquitectura Modular: La separación en módulos facilita el mantenimiento y la escalabilidad del sistema, permitiendo actualizaciones y mejoras continuas.
- Automatización de Reglas: La generación automática de reglas a partir de los análisis posibilita una respuesta rápida y adaptativa ante nuevos tipos de amenazas.
- Contribución a la Ciberseguridad: Este enfoque proactivo no solo mejora la detección de ataques, sino que también aporta información valiosa para la toma de decisiones estratégicas en la gestión de la seguridad.
  Este sistema representa un avance significativo en la automatización de la seguridad de redes, sentando las bases para futuras mejoras y la integración de técnicas adicionales de machine learning que puedan adaptarse a la evolución constante del panorama de amenazas.
